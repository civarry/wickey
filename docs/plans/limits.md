# Plan: per-key limits, activity log, auto-renew

Status: approved 2026-10-23, including D10 (auto-renew) with the conditions below and D3 defaulting
to refuse. Proxy keys today limit time, not damage: within its lifetime a runaway or hijacked agent
can call any model and spend without limit.

## What exists today

- Scopes, usage tracking, activity log, auto-renew: none. The proxy pipes request and response
  bodies straight through.
- Threat-model docs: README "What this protects, and what it doesn't" and SECURITY.md exist; they
  get updated, not rewritten.

## Where the signing key lives

Rows are signed with an HMAC key derived (HKDF) from the vault's data key. On disk the data key
exists only encrypted in `vault.json` under a scrypt key from the passphrase, so reading files gives
a local program nothing to sign with. In memory it exists only in the running proxy after unlock. A
program running as the same user that attaches a debugger to the proxy (possible without root on
macOS) could extract it and forge signatures; nothing purely local prevents that.

## Decisions

| # | Decision |
|---|---|
| D1 | Add `stream_options.include_usage` only for token-capped keys. If the provider rejects it, retry once without it (before any bytes reach the client) and mark the credential as not reporting streaming usage (then D3 applies). Must never break the agent's request. |
| D2 | Meter a zlib-decompressed side copy; the client gets the original bytes unchanged. |
| D3 | Each credential remembers whether its provider reports usage (and streaming usage). Setting a token cap on a credential known not to report shows a warning in the issue form and an option "Refuse requests when usage can't be counted" (default on). Unexpected missing usage: refusing keys block, others run marked "uncapped". |
| D4 | Caps stop new requests; requests in flight finish, so a key can overshoot by what's in flight. Documented. |
| D5 | Exact model IDs (wildcards later). With an allowlist, only bodiless GET requests may omit a model; any other request whose model can't be read is refused. |
| D6 | Tightening a limit needs no passphrase; loosening or removing one does. |
| D7 | Limits and running usage totals are in the HMAC row signature. While running, the proxy keeps each key's latest totals in memory and refuses a key whose stored totals went backwards. Remaining gap: rolling the DB back across a restart (requires stopping the proxy and the user unlocking again). |
| D8 | Activity log: last 500 requests per key and at most 30 days; metadata only (time, model, status, tokens in/out, duration). Never prompt or response content, no option to log it. Totals kept separately so pruning never loses them. |
| D9 | Rate limit: in memory, sliding one-minute window; resets on restart (which needs the passphrase). |
| D10 | Auto-renew: opt-in, requires a hard maximum lifetime; extends by one lifetime only when used within N minutes of expiry, never past the maximum; never mints a new key; enabling needs the passphrase. Approved because the passphrase holder approves the hard maximum at issuance: auto-renew never grants more than a human approved, it only lets an idle key die sooner than an equivalent long-lived key. Conditions: (a) never renew a key that is expired/revoked, has hit any limit, or is flagged "usage counters went backwards"; (b) only requests actually forwarded upstream count as use, refused requests don't keep a key alive; (c) every renewal is written to the activity log, and the dashboard shows "auto-renews until <max>" on the key; (d) docs state plainly that with auto-renew, the hard maximum is the real lifetime being approved. |
| D11 | Spend cap: deferred. Prices would have to be user-entered per credential and model; a bundled table goes stale or needs network calls. |

## Tasks

| # | Task | Who | Depends on |
|---|---|---|---|
| 1 | Storage + migration + signed limits/totals, request log table, per-credential usage flags, API (issue/edit limits under D6, recent requests), CLI flags and `limits` command | Sonnet | none |
| 2 | Enforcement + metering in the proxy: body read only for limited keys, allowlist, rate limit, usage parsers (OpenAI chat + Responses, Anthropic; stream and non-stream), D1 retry, D3 fail-closed, D7 high-water check, activity log, OpenAI/Anthropic-style errors | Sonnet | 1 |
| 3 | Auto-renew with the hard maximum and D10 conditions (a)-(d) | Sonnet | 2 |
| 4 | Dashboard: limits in issue form (with D3 warning), edit limits, "Limit reached", totals, last used, recent requests | Sonnet | 1-3 |
| 5 | Red team against the limits (read-only) | Sonnet | 2, 3 |
| 6 | Checks, browser test, docs (README, SECURITY.md, ARCHITECTURE.md), commit | Haiku + me | 4, 5 |

## Constraints

Zero runtime dependencies; no network calls except to the configured providers; existing keys keep
working with no limits; tests for every enforcement path.

## Status (2026-10-23)

Tasks 1-6 are done: storage and signed limits, enforcement and metering, auto-renew, dashboard, red
team, docs. Red-team findings A-H were fixed, and the
passphrase gate held (see SECURITY.md for the list).

Known gaps that remain:

- Restoring an older database across a restart is not detected, and restarting accepts the older
  data. For a flagged key, rotate or delete it instead of restarting.
- A same-user program that reads the proxy's memory could extract the signing key and forge rows.
- The red team ran against mock providers, not real ones.
- Caps stop new requests only; overshoot is bounded by in-flight reservations, not zero.
- Providers that report no usage run uncounted on keys that allow it.

Deferred: spend caps in money (D11).
