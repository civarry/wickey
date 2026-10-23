# Architecture

wickey is a local HTTP server on `127.0.0.1` that swaps a short-lived proxy key for a real
provider key and forwards the request. Node 24 runs the TypeScript directly; there are no runtime
dependencies.

## Module map

| File | Role |
| --- | --- |
| `bin/wickey.js` | Entry point; imports `dist/cli.js` in the published package (compiled on pack), `src/cli.ts` in a checkout |
| `src/cli.ts` | Commands. Read-only ones read SQLite; state changes call the running proxy's API |
| `src/proxy.ts` | HTTP server: `/health`, then the dashboard and API, then `/p/<id>/...` forwarding |
| `src/api.ts` | Dashboard page and `/api/*`, with Host, Origin and header checks |
| `src/session.ts` | Setup, unlock, sign-in, in-memory sessions, grace period, `requireAuth`, wrong-passphrase throttle |
| `src/vault.ts` | Encrypted `vault.json`, the in-memory keys, row-signing HMAC |
| `src/events.ts` | Security event log (`events.log`): hash-chained, MAC-authenticated JSON Lines, `verifyLog`, `listEvents`, `checkpoint`. `src/audit.ts` is the call-site helper (`logEvent`, the `via` label); session.ts and api.ts emit the events |
| `src/store.ts` | SQLite (`node:sqlite`): credentials, proxies, usage totals, request log, row signatures, issue/renew/rotate, limits, auto-renew |
| `src/metering.ts` | Usage parsing (JSON and SSE, OpenAI and Anthropic shapes), the decoded response side copy, rate limiter, in-flight reservations, usage high-water marks, error bodies in OpenAI or Anthropic format |
| `src/prompt.ts` | Hidden passphrase prompt (and a visible one for confirmations) via `/dev/tty` or `CONIN$` |
| `src/reset.ts` | `wickey reset`: read-only plan (counts), proxy-running check, deletion of vault and DB files. CLI only |
| `src/netguard.ts` | Destination rules for base URLs: classification at save time, plus the `lookup` guard that validates what a name resolves to at connect time (used by `proxy.ts` and `models.ts`) |
| `src/providers.ts` | Provider presets: base URL, auth style, env var prefix, and the detection hints the .env import reads (key and base URL variable names, key prefixes, hosts) |
| `src/credimport.ts` | Dry run and import behind `POST /api/credentials/import`: reuses `checkNewCredential` and `addCredential`, finds already-stored keys by SHA-256 digest |
| `src/brand.ts` | Every product name used for files and OS integration (command, data dir, DB file, env prefix, launchd label, systemd unit, Windows task, log names) and `envVar()`. Wire formats are deliberately not here |
| `src/config.ts` | Home directory, DB path, log paths, host and port, read from env at call time |
| `src/service.ts` | `service install / uninstall / status`: plist, systemd unit and `schtasks` generation, and the OS calls through an injectable `run` (tests and `WICKEY_SERVICE_DRYRUN=1` never reach the real tools) |
| `src/logfile.ts` | Rotating log writer (1 MB x 3), stdout/stderr redirection for `start --service`, secret redaction, permission hardening |
| `src/setup.ts` | `wickey setup`: the guided walkthrough; hosts a proxy in-process when none is running |
| `src/ttl.ts` | Parses lifetimes such as `30s`, `5m`, `2h`, `1d` |
| `web/` | Dashboard: Svelte 5 + Vite + Tailwind v4. `src/app.css` holds every design token, `src/lib/api.ts` every API call, `src/lib/components/` the shared components, `src/lib/pages/proxies/` the Proxies page, `src/lib/pages/activity/` the Activity page (request log across proxies, filters kept in the URL hash) |
| `test/*.test.ts` | `node:test`. `security.test.ts` plays a local attacker |

## Request flow for a proxied call

```
client  --  POST /p/<id>/chat/completions  (Authorization: Bearer sk-wick-...)
   |
   v
proxy.ts  /health?  -> api.ts (dashboard, /api/*)?  -> match /p/<id>/<path>
   |
   v
store.authorize(id, token)
   - vault is unlocked (otherwise 503)
   - proxy row exists and its HMAC signature verifies
   - SHA-256(token) matches the stored hash (constant-time compare; the key itself is never stored)
   - not expired (checked when the request starts)
   - credential row signature verifies (otherwise 502)
   |
   v
netguard.classifyBaseUrl(credential.baseUrl)   (403 for rows saved before the rules: metadata
   |                                              hosts, the proxy itself, plain http to a public host)
   v
vault.getSecret(credential id)   (500 if the entry is missing or was tampered with)
   |
   v
strip client auth and hop-by-hop headers, add the real key
(Authorization: Bearer or x-api-key, per the credential), set Host to the upstream
   |
   v
https request to the credential's base URL + <path>; response piped back unbuffered
```

Notes:

- The proxy reads the database on every request, so `expire`, `renew` and `rotate` take effect at once.
- What happens after `authorize` depends on whether the key has limits. See the next section.
- A stream that is already running is allowed to finish after expiry.
- Redirects from the upstream are passed to the client, not followed.
- If the client disconnects mid-stream, the upstream request is destroyed.
- Any exception while handling one request becomes a 500 for that request only.

Connect time: the upstream request carries `netguard.guardedLookup`, which resolves the name,
refuses the request if any answer is a metadata, link-local or unspecified address (or loopback on
the proxy's own port), and connects to exactly the addresses it checked. The model-list fetch in
`models.ts` uses the same guard.

## Limited and unlimited keys

A key is limited if it has an allowlist, a rate or a token cap. Auto-renew alone does not make it
limited.

**Allowed models** has three modes, stored in the signed `proxies.allowed_models` column: Selected (a
JSON array of exact IDs), None (`[]`, every request refused, even a bodiless GET) and All (`NULL`).
All means "any model the credential's provider lists". `src/models.ts` fetches the list with the
real key (`/models`, or paginated `/v1/models` for Anthropic; 10 s timeout, 5 MB and 5000-ID caps)
and caches it in `credential_models`. A request for a model not in the cache triggers one refresh,
shared by all concurrent callers (single-flight) and allowed at most once per 60 s per credential;
if the model is still missing it is refused. A key in All mode with a known list is treated like
an allowlist key for body handling (buffered, parsed, URL-named models refused). If the provider
definitively has no list (HTTP 404/405/501 only), the credential is marked
`unavailable` and All keys pass models through as before; transient failures (timeouts, 5xx, 401)
and a 2xx whose body is not a readable list (HTML, junk JSON; `{data:[...]}` and a bare array are
accepted) refuse instead. The dashboard's forced refresh is also limited to once per 10 s per credential.
URL paths that name a model (`deployments`, and a segment after `models`, `engines` or `model`) are refused. Editing the base URL, auth style or key drops the cached list.

**Unlimited keys** are streamed untouched: the request body is piped through and the response is
piped back unbuffered. Metering is passive. The request body is peeked at (up to 2 MB) only to log
the model, and the response is read from a decoded side copy (`ResponseMeter`) that can't slow or
alter what the client receives. After the response ends, `account()` adds the usage to the totals,
writes an activity log row and checks auto-renew.

**Limited keys** go through these steps in `proxy.ts` before anything is forwarded:

1. Integrity: stored usage totals must verify, and the key must not be flagged as rolled back
   (403 `usage_rollback`).
2. Rate: `RateLimiter.peek` (429 `rate_limit_exceeded`, with `Retry-After`).
3. Token cap, against recorded usage (429 `token_cap_reached`).
4. Allowlist (or All with a known list) and URL: a path naming a model or deployment is refused (403 `model_not_allowed`).
5. Read the body, at most 10 MB (413 `request_too_large`). A key with an allowlist or token cap
   needs a UTF-8 JSON object (400 `invalid_body`) and then the model is checked. Anything truthy in
   `stream` becomes `true`.
6. For a token cap on a refusing key: unmetered endpoints and providers known not to report usage
   are refused (403 `usage_uncountable`).
7. For a token cap: stream requests on `*/completions` get `stream_options: {include_usage: true}`
   (the client's are replaced), and `accept-encoding` is set to what the meter can decode.
8. Reservation: at most 8 in flight, and recorded usage plus reserved tokens must stay under the
   cap. The request then reserves its `max_tokens` (or 4096). Only now is the request counted
   against the rate (`RateLimiter.take`), in the same synchronous step so parallel requests can't
   all pass.
9. The body is re-serialized (allowlist or cap keys only; a rate-only key forwards its bytes
   untouched) and sent.

On the way back, the final `end()` waits for accounting, so the next request from the same client
already sees the new totals. If the provider rejects the injected `stream_options` (400 or 422
mentioning it), the response is held back: a key that allows uncounted usage retries once without
the option, and a refusing key gets 403 `usage_uncountable`. If the client disconnects, a capped
key keeps reading the provider's response for up to 10 minutes so the final usage is still seen.
Other keys destroy the upstream request.

Refusals are written to the activity log but never counted as usage, and never trigger auto-renew.
Auto-renew runs in `account()` after the usage is recorded, only when the provider answered
(`renewIfDue` in `store.ts` re-verifies the row, and declines a key at its token cap).

### In-memory state

Held per proxy in the running process, gone on restart: the rate window, the in-flight
reservations, the highest usage totals seen (`checkHighWater` / `observeUsage` in `metering.ts`),
the highest row version seen (`versionHigh` in `store.ts`), and the set of keys flagged as rolled
back. A limited key whose usage totals drop below the mark is refused (403 `usage_rollback`), and an
unlimited one is flagged so it can't auto-renew. A row version that drops is refused for every
key, since an old row can revive an expired key or loosened limits. Because this lives in
memory, it cannot catch a database restored while the proxy was stopped.

## The CLI goes through the running proxy

Only the running proxy holds the unlocked vault keys, and they exist only in its memory. So every
command that changes state (`add`, `edit`, `remove`, `issue`, `env`, `renew`, `rotate`,
`expire`, `delete`, `limits`, `models`, `passphrase`, `lock`, `unlock`) calls `/api/*` on the proxy.
Each one first asks for the passphrase, trades it for a session (`POST /api/signin`, or
`/api/unlock` when the proxy restarted and is locked), keeps the cookie in process memory only,
and ends the session (`POST /api/signout`) when the command finishes. `setup` signs in once for
its whole walkthrough. The passphrase typed is also sent with a mint when the grace period is off.
Reasons:

- The data key is never written to disk, so a separate CLI process cannot sign rows or decrypt keys.
- Rows are re-signed by the one process that can sign them, right after each write.
- One place enforces the passphrase gate (`requireAuth`), instead of one per command.

`list`, `creds` and `show` only read, so they open the SQLite file directly and work when the
proxy is stopped. They never print a key: only a hash is stored, and `show` prints the masked form. The CLI collects the passphrase through `prompt.ts`, which reads the terminal
directly so it works inside `eval "$(wickey env ...)"`. With no terminal it cannot ask, so
it fails with a message instead of minting.

## Data at rest

Everything lives in `WICKEY_HOME` (default `~/.wickey`). The directory and `logs/` are
mode 700; the vault, database and log files are 600, tightened at every `start`.

`start --service` is how the start-on-login definitions run the proxy: no prompts (it starts
locked), and stdout/stderr are replaced by a `RotatingLog` at `logs/wickey.log` while the
OS-level streams point at `/dev/null`. Tests override the label (`WICKEY_SERVICE_LABEL`), the
definition directory (`WICKEY_SERVICE_DIR`), the platform (`WICKEY_SERVICE_PLATFORM`) and
dry-run mode (`WICKEY_SERVICE_DRYRUN=1`).

### events.log (mode 600, append-only)

One JSON object per line: `{ seq, ts, type, data, prev, hash, mac }`. `hash` is SHA-256 over a
canonical (sorted-key) JSON of `{seq, ts, type, data, prev}`; `prev` is the previous entry's hash
(a fixed genesis string for the first). `mac` is HMAC-SHA256 of `hash` under a third HKDF subkey of
the data key (`.../events`, `eventMac` / `verifyEventMac` in `vault.ts`), or `null` when the vault
was locked. Writes use `O_APPEND` and never rewrite the file. Entries made while locked stay
unsigned until the next unlock, when `checkpoint()` appends a signed `checkpoint` entry; because of
the chain, its MAC authenticates everything before it. `verifyLog()` recomputes hashes, links and
sequence numbers and checks every MAC while unlocked. `data` holds ids, names and limits only.

`wickey reset` keeps this file and appends an unsigned `reset` entry. The old key is gone, so older
MACs are reported as `before_reset` (not verifiable), not as tampering. A real reset fails every old
MAC; a mix of passing and failing old MACs before a `reset` is reported as tampering (someone
inserting a fake reset). `GET /api/events?before=<seq>&limit=<n>` (session required, default 50,
max 200, newest first) returns entries with a `trust` field plus the `verifyLog` summary.

Events written by actions (`data` is ids, names and limits only; `via` is `dashboard`, `cli`,
`terminal` or `setup_link`). One action writes one event, with `auto_renew_enabled` as the one
companion event:

| Type | Emitted in | Data |
|---|---|---|
| `vault_created` | `setUp` (session.ts) | via |
| `unlocked` / `signed_in` | `unlock`, `signIn` | via. `unlocked` = locked to unlocked; `signed_in` = a session made while already unlocked |
| `unlock_failed` | `recordAttempt` (unlock, sign-in, passphrase change, gated actions) | via |
| `passphrase_throttled` | `checkThrottle` | once per throttle window |
| `locked`, `passphrase_changed` | `lock`, `changePassphrase` | via |
| `reset` | `performReset` (reset.ts) | credentials, proxies (unsigned) |
| `key_issued` | api.ts `logMint`: issue, env, rotate | proxyId, credential, label, via, op, models (`all`/`none`/count), rpm, tokenCap, autoRenew, unlimited |
| `key_renewed` | api.ts renew (same key, no mint) | proxyId, via |
| `limits_loosened` / `limits_tightened` | api.ts limits PATCH (uses `isLoosening`) | proxyId, via, before, after (text summaries) |
| `auto_renew_enabled` | issue/env or a limits change that turns it on | proxyId, via, window, maxLifetime (seconds) |
| `credential_added` / `credential_changed` / `credential_removed` | api.ts | name, provider, baseUrlHost, via; changed adds fields, keyReplaced, baseUrlChanged |
| `credentials_imported` | api.ts import (not dry runs) | count, via |

`via` comes from the `x-wickey-via: cli` request header the CLI sets (anything else counts as
`dashboard`); `setUp`/`unlock` called in a terminal default to `terminal`, and the setup link
passes `setup_link`. It is a display label: a local program can send any value, so it is not proof.
Logging is a record, not a gate (`logEvent`): a failed write never blocks unlock, sign-in or lock
(silent), and for minting and credential changes it prints one line to stderr and carries on.

### vault.json (mode 600, written by atomic rename)

```
{
  "version": 1,
  "kdf":  { "name": "scrypt", "salt": ..., "N": 131072, "r": 8, "p": 1 },
  "dk":   { iv, tag, data },            data key, AES-256-GCM under the passphrase-derived key
  "secrets": { "<credential id>": { iv, tag, data }, ... }
}
```

- A random 32-byte data key (DK) does the real work. It is stored encrypted under a key derived
  from the passphrase with scrypt, so changing a passphrase only means re-wrapping the DK.
- Two subkeys come from the DK via HKDF-SHA256: one encrypts secrets, one signs database rows.
- Each secret is an AES-256-GCM box whose additional authenticated data includes the credential
  id (`wickey/v1/secret/<id>`), so moving one credential's box onto another fails to decrypt.
- The DK box is authenticated too, so editing `kdf` parameters (for example to weaken scrypt)
  makes the wrong key and the unwrap fails.
- Real keys and the DK are never written to disk in plaintext.

### wickey.db (SQLite, mode 600; the -wal and -shm files are tightened to 600 too)

| Table | Columns of note |
| --- | --- |
| `credentials` | `id`, `name`, `provider`, `base_url`, `auth_style`, `sig` |
| `proxies` | `id`, `label`, `credential_id`, `token_hash`, `token_tail`, `ttl_seconds`, `expires_at`, `revoked_at`, `allowed_models`, `rpm`, `token_cap`, `refuse_uncounted`, `renew_window_s`, `max_expires_at`, `version`, `sig` |
| `proxy_usage` | `proxy_id`, `requests`, `tokens_in`, `tokens_out`, `uncounted`, `last_used_at`, `sig` |
| `credential_models` | Cached provider model list per credential: `credential_id`, `models` (JSON), `fetched_at` (last attempt), `error`, `unavailable`. Unsigned (see SECURITY.md) |
| `requests` | Activity log: `proxy_id`, `at`, `model`, `status`, `tokens_in`, `tokens_out`, `duration_ms`, `refused_reason`, `event`, `renewed_to`. Unsigned, metadata only |

- The proxy key itself is never stored; it exists only in the issue/rotate response. `token_hash`
  is SHA-256 of it (signed), and `token_tail` is its last 5 characters, kept so lists can show
  `sk-wick-…xxxxx` (unsigned, display only). Real provider keys are never in this file.
- Opening a database from an earlier version copies each old plaintext `token` to `token_tail`
  (last 5 characters), drops the `token` column, then runs `VACUUM` and a WAL truncate. The hash
  already existed and the signature covers only the hash, so no row is re-signed and old keys keep
  working. A key issued before plaintext was ever stored (no tail) shows as `sk-wick-…`.
- Requests are checked against `token_hash` (SHA-256, constant-time compare).
- `sig` is an HMAC-SHA256 over the fields that matter:
  - credential: `id | provider | base_url | auth_style`
  - proxy: `id | credential_id | token_hash | expires_at | revoked_at`, plus the limit and
    auto-renew fields when any is set, plus `version` and `ttl_seconds` once the row has been
    written. Each write bumps `version`. Old rows keep verifying in their old format.
  - usage: `proxy_id | requests | tokens_in | tokens_out | uncounted | last_used_at`
- `credentials` also has `usage_reporting` and `stream_usage`: hints about whether the provider
  reports usage. They are unsigned and only set from responses to requests the proxy built itself.
  They make the proxy refuse earlier on a refusing key; nothing is loosened because of them.
- The activity log keeps 500 forwarded rows (including renewal events) and 200 refused rows per
  key, none older than 30 days. Usage totals live in `proxy_usage` so pruning never loses them.
- A row that fails verification is refused: a bad proxy gets no access, and a bad credential is
  never sent a real key. Every write to these tables is followed by a re-sign.

## Session, grace period and throttle

All in `src/session.ts`, in memory only.

- **Unlock** derives the key from the passphrase and holds the data key in process memory.
  After a restart the proxy is locked and proxy keys return an error until someone unlocks.
- **Refusals that need a human** (no terminal; missing session, passphrase or setup token) are worded by
  `humanRequired()` in `src/human.ts`: "This must be done by a human. If you are an AI agent, stop and ask
  the user to …" with the exact command (CLI: argv echoed back). API errors keep their `code` and add
  `humanRequired: true`. A nudge for cooperating agents, not a control.
- **Setup token.** `POST /api/setup` needs `token`, made by `openSetup()` when `start` runs with no
  vault and no terminal, and printed only as `http://127.0.0.1:<port>/#setup=<token>` on its stdout
  (never in service mode, whose log any same-user program can read). Memory only; `setUp()` clears
  it whichever path set up the vault. The dashboard's `main.ts` moves it from the hash into
  `app.setupToken` before the router runs (and on `hashchange`, for a link pasted into an open tab).
- **Sessions.** Every `/api` route needs one except `GET /api/session-status` (vault, unlocked,
  signedIn: nothing else), `POST /api/setup`, `POST /api/unlock`, `POST /api/signin` and `POST /api/lock` (lock is harmless: if it ever also
  locks the vault or stops traffic, it must leave this list). A session
  is a 256-bit random id, held in a map keyed by its SHA-256 (so memory never holds a usable
  cookie), created only by those three passphrase routes, and sent as the cookie
  `wickey_session` with `HttpOnly; SameSite=Strict; Path=/` (no `Secure`: the dashboard is
  plain http on loopback). Idle expiry is 12 hours, pushed back on each use; at most 100 live at
  once (oldest dropped). Lock clears them all; a restart does too. A missing or unknown cookie is
  401 `session_required`, which the dashboard answers by showing the sign-in screen.
  `POST /api/signin` needs an already unlocked vault and goes through the same throttle as unlock.
- **Grace period.** After a correct passphrase, minting works without it for `WICKEY_GRACE`
  seconds (default 300, `0` disables). Like `sudo`. It only helps a request that has a session.
- **`requireAuth(passphrase?)`** passes if a correct passphrase is given, or if the vault is
  unlocked and the grace period is running. Otherwise it throws `passphrase_required` (or
  `setup_required` if no vault exists). The API turns that into a 401.
- **Locking** (`wickey lock`, "Lock now", no session needed) ends the grace period and clears every session. The
  vault stays unlocked and existing proxy keys keep working.
- **Throttle.** After 5 wrong passphrases, each further attempt waits twice as long as the last,
  capped at 5 minutes; the API answers 429. A correct passphrase resets the count.
  State is in memory, so a restart resets it.

- **Changing the passphrase** (`POST /api/passphrase {current, next}`, `changePassphrase` in
  `session.ts` and `vault.ts`) never uses `requireAuth` or the grace period: it verifies `current`
  against `vault.json` through the throttle, re-wraps the same data key with a fresh salt, and
  writes the file atomically (temp file 0600, fsync, rename). The data key is unchanged, so
  secrets and row signatures stay valid and nothing is re-encrypted. It then ends the grace
  period. The 12-character minimum applies to the new passphrase only, never to unlocking.
  Old copies of `vault.json` still open with the old passphrase.
- **Reset** is CLI-only (`src/reset.ts`): it refuses while a proxy answers `/health` on the
  configured port, deletes `vault.json` and the database files (the schema is recreated on the
  next start, which keeps migrations simple), and leaves the directory.

What goes through `requireAuth`: issue, rotate, renew, `env` (every run mints), add and edit
credential. What does not: expire, delete, remove (they only remove access); they still need a session.

`env` (`store.mintEnvProxy`) mints a new proxy on every run with the template name as its label,
then marks that label's expired proxies `cleaned_at` (hidden from lists, row and activity log kept;
unsigned because it only affects display; renew and rotate refuse them). Several active proxies may share a label, one per
terminal; nothing is reused or revived. A rejected request (bad limit, bad TTL) cleans nothing,
because the mint happens first.

## Dashboard and its API checks

The page is a Svelte 5 + Vite + Tailwind build from `web/` (output in `web/dist`, built by
`npm run build`, which `npm install` runs automatically). `api.ts` serves `index.html` at `/` and
flat files from `/assets/` (plain file names with a known type only, so no path can reach outside
the build); if the build is missing, `/` says to run `npm run build`. `/api/*` serves the page and
the CLI. Because any
web page open in the user's browser can send requests to `127.0.0.1`, `api.ts` only answers
requests that are provably from the dashboard, and then only with a session (above):

- `Host` must be `127.0.0.1:<port>` or `localhost:<port>` (defeats DNS rebinding).
- `Origin`, if sent, must be that same address (blocks cross-site form posts).
- `/api/*` also requires the header `x-wickey: 1`, which forces a CORS preflight the server never approves.
  These three checks run before the session check and stay even though the cookie exists: browsers
  treat every port on 127.0.0.1 as one site, so another local web page would be sent the cookie.
- Request bodies are limited to 64 KB, must be a JSON object, and may carry only the fields the
  route reads (plus `passphrase` where it calls `requireAuth`); anything else is a 400 naming the
  field. Base URLs in responses always use `127.0.0.1`, whatever `Host` the dashboard was opened with.
- The dashboard asks `GET /api/session-status` first when it has no data, and shows setup, unlock or
  sign-in from that. Any 401 `session_required` (Lock elsewhere, idle expiry) drops its data and
  returns to the gate. A full proxy key reaches the browser only in the issue/rotate response; the
  Proxies page keeps it in component state for the one-time panel (not in the polled app store) and
  discards it on Done, collapsing the row, leaving for Activity, or sign-out.
- `GET /api/requests?proxy=&status=ok|refused&before=<id>&limit=` (default 50, max 200) reads the
  request log across proxies for the Activity page: `store.requestsPage`, keyset-paged by `id < before`,
  returns `{requests, nextBefore}`. Read-only metadata, so no `requireAuth`, like
  `GET /api/proxies/:id/requests`. An unknown `proxy` is 404, a bad `status`, `before` or `limit` is 400.
- The page is served with a strict `Content-Security-Policy`: `script-src 'self'` and
  `style-src 'self'` with no `unsafe-inline` or `unsafe-eval`, fonts bundled locally, no
  framing. So the frontend uses no inline scripts and no `style="..."` attributes (Svelte's
  `style:` directive is fine, since it sets styles from script). Plus `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` on the page.
- Stored values such as proxy names are rendered as text, not HTML. Proxy names are also
  restricted so the copyable "Shell profile" line cannot carry a shell command.
- The stored real key is never sent back to the browser.
- **Import from .env.** `src/dotenv.ts` (pure, so the dashboard, `setup` and tests all import it) parses the file in the
  tab; unticked and unrelated variables never leave it. `POST /api/credentials/import` takes at most
  50 entries and `dryRun: true|false`. Both modes go through `requireAuth`, because even a preview
  reveals whether a key is already stored. Each entry is validated like a normal add, handled on
  its own (`imported`, `would_import`, `duplicate_key`, `duplicate_name`, `invalid`), and error
  text never contains the key. No provider is contacted and no proxy key is issued.

These checks stop web pages. They do not stop programs running as the user; that is what the
passphrase gate is for. See [SECURITY.md](../SECURITY.md).
