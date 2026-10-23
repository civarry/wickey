# Security

## Reporting a vulnerability

Please report privately, not in a public issue or pull request.

Use GitHub's private vulnerability reporting: on the repository page open the **Security** tab and
choose **Report a vulnerability** (Security Advisories). Include what you did, what you expected,
what happened, your OS and Node version, and a proof of concept if you have one. Do not include
a real provider key.

This is a small project maintained in spare time, so replies may take a while.

## Threat model

wickey defends against a **local program running as the same user, without the passphrase**:
an AI agent, a script, a dependency's install hook, or a web page in the user's browser. It aims
to keep that program from reading the real provider keys and from minting new proxy keys.

It is not a defense against someone who already has the passphrase, an attacker with root or a
kernel-level foothold, or a compromised provider.

## What is protected

- Real provider keys are only in `vault.json`, encrypted with AES-256-GCM under a data key that
  is wrapped with a scrypt-derived key (N=2^17 by default). They are decrypted only in the
  running proxy's memory, and only the proxy's outgoing request carries one.
- Proxy keys are short-lived and work only against the local proxy.
- Proxy keys are **shown once**, in the response to issue or rotate, and never stored. The database
  keeps SHA-256(key) (the row signature covers it) and the last 5 characters for display. No API
  route, CLI command or file can show a key again; a lost key means rotating. A local program with
  key A therefore cannot read key B from the database, the API or `wickey show`.
- Every `/api` route needs a **session**, except the sign-in status, setup, unlock, sign-in and
  lock routes (lock only ends the grace period and clears sessions, so anyone may do it; if it
  ever also locks the vault or stops proxy traffic it must require a session again). A session exists only after the passphrase was typed (setup, unlock, or sign-in), is a
  256-bit random id kept in the proxy's memory (a restart signs everyone out), travels in an
  `HttpOnly; SameSite=Strict; Path=/` cookie, expires after 12 hours idle, and is cleared for
  everyone by Lock. Without one, a local program gets 401 `session_required` for everything,
  including the proxy list.
- **First-time setup needs the person who started Wickey.** Before a vault exists, no session can
  exist, so `POST /api/setup` would otherwise let any local program set the first passphrase
  before the user does, and know it after the user adds real keys. Setup over HTTP therefore needs
  a one-time token. `wickey start` without a terminal prints it as a link
  (`http://127.0.0.1:<port>/#setup=…`): a URL fragment, which the browser never sends in requests,
  and which the dashboard removes from the address bar on load. The token is 256 bits, kept only in
  the proxy's memory, compared in constant time, cleared by any successful setup (dashboard or
  terminal), and gone when the process stops. A typo'd passphrase doesn't burn it. Without it,
  setup is 403 and no vault is created. Setup in a terminal (`wickey start`, `wickey setup`) is
  unchanged: the server starts listening only after the prompt is answered. The start-on-login
  service never prints a link, because its output goes to a log that any program running as you can
  read; set the passphrase in a terminal before installing it. Not covered: a program that runs
  `wickey start` itself sees its own link and can set up the vault of the instance it started. You
  would notice when Wickey asks you to unlock with a passphrase you never set; run `wickey reset`.
- `env` cleanup marks a name's expired proxies `cleaned_at` instead of deleting them, so their
  activity log survives and an agent cannot erase its trail by rerunning `env`. A cleaned-up proxy
  never authenticates and renew/rotate refuse it. `cleaned_at` is deliberately outside the row
  signature, so it is never trusted on its own: a row is hidden only when `cleaned_at` is set AND its
  signed expiry has passed. A DB edit that marks an ACTIVE key cleaned up therefore can't hide a
  working key: the dashboard and `list` show it with a "Tampered: marked cleaned up while active"
  warning, the proxy refuses it (fail closed, like a failed integrity check), and rotate clears the
  mark and gives a working key back. Log retention (per-key row caps, 30 days) bounds the size.
- Minting a key, or editing a credential so a real key could be sent elsewhere, needs the passphrase
  (or, inside a session, a running grace period). Expire, delete and remove do not need the
  passphrase, only a session, since they only remove access.
- The CLI asks for the passphrase for every command that changes something, signs in for that
  one command and signs out at the end. The session id is never written to disk. With no terminal
  to ask in (cron, CI, an agent's subprocess) it refuses.
- Database rows are HMAC-signed with a key from the vault, so rows written or edited directly in
  the SQLite file are refused.
- The management API only answers loopback Host/Origin requests that carry a custom header. These
  checks stay on top of the session: browsers treat every port on 127.0.0.1 as one site, so another
  local web page would be sent the cookie, and only the Origin and header checks stop it.
- Per-key limits (allowed models, requests per minute, a token cap, optional auto-renew) bound what
  a hijacked or runaway agent can do with a valid key. They are checked before a request is
  forwarded. Tightening a limit needs no passphrase; loosening or removing one, or turning on or
  extending auto-renew, does.
- Allowed models: Selected and None are enforced from the signed row. All means "the models the
  provider lists", checked against a cached list in `credential_models`. That cache is **not signed**:
  in All mode the provider would serve any model it lists anyway, so a forged list can only change
  which names are pre-filtered, never reach a model the key was not meant to have. A same-user
  attacker who can edit the file could mark a credential `unavailable`, which makes All keys pass
  models through (the pre-existing All behavior), or set `fetched_at` to cause extra upstream
  `/models` calls; use Selected for a hard restriction. Refreshes are single-flight and limited to
  one per 60 s per credential (the dashboard's forced refresh: one per 10 s), so unknown model names
  cannot make the proxy hammer the provider. Only HTTP 404/405/501 makes a list `unavailable`; a 200
  that is not a readable list refuses All keys. Fetch errors never include the API key.
- Limits, auto-renew settings, the lifetime, a row version and the usage totals are HMAC-signed with
  a key derived from the vault's data key. On disk that key exists only encrypted under the
  passphrase; in memory only in the running proxy. While running, the proxy remembers the latest row
  version and usage totals per key and refuses ("Needs review") a key whose stored data went
  backwards.
- The activity log holds metadata only (time, model, status, token counts, duration, refusal
  reason). Prompts and responses are never stored.
- Limited keys forward only a UTF-8 JSON body the proxy parsed and re-serialized, so the provider
  sees what was checked.

Limits do not stop a process that holds a valid key from using it within those limits until the key
expires or hits one.

## Where a key may be sent

A credential holds a real key and a base URL, so a bad URL is a way to leak the key or reach
internal services through the proxy. `src/netguard.ts` enforces this when a URL is saved and again
when the proxy connects.

- **Always refused:** cloud metadata and link-local destinations (169.254.0.0/16, fe80::/10,
  fd00:ec2::254, 100.100.100.200, their IPv4-mapped forms, `metadata`, `metadata.google.internal`,
  `metadata.goog`, `instance-data`, `instance-data.ec2.internal`), and unspecified addresses
  (0.0.0.0/8, `::`). These hand out cloud credentials to anything that can send a request.
- **The proxy itself:** a loopback URL on Wickey's own port is refused, since it would loop.
- **Transport:** only http and https, no `user:pass@`, and plain http only to loopback or private
  hosts. A public host needs https.
- **Connect time:** a public name that resolves to a refused address (DNS rebinding) is refused
  too. The request connects to the addresses that were checked, so they cannot change in between.
  Rows saved before these rules are judged on every use and answered with a 403 that says to edit
  the credential.
- **Deliberately allowed:** loopback and private ranges (10/8, 172.16/12, 192.168/16, 100.64/10,
  fc00::/7, `*.local`, `*.internal`, single-label names). Ollama, LM Studio and corporate gateways
  live there, and a user who can add a credential can already point it anywhere they choose. The
  API reports `baseUrlScope` (`public`, `private`, `loopback`) so the dashboard can flag them.
- **Not covered:** a hostname on a private network that the user controls can still point at any
  private service; this is a guard against accidents and metadata theft, not a network sandbox.

## Red-team results (2026-10-23)

A red-team pass played a local attacker against the current code.

### Held

- Forging or editing database rows (HMAC signatures).
- Vault tampering, including weakened KDF parameters.
- API tricks with headers, Host, Origin, paths and request bodies.
- Request smuggling and header injection through the proxy.
- Upstream redirects (they are not followed by the proxy).
- Dashboard XSS (values are rendered as text).
- Minting from the CLI without a terminal.

### Key B from key A (2026-10-23, added with hashed keys and sessions)

A program that holds one proxy key (A) and no passphrase tried to get another (B). Checklist, each
with an automated test in `test/token-security.test.ts`:

- `/api/state`, `/api/requests`, per-proxy logs, with and without the `x-wickey` header and with
  key A as a bearer, API key or cookie: 401 or 403, and no response ever contains a full key.
- `POST /api/env`, rotate and issue without a session: 401, even with the right passphrase in the body.
- The database and its write-ahead log: no table holds a key; a database from before this change
  is scrubbed on open and its keys keep working.
- Editing `token_hash` in the file to a key the attacker knows: the row signature fails.
- `wickey show`, `list`, `env`, `issue`, `rotate` with no terminal: they print the masked key or
  refuse. None prints a key.
- A restart or Lock makes every old cookie useless.

Still possible: reading the proxy's memory with a debugger, or watching the user type the passphrase.

### Broken (accepted, documented)

- **Database rollback.** Restoring an older copy of the database revives a rotated or expired
  proxy key until its original expiry. The attacker must stop the proxy, and the user must unlock
  again afterwards. There is no same-user, cross-platform fix: any "latest state" record is also a
  file the attacker can restore. Mitigations: use short lifetimes, and rotate the real provider key
  after a real leak.

### Partial

- **Wrong-passphrase throttle.** It is held in memory, so restarting the proxy resets it. Offline
  guessing against a copied `vault.json` is the bigger threat anyway. Measured on an Apple-silicon
  Mac at scrypt N=2^17: about 172 ms per guess, roughly 6 guesses per second per core. Passphrase
  length is what protects you. Use a long one.
- **Debugger attach.** A program running as the same user could attach a debugger to the running
  proxy (this worked without root on macOS). Extracting keys from memory is likely feasible with
  effort; it was not demonstrated.

## Red-team results: per-key limits (2026-10-23)

A second round targeted the limits, playing a local attacker holding a valid limited key or write
access to the database file. Findings A to H were all fixed:

- **A.** A client-sent `stream_options` could poison the credential's usage flags, uncounting
  streams for every key on it. Now the client's `stream_options` are replaced, and only an error
  about our own option can set a flag.
- **B.** Bodies the proxy could not parse but a lenient provider accepts (UTF-16, a BOM,
  `"stream":1`) skipped metering. Capped keys now forward only the re-serialized UTF-8 JSON the
  proxy parsed, and any truthy `stream` counts as streaming.
- **C.** A model named in the URL path (Azure-style deployments) bypassed the allowlist. Such paths
  are refused on keys with an allowlist.
- **D.** Parallel requests could overshoot a cap without bound. Requests in flight now reserve
  tokens, and a capped key allows at most 8 at once.
- **E.** Restoring an older signed `proxies` row while running revived loosened limits or an
  expired key. Rows carry a signed version, and the proxy refuses one that went backwards.
- **F.** `ttl_seconds` was not signed, so editing it let one renewal jump to the maximum. It is
  signed now.
- **G.** A 502 for an unreachable provider renewed the key. Only a response from the provider counts.
- **H.** An unknown `Content-Encoding` left usage uncounted. Capped keys now ask the provider only
  for encodings the proxy can read.

Also fixed: refused requests could push forwarded entries out of the activity log. The two are
retained separately.

The passphrase gate held: no way was found to loosen a limit, enable auto-renew or mint a key
without the passphrase.

What remains:

- **Rollback across a restart.** The high-water checks live in the running proxy. Restoring an
  older database while it is stopped, then unlocking, is not detected, and restarting accepts older
  data. For a flagged key, rotate or delete it; don't restart.
- **Memory reading.** A same-user program that reads the proxy's memory could extract the signing
  key and forge rows.
- **Mock providers.** The results come from tests against mock providers. Real providers may report
  usage in ways not covered.
- **Overshoot.** Caps stop new requests. In-flight requests can exceed a cap by their reservations,
  and a response to a client that hung up can cost tokens nobody reads.
- **Uncounted usage.** If you allow it on a capped key, a provider that reports no usage runs
  uncounted.

## Red-team results: model lists and .env import (2026-10-23)

A third pass reviewed All/None/Selected model modes, the base URL guard and the .env import.

Held:

- Import and dry run return 401 without the passphrase, refuse more than 50 entries, and put no
  key in any response or log.
- Metadata, link-local and the proxy's own port are refused on add, edit and import across about
  40 encodings. An upstream 302 is not followed.
- None refuses every method. Loosening a model setting needs the passphrase.
- Duplicate JSON `"model"` keys forward the model that was checked. Parallel unknown models cause
  no extra fetches. Bodies stay intact after a slow list lookup. An 11 MB body gets a 413.

Fixed:

- **Forced refresh was unthrottled.** Any local process could make unlimited `/models` calls with
  the real key. Now single-flight and once per 10 s per credential.
- **A 200 that was not a model list passed everything.** A captive portal or gateway page made All
  keys pass any model for an hour. Now only 404/405/501 means "no list"; anything else unreadable refuses.
- **Models named in the path.** `/engines/<id>/...` and Bedrock-style `/model/<id>/invoke` slipped
  past the URL check. Now refused on keys with an allowlist.
- **Names such as `..`, `--help` and `-x`** passed validation and could act as options in pasted
  commands. Names must now start with a letter or digit. Existing names are not migrated.
- **A proxy key (`sk-wick-...`) could be stored as a provider key.** Refused on add, edit and import.

Accepted:

- The model-list cache is unsigned. A same-user process that can write the SQLite file can set
  `unavailable` to make All keys pass models through, or change `fetched_at` to cause extra
  upstream `/models` calls. Same class as the other same-user database-write gaps; use Selected
  for a hard restriction.
- One passphrase entered in the dashboard can authorize two dashboard actions that asked at the
  same moment, because the dialog is shared. This is within the same grace-period trust as
  everything else.

## Start-on-login service and logs

- The service always starts **locked**. The passphrase is never written to the plist, unit, task,
  environment or any file, so a restart or reboot leaves the proxy refusing key requests until you
  unlock it once. A reboot therefore cannot be used to get an unlocked proxy.
- The service definition holds only the node path, the script path and, if you set them at install
  time, `WICKEY_HOME` and `WICKEY_PORT`. OS commands run through `execFile` with argument
  arrays, never a shell string; paths are XML-escaped (plist) and quoted (systemd).
- Logs never contain secrets. Audit of every `console.*` and error path in `src/`: the only
  runtime messages are startup lines, the database error text from `logQuietly`, and the usage
  rollback notice (proxy id only). Upstream errors, request headers, bodies, keys and tokens are
  never logged, and the final uncaught-error handler logs the message only (no stack). As a second
  layer, the log writer redacts `sk-` shaped keys, `Bearer` values and `Authorization` / `x-api-key`
  values. That filter is a backstop for unknown key formats, not a guarantee. A test sends a real
  looking key through a service-mode proxy against an erroring upstream and checks the log.
- Permissions: data and logs directories `700`; vault, database (and its WAL files) and logs `600`,
  tightened on every start. Skipped on Windows.
- Logs are size-capped in-process (1 MB x 3 files). Under systemd the service's own stdout is
  discarded rather than sent to journald, so journald's limits do not apply.
- Windows start-on-login is experimental and unverified.

## Security event log (`events.log`)

An append-only, hash-chained file of security events with an HMAC (under a key derived from the
vault's data key) on entries written while unlocked. It exists so a same-user program without the
passphrase cannot quietly edit, delete, reorder or forge events: those break the chain or the MACs,
and `verifyLog` reports the first bad entry. Honest limits:

- **Truncating the tail is not detected.** Removing the newest entries leaves a consistent chain.
  An anchor outside the data directory is planned to close this.
- **Entries written while locked (failed unlocks) carry no MAC.** A local program could add such
  entries. They are shown as "recorded while locked" and only become part of the authenticated
  chain when the next unlock appends a checkpoint; they are never presented as verified. The
  checkpoint signs whatever unsigned chain precedes it, so until the anchor exists, a program that
  rewrites the log as unsigned entries gets that rewrite folded in at the next unlock. The anchor
  must be checked before any checkpoint is written.
- **Entries from before a `wickey reset` cannot have their MACs checked** (the key is gone). They
  are labelled "before reset, integrity not verifiable". A program that rewrites the whole file
  with no MACs and a fake `reset` at the end is not detectable until the anchor exists.
- The file is readable by any same-user program; `data` is limited to ids, names and limits, never
  keys, tokens or passphrases. While the vault is locked only hashes and links are checked.
- Logging is a record, not a gate: if the file cannot be written, unlock, sign-in and lock still
  work (silently) and minting or credential changes go ahead with one line on stderr. The `via`
  field is a label the caller sends; a local program can fake it.

## Other known limits

- A key you put in your shell environment (`wickey env`, or one you exported yourself) is
  readable by programs that run in that shell. `env` mints a fresh short-lived key per terminal, so
  one terminal's key is not another's, but a program inside that terminal has its own.
- Proxy keys are no longer readable from the database (this was an accepted gap before: they sat in
  a `token` column in plain text). Opening an older database hashes nothing new (the hash was
  already there), keeps the last 5 characters, drops the column and vacuums the file so the old text
  is gone from free pages and the write-ahead log.
- A same-user debugger or memory reader can still read the unlocked vault, the signing key and live
  session ids from the proxy, and a program that watches the keyboard or the terminal while you type
  the passphrase gets the passphrase. Sessions do not defend against either.
- Changing the passphrase re-wraps the same data key, so an old copy of `vault.json` (a backup,
  Time Machine, a migration copy) still opens with the passphrase it had when copied. Delete old
  copies if the old passphrase was exposed. Rotating the data key is not implemented.
- Changing the passphrase always requires the current one, even during the grace period (otherwise
  any local program could take over the vault in that window); wrong guesses count toward the
  throttle, and a success ends the grace period.
- There is no recovery for a forgotten passphrase, by design. `wickey reset` deletes the vault
  and database (CLI only, never an API endpoint). It cannot reveal keys, so it is not treated as
  protected: any local process can also just delete the files, and the terminal and typed
  confirmation only guard against accidents. It does not revoke provider keys, which stay valid at
  the provider.
- During the grace period (default 5 minutes after the passphrase is entered), a **session** can
  mint keys without the passphrase. Programs without a session cannot, so this is no longer open to
  anything on the computer; it is open to the dashboard tab you signed in with. The CLI also sends
  the passphrase it typed, so `WICKEY_GRACE=0` still works. Lower `WICKEY_GRACE` or use
  Lock / `wickey lock` to shorten the window; it signs every session out.
- Rolling back `vault.json` is not detected either.
- A local process holding a valid key can use it until it expires or reaches a limit. With
  auto-renew, the maximum lifetime is the real lifetime you approved.
- Request rate is counted in memory and resets when the proxy restarts.
- Windows paths (`CONIN$` prompt, PowerShell output) are not yet verified.

If you find something that contradicts this page, that is worth reporting.
