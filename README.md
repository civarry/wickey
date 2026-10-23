# Wickey

A local proxy for LLM API keys. Your real provider keys stay in an encrypted vault on your machine,
locked by a passphrase. Your apps, scripts and AI agents get a localhost base URL and a short-lived
`sk-wick-…` key instead. When that key's time runs out it stops working; the real key was never in
a `.env` file, a log, or an agent's context.

> Status: MVP. Works on macOS and Linux. Windows is untested: the code paths exist (PowerShell
> output, `CONIN$` terminal prompt, the Task Scheduler start-on-login) but nobody has verified them. Subscription sign-in (ChatGPT,
> Claude Pro/Max) is planned, not built.

## Quickstart

Needs Node.js 24+ and a terminal (the passphrase prompts read from it).

```sh
npm install -g wickey
wickey start                                     # sets your passphrase; leave it running

# in a second terminal
wickey add openai --provider openai              # paste your real key at the hidden prompt
eval "$(wickey issue openai --ttl 10m --env)"    # sets OPENAI_BASE_URL and OPENAI_API_KEY
curl "$OPENAI_BASE_URL/models" -H "Authorization: Bearer $OPENAI_API_KEY"
```

That request went through Wickey with a key that dies in 10 minutes. Anything that reads
`OPENAI_BASE_URL` and `OPENAI_API_KEY` (the OpenAI SDKs, most agents) now works the same way.
Prefer clicking? Open `http://127.0.0.1:7777/` while `start` runs.

You can let an agent install Wickey, but set the passphrase and add your keys yourself.

## Why Wickey

If you run AI agents, your API key probably lives in a `.env` file or an `export` in your shell
profile. Every agent, script and plugin you run can read it, it never expires, and it has no
ceiling. It ends up in transcripts, logs, screenshots and the odd public commit. When it leaks, you
usually find out from the bill.

Wickey changes what you hand out:

- **Agents never hold your real key.** They get a `sk-wick-…` key that only works against
  `127.0.0.1` on your machine. Pasted into a chat, a log or a commit, it is useless anywhere else.
- **Keys expire on their own.** Ten minutes for one task, eight hours for a workday. A leaked key
  is already dead, or will be soon.
- **A runaway agent hits a wall.** Limit each key to specific models, a request rate and a total
  token budget. A loop that would have burned your credits gets refused at the cap.
- **You can see what each key did.** Every key keeps its own activity log, even after it expires.
- **One terminal, one key.** One line in your shell profile gives each new terminal its own fresh
  key instead of one permanent secret shared by everything.
- **No code changes.** OpenAI and Anthropic SDKs work as they are: swap the base URL and key.
  Streaming works.
- **Nothing leaves your machine.** No account, no hosted service, no runtime dependencies. Requests
  go straight from the proxy to your provider.

### A proxy in front of your proxy

Already using OpenRouter, LiteLLM, Ollama or a company gateway? Keep it. Add it as a credential and
Wickey sits in front of it:

```
agent ──sk-wick-…──▶ Wickey (127.0.0.1) ──real key──▶ OpenRouter / LiteLLM / your gateway ──▶ models
```

The gateway still does routing, fallbacks and billing. Wickey decides who gets a key, for how long
and with what limits, and keeps the gateway's own key out of your agents' hands. Local gateways on
`localhost` or a private network are allowed as targets.

### Compared to what you might use now

| | Your agent holds | If that key leaks | Expires on its own | Model, rate and token limits per key | Runs |
| --- | --- | --- | --- | --- | --- |
| Key in `.env` or shell profile | The real key | Works from anywhere | No | No | Nothing to run |
| Secret manager (`op run`, Doppler, …) | The real key, injected at start | Works from anywhere | No | No | A CLI, often an account |
| Provider project keys and spend limits | A real key | Works from anywhere until you revoke it | No | Per project, not per agent or terminal | The provider's console |
| OpenRouter or LiteLLM keys | A real gateway key | Works from anywhere the gateway is reachable | LiteLLM can set a duration | Yes | A hosted account, or a server and database |
| **Wickey** | A `sk-wick-…` key | Works only on your machine, until it expires | Yes, by default | Yes | One local process, no account |

These tools combine well. Keep your secret manager or gateway, and let Wickey be the only thing that
holds its key.

## Requirements and install

Node.js 24 or newer. No runtime dependencies.

```sh
npm install -g wickey
wickey setup       # passphrase, first credentials, start on login
```

Install it globally before `wickey service install` (or the start-on-login step of `setup`): the
service records the path it was installed from, and a `npx` cache can disappear.

From source, if you want to hack on it (runs the TypeScript directly, no build step):

```sh
git clone https://github.com/civarry/wickey.git && cd wickey
npm install      # dev tools only
npm link         # puts `wickey` on your PATH
```

## First run

```sh
wickey start
```

On first run it asks you to set a passphrase (at least 12 characters, asked twice; four or more
random words work well). On later runs it
asks for the passphrase to unlock (or press Enter to start locked and unlock in the dashboard).

Started without a terminal on a fresh install, it prints a **one-time setup link** instead. Open it
to set the passphrase in the dashboard. The link works once and only while that process runs, so no
other program on your computer can set the passphrase before you do. The start-on-login service
never prints one (its log is readable by any program running as you), so set the passphrase in a
terminal before you install the service.

**The passphrase can't be recovered.** It encrypts your provider keys. Forget it and you re-add
every key. Pick a long one (see [What this protects](#what-this-protects-and-what-it-doesnt)).
If you do forget it, stop the proxy and run `wickey reset` (see
[Change or reset the passphrase](#change-or-reset-the-passphrase)).

Leave `start` running; it is the proxy. All other commands that change anything talk to it.

Prefer a walkthrough? `wickey setup` does the passphrase, your first credentials and
start-on-login in one go (see below). Every step can be skipped and is also its own command.

## Guided setup

```sh
wickey setup
```

Needs a terminal. Four steps, each skippable with Enter:

1. **Passphrase.** Creates the vault (hidden prompt, twice, at least 12 characters), or notes that
   one exists.
2. **Credentials.** Add one now, or import a `.env` file by path. The import uses the same parser
   as the dashboard: you see the detected keys (last four characters only), pick numbers, and a
   dry run reports duplicates before anything is stored.
3. **Start on login.** Runs `service install` (below).
4. **Next steps.** Prints the dashboard URL and the commands to issue a key.

Step 2 needs a running proxy. If none is running, `setup` hosts one itself for the duration of the
walkthrough and stops it at the end (nothing detached is left behind); if you install the service
in step 3, the service takes over the port. Ctrl+C at any point is safe: each credential is saved
atomically, so you keep whatever you finished.

## Start on login

```sh
wickey service install     # replaces a previous install cleanly
wickey service status      # installed? running? locked? node path still valid? log path
wickey service uninstall   # friendly no-op if it isn't installed
```

| OS | What it installs |
| --- | --- |
| macOS | A LaunchAgent in `~/Library/LaunchAgents/dev.wickey.proxy.plist` (RunAtLoad, restarts after a crash) |
| Linux | A systemd user unit `~/.config/systemd/user/wickey.service` (`Restart=on-failure`). Without a systemd user session it says so and prints the command to run by hand. It starts at login; run `loginctl enable-linger` to start at boot |
| Windows | **Experimental and unverified.** A Task Scheduler task at logon via `schtasks`. It does not carry `WICKEY_HOME` / `WICKEY_PORT` over |

**It starts locked.** After login the proxy runs but refuses key requests until you unlock it once,
in the dashboard or with `wickey unlock`. The passphrase is never stored anywhere. If you set
`WICKEY_HOME` or `WICKEY_PORT` when you install, those two values are baked into the
service.

If a `wickey start` you ran by hand holds the port, `service install` says so and stops; it
never kills anything. The service records the absolute path of the node binary. If an upgrade
removes that node version, `service status` warns and `service install` fixes it.

### Logs

The service writes its own log at `~/.wickey/logs/wickey.log`. The OS-level stdout and
stderr of the service go to `/dev/null`, because launchd and systemd would append to a file
forever. The process rotates its own log instead: 1 MB per file, three files kept
(`wickey.log`, `.log.1`, `.log.2`), so at most about 3 MB. Logs never contain keys, proxy
tokens or auth headers: no code path prints them, and a final filter hides anything shaped like
one. The data directory and logs directory are mode `700`; the vault, database and log files are
`600` (not applied on Windows).

## Usage

```sh
# 1. Store a real key (hidden prompt, or pipe it in)
wickey add openai --provider openai
wickey add claude --provider anthropic
wickey add groq --provider custom --base-url https://api.groq.com/openai/v1

# 2. Issue a proxy key for an app or agent
wickey issue openai --ttl 10m --name my-agent
#   BASE_URL=http://127.0.0.1:7777/p/3f9a1c2e
#   API_KEY=sk-wick-...     (shown once: only a hash is kept, so copy it now)

# or straight into your shell, using the env var names the provider's SDK reads
eval "$(wickey issue openai --ttl 2h --env)"

# 3. Manage it
wickey list
wickey renew 3f9a1c2e           # same key, timer restarts
wickey rotate 3f9a1c2e          # new key, old one dies now
wickey expire 3f9a1c2e
```

Every command that changes something asks for your passphrase (hidden prompt, once per command), and
with no terminal to ask in (cron, CI, an agent's subprocess) it refuses. A proxy key is printed
**once**, when it is issued or rotated. `list` and `show` only ever print the masked form
(`sk-wick-…` and the last 5 characters); lost a key, `rotate` makes a new one.

Point your client at `BASE_URL` and `API_KEY` where you would put the real ones. Request paths pass
through unchanged, so `BASE_URL/chat/completions` reaches `https://api.openai.com/v1/chat/completions`.
The proxy key can be sent as `Authorization: Bearer` or `x-api-key`, so OpenAI-style and Anthropic
SDKs work unchanged. Env lines use `OPENAI_*` for `openai`, `openrouter` and `custom`, and
`ANTHROPIC_*` for `anthropic`.

### No terminal?

Commands that change anything need a terminal for the passphrase prompt, on purpose: a background
job (cron, CI, an agent's subprocess) can't answer it, so it can't mint keys. Without a terminal:

- **Use the dashboard** at `http://127.0.0.1:7777/` in a browser. It covers credentials, keys and limits,
  and asks for the passphrase in the page. On a fresh install, open the one-time setup link that
  `wickey start` printed instead (see [First run](#first-run)).
- **For an unattended job**, issue a key for it from a terminal or the dashboard, with the limits
  that job needs (models, rate, token cap), and hand that key to the job.

The dashboard's `/api` is internal: it can change between versions and is not a supported way to
script Wickey.

### Commands

| Command | What it does |
| --- | --- |
| `start` | Run the proxy and dashboard on `127.0.0.1:7777`. Asks for your passphrase, or sets one up on first run |
| `setup` | Guided first run: passphrase, credentials (add or import a `.env`), start on login. Needs a terminal; every step is skippable |
| `service install\|uninstall\|status` | Start the proxy when you log in. It starts locked. Windows is experimental |
| `unlock` | Unlock a running proxy and start the grace period |
| `lock` | End the grace period now and sign every dashboard tab out (no passphrase needed) |
| `passphrase` | Change the passphrase. Asks (hidden) for the current one, even during the grace period, then the new one twice |
| `reset` | Forgot the passphrase: delete the vault and all data, then set up again. Asks you to type `reset` in a terminal, and refuses while the proxy runs |
| `add <name> --provider <p> [--base-url <url>] [--auth bearer\|x-api-key]` | Store a credential; the key comes from a hidden prompt or stdin. Providers: `openai`, `anthropic`, `openrouter`, `custom` (needs `--base-url`) |
| `creds` | List stored credentials (never shows keys) |
| `edit <name> [--name] [--base-url] [--auth] [--key]` | Change a credential; `--key` prompts for a replacement key. Its proxies keep working |
| `remove <name>` | Delete a credential and every proxy issued from it |
| `issue <credential> [--ttl] [--name] [--env\|--powershell\|--json] [limit flags]` | Issue a proxy. TTL takes `30s`, `5m`, `2h`, `1d`; default `60s`. Limit flags: `--models all\|none\|a,b`, `--rpm N`, `--max-tokens N`, `--allow-uncapped`, `--auto-renew <window> --max-lifetime <ttl>` |
| `env <name> --credential <c> [--ttl] [--powershell] [limit flags]` | Print env lines with a new key minted for this terminal, every time (asks for the passphrase). Expired proxies with the same name are marked cleaned up (hidden, activity kept); active ones stay. For shell profiles. Takes the same limit flags as `issue` |
| `limits <id> [--models all\|none\|a,b \| --any-model] [--rpm N \| --no-rpm] [--max-tokens N \| --no-max-tokens] [--allow-uncapped \| --refuse-uncapped] [--no-auto-renew \| --auto-renew <window> \| --max-lifetime <ttl>]` | Change a proxy's limits. Tightening needs no passphrase; loosening or removing a limit does |
| `models <credential> [--refresh]` | List the models the credential's provider serves (fetched with the real key, cached). `--refresh` fetches again, at most once per 10 seconds |
| `list [--all]` | Proxies with status, time left, limits and usage. `--all` also shows expired ones `env` has cleaned up |
| `show <id> [--json]` | Print a proxy's base URL and masked key. The full key is shown only once, at issue or rotate |
| `renew <id> [--ttl]` | Restart the timer, same key (nothing to update, nothing printed) |
| `rotate <id> [--ttl] [--env\|--powershell\|--json]` | New key (shown once), restart the timer; the old key stops working now |
| `expire <id>` | End a proxy now, as if its time ran out. It stays listed |
| `delete <id>` | Remove a proxy |

`list`, `creds` and `show` read the database directly, work even when the proxy is stopped and never
print a key. Everything else asks for the passphrase, signs in to the running proxy for that one
command, and signs out when it ends.

## Shell profile

Instead of `export OPENAI_API_KEY=<real key>` in your profile, add this to `~/.zshrc` or `~/.bashrc`:

```sh
eval "$(wickey env work --credential work --ttl 8h)"
```

PowerShell profile (untested on Windows):

```powershell
wickey env work --credential work --ttl 8h --powershell | Invoke-Expression
```

How it behaves:

- **Every new terminal asks for your passphrase** and gets its own freshly minted key, named `work`,
  with the TTL and limits you gave. Nothing is reused or revived, so a key that leaked stays dead
  and one terminal's key is not another's.
- Several active proxies can share the name `work`, one per terminal. Each run marks the expired
  ones with that name as cleaned up: they leave the default lists (`wickey list --all` and the
  dashboard's **Show cleaned up** toggle bring them back) but keep their activity log, so rerunning
  `env` cannot erase what a key did. They cannot be renewed or rotated. Active ones stay, since other terminals
  are using them. Tell them apart by the last 5 characters in the dashboard and `wickey list`.
- Terminals opened before a key expires keep the dead key until you open a new one or re-run the line.
- A script with no terminal (cron, CI, an agent's subprocess) can't answer the prompt, so it gets no
  key and the command fails with a message saying so. That is the point: it cannot mint either.

## Per-key limits

A proxy key limits time by default. Limits also bound what a key can do while it is alive. All are
optional, and you can set them when you issue a key or change them later.

| Limit | What it does |
| --- | --- |
| Allowed models | **Selected**: exact model IDs, anything else refused, models the provider adds later stay blocked. **All**: any model on the provider's own model list; an unlisted model is refused after one refresh. **None**: every request refused. The dashboard defaults to Selected; the CLI defaults to All so existing shell profiles keep working. A provider with no model list endpoint lets All pass any model through and takes typed IDs for Selected |
| Requests per minute | Sliding one-minute window, held in memory (resets when the proxy restarts) |
| Token cap | Input plus output tokens over the key's whole life, read from the provider's `usage` field, streaming included. Rotating a key does not reset it |
| Refuse when usage can't be counted | On by default. With a token cap, a request that could run without being counted is refused instead |

```sh
# Only gpt-4o-mini, 30 requests a minute, 200k tokens in total
wickey issue openai --ttl 2h --models gpt-4o-mini --rpm 30 --max-tokens 200000

# Same limits in a shell profile
eval "$(wickey env work --credential work --ttl 8h --models gpt-4o-mini --max-tokens 200000)"

# Change them later. Tightening needs no passphrase; loosening or removing one does.
wickey limits 3f9a1c2e --max-tokens 100000
wickey limits 3f9a1c2e --models all --no-rpm
wickey models work               # model IDs you can pass to --models
wickey list                      # shows limits, tokens used and last use
```

In the dashboard, the issue form has a **Limits** popover, and each row has one to edit limits.
Rows show **Limit reached** and **Needs review** badges, tokens used and last used, and
"auto-renews until <time>". A **Token cap not enforceable** note appears when a cap is set on a key
that allows uncounted usage, for a provider that has not reported usage. The expanded row shows the
request count and last use, with a **View activity** link to that key's requests.

### What a refused request looks like

The limit is checked before anything is sent to the provider. The error is in OpenAI or Anthropic
format (by provider and path) and names the limit:

| Status | Code | Why |
| --- | --- | --- |
| 403 | `model_not_allowed` | Model not on the allowlist, no readable model, or a model or deployment named in the URL path |
| 429 | `rate_limit_exceeded` | Over the rate (sends `Retry-After`), or more than 8 requests in flight on a capped key |
| 429 | `token_cap_reached` | Cap used up, or the remaining budget is reserved by requests still running |
| 403 | `usage_uncountable` | The key refuses what it can't count (see below) |
| 403 | `usage_rollback` | The key's stored data failed its integrity check or went backwards. Rotate or delete the key |
| 400 | `invalid_body` | A key with an allowlist or token cap got something other than a UTF-8 JSON object |
| 413 | `request_too_large` | Body over 10 MB on a limited key |

### How limited keys forward requests

- A key with an allowlist or a token cap only accepts a UTF-8 JSON object as the body. The proxy
  re-serializes it before forwarding, so the provider sees exactly what was checked. A key with only
  a rate limit forwards the body untouched.
- With a token cap, streaming chat and completions requests get `stream_options: {include_usage: true}`
  so the provider reports usage. The client's own `stream_options` are replaced. If a provider
  rejects that option, a key that allows uncounted usage retries once without it, and a refusing key
  gets a clear 403.
- A capped key asks the provider only for response encodings the proxy can read (gzip, deflate,
  brotli, and zstd where Node supports it).
- A key with an allowlist refuses any URL path that names a model or deployment, since only the
  body is checked. Put the model in the JSON body.
- Keys with no limits are not touched: the request and response stream through unchanged. The
  response is still read from a side copy to count usage and fill the activity log.

### Caps stop new requests

A cap is checked when a request starts. Requests already running finish. Each one holds back its
`max_tokens` (or 4096 if it doesn't say) against the cap, and a capped key allows at most 8 in
flight, so the overshoot is bounded, not zero.

If the agent disconnects mid-stream, a capped key keeps reading the provider's response, for up to
10 minutes, so the tokens are still counted. That response may cost tokens nobody reads.

### Providers that don't report usage

Each credential remembers whether its provider reports usage, learned from real responses. The
issue form warns when you set a cap on one that doesn't. The default is to refuse requests that
can't be counted, rather than run uncapped. `--allow-uncapped` (or unticking the box) lets them
through, and they are then counted as uncounted requests, not as tokens. These remembered flags are
display hints and are not signed. The first request to a provider not yet seen can run before the
proxy knows it reports nothing.

### Activity log

Each key keeps a log: time, model, status, tokens in and out, duration, the refusal reason, and
renewal events. It is metadata only. Prompts and responses are never stored and there is no option
to store them. It keeps the last 500 forwarded and 200 refused entries per key, and nothing older
than 30 days. Totals are kept separately, so pruning never loses them.

### Auto-renew

Opt-in, and set with the passphrase. You give a renew window and a **required** maximum lifetime:

```sh
wickey issue openai --ttl 1h --auto-renew 10m --max-lifetime 7d
```

A request that the provider actually answered, inside the window before expiry, extends the key by
one lifetime (`--ttl`), never past the maximum. The window must be at least 1 minute and shorter
than the key's lifetime, and the maximum can be at most 365 days. It never renews an expired key, a
key at its token cap, or a key flagged "Needs review", and it never mints a new key. Refused
requests and a 502 from an unreachable provider don't count as use.

**With auto-renew, the maximum lifetime is the real lifetime you are approving.** A key that is
used often lives until that date.

### Integrity

Limits, auto-renew settings, the lifetime, a row version and the usage totals are HMAC-signed with
a key derived from the vault's data key. That key exists on disk only encrypted under your
passphrase, and in memory only in the running proxy, so editing the database file doesn't work. A
same-user program that reads the proxy's memory could forge signatures (a debugger can attach
without root on macOS).

While the proxy runs, it remembers the latest row version and usage totals per key and refuses a
key whose stored data went backwards ("Needs review"). Restoring an older database **across a
restart** is not detected, and restarting accepts the older data. So for a flagged key, rotate or
delete it. Don't restart.

Spend caps in money are not built. Prices would have to be entered by hand.

## Passphrase and grace period

| Asks for the passphrase | Does not |
| --- | --- |
| `issue`, `rotate`, `renew` | `expire`, `delete`, `remove` |
| Loosening or removing a limit; turning on or extending auto-renew | Tightening a limit; turning auto-renew off |
| `env` (it always mints a key) | Using a proxy key against the proxy |
| `add` and `edit` (a credential can point a real key at another server) | |

Nothing works without a **session**, and a session is created only by typing the passphrase: in
the dashboard (setup, unlock or sign-in) or per CLI command. Sessions live in the proxy's memory
(a restart signs everyone out), travel in an `HttpOnly; SameSite=Strict` cookie and expire after 12
hours idle. A program on your computer that does not know the passphrase gets `401 session_required`
for every `/api` route, the proxy list included.

Inside a session, after you enter the passphrase, minting works without it for **5 minutes** (the
grace period, like `sudo`). Change it with `WICKEY_GRACE=<seconds>`; `0` turns it off, so every
mint asks. The dashboard shows a countdown banner with **Lock now**; `wickey lock` does the
same, and needs no passphrase or session. Locking ends the grace period and signs every session out:
existing proxy keys keep working.

**Risk: during the grace period, a tab you signed in to can mint keys without the passphrase.** A
program with no session still cannot. Keep the window short, and lock when you step away.

Wrong passphrases are throttled: after 5 misses, each further attempt waits twice as long as the
last, up to 5 minutes.

## Change or reset the passphrase

`wickey passphrase` (or **Change passphrase** in the dashboard header) re-wraps the vault's
data key under the new passphrase. It always asks for the **current** passphrase, even during the
grace period, and wrong guesses count toward the throttle. The new one needs at least 12
characters and must differ from the old one. Your stored keys and proxy keys are not touched.
Afterwards the grace period ends, so the next mint asks for the new passphrase.

**An old copy of `vault.json` still opens with the old passphrase.** The data key itself does not
change, so a backup, a Time Machine snapshot or any other earlier copy stays readable with the
passphrase it had back then. If an old passphrase was exposed, delete those copies. Changing the
passphrase does not fix a leaked one for copies already made.

There is no recovery. If you forget the passphrase, stop the proxy and run `wickey reset`: it
lists what will be deleted (the vault, all credentials, all proxies and their activity log) and
asks you to type `reset`. **Your real provider keys are not revoked**; they stay valid at the
provider, so revoke or rotate them there if needed. Then `wickey start` sets a new passphrase,
and importing from a `.env` file makes re-adding keys quick. The terminal check on `reset` guards
against running it by accident; it is not a security boundary.

## Dashboard

`wickey start` also serves a dashboard at `http://127.0.0.1:7777/`:

- **Setup / unlock / sign-in screen**: set the passphrase on first run, unlock after a restart (that
  also signs you in), or sign in with the passphrase when the proxy is already unlocked and this
  browser has no session. The unlock and sign-in screens have a "Forgot your passphrase?" note with
  the reset command.
- **Change passphrase**: button in the header (needs the current passphrase).
- **Grace banner**: countdown to the end of the grace period, with **Lock now** (signs every tab out).
- **Expired line**: one line when proxies have expired, with **Renew all** (same keys).

The sidebar has two pages, **Proxies** (with its Credentials section) and **Activity**. The URL hash
holds the view, so reload and the back button keep it.

**Activity** (`#/activity`) lists requests across all proxies, newest first: time, proxy, model,
status (refused requests say why), tokens in and out, and duration, plus auto-renew events. Filter by
proxy (also by clicking a proxy name in the table) and by status (All, OK, Refused); the filters live in
the URL, e.g. `#/activity?proxy=<id>&status=refused`. **Load more** pages back through the log. Only
metadata is kept, never prompts or responses.

The Proxies page follows the order you work in:

1. **Credentials**: one row per provider key with its base URL, auth type and "X of Y active".
   **Issue proxy** jumps to the issue form with that credential selected; **Edit** and
   **+ Add credential** open a side panel. The stored key is never sent back to the browser;
   editing keeps it unless you choose **Replace key**.
   **Import from .env** takes a dropped or chosen `.env` file: the browser tab reads and parses
   it, recognises provider keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, or any
   `<NAME>_API_KEY` with a `<NAME>_BASE_URL`), and shows a review list with masked keys. Other
   variables are never shown or sent. Only the entries you tick go to Wickey, after a dry run
   that flags duplicate keys and names (it asks for your passphrase, like adding a credential).
   Nothing is tested against the provider and no proxy keys are created.
2. **Issue a proxy key**: credential, lifetime (15 min, **1 hour** by default, 1 day, or **Custom**
   for a number of seconds/minutes/hours/days or an exact "expire at" time) and an optional name.
   The new key appears at the top of the list, already open, with its full key in a one-time panel:
   **Copy it now. It won't be shown again.** Close the panel, collapse the row or leave the page and
   the key is gone; the browser never holds it in the poll data or the page after that.
3. **All proxies**: search, filter by status, a **Show cleaned up** toggle for proxies `env` retired, and expand a row to copy its base URL and see its masked key,
   plus ready-made snippets (the full key only while the one-time panel is open, masked after):
   **Shell**, a **cURL test** that lists models (no tokens spent), **Python** for the OpenAI or
   Anthropic SDK, and, for named proxies, a **Shell profile** line. Row actions: **Renew**
   (expired only, same key), **Rotate** and **Delete** (both confirm first).

Actions that need the passphrase ask for it in a dialog.

Changes made from the CLI show up within 5 seconds. The page loads no external resources.

## How it works

- **Vault.** Real keys live in `~/.wickey/vault.json` (file mode `600`), encrypted with
  AES-256-GCM. A random data key encrypts everything; that data key is wrapped with a key derived
  from your passphrase using scrypt (N=2^17, about 128 MB per unlock). Each secret is bound to its
  credential, so moving one credential's encrypted key onto another fails to decrypt.
- **Keys exist only in the proxy's memory.** The unlocked data key is held by the running proxy and
  never written to disk. After a restart it is locked, and proxy keys return `503` until you unlock.
- **Database.** Credentials and proxies live in `~/.wickey/wickey.db` (SQLite). Proxy keys
  are stored only as a SHA-256 hash plus their last 5 characters, so they can't be shown again. Real
  provider keys are never in this file.
- **Signed rows.** Every credential and proxy row carries an HMAC made with a key from the vault.
  A row written or edited directly in the SQLite file fails the check: such a proxy is refused, and
  a credential that fails is never sent a real key.
- **The proxy** listens on `127.0.0.1` only. It checks the key against `/p/<proxy-id>`, rejects it
  if expired, strips the incoming auth, adds the real key (`Authorization: Bearer` or `x-api-key`),
  and pipes the response back unbuffered so streaming works. Expiry is checked when a request
  starts; a stream already running is allowed to finish. It reads the database on every request, so
  `expire`, `renew` and `rotate` from another terminal apply immediately.
- **Management API.** `/api/*` only answers requests whose `Host` is `127.0.0.1` or `localhost` on
  the proxy's port (blocks DNS rebinding), whose `Origin`, if sent, is that same address, and that
  carry an `x-wickey` header (forces a CORS preflight the server never approves). This stops
  web pages in your browser. Programs running as you are stopped by the session requirement and the
  passphrase gate.
- **Terminal prompts** read from the terminal directly (`/dev/tty`, or `CONIN$` on Windows), so they
  work inside `eval "$(wickey env …)"` where stdout is captured.

## What this protects, and what it doesn't

**Protects against**

- Real keys leaking off your machine through transcripts, logs, screenshots, or commits: only
  `sk-wick-…` keys appear there, and they expire and work only against this proxy.
- A local program minting new keys, reading real keys, forging or extending proxy records, or
  redirecting a credential to another server, without the passphrase. Proxy keys are stored only as
  a hash and every API route needs a session, so a program holding key A cannot get key B.
- **A hijacked or runaway agent that holds a valid key.** Per-key limits bound it: it can call only
  the models on the allowlist, at the rate you set, and spend only the token cap. It can't raise
  those limits without the passphrase, and editing the database to do so fails the signature check.

**Does not protect against**

- A key in your shell environment (`env`) being read by a program running in that shell.
- A same-user debugger reading the proxy's memory, or a program watching you type the passphrase.
- A tab you signed in to minting keys during the grace period.
- **Any local process holding a valid key** can use it until it expires or hits a limit. Limits
  narrow what that key can do; they don't hide it.
- **Limits are not exact.** Caps stop new requests, so in-flight requests can overshoot by what they
  reserved (at most 8 in flight). A client that hangs up mid-stream can leave a response nobody
  reads, which still costs tokens.
- **Providers that report no usage**, if you allow uncounted usage on a capped key: those requests
  run and are not counted against the cap. The default is to refuse them.
- **Rollback across a restart.** While running, the proxy flags a key whose usage or row went
  backwards. After a restart it accepts whatever is on disk, so an older database copy restores old
  totals and limits. Rotate or delete a flagged key.
- **Auto-renew** keeps a key alive as long as it is used, up to the maximum lifetime you approved.
- **Restoring an older copy of the database** (confirmed in testing): an old rotated or expired
  proxy key works again until its original expiry. The attacker has to stop the proxy, and you have
  to unlock it again, so watch for unexpected unlock prompts. No same-user fix exists on every OS,
  because any "latest state" record is also a file that can be restored. Keep lifetimes short, and
  after a real leak rotate the key at the provider too.
- **Offline guessing against a copied `vault.json`**: measured at about 6 guesses per second per
  core on an Apple-silicon Mac. That is why new passphrases need 12+ characters. The online
  wrong-passphrase limit resets when the proxy restarts, so it only slows casual guessing.
- **Reading the proxy's memory**: a debugger running as you could attach to the proxy without root
  on macOS. Pulling keys out of memory wasn't demonstrated, but assume it's possible with effort.
  The same goes for the row-signing key: someone who gets it can forge limits.

These results come from an adversarial test run against a throwaway instance. Attacks that did
**not** work: forging or editing database rows, tampering with `vault.json` (including weakening its
encryption settings), API header, host, path and body tricks, request smuggling and header
injection, upstream redirects (never followed), script injection in the dashboard, and minting from
the CLI without a terminal, and loosening a key's limits without the passphrase. The limits were
red-teamed against mock providers, not real ones. See [SECURITY.md](SECURITY.md) for the full threat model.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md): it explains what Wickey is for, the principles
every change keeps (local-first, zero runtime dependencies, cross-platform, honest security
claims), and how to run and test it. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) maps the code,
and [SECURITY.md](SECURITY.md) has the threat model and how to report a vulnerability privately.
Licensed under [MIT](LICENSE).

## Configuration

| Env var | Default | Purpose |
| --- | --- | --- |
| `WICKEY_PORT` | `7777` | Proxy and dashboard port |
| `WICKEY_HOME` | `~/.wickey` | Where `vault.json` and the database live |
| `WICKEY_GRACE` | `300` | Grace period in seconds; `0` turns it off |
| `WICKEY_SCRYPT_N` | `131072` | scrypt cost for new vaults. Tests only: lowering it weakens the vault |

## Development

```sh
npm test          # node:test against a fake upstream
npm run typecheck
npm pack          # builds the dashboard and compiles src/ to dist/ (Node won't run .ts from node_modules)
```

Tests isolate themselves with `WICKEY_HOME`, `WICKEY_PORT`,
`WICKEY_SCRYPT_N` and `WICKEY_GRACE`, so they never touch your real vault.

## Roadmap

1. ~~Vault, issue, proxy, expiry (API keys)~~
2. ~~CLI~~
3. ~~Local web dashboard~~
4. ~~Passphrase-encrypted cross-platform vault, signed records, grace period~~
5. Verify on Windows
6. ChatGPT sign-in as a credential source (needs translation to the Codex backend's request format)
7. Claude Pro/Max sign-in, off by default behind a risk switch. Anthropic's terms restrict
   subscription logins to its own apps, and accounts using them elsewhere have been suspended.
8. ~~Per-key limits and activity log~~
9. Spend caps in money (deferred: prices would have to be entered by hand)
