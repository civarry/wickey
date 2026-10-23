# Contributing to Wickey

Thanks for helping. This page covers what the project is for, the rules every change follows, and
how to run and test it. For how the code fits together, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
To report a vulnerability, read [SECURITY.md](SECURITY.md) first and do not open a public issue.

## What Wickey is for

Real LLM provider keys should stay out of reach of the apps and AI agents that use them.

- Real keys live in a passphrase-encrypted vault on the user's machine.
- Apps and agents get a localhost base URL and a short-lived `sk-wick-...` proxy key instead.
- The proxy key works only against the local proxy and stops working when its time runs out.
- Minting a key (or changing where a real key goes) needs the user's passphrase.

If a change does not serve that goal, it probably does not belong here.

## Principles

Every change should respect these.

- **Local-first.** Nothing leaves the machine except proxied requests to the provider the user chose.
  No telemetry, no update checks, no external resources in the dashboard.
- **Zero runtime dependencies.** Node 24 built-ins only. Dev dependencies (TypeScript, `@types/node`)
  are fine. A new runtime dependency needs a very strong reason.
- **Cross-platform.** macOS, Linux and Windows. Windows is not yet verified, so be careful with
  paths, terminals and shell output, and say so when you could not test a platform.
- **Honest security claims.** Never claim protection the code does not give. If you find a limit,
  document it in the README and in [SECURITY.md](SECURITY.md).
- **Small and boring over clever.** Prefer the plain solution a stranger can review in one sitting.
- **One passphrase gate.** Anything that mints a key or can redirect a real key goes through
  `requireAuth` in `src/session.ts`.

## Non-goals

- A hosted or multi-user service. This is one user, one machine, `127.0.0.1` only.
- Storing keys in plaintext anywhere (files, database, logs, environment of the proxy).
- Provider-specific features beyond authentication, forwarding and per-key limits (no model
  routing or prompt handling). Requests are rewritten only for keys with a token cap or model
  allowlist, so the provider sees exactly what was checked.
- Logging prompts or responses. The activity log is metadata only, with no option to change that.

Per-key limits and the activity log are built. Spend caps in money are not: prices would have to be
entered by hand, so they are deferred. Discuss them in an issue before building.

## Dev setup

You need Node.js 24 or newer.

```sh
git clone https://github.com/civarry/wickey.git && cd wickey
npm install          # dev tools only; also builds the dashboard (web/dist)
npm test             # node:test, uses a fake upstream
npm run typecheck    # same as npx tsc
npm run build        # rebuild the dashboard after changing web/
npm run check        # svelte-check for the dashboard
npm run dev:web      # Vite dev server for web/, proxying to a running backend
```

Node runs the TypeScript source directly. There is no build step in development; `npm pack` compiles
`src/` to `dist/` for the published package, because Node won't run `.ts` files from `node_modules`.

### Run against a throwaway instance

Never develop against your real `~/.wickey`. Point everything at a temp directory:

```sh
export WICKEY_HOME="$(mktemp -d)"
export WICKEY_PORT=7790
export WICKEY_SCRYPT_N=1024     # fast KDF, for development only
export WICKEY_GRACE=30          # seconds; 0 asks for the passphrase on every mint
node bin/wickey.js start
```

In a second terminal with the same variables, use the CLI (`add`, `issue`, `list`, ...). When done,
stop the proxy and delete the temp directory.

## Code conventions

- TypeScript with erasable syntax only: no enums, no constructor parameter properties. The
  `erasableSyntaxOnly` option in `tsconfig.json` enforces this.
- Import with the `.ts` extension (`import { x } from './store.ts'`).
- Comments explain why, briefly. Match the density of the surrounding code.
- No em dashes in user-facing text (CLI output, dashboard, README, docs). Use a colon, comma or period.
- Error messages say what to do next ("Enter your passphrase to continue", not just "Unauthorized").
- Every write to the `credentials` or `proxies` table must be followed by re-signing that row
  (`resignCredential` / `resignProxy` in `src/store.ts`).
- Minting and credential-changing paths go through `requireAuth`: issue, rotate, renew, `env` when
  it has to mint, and adding or editing a credential. Expire, delete and remove must not, because
  they only take access away.
- Commands that change state go through the running proxy's API, not the database. See the
  architecture doc for why.

## Renaming the project

Rename = edit `src/brand.ts` and `package.json` (`name`, `bin`). `brand.ts` holds the command, data
directory, database file, env prefix, launchd label, systemd unit, Windows task and log names.
The wire and crypto strings in `brand.ts` break deployed clients or stored data if changed:
the `sk-wick-` key prefix, the `x-wickey` header, the `wickey_error` type, the cookie name, and the
`wickey/v1/...` context strings in `src/vault.ts` (changing those makes existing vaults
undecryptable). Changing any of them is a migration, not a rename. User-facing help and error text
still says `wickey` literally.

## Security-sensitive changes

If you touch the vault, signatures, the passphrase gate, the grace period, the API checks or the
proxy's header handling:

1. Add a test that fails without your fix. `test/security.test.ts` plays a local attacker and is
   the right place for most of them.
2. Prove it: temporarily break the code (or revert your fix), run the **whole** test file, and
   confirm the new test fails. Restore the code. Running one test by name skips the setup tests and
   gives false results.
3. Update the README and [SECURITY.md](SECURITY.md) if the change alters what is or is not protected.

## Testing rules

- Tests must never touch the real `~/.wickey`. Use
  `WICKEY_HOME`, `WICKEY_PORT`, `WICKEY_SCRYPT_N` and
  `WICKEY_GRACE`, as the existing tests do.
- Tests in one file share module state (vault keys, grace period, throttle), so order matters
  within a file.
- If you change the dashboard, drive it in a browser. Reading the code is not proof.

## Pull requests

Before opening one:

- [ ] `npm test` passes
- [ ] Dashboard changes: `npm run build` and `npm run check` are clean, colours come only from
      tokens in `web/src/app.css`, and buttons/inputs use the shared components
- [ ] `npx tsc` passes
- [ ] Security-sensitive changes have a test that fails without the fix
- [ ] README and docs updated if behavior changed
- [ ] No new runtime dependency
- [ ] Works without network access beyond the provider
- [ ] No em dashes in user-facing text

Keep each PR to one logical change. Say which platforms you tested on.

## Commit messages

Plain and descriptive: one short imperative subject line, under about 60 characters, no trailing
period, no prefixes like `feat:`. Examples: `Add grace period banner to dashboard`,
`Fix throttle reset after unlock`. Add a short body only when the reason is not obvious from the
subject.

## Releasing (maintainers)

Releases are built and staged by CI with npm provenance; a maintainer approves them with 2FA.
Nobody publishes from a laptop: `npm publish` packs the working tree, so uncommitted files would
ship.

1. Bump the version: `npm version <x.y.z> --no-git-tag-version`, commit `Release x.y.z`, push.
2. Tag that commit and push the tag: `git tag vx.y.z && git push origin vx.y.z`.
3. The Release workflow (`.github/workflows/release.yml`) checks the tag matches `package.json`,
   runs typecheck and tests, and runs `npm stage publish --provenance`.
4. Approve the staged version on npmjs.com (package page, staged versions). Check its version and
   that the build came from the tagged commit.

One-time setup, already needed before the first CI release: on npmjs.com, open the `wickey`
package settings, add a trusted publisher for GitHub Actions (owner `civarry`, repository
`wickey`, workflow `release.yml`), and allow it to stage publishes.

## License

By contributing you agree your work is released under the [MIT License](LICENSE).
