import { parseArgs } from 'node:util';
import { BRAND } from './brand.ts';
import { config } from './config.ts';
import { parseModelsFlag } from './models.ts';
import { PROVIDERS, isProvider } from './providers.ts';
import { hasTerminal, promptHidden, promptVisible, readPiped } from './prompt.ts';
import { RotatingLog, hardenDataDir, redirectOutput } from './logfile.ts';
import { createProxyServer } from './proxy.ts';
import { isProxyRunning, performReset, planReset } from './reset.ts';
import { runServiceCommand } from './service.ts';
import { graceSeconds, openSetup, setUp, unlock } from './session.ts';
import { runSetup } from './setup.ts';
import { getProxy, listCredentials, listProxies, type Limits, type Proxy } from './store.ts';
import { DEFAULT_TTL_SECONDS, formatDuration, parseTtl } from './ttl.ts';
import { MIN_PASSPHRASE, WrongPassphraseError, vaultExists } from './vault.ts';

const HELP = `Wickey: hand out short-lived proxy credentials instead of your real LLM API keys.

Real keys live in an encrypted vault (~/${BRAND.dataDirName}/vault.json) locked by your passphrase.
Every command that changes something asks for it (hidden prompt, once per command; no terminal, no
command). Keys are shown only once, when issued or rotated; only a hash is kept. Minting from a
dashboard tab you are signed in to skips the prompt for ${formatDuration(graceSeconds())} after you last entered it
(${BRAND.envPrefix}GRACE=<seconds> to change, 0 to turn off).

Server
  start                  Run the proxy and dashboard on http://127.0.0.1:${config().port} (${BRAND.envPrefix}PORT to change).
                         Asks for your passphrase (or sets one up on first run).
                         --service: how the start-on-login service runs it (no prompts, starts locked, own log file).
  unlock                 Unlock a running proxy and start the grace period
  lock                   End the grace period now and sign every session out (no passphrase needed)
  passphrase             Change the passphrase (asks for the current one even during the grace period)
  reset                  Forgot the passphrase? Delete the vault and all data, then set up again.
                         Asks for confirmation in a terminal, with the proxy stopped. Provider keys are not revoked.

  setup                  Guided first run: passphrase, credentials (add or import a .env file), start on login.
                         Every step can be skipped and is also its own command. Needs a terminal.
  service install | uninstall | status
                         Start the proxy when you log in (macOS LaunchAgent, Linux systemd user unit,
                         Windows Task Scheduler: experimental). It starts locked; unlock it once per login.
                         Its log is ${BRAND.dataDirName}/logs/${BRAND.logFileName} (1 MB cap, 3 files).

Credentials
  add <name> --provider <p> [--base-url <url>] [--auth bearer|x-api-key]
                         Store a credential. The key is read from a hidden prompt or stdin.
                         Providers: ${Object.keys(PROVIDERS).join(', ')}
  creds                  List stored credentials
  edit <name> [--name <new>] [--base-url <url>] [--auth bearer|x-api-key] [--key]
                         Change a credential; --key prompts for a replacement key.
  models <credential> [--refresh]
                         List the model IDs the provider reports for a credential, one per line.
                         Cached; --refresh asks the provider again.
  remove <name>          Delete a credential and every proxy issued from it

Proxies (temporary base URL + key)
  issue <credential> [--ttl 60s] [--name <label>] [--env | --powershell | --json]
        [--models all|none|a,b,c] [--rpm N] [--max-tokens N] [--allow-uncapped]
        [--auto-renew <window> --max-lifetime <ttl>]
                         Issue a proxy. TTL accepts 30s, 5m, 2h, 1d (default ${DEFAULT_TTL_SECONDS}s).
                         Optional limits: allowed models, requests per minute, a total token cap.
                         --models all (default): any model the provider lists for this credential,
                         checked against its model list (see the models command). none: refuse every request.
                         a,b,c: exactly those IDs. Raising the models (none -> list/all, list -> all,
                         adding IDs) is loosening and needs the passphrase.
                         With a token cap, requests whose usage can't be counted are refused
                         unless --allow-uncapped.
                         Auto-renew (opt-in, needs the passphrase): a key used within <window> of its
                         expiry extends itself by one TTL, never past --max-lifetime from now. Both flags
                         are required together. The maximum is the real lifetime you are approving.
                         Only requests sent upstream count; expired, limit-hit or refused keys never renew.
  limits <id> [--models all|none|a,b | --any-model] [--rpm N | --no-rpm] [--max-tokens N | --no-max-tokens]
              [--allow-uncapped | --refuse-uncapped]
              [--no-auto-renew | --auto-renew <window> | --max-lifetime <ttl>]
                         Change a proxy's limits. Tightening needs no passphrase; loosening does.
                         --any-model is the same as --models all.
                         --max-lifetime counts from now. Enabling auto-renew, a later maximum or a
                         wider window is loosening; --no-auto-renew, an earlier maximum or a
                         narrower window is not.
  env <name> --credential <cred> [--ttl 8h] [--powershell] [limit flags as for issue]
                         Print env lines with a NEW key minted for this terminal (asks for the
                         passphrase every time; expired keys of the same name are cleaned up).
                         For shell profiles:
                           zsh/bash:    eval "$(wickey env work --credential work --ttl 8h)"
                           PowerShell:  wickey env work --credential work --ttl 8h --powershell | Invoke-Expression
  list [--all]           List proxies with status, time left, limits and usage. --all adds the
                         expired ones env has cleaned up (hidden by default; their activity is kept).
  show <id> [--env | --powershell | --json]
                         Print a proxy's base URL and masked key (the full key is shown only once)
  renew <id> [--ttl <t>] Restart the timer, keeping the same key
  rotate <id> [--ttl <t>] [--env | --powershell | --json]
                         Replace the key (shown once) and restart the timer; the old key stops working now
  expire <id>            End a proxy now, as if its time ran out
  delete <id>            Remove a proxy
`;

// setup keeps going after a rejected entry; everywhere else a failure ends the command.
let failThrows = false;

function fail(message: string): never {
  if (failThrows) throw new Error(message);
  process.stderr.write(`error: ${message}\n`);
  process.exit(1);
}

function proxyBaseUrl(proxy: Proxy): string {
  const { host, port } = config();
  return `http://${host}:${port}/p/${proxy.id}`;
}

function timeLeft(proxy: Proxy): string {
  if (proxy.status === 'expired') return `expired ${formatDuration((Date.now() - proxy.expiresAt) / 1000)} ago`;
  return `${formatDuration((proxy.expiresAt - Date.now()) / 1000)} left`;
}

// One command, one session. The passphrase is typed (hidden) once per command, traded for a
// session cookie held only in this process, and the session is ended when the command finishes.
// Neither the passphrase nor the cookie is written anywhere.
const cli: { cookie: string | null; passphrase: string | null } = { cookie: null, passphrase: null };

const NO_TERMINAL = 'This needs your passphrase, but there is no terminal to ask it in. Run it in a terminal (cron, CI and other background jobs cannot mint keys).';

function url(path: string): string {
  const { host, port } = config();
  return `http://${host}:${port}${path}`;
}

function cookieFrom(res: Response): string | null {
  const first = res.headers.get('set-cookie')?.split(';')[0];
  return first && first.includes('=') ? first : null;
}

async function send(method: string, path: string, body: Record<string, unknown>, cookie: string | null): Promise<Response> {
  try {
    return await fetch(url(path), {
      method,
      headers: { [BRAND.requestHeader]: '1', 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
      body: method === 'GET' ? undefined : JSON.stringify(body),
    });
  } catch {
    return fail("wickey isn't running. Start it with `wickey start`.");
  }
}

/** Ends this command's session on the proxy; best effort, never throws. */
async function endCliSession(): Promise<void> {
  const cookie = cli.cookie;
  cli.cookie = null;
  if (!cookie) return;
  await fetch(url('/api/signout'), { method: 'POST', headers: { [BRAND.requestHeader]: '1', cookie } }).catch(() => {});
}

async function failAfterSignOut(message: string): Promise<never> {
  await endCliSession();
  return fail(message);
}

async function askPassphrase(): Promise<string> {
  const passphrase = await promptHidden('Wickey passphrase: ');
  if (passphrase === null) return failAfterSignOut(NO_TERMINAL);
  if (!passphrase) return failAfterSignOut('Cancelled.');
  return passphrase;
}

/** Proves the passphrase to the running proxy (signing in, or unlocking it first) and keeps the cookie. */
async function ensureSession(reprompt = true): Promise<void> {
  if (cli.cookie) return;
  for (let attempt = 0; ; attempt++) {
    const preset = cli.passphrase !== null;
    const passphrase = cli.passphrase ?? await askPassphrase();
    let res = await send('POST', '/api/signin', { passphrase }, null);
    let data = await res.json().catch(() => ({}));
    // A locked proxy (after a restart) cannot sign anyone in; the passphrase unlocks it.
    if (res.status === 401 && data.error?.code === 'passphrase_required') {
      res = await send('POST', '/api/unlock', { passphrase }, null);
      data = await res.json().catch(() => ({}));
    }
    if (res.ok) {
      cli.passphrase = passphrase;
      cli.cookie = cookieFrom(res);
      if (!cli.cookie) fail('The proxy did not start a session. Update Wickey and restart it.');
      return;
    }
    if (data.error?.code === 'setup_required') fail('No passphrase set yet. Run `wickey start` in a terminal to set one up.');
    if (data.error?.code !== 'wrong_passphrase') fail(data.error?.message ?? `Sign-in failed (${res.status}).`);
    cli.passphrase = null;
    if (preset && !reprompt) fail('Wrong current passphrase. Nothing was changed; run `wickey passphrase` to try again.');
    if (attempt >= 2) fail('Wrong passphrase.');
    process.stderr.write('Wrong passphrase.\n');
  }
}

/**
 * Commands that change anything go through the running proxy: it is the only process holding the
 * unlocked vault. Each one signs in with the passphrase first (see above); minting and other
 * sensitive calls send the passphrase again when the grace period is off or over.
 */
async function call(method: string, path: string, body: Record<string, unknown> = {}, retryWithPassphrase = true): Promise<any> {
  // Setup is the one call made before any passphrase exists; it hands back a session of its own.
  const pre = path === '/api/setup';
  if (!pre) await ensureSession(retryWithPassphrase);
  let res = await send(method, path, body, cli.cookie);
  let data = await res.json().catch(() => ({}));
  if (pre && res.ok) cli.cookie = cookieFrom(res);
  if (res.status === 401 && data.error?.code === 'session_required' && !pre) {
    // Idle expiry or a Lock from the dashboard ended it: sign in again.
    cli.cookie = null;
    await ensureSession(retryWithPassphrase);
    res = await send(method, path, body, cli.cookie);
    data = await res.json().catch(() => ({}));
  }
  for (let attempt = 0; retryWithPassphrase && attempt < 3 && res.status === 401 && ['passphrase_required', 'wrong_passphrase'].includes(data.error?.code); attempt++) {
    if (data.error.code === 'wrong_passphrase') process.stderr.write('Wrong passphrase.\n');
    const passphrase = cli.passphrase && data.error.code === 'passphrase_required' ? cli.passphrase : await askPassphrase();
    cli.passphrase = passphrase;
    res = await send(method, path, { ...body, passphrase }, cli.cookie);
    data = await res.json().catch(() => ({}));
  }
  if (data.error?.code === 'setup_required') return failAfterSignOut('No passphrase set yet. Run `wickey start` in a terminal to set one up.');
  if (!res.ok) return failAfterSignOut(data.error?.message ?? `Request failed (${res.status}).`);
  return data;
}

type Format = { env?: boolean; powershell?: boolean; json?: boolean };

function envLines(proxy: Proxy, token: string, powershell?: boolean): string {
  const prefix = PROVIDERS[proxy.provider].envPrefix;
  const pairs: [string, string][] = [[`${prefix}_BASE_URL`, proxyBaseUrl(proxy)], [`${prefix}_API_KEY`, token]];
  return pairs.map(([k, v]) => (powershell ? `$env:${k} = "${v}"` : `export ${k}=${v}`)).join('\n');
}

function printIssued(proxy: Proxy, token: string, format: Format): void {
  if (format.json) {
    console.log(JSON.stringify({ id: proxy.id, baseUrl: proxyBaseUrl(proxy), apiKey: token, expiresAt: new Date(proxy.expiresAt).toISOString() }));
    return;
  }
  if (format.env || format.powershell) return console.log(envLines(proxy, token, format.powershell));
  const label = proxy.label ? ` (${proxy.label})` : '';
  console.log(`Proxy ${proxy.id}${label} -> ${proxy.credentialName}, expires in ${formatDuration(proxy.ttlSeconds)} ` +
    `at ${new Date(proxy.expiresAt).toLocaleTimeString()}\n`);
  console.log(`BASE_URL=${proxyBaseUrl(proxy)}`);
  console.log(`API_KEY=${token}\n`);
  if (proxy.autoRenew) {
    console.log(`Auto-renews when used within ${formatDuration(proxy.autoRenew.windowSeconds)} of expiry, until ${new Date(proxy.autoRenew.maxExpiresAt).toLocaleString()} at the latest.\n`);
  }
  console.log('Shown only once: copy the key now. If it is lost, `wickey rotate ' + proxy.id + '` makes a new one.');
}

function graceNote(): string {
  const s = graceSeconds();
  return s
    ? `For the next ${formatDuration(s)}, a dashboard tab you are signed in to can mint keys without the passphrase. Run \`wickey lock\` to end that early and sign every tab out.`
    : 'Grace period is off: every key you mint asks for the passphrase.';
}

function parseCount(flag: string, value: string): number {
  if (!/^\d+$/.test(value)) fail(`--${flag} needs a whole number, like --${flag} 60.`);
  return Number(value);
}

function modelsOrFail(value: string): string[] | null {
  try { return parseModelsFlag(value); } catch (err) { return fail((err as Error).message); }
}

/** Limits named by issue/env flags; undefined when none were given. */
function limitsFromFlags(v: Record<string, any>): Partial<Limits> | undefined {
  if (v.models === undefined && v.rpm === undefined && v['max-tokens'] === undefined && !v['allow-uncapped']) return undefined;
  return {
    models: v.models === undefined ? null : modelsOrFail(String(v.models)),
    rpm: v.rpm === undefined ? null : parseCount('rpm', v.rpm),
    tokenCap: v['max-tokens'] === undefined ? null : parseCount('max-tokens', v['max-tokens']),
    refuseUncounted: !v['allow-uncapped'],
  };
}

/** The auto-renew part of issue/env flags; undefined when none were given. Both flags must come together. */
function autoRenewFromFlags(v: Record<string, any>): { windowSeconds: number; maxLifetime: string } | undefined {
  if (v['auto-renew'] === undefined && v['max-lifetime'] === undefined) return undefined;
  if (v['auto-renew'] === undefined || v['max-lifetime'] === undefined) {
    fail('Auto-renew needs both flags: --auto-renew <window> and --max-lifetime <ttl>, e.g. --auto-renew 10m --max-lifetime 7d.');
  }
  let windowSeconds: number;
  try { windowSeconds = parseTtl(String(v['auto-renew'])); } catch (err) { return fail((err as Error).message); }
  return { windowSeconds, maxLifetime: String(v['max-lifetime']) };
}

function compact(n: number): string {
  if (n >= 1e6) return `${+(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${+(n / 1e3).toFixed(1)}k`;
  return String(n);
}

/** "3 models, 60 rpm, 12k/100k tok", or "-" for a key with no limits and no use. */
function limitsSummary(p: Proxy): string {
  const parts: string[] = [];
  if (p.limits.models?.length === 0) parts.push('no models');
  else if (p.limits.models) parts.push(`${p.limits.models.length} model${p.limits.models.length === 1 ? '' : 's'}`);
  if (p.limits.rpm !== null) parts.push(`${p.limits.rpm} rpm`);
  const used = p.usage.tokensIn + p.usage.tokensOut;
  if (p.limits.tokenCap !== null) parts.push(`${compact(used)}/${compact(p.limits.tokenCap)} tok`);
  else if (used > 0) parts.push(`${compact(used)} tok`);
  if (p.autoRenew && p.status === 'active') parts.push(`auto-renews until ${new Date(p.autoRenew.maxExpiresAt).toLocaleString()}`);
  if (!p.usage.ok) parts.push('USAGE TAMPERED');
  return parts.join(', ') || '-';
}

function pad(value: string, width: number): string {
  return value.length >= width ? value : value + ' '.repeat(width - value.length);
}

function table(rows: string[][]): string {
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => r[i].length)));
  return rows.map((r) => r.map((cell, i) => pad(cell, widths[i])).join('  ').trimEnd()).join('\n');
}

async function askNewPassphrase(): Promise<string | null> {
  if (!hasTerminal()) return null;
  console.log('Set a passphrase. It encrypts your provider keys and is needed to mint proxy keys.');
  console.log(`Use at least ${MIN_PASSPHRASE} characters; four or more random words work well. It can't be recovered if you forget it.`);
  for (let i = 0; i < 3; i++) {
    const first = await promptHidden('New passphrase: ');
    if (first === null) return null;
    if (first.length < MIN_PASSPHRASE) { console.log(`Too short: use at least ${MIN_PASSPHRASE} characters.`); continue; }
    const again = await promptHidden('Repeat passphrase: ');
    if (again === first) return first;
    console.log("Those didn't match. Try again.");
  }
  fail('Passphrase not set.');
}

async function start(asService: boolean): Promise<void> {
  const { host, port } = config();
  let setupToken: string | null = null;
  hardenDataDir();
  if (asService) {
    // Started by launchd/systemd/Task Scheduler: no terminal, so never prompt. The proxy comes up
    // locked and waits for an unlock; its own capped log replaces the OS-level output files.
    redirectOutput(new RotatingLog(config().logFile));
    // No setup link here: this output goes to a log file that any program running as the user
    // can read, and the link is exactly what such a program must not get.
    console.log(vaultExists() ? 'Starting locked: unlock in the dashboard or with `wickey unlock`.' : 'No passphrase set yet. Run `wickey service uninstall`, then `wickey setup` in a terminal (it can reinstall the service).');
  } else if (!vaultExists()) {
    const passphrase = await askNewPassphrase();
    if (passphrase === null) {
      setupToken = openSetup();
    } else {
      setUp(passphrase);
      console.log('Passphrase set. Your keys are now in the encrypted vault.');
      console.log(graceNote());
    }
  } else {
    for (let i = 0; ; i++) {
      const passphrase = await promptHidden('Wickey passphrase: ');
      if (passphrase === null || passphrase === '') {
        console.log('Starting locked: proxy keys stop working until you unlock in the dashboard or run `wickey unlock`.');
        break;
      }
      try {
        unlock(passphrase);
        console.log(`Unlocked. ${graceNote()}`);
        break;
      } catch (err) {
        if (!(err instanceof WrongPassphraseError) || i === 2) throw err;
        console.log('Wrong passphrase.');
      }
    }
  }
  const server = createProxyServer();
  server.on('error', (err: NodeJS.ErrnoException) =>
    fail(err.code === 'EADDRINUSE' ? `Port ${port} is already in use. Is Wickey already running?` : err.message));
  server.listen(port, host, () => {
    console.log(`Wickey proxy listening on http://${host}:${port}\nDashboard: http://${host}:${port}/`);
    // Printed only here, where it reaches whoever ran `start`. It works once and dies with this process.
    if (setupToken) console.log(`\nNo terminal to set a passphrase in. Open this one-time link to set it:\n  http://${host}:${port}/#setup=${setupToken}`);
  });
}

async function main(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      provider: { type: 'string' },
      'base-url': { type: 'string' },
      auth: { type: 'string' },
      ttl: { type: 'string' },
      name: { type: 'string' },
      env: { type: 'boolean' },
      powershell: { type: 'boolean' },
      json: { type: 'boolean' },
      all: { type: 'boolean' },
      key: { type: 'boolean' },
      credential: { type: 'string' },
      models: { type: 'string' },
      'any-model': { type: 'boolean' },
      refresh: { type: 'boolean' },
      rpm: { type: 'string' },
      'no-rpm': { type: 'boolean' },
      'max-tokens': { type: 'string' },
      'no-max-tokens': { type: 'boolean' },
      'auto-renew': { type: 'string' },
      'no-auto-renew': { type: 'boolean' },
      'max-lifetime': { type: 'string' },
      'allow-uncapped': { type: 'boolean' },
      'refuse-uncapped': { type: 'boolean' },
      service: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const [command, arg] = values.help ? ['help'] : positionals;
  const enc = (s: string) => encodeURIComponent(s);

  switch (command) {
    case 'start':
      return start(!!values.service);

    case 'service': {
      const code = await runServiceCommand(arg);
      if (code) process.exitCode = code;
      return;
    }

    case 'setup':
      return runSetup({
        call: (method, p, body) => call(method, p, body),
        rememberPassphrase: (passphrase) => { cli.passphrase = passphrase; },
        askNewPassphrase,
        fail,
        soft: async (fn) => {
          failThrows = true;
          try { return await fn(); } finally { failThrows = false; }
        },
      });

    case 'unlock': {
      const passphrase = await promptHidden('Wickey passphrase: ');
      if (passphrase === null) fail(NO_TERMINAL);
      if (!passphrase) fail('Cancelled.');
      // Unlock hands back a session, which this command has no use for.
      const res = await send('POST', '/api/unlock', { passphrase }, null);
      const data = await res.json().catch(() => ({}));
      cli.cookie = cookieFrom(res);
      if (!res.ok) await failAfterSignOut(data.error?.message ?? `Unlock failed (${res.status}).`);
      console.log(`Unlocked. ${graceNote()}`);
      return;
    }

    case 'lock': {
      // Lock needs no session (it only ends the grace period), so no passphrase prompt.
      const res = await send('POST', '/api/lock', {}, null);
      if (!res.ok) fail(`Lock failed (${res.status}). Update Wickey and restart it.`);
      console.log('Locked: minting keys needs the passphrase again. Existing proxy keys keep working.');
      return;
    }

    case 'passphrase': {
      if (!hasTerminal()) fail('Changing the passphrase needs a terminal to type it in. Run `wickey passphrase` in one.');
      const current = await promptHidden('Current passphrase: ');
      if (!current) fail('Cancelled.');
      const next = await promptHidden('New passphrase: ');
      if (!next) fail('Cancelled.');
      if (next.length < MIN_PASSPHRASE) fail(`The new passphrase must be at least ${MIN_PASSPHRASE} characters. Nothing was changed.`);
      if (next === current) fail('The new passphrase must be different from the current one. Nothing was changed.');
      if ((await promptHidden('Repeat new passphrase: ')) !== next) fail("The new passphrases didn't match. Nothing was changed.");
      // Its own passphrases, so the generic "ask for the passphrase and retry" loop must stay off.
      cli.passphrase = current;
      const data = await call('POST', '/api/passphrase', { current, next }, false);
      console.log(data.message);
      return;
    }

    case 'reset': {
      if (!hasTerminal()) fail('Reset asks you to confirm in a terminal, to guard against running it by accident. Run `wickey reset` in one.');
      if (await isProxyRunning()) fail(`Wickey is running on port ${config().port}. Stop it first (Ctrl-C in the terminal running \`wickey start\`), then run \`wickey reset\` again.`);
      const plan = planReset();
      if (!plan.vaultFile && !plan.credentials.length && !plan.proxies) return console.log('Nothing to reset: there is no vault or data in ' + config().home + '.');
      console.log('This permanently deletes:');
      console.log(`  ${plan.vaultFile ?? '(no vault file)'}  (your encrypted provider keys)`);
      console.log(`  ${plan.credentials.length} credential(s)${plan.credentials.length ? `: ${plan.credentials.join(', ')}` : ''}`);
      console.log(`  ${plan.proxies} proxy key(s) and ${plan.logEntries} activity log entr${plan.logEntries === 1 ? 'y' : 'ies'}`);
      console.log('\nYour real provider keys are NOT revoked. They stay valid at the provider, so revoke or rotate them there if you worry about them.');
      console.log('The passphrase cannot be recovered. After a reset you set a new one and add your provider keys again.\n');
      const answer = await promptVisible('Type reset to delete everything: ');
      if (answer?.trim() !== 'reset') fail('Cancelled. Nothing was deleted.');
      performReset();
      console.log('Deleted. Run `wickey start` to set a new passphrase, then add your provider keys again.');
      return;
    }

    case 'add': {
      if (!arg) fail('Usage: wickey add <name> --provider <provider>');
      const provider = values.provider ?? (isProvider(arg) ? arg : undefined);
      if (!provider || !isProvider(provider)) fail(`--provider must be one of: ${Object.keys(PROVIDERS).join(', ')}`);
      if (values.auth && values.auth !== 'bearer' && values.auth !== 'x-api-key') fail('--auth must be bearer or x-api-key');
      const apiKey = process.stdin.isTTY ? await promptHidden(`API key for ${arg}: `) : await readPiped();
      if (!apiKey) fail('No API key given.');
      const { credential } = await call('POST', '/api/credentials', {
        name: arg, provider, apiKey, baseUrl: values['base-url'], authStyle: values.auth,
      });
      console.log(`Stored "${credential.name}" (${credential.provider}, ${credential.baseUrl}) in the vault.`);
      return;
    }

    case 'creds': {
      const creds = listCredentials();
      if (!creds.length) return console.log('No credentials yet. Add one with `wickey add <name> --provider <p>`.');
      console.log(table([['NAME', 'PROVIDER', 'BASE URL', 'AUTH'], ...creds.map((c) => [c.name, c.provider, c.baseUrl, c.authStyle])]));
      return;
    }

    case 'edit': {
      if (!arg) fail('Usage: wickey edit <name> [--name <new>] [--base-url <url>] [--auth <style>] [--key]');
      if (values.auth && values.auth !== 'bearer' && values.auth !== 'x-api-key') fail('--auth must be bearer or x-api-key');
      if (!values.name && !values['base-url'] && !values.auth && !values.key) fail('Nothing to change. Pass --name, --base-url, --auth or --key.');
      const apiKey = values.key ? await promptHidden(`New API key for ${arg}: `) : undefined;
      if (values.key && !apiKey) fail('No API key given.');
      const { credential } = await call('PATCH', `/api/credentials/${enc(arg)}`, {
        name: values.name, baseUrl: values['base-url'], authStyle: values.auth, apiKey,
      });
      console.log(`Updated "${credential.name}" (${credential.baseUrl}, ${credential.authStyle}${apiKey ? ', new key' : ''}).`);
      return;
    }

    case 'remove': {
      if (!arg) fail('Usage: wickey remove <name>');
      const { credential } = await call('DELETE', `/api/credentials/${enc(arg)}`);
      console.log(`Removed "${credential.name}" and its proxies.`);
      return;
    }

    case 'issue': {
      if (!arg) fail('Usage: wickey issue <credential> [--ttl 60s]');
      const { proxy, token } = await call('POST', '/api/proxies', { credential: arg, ttl: values.ttl, label: values.name, limits: limitsFromFlags(values), autoRenew: autoRenewFromFlags(values) });
      return printIssued(proxy, token, values);
    }

    case 'env': {
      if (!arg || !values.credential) fail('Usage: wickey env <name> --credential <credential> [--ttl 8h]');
      const { proxy, token } = await call('POST', '/api/env', { label: arg, credential: values.credential, ttl: values.ttl, limits: limitsFromFlags(values), autoRenew: autoRenewFromFlags(values) });
      // stdout is evaluated by the shell, so it carries only the env lines; notes go to stderr.
      console.log(envLines(proxy, token, values.powershell));
      return;
    }

    case 'models': {
      if (!arg) fail('Usage: wickey models <credential> [--refresh]');
      const data = values.refresh
        ? await call('POST', `/api/credentials/${enc(arg)}/models/refresh`)
        : await call('GET', `/api/credentials/${enc(arg)}/models`);
      if (data.message) process.stderr.write(`wickey: ${data.message}\n`);
      if (data.unavailable) {
        process.stderr.write(`wickey: ${arg}'s provider has no model list (${data.error ?? 'no /models endpoint'}). Keys set to "all" pass any model through for this credential; use selected models to restrict it.\n`);
      } else if (data.error) {
        process.stderr.write(`wickey: could not refresh the model list (${data.error}).${data.models.length ? ' Showing the last list.' : ' Keys set to "all" will refuse requests until it works.'}\n`);
      }
      for (const id of data.models) console.log(id);
      return;
    }

    case 'list': {
      const proxies = listProxies({ includeCleaned: !!values.all });
      if (!proxies.length) return console.log('No proxies yet. Issue one with `wickey issue <credential>`.');
      console.log(table([
        ['ID', 'NAME', 'CREDENTIAL', 'KEY', 'STATUS', 'TIME', 'LIMITS / USAGE', 'BASE URL'],
        ...proxies.map((p) => [p.id, p.label ?? '-', p.credentialName, p.maskedKey, p.cleanedUp ? 'cleaned up' : p.cleanedTampered ? `${p.status} (TAMPERED: marked cleaned up while active)` : p.status, timeLeft(p), limitsSummary(p), proxyBaseUrl(p)]),
      ]));
      return;
    }

    case 'limits': {
      if (!arg) fail('Usage: wickey limits <id> [--models all|none|a,b | --any-model] [--rpm N | --no-rpm] [--max-tokens N | --no-max-tokens] [--allow-uncapped | --refuse-uncapped] [--no-auto-renew | --auto-renew <window> | --max-lifetime <ttl>]');
      const conflicts: [string, string][] = [['models', 'any-model'], ['rpm', 'no-rpm'], ['max-tokens', 'no-max-tokens'], ['allow-uncapped', 'refuse-uncapped'], ['auto-renew', 'no-auto-renew'], ['max-lifetime', 'no-auto-renew']];
      for (const [a, b] of conflicts) if (values[a as keyof typeof values] !== undefined && values[b as keyof typeof values]) fail(`Use either --${a} or --${b}, not both.`);
      if (!conflicts.flat().some((f) => values[f as keyof typeof values] !== undefined)) fail('Nothing to change. Pass --models, --any-model, --rpm, --no-rpm, --max-tokens, --no-max-tokens, --allow-uncapped, --refuse-uncapped, --auto-renew, --max-lifetime or --no-auto-renew.');
      const current = getProxy(arg);
      if (!current) fail(`No proxy with id "${arg}".`);
      // The API takes the whole limits value, so start from what is stored and apply the flags.
      const next: Limits = { ...current.limits };
      if (values['any-model']) next.models = null;
      if (values.models !== undefined) next.models = modelsOrFail(values.models);
      if (values['no-rpm']) next.rpm = null;
      if (values.rpm !== undefined) next.rpm = parseCount('rpm', values.rpm);
      if (values['no-max-tokens']) next.tokenCap = null;
      if (values['max-tokens'] !== undefined) next.tokenCap = parseCount('max-tokens', values['max-tokens']);
      if (values['allow-uncapped']) next.refuseUncounted = false;
      if (values['refuse-uncapped']) next.refuseUncounted = true;
      // autoRenew is left out unless a flag touches it, so a limits-only edit never changes it.
      let autoRenew: Record<string, unknown> | null | undefined;
      if (values['no-auto-renew']) {
        autoRenew = null;
      } else if (values['auto-renew'] !== undefined || values['max-lifetime'] !== undefined) {
        const cur = current.autoRenew;
        if (!cur && (values['auto-renew'] === undefined || values['max-lifetime'] === undefined)) {
          fail('This key has no auto-renew yet. Turn it on with both --auto-renew <window> and --max-lifetime <ttl>.');
        }
        let windowSeconds = cur?.windowSeconds ?? 0;
        if (values['auto-renew'] !== undefined) {
          try { windowSeconds = parseTtl(values['auto-renew']); } catch (err) { fail((err as Error).message); }
        }
        autoRenew = values['max-lifetime'] !== undefined
          ? { windowSeconds, maxLifetime: values['max-lifetime'] }
          : { windowSeconds, maxExpiresAt: cur!.maxExpiresAt };
      }
      const { proxy } = await call('PATCH', `/api/proxies/${enc(arg)}/limits`, { limits: next, autoRenew });
      console.log(`Limits for ${proxy.id}: ${limitsSummary(proxy)}${proxy.limits.refuseUncounted ? '' : ' (uncounted requests allowed)'}`);
      return;
    }

    case 'show': {
      if (!arg) fail('Usage: wickey show <id>');
      const proxy = getProxy(arg);
      if (!proxy) fail(`No proxy with id "${arg}".`);
      // Only a hash of the key is stored, so the full key cannot be printed again.
      if (values.env || values.powershell) fail(`Keys are shown only once, so there is no key to put in env lines. Run \`wickey rotate ${proxy.id} --env\` for a new one.`);
      if (values.json) return console.log(JSON.stringify({ id: proxy.id, baseUrl: proxyBaseUrl(proxy), maskedKey: proxy.maskedKey, status: proxy.status, expiresAt: new Date(proxy.expiresAt).toISOString() }));
      console.log(`Proxy ${proxy.id}${proxy.label ? ` (${proxy.label})` : ''} -> ${proxy.credentialName}, ${proxy.status}, ${timeLeft(proxy)}\n`);
      console.log(`BASE_URL=${proxyBaseUrl(proxy)}`);
      console.log(`API_KEY=${proxy.maskedKey}\n`);
      console.log(`Shown only once, when it was issued. Run \`wickey rotate ${proxy.id}\` for a new key.`);
      return;
    }

    case 'renew': {
      if (!arg) fail('Usage: wickey renew <id> [--ttl <t>]');
      const { proxy } = await call('POST', `/api/proxies/${enc(arg)}/renew`, { ttl: values.ttl });
      if (values.json) return console.log(JSON.stringify({ id: proxy.id, baseUrl: proxyBaseUrl(proxy), maskedKey: proxy.maskedKey, expiresAt: new Date(proxy.expiresAt).toISOString() }));
      console.log(`Renewed proxy ${proxy.id} for ${formatDuration(proxy.ttlSeconds)} with the same key (${proxy.maskedKey}). Nothing to update in your apps.`);
      return;
    }

    case 'rotate': {
      if (!arg) fail('Usage: wickey rotate <id> [--ttl <t>]');
      const { proxy, token } = await call('POST', `/api/proxies/${enc(arg)}/rotate`, { ttl: values.ttl });
      if (!values.json && !values.env && !values.powershell) console.log('Rotated: the old key no longer works. Update your apps with the new key below.\n');
      return printIssued(proxy, token, values);
    }

    case 'expire':
    case 'revoke': {
      if (!arg) fail('Usage: wickey expire <id>');
      const { proxy } = await call('POST', `/api/proxies/${enc(arg)}/expire`);
      console.log(`Expired proxy ${proxy.id}. Rotate it with \`wickey rotate ${proxy.id}\` to get a new key.`);
      return;
    }

    case 'delete': {
      if (!arg) fail('Usage: wickey delete <id>');
      await call('DELETE', `/api/proxies/${enc(arg)}`);
      console.log(`Deleted proxy ${arg}.`);
      return;
    }

    case undefined:
    case 'help':
      process.stdout.write(HELP);
      return;

    default:
      fail(`Unknown command "${command}". Run \`wickey help\`.`);
  }
}

main(process.argv.slice(2)).then(endCliSession, async (err: Error) => {
  await endCliSession();
  fail(err.message);
});
