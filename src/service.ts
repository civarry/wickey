import { execFile } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BRAND, envVar } from './brand.ts';
import { config } from './config.ts';

// Start-on-login for the proxy. The service always starts LOCKED: it serves the dashboard and
// refuses key requests until someone unlocks it once. The passphrase is never stored anywhere.
// Every OS call goes through `deps.run` (execFile with an argument array, never a shell string),
// so tests inject a fake and WICKEY_SERVICE_DRYRUN=1 prints instead of running.

export interface RunResult { code: number; stdout: string; stderr: string }

export type PortState = 'free' | 'wickey' | 'other';

export interface ServiceDeps {
  platform: NodeJS.Platform;
  run(cmd: string, args: string[]): Promise<RunResult>;
  say(line: string): void;
  /** Where the plist or unit file goes. */
  dir: string;
  node: string;
  script: string;
  uid: number;
  home: string;
  port: number;
  logFile: string;
  /** Env overrides to bake into the service (only ones the user set at install time). */
  env: Record<string, string>;
  names: { label: string; unit: string; task: string };
  dryRun: boolean;
  probePort(): Promise<PortState>;
  /** Session state of the proxy on the configured port, or null when nothing answers. */
  sessionState(): Promise<{ vault: boolean; unlocked: boolean } | null>;
  sleep(ms: number): Promise<void>;
}

// ---- file contents (pure, so tests can check escaping) ----

export function xmlEscape(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function noNewlines(...values: string[]): void {
  if (values.some((v) => /[\r\n\0]/.test(v))) throw new Error('A path or value contains a line break, which a service definition cannot hold.');
}

export interface ProgramSpec { node: string; script: string; env: Record<string, string>; logFile?: string }

export function launchdPlist(label: string, spec: ProgramSpec): string {
  noNewlines(label, spec.node, spec.script, ...Object.values(spec.env));
  const str = (s: string) => `<string>${xmlEscape(s)}</string>`;
  const envBlock = Object.keys(spec.env).length
    ? `\n  <key>EnvironmentVariables</key>\n  <dict>\n${Object.entries(spec.env).map(([k, v]) => `    <key>${xmlEscape(k)}</key>\n    ${str(v)}`).join('\n')}\n  </dict>`
    : '';
  // SuccessfulExit=false: restart after a crash or failed start, but not after a clean stop.
  // Output goes nowhere at the OS level: the process writes its own size-capped log.
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  ${str(label)}
  <key>ProgramArguments</key>
  <array>
    ${str(spec.node)}
    ${str(spec.script)}
    ${str('start')}
    ${str('--service')}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>30</integer>
  <key>StandardOutPath</key>
  <string>/dev/null</string>
  <key>StandardErrorPath</key>
  <string>/dev/null</string>${envBlock}
</dict>
</plist>
`;
}

/** One double-quoted systemd word. `%` and `$` would otherwise be expanded as specifiers/variables. */
export function systemdQuote(s: string): string {
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/%/g, '%%').replace(/\$/g, '$$$$')}"`;
}

export function systemdUnit(spec: ProgramSpec): string {
  noNewlines(spec.node, spec.script, ...Object.values(spec.env));
  const envLines = Object.entries(spec.env).map(([k, v]) => `Environment=${systemdQuote(`${k}=${v}`)}`);
  return `[Unit]
Description=${BRAND.command} local LLM key proxy (starts locked)

[Service]
ExecStart=${systemdQuote(spec.node)} ${systemdQuote(spec.script)} start --service
Restart=on-failure
RestartSec=5
StandardOutput=null
StandardError=null
${envLines.join('\n')}${envLines.length ? '\n' : ''}
[Install]
WantedBy=default.target
`;
}

/** Arguments for `schtasks`. The /TR value is one string: schtasks has no argv form for the command. */
export function schtasksCreateArgs(taskName: string, spec: ProgramSpec): string[] {
  noNewlines(taskName, spec.node, spec.script);
  if (/"/.test(spec.node + spec.script)) throw new Error('A path contains a double quote, which Task Scheduler cannot hold.');
  const tr = `"${spec.node}" "${spec.script}" start --service`;
  return ['/Create', '/SC', 'ONLOGON', '/TN', taskName, '/TR', tr, '/RL', 'LIMITED', '/F'];
}

// ---- defaults ----

function run(cmd: string, args: string[]): Promise<RunResult> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 30_000, windowsHide: true }, (err, stdout, stderr) => {
      const code = err ? (typeof (err as { code?: unknown }).code === 'number' ? (err as unknown as { code: number }).code : 1) : 0;
      resolve({ code, stdout: String(stdout), stderr: String(stderr || (err && code === 1 && !stdout ? err.message : '')) });
    });
  });
}

async function sessionState(): Promise<{ vault: boolean; unlocked: boolean } | null> {
  const { host, port } = config();
  try {
    // The sign-in status needs no session and carries no proxy or credential data.
    const res = await fetch(`http://${host}:${port}/api/session-status`, { headers: { [BRAND.requestHeader]: '1' }, signal: AbortSignal.timeout(1500) });
    const s = await res.json();
    return res.ok && s && typeof s.vault === 'boolean' ? { vault: s.vault, unlocked: !!s.unlocked } : null;
  } catch {
    return null;
  }
}

async function probePort(): Promise<PortState> {
  const { host, port } = config();
  try {
    const res = await fetch(`http://${host}:${port}/health`, { signal: AbortSignal.timeout(1500) });
    if (res.ok && (await res.json())?.ok === true) return 'wickey';
  } catch { /* not our proxy, or nothing there */ }
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', (e: NodeJS.ErrnoException) => resolve(e.code === 'EADDRINUSE' ? 'other' : 'free'));
    srv.listen(port, host, () => srv.close(() => resolve('free')));
  });
}

export function defaultDeps(): ServiceDeps {
  const cfg = config();
  const dryRun = envVar('SERVICE_DRYRUN') === '1';
  const platform = (envVar('SERVICE_PLATFORM') as NodeJS.Platform | undefined) ?? process.platform;
  const label = envVar('SERVICE_LABEL') || undefined;
  const names = label
    ? { label, unit: `${label}.service`, task: label }
    : { label: BRAND.launchdLabel, unit: BRAND.systemdUnit, task: BRAND.windowsTask };
  const xdg = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  // A dry run must never write into the real LaunchAgents or systemd directories.
  const dir = envVar('SERVICE_DIR')
    ?? (dryRun ? path.join(cfg.home, 'service-dryrun')
      : platform === 'darwin' ? path.join(os.homedir(), 'Library', 'LaunchAgents')
        : path.join(xdg, 'systemd', 'user'));
  const env: Record<string, string> = {};
  for (const name of ['HOME', 'PORT']) {
    const v = envVar(name);
    if (v) env[BRAND.envPrefix + name] = v;
  }
  return {
    platform,
    run: dryRun
      ? async (cmd, args) => { console.log(`[dry run] ${[cmd, ...args].join(' ')}`); return { code: 0, stdout: '', stderr: '' }; }
      : run,
    say: (line) => console.log(line),
    dir,
    node: process.execPath,
    script: fileURLToPath(new URL('../bin/wickey.js', import.meta.url)),
    uid: process.getuid?.() ?? 0,
    home: cfg.home,
    port: cfg.port,
    logFile: cfg.logFile,
    env,
    names,
    dryRun,
    probePort,
    sessionState,
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  };
}

// ---- operations ----

function definitionFile(d: ServiceDeps): string | null {
  if (d.platform === 'darwin') return path.join(d.dir, `${d.names.label}.plist`);
  if (d.platform === 'linux') return path.join(d.dir, d.names.unit);
  return null;
}

export async function isInstalled(d: ServiceDeps): Promise<boolean> {
  const file = definitionFile(d);
  if (file) return fs.existsSync(file);
  if (d.platform === 'win32') return (await d.run('schtasks', ['/Query', '/TN', d.names.task])).code === 0;
  return false;
}

/** Best effort: the node binary the installed definition points at. */
async function installedNode(d: ServiceDeps): Promise<string | null> {
  const file = definitionFile(d);
  try {
    if (file && d.platform === 'darwin') {
      const m = /<key>ProgramArguments<\/key>\s*<array>\s*<string>([\s\S]*?)<\/string>/.exec(fs.readFileSync(file, 'utf8'));
      return m ? m[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&') : null;
    }
    if (file && d.platform === 'linux') {
      const m = /^ExecStart="((?:[^"\\]|\\.)*)"/m.exec(fs.readFileSync(file, 'utf8'));
      return m ? m[1].replace(/%%/g, '%').replace(/\$\$/g, '$').replace(/\\(.)/g, '$1') : null;
    }
    if (d.platform === 'win32') {
      const r = await d.run('schtasks', ['/Query', '/TN', d.names.task, '/V', '/FO', 'LIST']);
      const m = /Task To Run:\s*"?([^"\r\n]+?)"?(?:\s+"|\r?\n)/.exec(r.stdout);
      return m ? m[1] : null;
    }
  } catch { /* unreadable: the caller treats it as unknown */ }
  return null;
}

async function waitFor(d: ServiceDeps, want: PortState, tries = 20): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    if ((await d.probePort()) === want) return true;
    await d.sleep(250);
  }
  return false;
}

async function unloadAndRemove(d: ServiceDeps): Promise<void> {
  const file = definitionFile(d);
  if (d.platform === 'darwin' && file) {
    const r = await d.run('launchctl', ['bootout', `gui/${d.uid}/${d.names.label}`]);
    if (r.code !== 0 && fs.existsSync(file)) await d.run('launchctl', ['unload', '-w', file]); // older macOS
    fs.rmSync(file, { force: true });
  } else if (d.platform === 'linux' && file) {
    await d.run('systemctl', ['--user', 'disable', '--now', d.names.unit]);
    fs.rmSync(file, { force: true });
    await d.run('systemctl', ['--user', 'daemon-reload']);
  } else if (d.platform === 'win32') {
    await d.run('schtasks', ['/End', '/TN', d.names.task]);
    await d.run('schtasks', ['/Delete', '/TN', d.names.task, '/F']);
  }
}

const manualCommand = (d: ServiceDeps) => `"${d.node}" "${d.script}" start`;

/** Returns the process exit code. */
export async function installService(d: ServiceDeps): Promise<number> {
  if (!['darwin', 'linux', 'win32'].includes(d.platform)) {
    d.say(`Start on login is not supported on ${d.platform}. Run \`${BRAND.command} start\` yourself.`);
    return 1;
  }
  if (!fs.existsSync(d.node)) { d.say(`Cannot find the node binary at ${d.node}.`); return 1; }
  if (!fs.existsSync(d.script)) { d.say(`Cannot find ${d.script}. Reinstall ${BRAND.command} and try again.`); return 1; }

  if (d.platform === 'linux') {
    const probe = await d.run('systemctl', ['--user', 'show-environment']);
    if (probe.code !== 0) {
      d.say("systemd user services aren't available here (no user session; common in containers and some SSH sessions).");
      d.say(`Nothing was installed. Run the proxy yourself with:\n  ${manualCommand(d)}`);
      return 1;
    }
  }
  if (d.platform === 'win32') d.say('Windows support is EXPERIMENTAL and unverified. Please report problems.');

  // A previous install of ours holds the port; take it down first so this is a clean replace.
  const wasInstalled = await isInstalled(d);
  if (wasInstalled) {
    await unloadAndRemove(d);
    if (!d.dryRun) await waitFor(d, 'free', 12);
  }
  if (!d.dryRun) {
    const port = await d.probePort();
    if (port !== 'free') {
      d.say(port === 'wickey'
        ? `Port ${d.port} is taken by a ${BRAND.command} you started by hand. Nothing was installed or stopped. Stop it first (Ctrl-C in its terminal), then run this again.`
        : `Port ${d.port} is taken by another program. Nothing was installed. Free it, or pick another port with ${BRAND.envPrefix}PORT=<port> and run this again.`);
      return 1;
    }
  }

  const spec: ProgramSpec = { node: d.node, script: d.script, env: d.env };
  const file = definitionFile(d);
  if (file) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, d.platform === 'darwin' ? launchdPlist(d.names.label, spec) : systemdUnit(spec), { mode: 0o644 });
  }

  if (d.platform === 'darwin' && file) {
    let r = await d.run('launchctl', ['bootstrap', `gui/${d.uid}`, file]);
    if (r.code !== 0) {
      const fallback = await d.run('launchctl', ['load', '-w', file]); // macOS versions without bootstrap
      if (fallback.code !== 0) {
        fs.rmSync(file, { force: true });
        d.say(`launchctl could not load the service: ${(r.stderr || fallback.stderr).trim() || `exit ${r.code}`}. Nothing was installed.`);
        return 1;
      }
      r = fallback;
    }
  } else if (d.platform === 'linux') {
    await d.run('systemctl', ['--user', 'daemon-reload']);
    const r = await d.run('systemctl', ['--user', 'enable', '--now', d.names.unit]);
    if (r.code !== 0) {
      fs.rmSync(file!, { force: true });
      d.say(`systemctl could not start the service: ${r.stderr.trim() || `exit ${r.code}`}. Nothing was installed.\nRun the proxy yourself with:\n  ${manualCommand(d)}`);
      return 1;
    }
  } else if (d.platform === 'win32') {
    const r = await d.run('schtasks', schtasksCreateArgs(d.names.task, spec));
    if (r.code !== 0) { d.say(`schtasks failed: ${r.stderr.trim() || `exit ${r.code}`}`); return 1; }
    if (Object.keys(d.env).length) d.say(`Note: ${Object.keys(d.env).join(', ')} are not carried into the scheduled task; it uses the defaults.`);
    await d.run('schtasks', ['/Run', '/TN', d.names.task]);
  }

  if (d.dryRun) {
    d.say(`[dry run] ${wasInstalled ? 'Replaced' : 'Installed'} ${file ?? `task ${d.names.task}`}`);
    return 0;
  }
  const up = await waitFor(d, 'wickey', 40);
  d.say(`${wasInstalled ? 'Replaced the' : 'Installed the'} start-on-login service.`);
  d.say(up ? `Running on http://127.0.0.1:${d.port}/. It starts locked: unlock it once in the dashboard or with \`${BRAND.command} unlock\`.`
    : `It was installed but isn't answering on port ${d.port} yet. Check \`${BRAND.command} service status\` and the log at ${d.logFile}.`);
  if (d.platform === 'linux') d.say('It starts when you log in. To start at boot without logging in, run `loginctl enable-linger`.');
  d.say(`Log: ${d.logFile} (1 MB cap, 3 files). The passphrase is never stored: after each login it needs unlocking once.`);
  return 0;
}

export async function uninstallService(d: ServiceDeps): Promise<number> {
  if (!(await isInstalled(d))) {
    d.say('The start-on-login service is not installed. Nothing to do.');
    return 0;
  }
  await unloadAndRemove(d);
  if (!d.dryRun) await waitFor(d, 'free', 12);
  d.say('Removed the start-on-login service. Your vault, data and logs were not touched.');
  return 0;
}

export async function serviceStatus(d: ServiceDeps): Promise<number> {
  const installed = await isInstalled(d);
  d.say(`Installed:  ${installed ? 'yes' : 'no'}${installed && definitionFile(d) ? ` (${definitionFile(d)})` : ''}`);
  const session = await d.sessionState();
  d.say(`Running:    ${session ? `yes, on http://127.0.0.1:${d.port}/` : `no, nothing answers on port ${d.port}`}`);
  if (session) d.say(`Vault:      ${!session.vault ? 'no passphrase set yet (open the dashboard or run `' + BRAND.command + ' setup`)' : session.unlocked ? 'unlocked' : 'locked (unlock in the dashboard or with `' + BRAND.command + ' unlock`)'}`);
  if (installed) {
    const node = await installedNode(d);
    if (node && !fs.existsSync(node)) {
      d.say(`Warning:    the service points at ${node}, which no longer exists (upgrading node removes old versions). Run \`${BRAND.command} service install\` again.`);
    } else if (!node) {
      d.say('Warning:    could not read which node binary the service uses.');
    }
  } else if (session) {
    d.say(`Note:       something is answering, but it was not started by the service (started by hand?).`);
  }
  d.say(`Log:        ${d.logFile}`);
  return 0;
}

export async function runServiceCommand(sub: string | undefined, d: ServiceDeps = defaultDeps()): Promise<number> {
  if (sub === 'install') return installService(d);
  if (sub === 'uninstall') return uninstallService(d);
  if (sub === 'status') return serviceStatus(d);
  d.say(`Usage: ${BRAND.command} service install | uninstall | status`);
  return 1;
}
