import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-service-test-'));
process.env.WICKEY_HOME = path.join(tmp, 'home');
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const svc = await import('../src/service.ts');
type Deps = import('../src/service.ts').ServiceDeps;

const nodeBin = process.execPath;
const script = fileURLToPath(new URL('../bin/wickey.js', import.meta.url));

function makeDeps(over: Partial<Deps> = {}) {
  const said: string[] = [];
  const calls: string[][] = [];
  const dir = fs.mkdtempSync(path.join(tmp, 'dir-'));
  const deps: Deps = {
    platform: 'darwin',
    run: async (cmd, args) => { calls.push([cmd, ...args]); return { code: 0, stdout: '', stderr: '' }; },
    say: (l) => said.push(l),
    dir, node: nodeBin, script, uid: 501, home: path.join(tmp, 'home'), port: 7870,
    logFile: path.join(tmp, 'home', 'logs', 'wickey.log'),
    env: {}, names: { label: 'com.example.test', unit: 'com.example.test.service', task: 'com.example.test' },
    dryRun: false,
    probePort: async () => 'free',
    sessionState: async () => null,
    sleep: async () => {},
    ...over,
  };
  return { deps, said, calls, dir };
}

test('plist escapes XML metacharacters and spaces in paths', () => {
  const xml = svc.launchdPlist('com.x', { node: '/Users/a b/n&ode/bin/<node>', script: '/s/"q"/it\'s.js', env: { WICKEY_HOME: '/h/a&b' } });
  assert.ok(xml.includes('<string>/Users/a b/n&amp;ode/bin/&lt;node&gt;</string>'));
  assert.ok(xml.includes('<string>/s/&quot;q&quot;/it&apos;s.js</string>'));
  assert.ok(xml.includes('<key>WICKEY_HOME</key>\n    <string>/h/a&amp;b</string>'));
  assert.ok(xml.includes('<string>--service</string>'));
  assert.ok(xml.includes('<key>RunAtLoad</key>'));
  assert.ok(xml.includes('<key>ThrottleInterval</key>'));
  assert.ok(!/EnvironmentVariables/.test(svc.launchdPlist('com.x', { node: '/n', script: '/s', env: {} })), 'no env block unless the user set one');
  assert.throws(() => svc.launchdPlist('com.x', { node: '/n\nx', script: '/s', env: {} }));
});

test('systemd unit quotes paths, and neutralises % and $', () => {
  const unit = svc.systemdUnit({ node: '/opt/my node/bin/node', script: '/p/"x"/a%b$c\\d.js', env: { WICKEY_PORT: '7870' } });
  assert.ok(unit.includes('ExecStart="/opt/my node/bin/node" "/p/\\"x\\"/a%%b$$c\\\\d.js" start --service'));
  assert.ok(unit.includes('Environment="WICKEY_PORT=7870"'));
  assert.ok(unit.includes('Restart=on-failure'));
  assert.ok(unit.includes('StandardOutput=null'));
  assert.throws(() => svc.systemdUnit({ node: '/n', script: '/s\n[Service]', env: {} }));
});

test('schtasks args are an argv array with the command as one quoted string', () => {
  const args = svc.schtasksCreateArgs('my task', { node: 'C:\\Program Files\\nodejs\\node.exe', script: 'C:\\a&b\\wickey.js', env: {} });
  assert.deepEqual(args, ['/Create', '/SC', 'ONLOGON', '/TN', 'my task', '/TR',
    '"C:\\Program Files\\nodejs\\node.exe" "C:\\a&b\\wickey.js" start --service', '/RL', 'LIMITED', '/F']);
  assert.throws(() => svc.schtasksCreateArgs('t', { node: 'C:\\a"b\\node.exe', script: 's', env: {} }));
});

test('macOS install writes the plist, bootstraps it, and replaces cleanly on a second run', async () => {
  const t = makeDeps({ env: { WICKEY_PORT: '7870' } });
  assert.equal(await svc.installService(t.deps), 0);
  const plist = path.join(t.dir, 'com.example.test.plist');
  assert.ok(fs.existsSync(plist));
  assert.ok(fs.readFileSync(plist, 'utf8').includes('<string>7870</string>'));
  assert.deepEqual(t.calls, [['launchctl', 'bootstrap', 'gui/501', plist]]);
  t.calls.length = 0;
  assert.equal(await svc.installService(t.deps), 0);
  assert.equal(t.calls[0].join(' '), `launchctl bootout gui/501/com.example.test`);
  assert.equal(t.calls.at(-1)!.join(' '), `launchctl bootstrap gui/501 ${plist}`);
  assert.ok(t.said.some((l) => /Replaced/.test(l)));
});

test('macOS falls back to launchctl load -w, and cleans up when both fail', async () => {
  const t = makeDeps({ run: async (cmd, args) => { t.calls.push([cmd, ...args]); return { code: args[0] === 'bootstrap' ? 5 : 0, stdout: '', stderr: '' }; } });
  assert.equal(await svc.installService(t.deps), 0);
  assert.ok(t.calls.some((c) => c[1] === 'load' && c[2] === '-w'));
  const bad = makeDeps({ run: async () => ({ code: 5, stdout: '', stderr: 'boom' }) });
  assert.equal(await svc.installService(bad.deps), 1);
  assert.deepEqual(fs.readdirSync(bad.dir), [], 'a failed load leaves no plist behind');
});

test('uninstall unloads and removes; when not installed it is a friendly no-op', async () => {
  const t = makeDeps();
  assert.equal(await svc.uninstallService(t.deps), 0);
  assert.equal(t.calls.length, 0);
  assert.ok(t.said.some((l) => /not installed/i.test(l)));
  await svc.installService(t.deps);
  t.calls.length = 0;
  assert.equal(await svc.uninstallService(t.deps), 0);
  assert.equal(t.calls[0].join(' '), 'launchctl bootout gui/501/com.example.test');
  assert.deepEqual(fs.readdirSync(t.dir), []);
});

test('install refuses (and stops nothing) when a hand-started instance holds the port', async () => {
  for (const [state, text] of [['wickey', /by hand/], ['other', /another program/]] as const) {
    const t = makeDeps({ probePort: async () => state });
    assert.equal(await svc.installService(t.deps), 1);
    assert.match(t.said.join('\n'), text);
    assert.deepEqual(t.calls, [], 'no OS command ran');
    assert.deepEqual(fs.readdirSync(t.dir), []);
  }
});

test('Linux: unit file, enable --now, and a clear message when systemd user is unavailable', async () => {
  const t = makeDeps({ platform: 'linux' });
  assert.equal(await svc.installService(t.deps), 0);
  assert.ok(fs.existsSync(path.join(t.dir, 'com.example.test.service')));
  assert.ok(t.calls.some((c) => c.join(' ') === 'systemctl --user enable --now com.example.test.service'));
  t.calls.length = 0;
  assert.equal(await svc.uninstallService(t.deps), 0);
  assert.ok(t.calls.some((c) => c.join(' ') === 'systemctl --user disable --now com.example.test.service'));
  assert.deepEqual(fs.readdirSync(t.dir), []);

  const none = makeDeps({ platform: 'linux', run: async (cmd, args) => { none.calls.push([cmd, ...args]); return { code: 1, stdout: '', stderr: 'Failed to connect to bus' }; } });
  assert.equal(await svc.installService(none.deps), 1);
  assert.match(none.said.join('\n'), /aren't available[\s\S]*start/);
  assert.deepEqual(fs.readdirSync(none.dir), []);
});

test('Windows: creates a task, says it is experimental, and deletes it', async () => {
  const t = makeDeps({ platform: 'win32', env: { WICKEY_PORT: '1' } });
  assert.equal(await svc.installService(t.deps), 0);
  assert.match(t.said.join('\n'), /EXPERIMENTAL/);
  const create = t.calls.find((c) => c[1] === '/Create')!;
  assert.equal(create[0], 'schtasks');
  assert.ok(create.includes('ONLOGON'));
  await svc.uninstallService(t.deps);
  assert.ok(t.calls.some((c) => c.join(' ') === 'schtasks /Delete /TN com.example.test /F'));
});

test('status: installed, running, locked, and a warning when the node path is gone', async () => {
  const t = makeDeps({ sessionState: async () => ({ vault: true, unlocked: false }) });
  await svc.installService(t.deps);
  t.said.length = 0;
  await svc.serviceStatus(t.deps);
  const out = t.said.join('\n');
  assert.match(out, /Installed:\s+yes/);
  assert.match(out, /Running:\s+yes/);
  assert.match(out, /locked/);
  assert.doesNotMatch(out, /Warning/);
  assert.ok(out.includes(t.deps.logFile));

  // Simulate an nvm upgrade: the plist names a node that no longer exists.
  const plist = path.join(t.dir, 'com.example.test.plist');
  fs.writeFileSync(plist, svc.launchdPlist('com.example.test', { node: path.join(tmp, 'gone', 'node'), script, env: {} }));
  t.said.length = 0;
  await svc.serviceStatus(t.deps);
  assert.match(t.said.join('\n'), /no longer exists[\s\S]*service install/);

  const idle = makeDeps();
  await svc.serviceStatus(idle.deps);
  assert.match(idle.said.join('\n'), /Installed:\s+no/);
  assert.match(idle.said.join('\n'), /Running:\s+no/);
});

test('CLI dry run prints the OS commands, runs none, and writes only under the override dir', () => {
  const dir = path.join(tmp, 'dry');
  const env = { ...process.env, WICKEY_HOME: path.join(tmp, 'dryhome'), WICKEY_SERVICE_DRYRUN: '1', WICKEY_SERVICE_DIR: dir,
    WICKEY_SERVICE_PLATFORM: 'darwin', WICKEY_SERVICE_LABEL: 'com.example.dry' };
  const r = spawnSync(nodeBin, [script, 'service', 'install'], { env, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /\[dry run\] launchctl bootstrap gui\/\d+ /);
  assert.ok(fs.existsSync(path.join(dir, 'com.example.dry.plist')));
  const u = spawnSync(nodeBin, [script, 'service', 'uninstall'], { env, encoding: 'utf8' });
  assert.match(u.stdout, /\[dry run\] launchctl bootout/);
  assert.ok(!fs.existsSync(path.join(dir, 'com.example.dry.plist')));
});
