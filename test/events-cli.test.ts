import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, test } from 'node:test';
import { describeEvent, eventLine, integrityText, summarizeUnseen } from '../src/eventtext.ts';

// `wickey events` against a throwaway instance. The CLI needs the passphrase, which only a
// terminal can give, so the happy path runs in a pty (python3 + pty.fork); a detached child proves the refusal.

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-events-cli-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '300';

const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const vault = await import('../src/vault.ts');
const { appendEvent } = await import('../src/events.ts');
const { setNotifier, unavailableNotifier } = await import('../src/notify.ts');

const PASS = 'correct horse battery staple';
const bin = fileURLToPath(new URL('../bin/wickey.js', import.meta.url));
let server: http.Server;
let port = 0;

before(async () => {
  setNotifier(unavailableNotifier('tests'));
  session.setUp(PASS);
  vault.lockVault();
  try { session.unlock('wrong wrong wrong wrong', 'dashboard'); } catch { /* the event is the point */ }
  session.unlock(PASS, 'dashboard');
  appendEvent('limits_loosened', { proxyId: 'abc123', via: 'cli', before: 'x', after: 'rpm 5' });
  appendEvent('future_thing', { via: 'weird\u001b[31m' });
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});

after(() => {
  store.closeStore();
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
});

const env = () => ({ ...process.env, WICKEY_HOME: home, WICKEY_PORT: String(port), WICKEY_NOTIFY: '0' });

function runDetached(args: string[]): Promise<{ code: number | null; out: string; err: string }> {
  const child = spawn(process.execPath, [bin, ...args], { env: env(), detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (err += d));
  const timer = setTimeout(() => child.kill(), 20_000);
  return new Promise((resolve) => child.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err }); }));
}

// A pty without a native module: python's pty.fork gives the child a controlling terminal, types the
// passphrase when asked and relays the output. (`script` needs the parent's stdin to be a tty.)
const PTY_DRIVER = `
import os, pty, select, sys, time
passphrase, *argv = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    os.execv(argv[0], argv)
out, typed, end = b'', False, time.time() + 20
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        if not typed and b'assphrase:' in out:
            typed = True
            os.write(fd, (passphrase + '\\r').encode())
_, status = os.waitpid(pid, 0)
sys.stdout.buffer.write(out)
sys.exit(os.waitstatus_to_exitcode(status))
`;

/** Runs the CLI in a pty, typing the passphrase when asked. */
function runInPty(args: string[]): Promise<{ code: number | null; out: string }> {
  const child = spawn('python3', ['-c', PTY_DRIVER, PASS, process.execPath, bin, ...args], { env: env(), stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (d) => (out += d));
  const timer = setTimeout(() => child.kill(), 25_000);
  return new Promise((resolve) => child.on('close', (code) => { clearTimeout(timer); resolve({ code, out }); }));
}

const havePty = process.platform !== 'win32' && spawnSync('python3', ['-c', 'import pty']).status === 0;

test('events without a terminal refuses and prints no events', { skip: process.platform === 'win32' }, async () => {
  const r = await runDetached(['events']);
  assert.notEqual(r.code, 0);
  assert.match(r.err, /terminal/);
  assert.equal(r.out, '');
});

test('events prints plain sentences, trust labels and the integrity line', { skip: !havePty }, async () => {
  const r = await runInPty(['events']);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /OK: The event log is intact/);
  assert.match(r.out, /Wickey was unlocked\..*\[via dashboard\]/);
  assert.match(r.out, /A wrong passphrase was entered\./);
  assert.match(r.out, /Limits were loosened on proxy abc123: rpm 5\..*\[via command line\]/);
  assert.match(r.out, /An event this version does not recognise \("future_thing"\)\./);
  assert.match(r.out, /\(verified\)/);
  assert.match(r.out, /\(recorded while locked\)/);
  assert.ok(!r.out.includes('\u001b[31m'), 'log text must not reach the terminal as escape codes');
  assert.ok(!r.out.includes('"seq"'), 'no raw JSON in the plain output');
});

test('events --type and --json', { skip: !havePty }, async () => {
  const r = await runInPty(['events', '--type', 'unlock_failed', '--json']);
  assert.equal(r.code, 0, r.out);
  const json = JSON.parse(r.out.slice(r.out.indexOf('{')));
  assert.ok(json.events.length >= 1);
  assert.ok(json.events.every((e: any) => e.type === 'unlock_failed'));
  assert.equal(json.summary.ok, true);

  const bad = await runInPty(['events', '--type', 'Bad Type']);
  assert.notEqual(bad.code, 0);
  assert.match(bad.out, /--type must be an event type/);
});

test('the shared wording never throws and never prints raw JSON', () => {
  assert.equal(describeEvent({ type: 'future_thing', data: {} }), 'An event this version does not recognise ("future_thing").');
  assert.match(describeEvent({ type: 'key_issued', data: { credential: 'work', unlimited: true, op: 'rotate' } }), /rotated for credential "work", with no limits\./);
  assert.match(describeEvent({ type: 'tamper_detected', data: { anchor: 'truncated' } }), /cut off the end/);
  assert.equal(eventLine({ seq: 3, ts: 'garbage', type: 'locked', data: { via: 'cli' }, trust: 'verified' }).includes('{'), false);
  assert.equal(summarizeUnseen({ unlocked: 2, key_unrestricted: 1, unlock_failed: 1, weird: 1 }), '2 unlocks, 1 failed passphrase, 1 key with no limits, 1 other event');
  assert.equal(integrityText({ ok: false, reason: 'an entry was edited', macsChecked: true }).ok, false);
});
