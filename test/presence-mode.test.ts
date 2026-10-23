import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { after, before, test } from 'node:test';
import { sessionCookie } from './helpers.ts';

// Presence mode: unlocking needs the passphrase AND an approval backed by a (here: fake) Secure
// Enclave key. The fake helper never shows a prompt. Tests share module state, so order matters.

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-presence-mode-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '300';

const PASS = 'correct horse battery staple';
const PASS2 = 'tangerine umbrella window garden';

const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const vault = await import('../src/vault.ts');
const pm = await import('../src/presencemode.ts');
const pres = await import('../src/presence.ts');
const ev = await import('../src/events.ts');
const notify = await import('../src/notify.ts');
const { fakePresence } = await import('./fake-presence.ts');

const fake = fakePresence();
const sent: string[] = [];
const vaultFile = path.join(home, 'vault.json');
const logFile = path.join(home, 'events.log');
const keyDir = path.join(home, 'presence');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const readVault = () => JSON.parse(fs.readFileSync(vaultFile, 'utf8'));
const lastSeq = (): number => ev.listEvents({ limit: 1 }).events[0]?.seq ?? 0;
const since = (seq: number) => ev.listEvents({ limit: 200 }).events.filter((e) => e.seq > seq && e.type !== 'checkpoint').sort((a, b) => a.seq - b.seq);
const typesSince = (seq: number) => since(seq).map((e) => e.type);
const used = (seq: number) => since(seq).filter((e) => e.type === 'presence_used').map((e) => e.data.result);

let server: http.Server;
let port = 0;
let recovery = '';

before(async () => {
  notify.setNotifier({ name: 'test', available: true, send: (title, body) => { sent.push(`${title}: ${body}`); } });
  fake.install();
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});

after(() => {
  fake.uninstall();
  notify.setNotifier(null);
  store.closeStore();
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
});

async function api(method: string, p: string, body?: unknown, headers: Record<string, string> = {}) {
  const cookie = await sessionCookie();
  const res = await fetch(`http://127.0.0.1:${port}${p}`, {
    method,
    headers: { 'x-wickey': '1', cookie, ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
}

test('old vaults (no presence block) keep the passphrase-only format and behaviour', () => {
  session.setUp(PASS);
  const f = readVault();
  assert.ok(f.dk && !f.presence);
  vault.lockVault();
  // Nothing waits: the call completes before it returns.
  assert.equal(session.unlock(PASS, 'terminal'), undefined);
  assert.equal(vault.isUnlocked(), true);
});

test('enable refuses on a wrong passphrase and changes nothing', async () => {
  await assert.rejects(pm.enablePresenceMode('not the passphrase at all'), vault.WrongPassphraseError);
  assert.equal(readVault().presence, undefined);
  assert.equal(fake.uses().length, 0);
});

test('not macOS, and a Mac without a Secure Enclave: enable refuses, nothing changes', async () => {
  pres.setPresenceDeps({ platform: 'linux' });
  await assert.rejects(pm.enablePresenceMode(PASS), { message: pres.NOT_MACOS });
  fake.install();
  fake.available = false;
  await assert.rejects(pm.enablePresenceMode(PASS), { message: pres.NO_SECURE_ENCLAVE });
  fake.available = true;
  assert.equal(readVault().presence, undefined);
  assert.equal(fs.existsSync(pres.helperPath()), false, 'the helper built for the probe is removed again');
  assert.equal(fs.existsSync(keyDir), false);
});

test('enable: the passphrase alone no longer opens the vault; the recovery code is shown once, in groups', async () => {
  const seq = lastSeq();
  sent.length = 0;
  notify.resetNotifyState();
  const r = await pm.enablePresenceMode(PASS);
  recovery = r.recoveryCode;
  assert.match(recovery, /^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/); // 160 bits
  assert.deepEqual(fake.uses(), ['Wickey: turn on presence (terminal)']);

  const f = readVault();
  assert.equal(f.dk, undefined, 'the passphrase-only wrap is gone');
  assert.equal(f.presence.keyDir, 'presence');
  assert.equal(f.presence.helperSha256, (await import('node:crypto')).createHash('sha256').update(fs.readFileSync(pres.helperPath())).digest('hex'));
  vault.lockVault();
  assert.throws(() => vault.unlockVault(PASS), vault.PresenceRequiredError);

  assert.deepEqual(typesSince(seq), ['presence_used', 'presence_enabled']);
  assert.ok(sent.some((m) => m.includes('turn on presence mode') && m.includes('approved')), sent.join('\n'));
  assert.ok(sent.some((m) => m.includes('Presence mode was turned on')));
  // The recovery code is in no event and no notification.
  assert.ok(!fs.readFileSync(logFile, 'utf8').includes(recovery.replaceAll('-', '')));
  assert.ok(!sent.some((m) => m.includes(recovery.slice(0, 9))));
});

test('unlock: cancel refuses, logs + notifies, and counts as no wrong passphrase', async () => {
  const seq = lastSeq();
  sent.length = 0;
  notify.resetNotifyState();
  fake.mode = 'cancel';
  // Six cancels in a row: if they counted, the throttle (5 wrong) would stop the sixth.
  for (let i = 0; i < 6; i++) {
    await assert.rejects(Promise.resolve(session.unlock(PASS, 'dashboard', true)), (e: Error) => e instanceof pm.PresenceRefused && /cancelled/.test(e.message));
    notify.resetNotifyState();
  }
  assert.equal(vault.isUnlocked(), false);
  assert.deepEqual(used(seq), Array(6).fill('cancelled'));
  assert.ok(!typesSince(seq).includes('unlock_failed'));
  assert.ok(sent.some((m) => m.includes('unlock the vault (dashboard): cancelled')), sent.join('\n'));
});

test('unlock: approval unlocks, with the exact prompt wording', async () => {
  fake.mode = 'approve';
  const seq = lastSeq();
  await session.unlock(PASS, 'dashboard', true);
  assert.equal(vault.isUnlocked(), true);
  assert.equal(fake.uses().at(-1), 'Wickey: unlock vault (dashboard)');
  assert.deepEqual(typesSince(seq), ['presence_used', 'unlocked']);
});

test('sign-in while unlocked asks for no approval; a wrong passphrase is refused before any', async () => {
  const n = fake.uses().length;
  await session.signIn(PASS, 'cli');
  await assert.rejects(Promise.resolve(session.signIn('wrong wrong wrong wrong', 'cli')), vault.WrongPassphraseError);
  assert.equal(fake.uses().length, n);
  await session.signIn(PASS, 'cli'); // a right one clears the failure count for the next test
});

test('a wrong passphrase after an approved prompt counts toward the throttle', async () => {
  vault.lockVault();
  const seq = lastSeq();
  const n = fake.uses().length;
  for (let i = 0; i < 5; i++) {
    await assert.rejects(Promise.resolve(session.unlock('wrong wrong wrong wrong', 'dashboard')), vault.WrongPassphraseError);
  }
  assert.equal(fake.uses().length, n + 5, 'each guess needed an approval');
  assert.equal(typesSince(seq).filter((t) => t === 'unlock_failed').length, 5);
  assert.ok(!typesSince(seq).includes('presence_helper_mismatch'), 'a typo is not a helper mismatch');
  await assert.rejects(Promise.resolve(session.unlock(PASS, 'dashboard')), session.TooManyAttemptsError);
  assert.equal(fake.uses().length, n + 5, 'throttled before any prompt');
  await sleep(1200);
  await session.unlock(PASS, 'dashboard');
  assert.equal(vault.isUnlocked(), true);
});

test('only one approval can wait at a time', async () => {
  fake.delayMs = 200;
  const first = Promise.resolve(session.signIn(PASS, 'cli')); // has the verifier: no prompt, resolves fast
  await first;
  vault.lockVault();
  const a = Promise.resolve(session.unlock(PASS, 'dashboard'));
  const b = Promise.resolve(session.unlock(PASS, 'dashboard'));
  await assert.rejects(b, (e: Error) => e instanceof pm.PresenceRefused && /already waiting/.test(e.message));
  await a;
  fake.delayMs = 0;
  assert.equal(vault.isUnlocked(), true);
});

test('passphrase change prompts, rewraps, and the old passphrase stops working', async () => {
  fake.mode = 'cancel';
  await assert.rejects(Promise.resolve(session.changePassphrase(PASS, PASS2, 'dashboard')), pm.PresenceRefused);
  fake.mode = 'approve';
  const n = fake.uses().length;
  await assert.rejects(Promise.resolve(session.changePassphrase(PASS, 'short', 'dashboard')), /at least 12/);
  assert.equal(fake.uses().length, n, 'an impossible change asks for no approval');
  await session.changePassphrase(PASS, PASS2, 'dashboard');
  assert.equal(fake.uses().length, n + 1);
  assert.equal(fake.uses().at(-1), 'Wickey: change passphrase (dashboard)');

  vault.lockVault();
  await assert.rejects(Promise.resolve(session.unlock(PASS, 'dashboard')), vault.WrongPassphraseError);
  await sleep(50);
  await session.unlock(PASS2, 'dashboard');
  assert.equal(vault.isUnlocked(), true);
  assert.equal(readVault().dk, undefined);
});

test('turning a notification OFF needs an approval when presence is on', async () => {
  const n = fake.uses().length;
  fake.mode = 'cancel';
  const denied = await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: false, passphrase: PASS2 });
  assert.equal(denied.status, 400);
  assert.match(denied.body.error.message, /cancelled/);
  assert.equal(notify.notificationSettings().types.find((t) => t.type === 'unlocked')!.enabled, true);
  fake.mode = 'approve';
  const ok = await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: false, passphrase: PASS2 });
  assert.equal(ok.status, 200);
  assert.equal(fake.uses().length, n + 2);
  assert.equal(fake.uses().at(-1), 'Wickey: turn off a notification (dashboard)');
  // Turning one ON needs only the session.
  assert.equal((await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: true })).status, 200);
  assert.equal(fake.uses().length, n + 2);
});

test('dashboard unlock: the request waits for the approval, and a cancel comes back as a plain message', async () => {
  vault.lockVault();
  const status = await fetch(`http://127.0.0.1:${port}/api/session-status`, { headers: { 'x-wickey': '1' } }).then((r) => r.json());
  assert.equal(status.presence, true);
  fake.delayMs = 150;
  fake.mode = 'cancel';
  const t0 = Date.now();
  const r = await fetch(`http://127.0.0.1:${port}/api/unlock`, { method: 'POST', headers: { 'x-wickey': '1', 'content-type': 'application/json' }, body: JSON.stringify({ passphrase: PASS2 }) });
  assert.ok(Date.now() - t0 >= 140);
  assert.equal(r.status, 400);
  assert.match(((await r.json()) as any).error.message, /You cancelled the approval/);
  fake.delayMs = 0;
  fake.mode = 'approve';
});

test('recovery code: wrong code refused; the right one unlocks, is logged and notified, never shown again', async () => {
  vault.lockVault();
  assert.throws(() => session.unlockWithRecoveryCode('AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA', 'cli'), (e: Error) => e instanceof vault.WrongRecoveryCodeError && e.message === 'Wrong recovery code.');
  assert.equal(vault.isUnlocked(), false);
  // The dashboard cannot send one.
  assert.equal((await api('POST', '/api/unlock', { recovery: recovery })).status, 403);
  const seq = lastSeq();
  sent.length = 0;
  notify.resetNotifyState();
  const n = fake.uses().length;
  session.unlockWithRecoveryCode(recovery.toLowerCase(), 'cli');
  assert.equal(vault.isUnlocked(), true);
  assert.equal(fake.uses().length, n, 'no approval involved');
  assert.deepEqual(typesSince(seq), ['recovery_used', 'unlocked']);
  assert.ok(sent.some((m) => m.includes('recovery code was used')), sent.join('\n'));
  const everything = fs.readFileSync(logFile, 'utf8') + sent.join('\n');
  assert.ok(!everything.includes(recovery) && !everything.includes(recovery.replaceAll('-', '')));
  // Unlocked this way the process holds no passphrase verifier: sign-in asks for one approval, then none.
  const before = fake.uses().length;
  await session.signIn(PASS2, 'cli');
  assert.equal(fake.uses().length, before + 1);
  await session.signIn(PASS2, 'cli');
  assert.equal(fake.uses().length, before + 1);
});

test('helper mismatch: refused before the helper runs, logged and notified', async () => {
  const good = fs.readFileSync(pres.helperPath());
  fs.writeFileSync(pres.helperPath(), 'a swapped helper');
  vault.lockVault();
  const seq = lastSeq();
  const calls = fake.calls.length;
  sent.length = 0;
  notify.resetNotifyState();
  await assert.rejects(Promise.resolve(session.unlock(PASS2, 'dashboard')), pres.PresenceHelperMismatch);
  assert.equal(fake.calls.length, calls, 'the helper never ran');
  assert.deepEqual(typesSince(seq), ['presence_helper_mismatch']);
  assert.equal(since(seq)[0].data.stage, 'use');
  assert.ok(sent.some((m) => m.includes('presence repair')));
  fs.writeFileSync(pres.helperPath(), good);
});

test('editing helperSha256 in vault.json to match a swapped helper: unwrap fails and is logged', async () => {
  const good = fs.readFileSync(pres.helperPath());
  const original = fs.readFileSync(vaultFile, 'utf8');
  fs.writeFileSync(pres.helperPath(), 'a swapped helper');
  const f = readVault();
  f.presence.helperSha256 = (await import('node:crypto')).createHash('sha256').update('a swapped helper').digest('hex');
  fs.writeFileSync(vaultFile, JSON.stringify(f, null, 2));
  vault.lockVault();
  await sleep(1200);
  const seq = lastSeq();
  await assert.rejects(Promise.resolve(session.unlock(PASS2, 'dashboard')), vault.WrongPassphraseError);
  assert.equal(fake.uses().length > 0, true);
  const mism = since(seq).filter((e) => e.type === 'presence_helper_mismatch');
  assert.equal(mism.length, 1);
  assert.equal(mism[0].data.stage, 'unwrap');
  fs.writeFileSync(vaultFile, original);
  fs.writeFileSync(pres.helperPath(), good);
  await sleep(1200);
  await session.unlock(PASS2, 'dashboard');
  assert.equal(vault.isUnlocked(), true);
});

test('repair with a working key: new recovery code, old one stops working', async () => {
  const seq = lastSeq();
  const old = recovery;
  const r = await pm.repairPresenceMode(PASS2, async () => { throw new Error('should not ask'); });
  assert.equal(r.usedRecovery, false);
  assert.notEqual(r.recoveryCode, old);
  assert.ok(typesSince(seq).includes('presence_repaired'));
  vault.lockVault();
  assert.throws(() => session.unlockWithRecoveryCode(old, 'cli'), vault.WrongRecoveryCodeError);
  session.unlockWithRecoveryCode(r.recoveryCode, 'cli');
  recovery = r.recoveryCode;
  vault.lockVault();
});

test('repair with the key gone: needs the recovery code, makes a new key', async () => {
  fs.rmSync(keyDir, { recursive: true, force: true });
  vault.lockVault();
  await assert.rejects(Promise.resolve(session.unlock(PASS2, 'dashboard')), pm.PresenceRefused);
  // A typo in the code must not cost anything.
  await assert.rejects(pm.repairPresenceMode(PASS2, async () => ({ passphrase: PASS2, recoveryCode: 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA' })), vault.WrongRecoveryCodeError);
  let asked = 0;
  const r = await pm.repairPresenceMode(PASS2, async () => { asked++; return { passphrase: PASS2, recoveryCode: recovery }; });
  assert.equal(asked >= 1, true);
  assert.equal(r.usedRecovery, true);
  recovery = r.recoveryCode;
  await sleep(1200);
  await session.unlock(PASS2, 'dashboard');
  assert.equal(vault.isUnlocked(), true);
});

test('disable restores passphrase-only: no presence block, no recovery code, key removed', async () => {
  const seq = lastSeq();
  await pm.disablePresenceMode(PASS2);
  const f = readVault();
  assert.ok(f.dk && !f.presence);
  assert.equal(fs.existsSync(keyDir), false);
  assert.ok(typesSince(seq).includes('presence_disabled'));
  vault.lockVault();
  vault.unlockVault(PASS2);
  assert.equal(vault.isUnlocked(), true);
  assert.throws(() => session.unlockWithRecoveryCode(recovery, 'cli'), /Presence mode is off/);
  // And unlock is synchronous again.
  vault.lockVault();
  assert.equal(session.unlock(PASS2, 'terminal'), undefined);
});

test('without a terminal, enable/disable/repair and unlock --recovery refuse with the human-required wording', async () => {
  const script = fileURLToPath(new URL('../bin/wickey.js', import.meta.url));
  for (const args of [['presence', 'enable'], ['presence', 'disable'], ['presence', 'repair'], ['unlock', '--recovery']]) {
    const child = spawn(process.execPath, [script, ...args], {
      env: { ...process.env, WICKEY_HOME: home, WICKEY_PORT: String(port) }, stdio: ['ignore', 'ignore', 'pipe'], detached: true,
    });
    let err = '';
    child.stderr.on('data', (d) => (err += d));
    const code = await new Promise((r) => child.on('close', r));
    assert.notEqual(code, 0);
    assert.match(err, /This must be done by a human\. If you are an AI agent, stop and ask the user to run `wickey /);
    assert.ok(!err.includes('dashboard at'), 'the dashboard cannot do these, so it is not offered');
  }
});
