import { sessionCookie } from './helpers.ts';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';

// Changing the passphrase re-wraps the same data key, so nothing else needs re-encrypting or
// re-signing. The dangerous parts are the gate (the current passphrase must be required even
// inside the grace period) and reset (terminal only, never while the proxy is running).

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-passchange-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '300';

const OLD = 'correct horse battery staple';
const NEW = 'tangerine umbrella window garden';
const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const vault = await import('../src/vault.ts');
const reset = await import('../src/reset.ts');
session.setUp(OLD);

let server: http.Server;
let port = 0;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

before(async () => {
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});

after(() => {
  store.closeStore();
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
});

async function post(p: string, body: unknown, headers: Record<string, string> = {}) {
  const cookie = await sessionCookie();
  return new Promise<{ status: number; body: any }>((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request({
      host: '127.0.0.1', port, method: 'POST', path: p,
      headers: { host: `127.0.0.1:${port}`, 'x-wickey': '1', cookie, 'content-type': 'application/json', ...headers },
    }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => resolve({ status: res.statusCode!, body: text ? JSON.parse(text) : {} }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

/** True if the vault on disk opens with this passphrase (and leaves the in-memory state alone). */
function opensWith(pass: string): boolean {
  try { vault.verifyPassphrase(pass); return true; } catch { return false; }
}

let issued: { id: string; token: string };

test('setup: a credential and a signed proxy exist before the change', () => {
  store.addCredential({ name: 'work', provider: 'custom', apiKey: 'sk-REAL-work-key', baseUrl: 'http://127.0.0.1:9/v1' });
  const p = store.issueProxy({ credential: 'work', ttlSeconds: 3600 });
  issued = { id: p.proxy.id, token: p.token };
  assert.equal(store.authorize(issued.id, issued.token).ok, true);
  assert.ok(session.graceRemaining() > 0, 'grace is running for the tests below');
});

test('the grace period does not stand in for the current passphrase', async () => {
  // A program on this computer during the grace window must not be able to take over the vault.
  assert.ok(session.graceRemaining() > 0);
  for (const body of [{ next: NEW }, { current: '', next: NEW }, { current: 'not the passphrase', next: NEW }, { passphrase: OLD, next: NEW }]) {
    const res = await post('/api/passphrase', body);
    assert.ok(res.status === 400 || res.status === 401, `${JSON.stringify(Object.keys(body))} gave ${res.status}`);
  }
  assert.equal(opensWith(OLD), true, 'the old passphrase still works');
  assert.equal(opensWith(NEW), false, 'the new one was never set');
  assert.ok(session.graceRemaining() > 0, 'a refused change does not end the grace period');
});

test('a wrong current passphrase answers 401 and never echoes a passphrase', async () => {
  const res = await post('/api/passphrase', { current: 'wrong wrong wrong', next: NEW });
  assert.equal(res.status, 401);
  assert.equal(res.body.error.code, 'wrong_passphrase');
  assert.ok(!JSON.stringify(res.body).includes(NEW) && !JSON.stringify(res.body).includes('wrong wrong'));
});

test('too short and unchanged passphrases are refused without touching the vault', async () => {
  const short = await post('/api/passphrase', { current: OLD, next: 'short' });
  assert.equal(short.status, 400);
  assert.match(short.body.error.message, /at least 12 characters/);
  const same = await post('/api/passphrase', { current: OLD, next: OLD });
  assert.equal(same.status, 400);
  assert.match(same.body.error.message, /different/);
  assert.equal(opensWith(OLD), true);
});

test('the API needs the dashboard headers like every other endpoint', async () => {
  const res = await post('/api/passphrase', { current: OLD, next: NEW }, { 'x-wickey': '' });
  assert.equal(res.status, 403);
  const rebound = await post('/api/passphrase', { current: OLD, next: NEW }, { origin: 'http://evil.example' });
  assert.equal(rebound.status, 403);
  assert.equal(opensWith(NEW), false);
});

test('changing works, ends the grace period, and keeps secrets and signatures valid', async () => {
  const before = fs.readFileSync(path.join(home, 'vault.json'), 'utf8');
  const res = await post('/api/passphrase', { current: OLD, next: NEW });
  assert.equal(res.status, 200);
  assert.match(res.body.message, /next key you mint asks for the new passphrase/);
  assert.equal(res.body.session.graceRemaining, 0);
  assert.throws(() => session.requireAuth(), (e: any) => e.code === 'passphrase_required', 'minting needs auth again');

  const after = fs.readFileSync(path.join(home, 'vault.json'), 'utf8');
  assert.notEqual(JSON.parse(before).kdf.salt, JSON.parse(after).kdf.salt, 'fresh salt');
  assert.deepEqual(JSON.parse(before).secrets, JSON.parse(after).secrets, 'secrets are not re-encrypted');

  assert.equal(opensWith(OLD), false, 'the old passphrase stops working');
  assert.equal(opensWith(NEW), true);
  assert.equal(vault.getSecret(store.getCredential('work')!.id), 'sk-REAL-work-key');
  assert.equal(store.authorize(issued.id, issued.token).ok, true, 'row signatures still verify');
  assert.equal(fs.statSync(path.join(home, 'vault.json')).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(home).filter((f) => f.endsWith('.tmp')), [], 'no temp file left behind');
});

test('after a restart (lock + unlock) only the new passphrase works and everything still verifies', () => {
  vault.lockVault();
  assert.throws(() => vault.unlockVault(OLD), vault.WrongPassphraseError);
  vault.unlockVault(NEW);
  assert.equal(vault.getSecret(store.getCredential('work')!.id), 'sk-REAL-work-key');
  assert.equal(store.authorize(issued.id, issued.token).ok, true);
  session.unlock(NEW);
});

test('an interrupted earlier write does not break the next change', async () => {
  // A crash can leave the temp file (even with loose permissions); the rename must still land cleanly.
  const stale = path.join(home, `vault.json.${process.pid}.tmp`);
  fs.writeFileSync(stale, 'half a vault', { mode: 0o644 });
  const third = 'sunflower paperclip orbit lantern';
  assert.equal((await post('/api/passphrase', { current: NEW, next: third })).status, 200);
  assert.equal(fs.existsSync(stale), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(home, 'vault.json'), 'utf8')).version, 1);
  assert.equal(opensWith(third), true);
  assert.equal((await post('/api/passphrase', { current: third, next: NEW })).status, 200);
  session.unlock(NEW);
});

test('while locked, changing is refused with the locked message', async () => {
  vault.lockVault();
  try {
    const res = await post('/api/passphrase', { current: NEW, next: 'another long passphrase' });
    assert.equal(res.status, 409);
    assert.match(res.body.error.message, /locked/);
    assert.equal(opensWith(NEW), true);
  } finally {
    vault.unlockVault(NEW);
  }
});

test('wrong current passphrases count toward the throttle', async () => {
  // Run last among the API tests: 5 misses block further attempts, even with the right passphrase.
  for (let i = 0; i < 5; i++) assert.equal((await post('/api/passphrase', { current: `wrong-${i}-wrong-wrong`, next: OLD })).status, 401);
  const blocked = await post('/api/passphrase', { current: NEW, next: OLD });
  assert.equal(blocked.status, 429);
  assert.equal(opensWith(NEW), true, 'the blocked attempt changed nothing');
  await sleep(1200);
  assert.equal((await post('/api/passphrase', { current: NEW, next: OLD })).status, 200, 'works again after the wait');
});

test('the 12-character minimum only applies to setting a passphrase, never to unlocking', async () => {
  // A vault made before the minimum existed. Written by hand because createVault refuses it.
  const { createCipheriv, randomBytes, scryptSync } = await import('node:crypto');
  const short = 'short1';
  const salt = randomBytes(16);
  const dk = randomBytes(32);
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', scryptSync(short, salt, 32, { N: 1024, r: 8, p: 1 }), iv);
  c.setAAD(Buffer.from('wickey/v1/dk'));
  const data = Buffer.concat([c.update(dk), c.final()]);
  const file = path.join(home, 'vault.json');
  const saved = fs.readFileSync(file);
  vault.lockVault();
  fs.writeFileSync(file, JSON.stringify({
    version: 1, kdf: { name: 'scrypt', salt: salt.toString('base64'), N: 1024, r: 8, p: 1 },
    dk: { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') }, secrets: {},
  }));
  try {
    session.unlock(short);
    assert.equal(vault.isUnlocked(), true, 'a short passphrase still unlocks');
    const res = await post('/api/passphrase', { current: short, next: 'a much longer new passphrase' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(opensWith('a much longer new passphrase'), true);
    assert.equal(opensWith(short), false);
  } finally {
    fs.writeFileSync(file, saved);
    vault.lockVault();
    vault.unlockVault(OLD);
  }
});

// ---- reset ----

test('planReset counts what a reset would delete, read-only', () => {
  const plan = reset.planReset();
  assert.equal(plan.vaultFile, path.join(home, 'vault.json'));
  assert.deepEqual(plan.credentials, ['work']);
  assert.equal(plan.proxies, 1);
});

test('isProxyRunning sees a live proxy on the configured port and not a dead one', async () => {
  process.env.WICKEY_PORT = String(port);
  assert.equal(await reset.isProxyRunning(), true);
  const dead = http.createServer().listen(0, '127.0.0.1');
  await new Promise((r) => dead.once('listening', r));
  const deadPort = (dead.address() as AddressInfo).port;
  dead.close();
  process.env.WICKEY_PORT = String(deadPort);
  assert.equal(await reset.isProxyRunning(), false);
});

/** Runs the CLI with no controlling terminal (detached = new session, so /dev/tty can't open). */
function cli(args: string[], port: number) {
  return new Promise<{ status: number | null; stderr: string }>((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(import.meta.dirname, '..', 'bin', 'wickey.js'), ...args], {
      env: { ...process.env, WICKEY_PORT: String(port) }, detached: true, stdio: ['pipe', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr!.on('data', (c) => (stderr += c));
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stderr }));
    child.stdin!.end('reset\n');
  });
}

test('CLI reset and passphrase refuse without a terminal, and delete nothing', { skip: process.platform === 'win32' }, async () => {
  for (const cmd of ['reset', 'passphrase']) {
    const r = await cli([cmd], port);
    assert.notEqual(r.status, 0, cmd);
    assert.match(r.stderr, /terminal/, cmd);
  }
  assert.equal(fs.existsSync(path.join(home, 'vault.json')), true);
  assert.equal(store.listCredentials().length, 1);
});

test('performReset removes the vault and database but leaves the directory', () => {
  vault.lockVault();
  store.closeStore();
  reset.performReset();
  assert.equal(fs.existsSync(home), true);
  assert.deepEqual(fs.readdirSync(home).filter((f) => f === 'vault.json' || f.startsWith('wickey.db')), []);
  assert.equal(vault.vaultExists(), false);
  // A fresh setup works from the empty directory and imports nothing from the old rows.
  session.setUp('a brand new passphrase');
  assert.equal(store.listCredentials().length, 0);
});
