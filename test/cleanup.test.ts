import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { after, before, test } from 'node:test';

// Lock works without a session (it is harmless); `env` retires expired proxies by marking them,
// never by deleting them, so an agent cannot erase its own trail by rerunning env.

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-cleanup-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '300';
const PASS = 'correct horse battery staple';

const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
session.setUp(PASS);

const servers: http.Server[] = [];
let proxyPort = 0;
let upstreamHits = 0;
const script = fileURLToPath(new URL('../bin/wickey.js', import.meta.url));

function listen(server: http.Server): Promise<number> {
  servers.push(server);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
}

before(async () => {
  const upstream = http.createServer((req, res) => {
    req.resume();
    if (req.method === 'GET') { res.writeHead(404); return res.end(); }
    req.on('end', () => { upstreamHits++; res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ id: 'c', usage: { prompt_tokens: 1, completion_tokens: 1 } })); });
  });
  const upPort = await listen(upstream);
  proxyPort = await listen(createProxyServer());
  store.addCredential({ name: 'work', provider: 'custom', apiKey: 'sk-REAL', baseUrl: `http://127.0.0.1:${upPort}` });
});

after(() => {
  store.closeStore();
  for (const s of servers) s.close();
  fs.rmSync(home, { recursive: true, force: true });
});

async function raw(method: string, p: string, opts: { cookie?: string; body?: unknown } = {}) {
  const res = await fetch(`http://127.0.0.1:${proxyPort}${p}`, {
    method,
    headers: { 'x-wickey': '1', 'content-type': 'application/json', ...(opts.cookie ? { cookie: opts.cookie } : {}) },
    body: method === 'GET' ? undefined : JSON.stringify(opts.body ?? {}),
  });
  const text = await res.text();
  let body: any = text;
  try { body = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, body, headers: res.headers };
}

async function signIn(): Promise<string> {
  const res = await raw('POST', '/api/signin', { body: { passphrase: PASS } });
  assert.equal(res.status, 200);
  return String(res.headers.get('set-cookie')).split(';')[0];
}

async function use(k: { id: string; token: string }): Promise<number> {
  const r = await fetch(`http://127.0.0.1:${proxyPort}/p/${k.id}/chat/completions`, {
    method: 'POST', headers: { authorization: `Bearer ${k.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ model: 'm' }),
  });
  await r.text();
  return r.status;
}

// ---- lock without a session ----

test('lock works with no session: 200, sessions cleared, grace ended, and proxy keys still forward', async () => {
  const cookie = await signIn();
  assert.ok(session.graceRemaining() > 0);
  const key = store.issueProxy({ credential: 'work', ttlSeconds: 3600 });
  assert.equal(await use({ id: key.proxy.id, token: key.token }), 200);
  const before = upstreamHits;

  const res = await raw('POST', '/api/lock');
  assert.equal(res.status, 200, 'no cookie needed');
  assert.equal(session.graceRemaining(), 0, 'grace period ended');
  const old = await raw('GET', '/api/state', { cookie });
  assert.equal(old.status, 401, 'the old cookie is dead');
  assert.equal(old.body.error.code, 'session_required');

  assert.equal(await use({ id: key.proxy.id, token: key.token }), 200, 'locking does not cut proxy traffic');
  assert.equal(upstreamHits, before + 1);
  store.deleteProxy(key.proxy.id);
});

test('lock still needs the loopback header check', async () => {
  const res = await fetch(`http://127.0.0.1:${proxyPort}/api/lock`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(res.status, 403);
  await res.text();
});

test('the CLI lock command needs no passphrase and no terminal', async () => {
  // Async spawn: the proxy under test runs in this process and must keep answering.
  const child = spawn(process.execPath, [script, 'lock'], { env: { ...process.env, WICKEY_PORT: String(proxyPort) }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  child.stdout.on('data', (c) => (out += c));
  child.stderr.on('data', (c) => (err += c));
  const code = await new Promise((r) => child.once('exit', r));
  assert.equal(code, 0, err);
  assert.match(out, /Locked/);
});

// ---- env cleanup keeps history ----

test('env marks expired proxies cleaned up instead of deleting them; their activity stays', async () => {
  const cookie = await signIn();
  const env = () => raw('POST', '/api/env', { cookie, body: { label: 'shell', credential: 'work', ttl: '1h' } });
  const first = (await env()).body;
  assert.equal(await use({ id: first.proxy.id, token: first.token }), 200);
  store.expireProxy(first.proxy.id);

  const second = (await env()).body;
  const old = store.getProxy(first.proxy.id);
  assert.ok(old, 'the row is still there');
  assert.ok(old.cleanedAt && old.cleanedAt <= Date.now());
  assert.equal(store.getProxy(second.proxy.id)!.cleanedAt, null, 'the fresh key is not cleaned');
  assert.ok(store.recentRequests(first.proxy.id).length >= 1, 'activity rows intact');
  assert.ok(store.requestsPage({ proxyId: first.proxy.id }).requests.length >= 1, 'the activity page can still select it');

  // A third run does not touch the already-cleaned row's timestamp.
  const stamp = old.cleanedAt;
  store.expireProxy(second.proxy.id);
  await env();
  assert.equal(store.getProxy(first.proxy.id)!.cleanedAt, stamp);
  assert.equal(store.getProxy(second.proxy.id)!.cleanedAt !== null, true);
});

test('lists hide cleaned-up proxies by default and show them on request', async () => {
  assert.ok(!store.listProxies().some((p) => p.cleanedAt !== null));
  assert.ok(store.listProxies({ includeCleaned: true }).some((p) => p.cleanedAt !== null));
  const cookie = await signIn();
  const state = (await raw('GET', '/api/state', { cookie })).body;
  assert.ok(state.proxies.some((p: any) => p.cleanedAt !== null), 'the API returns them flagged; the dashboard filters');

  const cli = (args: string[]) => spawnSync(process.execPath, [script, ...args], { env: { ...process.env }, encoding: 'utf8', timeout: 20000 }).stdout;
  const cleanedId = store.listProxies({ includeCleaned: true }).find((p) => p.cleanedAt !== null)!.id;
  assert.ok(!cli(['list']).includes(cleanedId), 'default list hides it');
  const all = cli(['list', '--all']);
  assert.ok(all.includes(cleanedId) && all.includes('cleaned up'), '--all shows it');
});

test('a cleaned-up proxy cannot authenticate, renew or rotate, and nothing revives it', async () => {
  const cookie = await signIn();
  const k = (await raw('POST', '/api/env', { cookie, body: { label: 'retire', credential: 'work', ttl: '1h' } })).body;
  store.expireProxy(k.proxy.id);
  await raw('POST', '/api/env', { cookie, body: { label: 'retire', credential: 'work', ttl: '1h' } });
  assert.ok(store.getProxy(k.proxy.id)!.cleanedAt);

  const auth = store.authorize(k.proxy.id, k.token);
  assert.equal(auth.ok, false);
  assert.equal(await use({ id: k.proxy.id, token: k.token }), 401);

  for (const action of ['renew', 'rotate']) {
    const res = await raw('POST', `/api/proxies/${k.proxy.id}/${action}`, { cookie, body: {} });
    assert.equal(res.status, 400, action);
    assert.match(res.body.error.message, /retired by `wickey env`.*env` again/, action);
  }
  assert.throws(() => store.renewProxy(k.proxy.id), /retired/);
  assert.throws(() => store.rotateProxy(k.proxy.id), /retired/);
  const row = store.getProxy(k.proxy.id)!;
  assert.equal(row.status, 'expired');
  assert.equal(await use({ id: k.proxy.id, token: k.token }), 401, 'still refused after the attempts');
});

test('a cleaned-up mark on an ACTIVE key is tampering: the key stays visible with a warning, is refused, and rotate recovers it', async () => {
  // cleaned_at is unsigned, so a direct DB edit can set it. Only the signed expiry may decide hiding.
  const k = store.issueProxy({ credential: 'work', ttlSeconds: 3600 });
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(path.join(home, 'wickey.db'));
  db.prepare('UPDATE proxies SET cleaned_at = ? WHERE id = ?').run(Date.now(), k.proxy.id);
  db.close();

  const p = store.getProxy(k.proxy.id)!;
  assert.equal(p.status, 'active');
  assert.equal(p.cleanedUp, false);
  assert.equal(p.cleanedTampered, true);
  assert.ok(store.listProxies().some((x) => x.id === k.proxy.id), 'not hidden from the default list');

  const cookie = await signIn();
  const state = (await raw('GET', '/api/state', { cookie })).body;
  const fromApi = state.proxies.find((x: any) => x.id === k.proxy.id);
  assert.equal(fromApi.cleanedTampered, true, 'the dashboard gets the warning flag');
  assert.equal(fromApi.cleanedUp, false, 'and does not hide it');

  const out = spawnSync(process.execPath, [script, 'list'], { env: { ...process.env }, encoding: 'utf8', timeout: 20000 }).stdout;
  const line = out.split('\n').find((l) => l.includes(k.proxy.id));
  assert.ok(line, 'default CLI list shows it');
  assert.match(line!, /TAMPERED: marked cleaned up while active/);

  const auth = store.authorize(k.proxy.id, k.token);
  assert.equal(auth.ok, false, 'fails closed');
  assert.match((auth as { message: string }).message, /marked cleaned up while active/);

  const rotated = await raw('POST', `/api/proxies/${k.proxy.id}/rotate`, { cookie, body: {} });
  assert.equal(rotated.status, 200, 'rotate is the way out');
  assert.equal(store.getProxy(k.proxy.id)!.cleanedAt, null, 'rotate clears the mark');
  assert.equal(await use({ id: k.proxy.id, token: rotated.body.token }), 200);
  store.deleteProxy(k.proxy.id);
});
