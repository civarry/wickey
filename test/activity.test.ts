import { sessionCookie } from './helpers.ts';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import type http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-activity-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '0';

const PASS = 'correct horse battery staple';
const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const vault = await import('../src/vault.ts');
session.setUp(PASS);

let server: http.Server;
let port = 0;
let a: string;
let b: string;

before(async () => {
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
  vault.unlockVault(PASS);
  store.addCredential({ name: 'work', provider: 'custom', apiKey: 'sk-REAL', baseUrl: 'http://127.0.0.1:9/v1' });
  a = store.issueProxy({ credential: 'work', ttlSeconds: 3600, label: 'alpha' }).proxy.id;
  b = store.issueProxy({ credential: 'work', ttlSeconds: 3600, label: 'beta' }).proxy.id;
  // Interleaved so cross-proxy order is by log id, not grouped by proxy. Every 4th is refused.
  for (let i = 0; i < 12; i++) {
    const refused = i % 4 === 3;
    store.logRequest({
      proxyId: i % 2 ? b : a, at: Date.now() + i, model: `m${i}`, status: refused ? 403 : 200, tokensIn: 1, tokensOut: 2, durationMs: 3,
      refusedReason: refused ? 'model_not_allowed' : null,
    });
  }
});

after(() => {
  store.closeStore();
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
});

async function get(p: string, headers?: Record<string, string>) {
  const cookie = await sessionCookie();
  return fetch(`http://127.0.0.1:${port}${p}`, { headers: { cookie, ...(headers ?? { 'x-wickey': '1' }) } }).then(async (r) => ({ status: r.status, body: await r.json() as any }));
}

const models = (n: number) => Array.from({ length: n }, (_, i) => `m${11 - i}`);

test('requests from every proxy come back newest first with the proxy label', async () => {
  const r = await get('/api/requests');
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.requests.map((x: any) => x.model), models(12));
  assert.equal(r.body.nextBefore, null, 'everything fit in one page');
  assert.equal(r.body.requests[0].proxyId, b);
  assert.equal(r.body.requests[0].proxyLabel, 'beta');
  assert.equal(r.body.requests[1].proxyLabel, 'alpha');
});

test('the proxy and status filters narrow the list and combine', async () => {
  const onlyA = await get(`/api/requests?proxy=${a}`);
  assert.equal(onlyA.body.requests.length, 6);
  assert.ok(onlyA.body.requests.every((x: any) => x.proxyId === a));
  const refused = await get('/api/requests?status=refused');
  assert.deepEqual(refused.body.requests.map((x: any) => x.model), ['m11', 'm7', 'm3']);
  const ok = await get('/api/requests?status=ok');
  assert.equal(ok.body.requests.length, 9);
  assert.ok(ok.body.requests.every((x: any) => x.refusedReason === null));
  const both = await get(`/api/requests?proxy=${b}&status=refused`);
  assert.deepEqual(both.body.requests.map((x: any) => x.model), ['m11', 'm7', 'm3']);
  assert.equal((await get(`/api/requests?proxy=${a}&status=refused`)).body.requests.length, 0);
});

test('before and nextBefore page through without gaps or repeats', async () => {
  const seen: string[] = [];
  let before: number | null = null;
  let pages = 0;
  do {
    const r: any = await get(`/api/requests?limit=5${before === null ? '' : `&before=${before}`}`);
    assert.equal(r.status, 200);
    seen.push(...r.body.requests.map((x: any) => x.model));
    before = r.body.nextBefore;
    pages++;
  } while (before !== null && pages < 10);
  assert.equal(pages, 3, '5 + 5 + 2');
  assert.deepEqual(seen, models(12));
  // A page that ends exactly at the end has no next page.
  assert.equal((await get('/api/requests?limit=12')).body.nextBefore, null);
});

test('limit defaults to 50 and is capped at 200', async () => {
  for (let i = 0; i < 260; i++) store.logRequest({ proxyId: a, at: Date.now() + i, model: 'bulk', status: 200, durationMs: 1 });
  assert.equal((await get('/api/requests')).body.requests.length, 50);
  assert.equal((await get('/api/requests?limit=1000')).body.requests.length, 200);
  assert.equal((await get('/api/requests?limit=7')).body.requests.length, 7);
});

test('bad parameters are rejected with a message', async () => {
  const s = await get('/api/requests?status=nope');
  assert.equal(s.status, 400);
  assert.match(s.body.error.message, /"ok" or "refused"/);
  assert.equal((await get('/api/requests?before=abc')).status, 400);
  assert.equal((await get('/api/requests?limit=0')).status, 400);
  assert.equal((await get('/api/requests?proxy=deadbeef')).status, 404, 'same as the per-proxy endpoint');
});

test('the dashboard header and loopback origin are required', async () => {
  assert.notEqual((await get('/api/requests', {})).status, 200);
  assert.notEqual((await get('/api/requests', { 'x-wickey': '1', origin: 'http://evil.example' })).status, 200);
});
