import { sessionCookie } from './helpers.ts';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import type http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, before, test } from 'node:test';
import type { Limits } from '../src/store.ts';

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-limits-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '0';

const PASS = 'correct horse battery staple';
const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const vault = await import('../src/vault.ts');
session.setUp(PASS);

const dbFile = path.join(home, 'wickey.db');
let server: http.Server;
let port = 0;

before(async () => {
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
  vault.unlockVault(PASS);
  store.addCredential({ name: 'work', provider: 'custom', apiKey: 'sk-REAL', baseUrl: 'http://127.0.0.1:9/v1' });
});

after(() => {
  store.closeStore();
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
});

async function api(method: string, p: string, body?: Record<string, unknown>) {
  const cookie = await sessionCookie();
  return fetch(`http://127.0.0.1:${port}${p}`, {
    method, headers: { 'x-wickey': '1', 'content-type': 'application/json', cookie }, body: body ? JSON.stringify(body) : undefined,
  }).then(async (r) => ({ status: r.status, body: await r.json() as any }));
}
/** Edits the SQLite file directly, as a local program that lacks the passphrase would. */
function edit(sql: string, ...args: (string | number | null)[]) {
  const d = new DatabaseSync(dbFile);
  d.prepare(sql).run(...args);
  d.close();
}
const none: Limits = { models: null, rpm: null, tokenCap: null, refuseUncounted: true };
const issue = (limits?: Partial<Limits>) => store.issueProxy({ credential: 'work', ttlSeconds: 3600, limits });

test('rows signed before limits existed still verify after the migration', () => {
  store.closeStore();
  for (const f of ['', '-wal', '-shm']) fs.rmSync(dbFile + f, { force: true });
  // The schema and signature format of the previous version, signed with the live vault key.
  const old = new DatabaseSync(dbFile);
  old.exec(`
    CREATE TABLE credentials (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, provider TEXT NOT NULL,
      base_url TEXT NOT NULL, auth_style TEXT NOT NULL, created_at INTEGER NOT NULL, sig TEXT);
    CREATE TABLE proxies (id TEXT PRIMARY KEY, label TEXT, credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL, ttl_seconds INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      revoked_at INTEGER, token TEXT, sig TEXT);
  `);
  const token = 'sk-wick-legacy';
  const hash = createHash('sha256').update(token).digest('hex');
  const expires = Date.now() + 3600_000;
  const credSig = vault.sign(['credential', 'v1', 'c1', 'custom', 'http://127.0.0.1:9/v1', 'bearer'].join('|'));
  const proxySig = vault.sign(['proxy', 'v1', 'p1', 'c1', hash, expires, ''].join('|'));
  old.prepare("INSERT INTO credentials VALUES ('c1', 'legacy', 'custom', 'http://127.0.0.1:9/v1', 'bearer', 0, ?)").run(credSig);
  old.prepare("INSERT INTO proxies VALUES ('p1', NULL, 'c1', ?, 3600, 0, ?, NULL, ?, ?)").run(hash, expires, token, proxySig);
  old.close();

  const result = store.authorize('p1', token);
  assert.equal(result.ok, true, 'a legacy row with no limits verifies unchanged');
  if (result.ok) {
    assert.deepEqual(result.proxy.limits, none);
    assert.equal(result.proxy.usage.requests, 0);
    assert.equal(result.proxy.usage.ok, true);
    assert.equal(result.credential.usageReporting, null);
  }
  // It can then be limited, and the limited row verifies too.
  store.setLimits('p1', { rpm: 5 });
  assert.equal(store.authorize('p1', token).ok, true);
  store.deleteProxy('p1');
  store.removeCredential('c1');
  // The migration test replaced the database file, so the shared credential is added again.
  store.addCredential({ name: 'work', provider: 'custom', apiKey: 'sk-REAL', baseUrl: 'http://127.0.0.1:9/v1' });
});

test('editing any limit column in the file breaks the proxy integrity check', () => {
  const unlimited = issue();
  const limited = issue({ models: ['gpt-4o'], rpm: 10, tokenCap: 1000 });
  assert.equal(store.authorize(unlimited.proxy.id, unlimited.token).ok, true);
  assert.equal(store.authorize(limited.proxy.id, limited.token).ok, true);

  const attempts: [string, string, string | number | null, typeof unlimited][] = [
    ['allowed_models', 'allowed_models', '["gpt-4o","o1"]', limited],
    ['allowed_models removed', 'allowed_models', null, limited],
    ['rpm', 'rpm', 100000, limited],
    ['rpm removed', 'rpm', null, limited],
    ['token_cap', 'token_cap', 999999999, limited],
    ['token_cap removed', 'token_cap', null, limited],
    ['refuse_uncounted', 'refuse_uncounted', 0, unlimited],
    ['max_expires_at', 'max_expires_at', 9999999999999, unlimited],
    ['renew_window_s', 'renew_window_s', 600, unlimited],
    ['rpm added to an unlimited row', 'rpm', 1000, unlimited],
    ['allowed_models added to an unlimited row', 'allowed_models', '[]', unlimited],
  ];
  for (const [what, column, value, target] of attempts) {
    const d = new DatabaseSync(dbFile);
    const before = d.prepare(`SELECT ${column} AS v FROM proxies WHERE id = ?`).get(target.proxy.id) as any;
    d.close();
    edit(`UPDATE proxies SET ${column} = ? WHERE id = ?`, value, target.proxy.id);
    const result = store.authorize(target.proxy.id, target.token);
    assert.equal(result.ok, false, `${what}: edit should be rejected`);
    if (!result.ok) assert.match(result.message, /integrity/);
    edit(`UPDATE proxies SET ${column} = ? WHERE id = ?`, before.v, target.proxy.id);
    assert.equal(store.authorize(target.proxy.id, target.token).ok, true, `${what}: restoring the value verifies again`);
  }
});

test('editing usage counters in the file makes getUsage report not ok', () => {
  const { proxy } = issue({ tokenCap: 1000 });
  store.recordUsage(proxy.id, { tokensIn: 10, tokensOut: 5, counted: true, at: 1000 });
  store.recordUsage(proxy.id, { counted: false, at: 2000 });
  assert.deepEqual(store.getUsage(proxy.id), { requests: 2, tokensIn: 10, tokensOut: 5, uncounted: 1, lastUsedAt: 2000, ok: true });

  for (const column of ['requests', 'tokens_in', 'tokens_out', 'uncounted', 'last_used_at']) {
    edit(`UPDATE proxy_usage SET ${column} = 0 WHERE proxy_id = ?`, proxy.id);
    assert.equal(store.getUsage(proxy.id).ok, false, `${column} edit detected`);
    assert.equal(store.getProxy(proxy.id)!.usage.ok, false);
    // Counting must not launder the edit by re-signing it.
    assert.equal(store.recordUsage(proxy.id, { tokensIn: 1, counted: true, at: 3000 }).ok, false);
    edit('UPDATE proxy_usage SET requests = 2, tokens_in = 10, tokens_out = 5, uncounted = 1, last_used_at = 2000 WHERE proxy_id = ?', proxy.id);
    assert.equal(store.getUsage(proxy.id).ok, true);
  }
  // Deleting the row to reset a capped key is caught too.
  edit('DELETE FROM proxy_usage WHERE proxy_id = ?', proxy.id);
  assert.equal(store.getUsage(proxy.id).ok, false, 'a capped key with no usage row is not ok');
});

test('usage survives rotate and goes away with the proxy', () => {
  const { proxy } = issue({ tokenCap: 100 });
  store.recordUsage(proxy.id, { tokensIn: 7, tokensOut: 3, counted: true, at: 5 });
  store.rotateProxy(proxy.id);
  assert.equal(store.getUsage(proxy.id).tokensIn, 7, 'rotate does not reset the budget');
  store.deleteProxy(proxy.id);
  const d = new DatabaseSync(dbFile);
  assert.equal((d.prepare('SELECT COUNT(*) AS n FROM proxy_usage WHERE proxy_id = ?').get(proxy.id) as any).n, 0);
  d.close();
});

test('PATCH limits: tightening needs no passphrase, each kind of loosening does', async () => {
  const { proxy, token } = issue({ models: ['a', 'b'], rpm: 10, tokenCap: 1000 });
  const id = proxy.id;
  const patch = (limits: object, passphrase?: string) => api('PATCH', `/api/proxies/${id}/limits`, { limits, passphrase });
  const base = { models: ['a', 'b'], rpm: 10, tokenCap: 1000, refuseUncounted: true };

  let r = await patch({ ...base, models: ['a'], rpm: 5, tokenCap: 500 });
  assert.equal(r.status, 200, 'lowering everything is tightening');
  assert.deepEqual(r.body.proxy.limits, { models: ['a'], rpm: 5, tokenCap: 500, refuseUncounted: true });

  const loosenings: [string, object][] = [
    ['removing the allowlist', { ...base, models: null, rpm: 5, tokenCap: 500 }],
    ['adding a model', { models: ['a', 'c'], rpm: 5, tokenCap: 500, refuseUncounted: true }],
    ['raising rpm', { models: ['a'], rpm: 6, tokenCap: 500, refuseUncounted: true }],
    ['removing rpm', { models: ['a'], rpm: null, tokenCap: 500, refuseUncounted: true }],
    ['raising the token cap', { models: ['a'], rpm: 5, tokenCap: 501, refuseUncounted: true }],
    ['removing the token cap', { models: ['a'], rpm: 5, tokenCap: null, refuseUncounted: true }],
    ['allowing uncapped', { models: ['a'], rpm: 5, tokenCap: 500, refuseUncounted: false }],
  ];
  for (const [what, limits] of loosenings) {
    r = await patch(limits);
    assert.equal(r.status, 401, what);
    assert.equal(r.body.error.code, 'passphrase_required', what);
    assert.deepEqual(store.getProxy(id)!.limits, { models: ['a'], rpm: 5, tokenCap: 500, refuseUncounted: true }, `${what}: nothing changed`);
  }
  r = await patch(loosenings[0][1], 'not the passphrase');
  assert.equal(r.status, 401);
  assert.equal(r.body.error.code, 'wrong_passphrase');

  r = await patch(loosenings[0][1], PASS);
  assert.equal(r.status, 200);
  assert.equal(r.body.proxy.limits.models, null);
  assert.equal(store.authorize(id, token).ok, true, 'the row is re-signed after the edit');

  // Adding a limit to a key that has none is tightening.
  const open = issue();
  r = await api('PATCH', `/api/proxies/${open.proxy.id}/limits`, { limits: { models: ['x'], rpm: 1 } });
  assert.equal(r.status, 200);
  assert.equal(r.body.proxy.limits.refuseUncounted, true);
});

test('issue and env accept limits and still need the passphrase', async () => {
  let r = await api('POST', '/api/proxies', { credential: 'work', ttl: '1h', limits: { rpm: 3 } });
  assert.equal(r.status, 401);
  r = await api('POST', '/api/proxies', { credential: 'work', ttl: '1h', limits: { rpm: 3, models: ['m'] }, passphrase: PASS });
  assert.equal(r.status, 201);
  assert.equal(r.body.proxy.limits.rpm, 3);
  r = await api('POST', '/api/env', { label: 'limited-env', credential: 'work', ttl: '1h', limits: { tokenCap: 50, refuseUncounted: false }, passphrase: PASS });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.proxy.limits, { models: null, rpm: null, tokenCap: 50, refuseUncounted: false });
  const state = await api('GET', '/api/state');
  const listed = state.body.proxies.find((p: any) => p.id === r.body.proxy.id);
  assert.equal(listed.limits.tokenCap, 50);
  assert.equal(listed.usage.requests, 0);
  assert.equal(state.body.credentials[0].usageReporting, null);
  assert.ok(!JSON.stringify(state.body).includes('sk-REAL'));
});

test('request log: metadata only, 500 per key, nothing older than 30 days', async () => {
  const { proxy } = issue();
  const other = issue().proxy;
  const now = Date.now();
  store.logRequest({ proxyId: other.id, at: now, model: 'm', status: 200, durationMs: 1 });
  // Planted directly so the pruning has to come from the insert that follows.
  edit("INSERT INTO requests (proxy_id, at, model, status, duration_ms) VALUES (?, ?, 'old', 200, 5)", proxy.id, now - 31 * 24 * 3600 * 1000);
  edit("INSERT INTO requests (proxy_id, at, model, status, duration_ms) VALUES (?, ?, 'recent-enough', 200, 5)", proxy.id, now - 29 * 24 * 3600 * 1000);
  assert.equal(store.recentRequests(proxy.id, 100).length, 2);
  store.logRequest({ proxyId: proxy.id, at: now, model: 'gpt-4o', status: 200, durationMs: 1 });
  assert.deepEqual(store.recentRequests(proxy.id, 100).map((r) => r.model).sort(), ['gpt-4o', 'recent-enough'], 'only the 31-day-old row is pruned');
  for (let i = 0; i < 510; i++) store.logRequest({ proxyId: proxy.id, at: now + i, model: 'gpt-4o', status: 200, tokensIn: 1, tokensOut: 2, durationMs: 3 });
  const d = new DatabaseSync(dbFile);
  assert.equal((d.prepare('SELECT COUNT(*) AS n FROM requests WHERE proxy_id = ?').get(proxy.id) as any).n, 500);
  assert.equal((d.prepare("SELECT COUNT(*) AS n FROM requests WHERE model = 'old'").get() as any).n, 0, 'older than 30 days is gone');
  assert.equal((d.prepare('SELECT COUNT(*) AS n FROM requests WHERE proxy_id = ?').get(other.id) as any).n, 1, 'other keys are untouched');
  d.close();
  const recent = store.recentRequests(proxy.id, 3);
  assert.equal(recent.length, 3);
  assert.ok(recent[0].at > recent[1].at, 'newest first');
  assert.deepEqual(Object.keys(recent[0]).sort(), ['at', 'durationMs', 'event', 'id', 'model', 'proxyId', 'refusedReason', 'renewedTo', 'status', 'tokensIn', 'tokensOut']);

  const r = await api('GET', `/api/proxies/${proxy.id}/requests?limit=1000`);
  assert.equal(r.status, 200);
  assert.equal(r.body.requests.length, 100, 'limit is capped at 100');
  assert.equal((await api('GET', `/api/proxies/${proxy.id}/requests`)).body.requests.length, 20, 'default is 20');
  assert.equal((await api('GET', '/api/proxies/deadbeef/requests')).status, 404);
});

test('limit validation', async () => {
  const bad: [string, object][] = [
    ['a model with a space', { models: ['gpt 4'] }],
    ['an empty model', { models: [''] }],
    ['a newline in a model', { models: ['a\nb'] }],
    ['a model that is too long', { models: ['a'.repeat(201)] }],
    ['a non-string model', { models: [5] }],
    ['too many models', { models: Array.from({ length: 101 }, (_, i) => `m${i}`) }],
    ['models not a list', { models: 'gpt-4o' }],
    ['rpm 0', { rpm: 0 }],
    ['rpm too high', { rpm: 100001 }],
    ['rpm fractional', { rpm: 1.5 }],
    ['rpm as a string', { rpm: '5' }],
    ['token cap 0', { tokenCap: 0 }],
    ['token cap too high', { tokenCap: 1e12 + 1 }],
    ['refuseUncounted not a boolean', { refuseUncounted: 'no' }],
  ];
  for (const [what, limits] of bad) {
    assert.throws(() => store.normalizeLimits(limits as any), Error, what);
    const r = await api('PATCH', `/api/proxies/${issue().proxy.id}/limits`, { limits });
    assert.equal(r.status, 400, what);
  }
  assert.doesNotThrow(() => store.normalizeLimits({ models: ['gpt-4o', 'claude-3-5-sonnet@20240620', 'org/model:v1.2_x'], rpm: 100000, tokenCap: 1e12 }));
  assert.equal(store.normalizeLimits({ models: Array.from({ length: 100 }, (_, i) => `m${i}`) }).models!.length, 100);
});

test('isLoosening', () => {
  const l = (o: Partial<Limits>) => ({ ...none, ...o });
  assert.equal(store.isLoosening(l({}), l({ models: ['a'], rpm: 1, tokenCap: 1, refuseUncounted: true })), false);
  assert.equal(store.isLoosening(l({ models: ['a'] }), l({ models: ['a'] })), false, 'unchanged');
  assert.equal(store.isLoosening(l({ models: ['a', 'b'] }), l({ models: ['b'] })), false);
  assert.equal(store.isLoosening(l({ models: ['a'] }), l({ models: null })), true);
  assert.equal(store.isLoosening(l({ models: ['a'] }), l({ models: ['a', 'b'] })), true);
  assert.equal(store.isLoosening(l({ models: ['a'] }), l({ models: ['b'] })), true, 'swapping in a new model adds one');
  assert.equal(store.isLoosening(l({ rpm: 5 }), l({ rpm: 6 })), true);
  assert.equal(store.isLoosening(l({ tokenCap: 5 }), l({ tokenCap: null })), true);
  assert.equal(store.isLoosening(l({ refuseUncounted: true }), l({ refuseUncounted: false })), true);
  assert.equal(store.isLoosening(l({ refuseUncounted: false }), l({ refuseUncounted: true })), false);
});

test('credential usage hints are stored, validated and not signed', () => {
  const c = store.getCredential('work')!;
  store.setUsageReporting(c.id, { usage: 'reports', streamUsage: 'rejects_option' });
  assert.equal(store.getCredential('work')!.usageReporting, 'reports');
  assert.equal(store.getCredential('work')!.streamUsage, 'rejects_option');
  assert.throws(() => store.setUsageReporting(c.id, { usage: 'sometimes' as any }));
  const p = issue();
  assert.equal(store.authorize(p.proxy.id, p.token).ok, true, 'hints are not part of the credential signature');
});
