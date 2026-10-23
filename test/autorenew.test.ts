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

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-autorenew-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
// No grace period: every mint or loosening edit must carry the passphrase.
process.env.WICKEY_GRACE = '0';

const PASS = 'correct horse battery staple';
const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const vault = await import('../src/vault.ts');
const metering = await import('../src/metering.ts');
session.setUp(PASS);

const dbFile = path.join(home, 'wickey.db');
const servers: http.Server[] = [];
let proxyPort = 0;
let upstreamBase = '';
const CHAT = { id: 'c1', choices: [], usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function listen(server: http.Server): Promise<number> {
  servers.push(server);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
}

before(async () => {
  const upstream = http.createServer((req, res) => {
    req.resume();
    // No model list, so the default All-mode key passes models through.
    if (req.method === 'GET' && req.url?.endsWith('/models')) { res.writeHead(404); return res.end(); }
    req.on('end', () => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(CHAT)); });
  });
  upstreamBase = `http://127.0.0.1:${await listen(upstream)}`;
  proxyPort = await listen(createProxyServer());
  vault.unlockVault(PASS);
  store.addCredential({ name: 'work', provider: 'custom', apiKey: 'sk-REAL', baseUrl: upstreamBase });
});

after(() => {
  store.closeStore();
  for (const s of servers) s.close();
  fs.rmSync(home, { recursive: true, force: true });
});

async function api(method: string, p: string, body?: Record<string, unknown>) {
  const cookie = await sessionCookie();
  return fetch(`http://127.0.0.1:${proxyPort}${p}`, {
    method, headers: { 'x-wickey': '1', 'content-type': 'application/json', cookie }, body: body ? JSON.stringify(body) : undefined,
  }).then(async (r) => ({ status: r.status, body: await r.json() as any }));
}

/** Calls through the proxy as an agent would. */
async function use(k: { id: string; token: string }, body: object = { model: 'm' }, p = '/chat/completions') {
  const r = await fetch(`http://127.0.0.1:${proxyPort}/p/${k.id}${p}`, {
    method: 'POST', headers: { authorization: `Bearer ${k.token}`, 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  await r.text();
  return r.status;
}

/**
 * Moves a key's expiry (and optionally its maximum) the way only the passphrase holder could, by
 * re-signing with the live vault key. The signed string mirrors proxySigData in src/store.ts.
 */
function setTimes(id: string, expiresAt: number, maxExpiresAt?: number) {
  const d = new DatabaseSync(dbFile);
  d.prepare('UPDATE proxies SET expires_at = ? WHERE id = ?').run(expiresAt, id);
  if (maxExpiresAt !== undefined) d.prepare('UPDATE proxies SET max_expires_at = ? WHERE id = ?').run(maxExpiresAt, id);
  const r = d.prepare('SELECT * FROM proxies WHERE id = ?').get(id) as Record<string, any>;
  const f = (v: unknown) => (v == null ? '' : String(v));
  const data = ['proxy', 'v1', r.id, r.credential_id, r.token_hash, r.expires_at, r.revoked_at ?? '',
    'limits-v2', f(r.allowed_models), f(r.rpm), f(r.token_cap), r.refuse_uncounted === 0 ? 0 : 1, f(r.renew_window_s), f(r.max_expires_at),
    ...(r.version > 0 ? ['version-v1', r.version, r.ttl_seconds] : [])].join('|');
  d.prepare('UPDATE proxies SET sig = ? WHERE id = ?').run(vault.sign(data), id);
  d.close();
}
function rawEdit(sql: string, ...args: (string | number | null)[]) {
  const d = new DatabaseSync(dbFile);
  d.prepare(sql).run(...args);
  d.close();
}

const TTL = 3600;
const WINDOW = 600;
/** An auto-renew key with a 1h TTL, 10 minute window and a 2 day maximum. */
function key(opts: { limits?: object; ttl?: number; window?: number; maxLifetime?: string } = {}) {
  const { proxy, token } = store.issueProxy({
    credential: 'work', ttlSeconds: opts.ttl ?? TTL, limits: opts.limits as any,
    autoRenew: { windowSeconds: opts.window ?? WINDOW, maxLifetime: opts.maxLifetime ?? '2d' },
  });
  return { id: proxy.id, token };
}
const expiry = (id: string) => store.getProxy(id)!.expiresAt;
const inWindow = (id: string) => setTimes(id, Date.now() + 5 * 60_000);
const renewals = (id: string) => store.recentRequests(id, 100).filter((r) => r.event === 'renewed');

test('a forwarded request inside the window extends expiry by one TTL; outside it does not', async () => {
  const k = key();
  const first = expiry(k.id);
  assert.equal(await use(k), 200);
  assert.equal(expiry(k.id), first, 'outside the window nothing changes');
  assert.equal(renewals(k.id).length, 0);

  inWindow(k.id);
  const before = Date.now();
  assert.equal(await use(k), 200);
  const after = expiry(k.id);
  assert.ok(after >= before + TTL * 1000 && after <= Date.now() + TTL * 1000, 'now + ttl');
  assert.equal(store.authorize(k.id, k.token).ok, true, 'same token, row re-signed and still verifies');
});

test('never past the maximum: repeated use stops at it, and the key then expires', async () => {
  const k = key();
  const now = Date.now();
  setTimes(k.id, now + 400, now + 1500);
  assert.equal(await use(k), 200);
  assert.equal(expiry(k.id), now + 1500, 'clamped to the maximum');
  assert.equal(await use(k), 200);
  assert.equal(expiry(k.id), now + 1500, 'stays at the maximum');
  assert.equal(renewals(k.id).length, 1, 'no second renewal at the maximum');
  await sleep(Math.max(0, now + 1600 - Date.now()));
  assert.equal(await use(k), 401, 'expired at the maximum');
  assert.equal(expiry(k.id), now + 1500);
});

test('refused requests inside the window never renew', async () => {
  const cases: [string, { id: string }, () => Promise<number>, number][] = [];
  const allow = key({ limits: { models: ['ok-model'] } });
  cases.push(['allowlist', allow, () => use(allow, { model: 'other' }), 403]);
  const rate = key({ limits: { rpm: 1 } });
  cases.push(['rate limit', rate, () => use(rate, { model: 'm' }), 429]);
  const cap = key({ limits: { tokenCap: 10 } });
  cases.push(['token cap', cap, () => use(cap, { model: 'm' }), 429]);
  const unc = key({ limits: { tokenCap: 1_000_000 } });
  cases.push(['uncountable', unc, () => use(unc, { purpose: 'x' }, '/files'), 403]);

  // Use up the rate limit and the token cap with a request that is allowed to renew.
  assert.equal(await use(rate), 200);
  assert.equal(await use(cap), 200);
  for (const [name, k, run, status] of cases) {
    const id = k.id;
    inWindow(id);
    const set = expiry(id);
    const renewed = renewals(id).length;
    assert.equal(await run(), status, name);
    assert.equal(expiry(id), set, `${name}: expiry unchanged`);
    assert.equal(renewals(id).length, renewed, `${name}: nothing logged as renewed`);
  }
});

test('a key at its token cap does not renew, even if a request were forwarded', () => {
  const k = key({ limits: { tokenCap: 100 } });
  inWindow(k.id);
  const set = expiry(k.id);
  assert.equal(store.renewIfDue(k.id, 100), null);
  assert.equal(store.renewIfDue(k.id, 150), null);
  assert.equal(expiry(k.id), set);
  assert.ok(store.renewIfDue(k.id, 99) !== null, 'under the cap it renews');
});

test('the request that reaches the token cap does not renew the key (D10 a)', async () => {
  // The mock upstream reports 15 tokens per request, so one request takes this key to its cap.
  const k = key({ limits: { tokenCap: 15 } });
  inWindow(k.id);
  const before = expiry(k.id);
  assert.equal(await use(k), 200, 'the crossing request itself is forwarded (D4)');
  assert.equal(expiry(k.id), before, 'but it must not extend the key');
  assert.equal(renewals(k.id).length, 0);
  assert.equal(await use(k), 429, 'and the next request is refused at the cap');
});

test('a rollback-flagged key is forwarded (no limits) but does not renew', async () => {
  const k = key();
  const db = new DatabaseSync(dbFile);
  try {
    assert.equal(await use(k), 200);
    const old = db.prepare('SELECT * FROM proxy_usage WHERE proxy_id = ?').get(k.id) as Record<string, any>;
    assert.equal(await use(k), 200);
    db.prepare('UPDATE proxy_usage SET requests = ?, tokens_in = ?, tokens_out = ?, uncounted = ?, last_used_at = ?, sig = ? WHERE proxy_id = ?')
      .run(old.requests, old.tokens_in, old.tokens_out, old.uncounted, old.last_used_at, old.sig, k.id);
    inWindow(k.id);
    const set = expiry(k.id);
    assert.equal(await use(k), 200, 'unlimited keys keep working');
    assert.equal(metering.isRollbackFlagged(k.id), true);
    assert.equal(expiry(k.id), set, 'but a flagged key is not kept alive');
    assert.equal(renewals(k.id).length, 0);
  } finally {
    db.close();
  }
});

test('expired and "expire now" keys never renew', async () => {
  const gone = key();
  store.expireProxy(gone.id);
  const stopped = expiry(gone.id);
  assert.equal(await use(gone), 401);
  assert.equal(expiry(gone.id), stopped);
  assert.equal(store.renewIfDue(gone.id, 0), null, 'not even when asked directly');
  assert.equal(expiry(gone.id), stopped);

  const lapsed = key();
  setTimes(lapsed.id, Date.now() - 1000);
  assert.equal(await use(lapsed), 401);
  assert.equal(store.renewIfDue(lapsed.id, 0), null);
  assert.equal(renewals(lapsed.id).length, 0);
});

test('enabling auto-renew needs the passphrase; disabling or lowering does not', async () => {
  let r = await api('POST', '/api/proxies', { credential: 'work', ttl: '1h', autoRenew: { windowSeconds: 600, maxLifetime: '2d' } });
  assert.equal(r.status, 401);
  assert.equal(r.body.error.code, 'passphrase_required');
  r = await api('POST', '/api/proxies', { credential: 'work', ttl: '1h', autoRenew: { windowSeconds: 600, maxLifetime: '2d' }, passphrase: PASS });
  assert.equal(r.status, 201);
  const id = r.body.proxy.id;
  assert.equal(r.body.proxy.autoRenew.windowSeconds, 600);
  const max = r.body.proxy.autoRenew.maxExpiresAt;
  assert.ok(Math.abs(max - (Date.now() + 2 * 86400_000)) < 5000);
  assert.equal((await api('GET', '/api/state')).body.proxies.find((p: any) => p.id === id).autoRenew.maxExpiresAt, max);

  const patch = (autoRenew: unknown, passphrase?: string) => api('PATCH', `/api/proxies/${id}/limits`, { autoRenew, passphrase });
  // Tightening: no passphrase.
  r = await patch({ windowSeconds: 300, maxExpiresAt: max - 3600_000 });
  assert.equal(r.status, 200, 'shrink window and lower maximum');
  assert.equal(r.body.proxy.autoRenew.windowSeconds, 300);
  // Loosening: later maximum, wider window.
  r = await patch({ windowSeconds: 300, maxExpiresAt: max });
  assert.equal(r.body.error.code, 'passphrase_required', 'raising the maximum');
  r = await patch({ windowSeconds: 900, maxExpiresAt: max - 3600_000 });
  assert.equal(r.body.error.code, 'passphrase_required', 'widening the window');
  r = await patch({ windowSeconds: 300, maxExpiresAt: max }, PASS);
  assert.equal(r.status, 200);
  r = await patch(null);
  assert.equal(r.status, 200, 'turning it off needs no passphrase');
  assert.equal(r.body.proxy.autoRenew, null);
  r = await patch({ windowSeconds: 300, maxLifetime: '1d' });
  assert.equal(r.body.error.code, 'passphrase_required', 'turning it back on');
  r = await patch({ windowSeconds: 300, maxLifetime: '1d' }, PASS);
  assert.equal(r.status, 200);
  // A limits-only edit leaves auto-renew alone.
  r = await api('PATCH', `/api/proxies/${id}/limits`, { limits: { rpm: 5 } });
  assert.equal(r.status, 200);
  assert.ok(r.body.proxy.autoRenew);

  r = await api('POST', '/api/env', { label: 'ar-env', credential: 'work', ttl: '1h', autoRenew: { windowSeconds: '10m', maxLifetime: '1d' } });
  assert.equal(r.body.error.code, 'passphrase_required');
  r = await api('POST', '/api/env', { label: 'ar-env', credential: 'work', ttl: '1h', autoRenew: { windowSeconds: '10m', maxLifetime: '1d' }, passphrase: PASS });
  assert.equal(r.status, 200);
  assert.equal(r.body.proxy.autoRenew.windowSeconds, 600);
});

test('auto-renew input is validated', async () => {
  const bad = (autoRenew: unknown) => api('POST', '/api/proxies', { credential: 'work', ttl: '1h', autoRenew, passphrase: PASS });
  assert.match((await bad({ windowSeconds: 600 })).body.error.message, /both a renew window and a maximum/, 'window without a maximum');
  assert.equal((await bad({ maxLifetime: '1d' })).status, 400, 'maximum without a window');
  assert.equal((await bad({ windowSeconds: 30, maxLifetime: '1d' })).status, 400, 'window under 1 minute');
  assert.equal((await bad({ windowSeconds: 90000, maxLifetime: '1d' })).status, 400, 'window over 24 hours');
  assert.equal((await bad({ windowSeconds: 3600, maxLifetime: '1d' })).status, 400, 'window not shorter than the ttl');
  assert.equal((await bad({ windowSeconds: 600, maxLifetime: '30m' })).status, 400, 'maximum before the expiry');
  assert.equal((await bad({ windowSeconds: 600, maxLifetime: '366d' })).status, 400, 'maximum beyond 365 days');
  assert.equal((await bad({ windowSeconds: 600, maxLifetime: '1d', maxExpiresAt: Date.now() + 1e9 })).status, 400, 'both forms');
  assert.equal((await bad({ windowSeconds: 600, maxExpiresAt: Date.now() + 86400_000 })).status, 201, 'absolute maximum');
});

test('editing the window or the maximum directly in SQLite breaks the signature', async () => {
  for (const [col, value] of [['max_expires_at', Date.now() + 400 * 86400_000], ['renew_window_s', 86400]] as const) {
    const k = key();
    assert.equal(await use(k), 200);
    rawEdit(`UPDATE proxies SET ${col} = ? WHERE id = ?`, value, k.id);
    assert.equal(await use(k), 401, col);
    assert.match(String((store.authorize(k.id, k.token) as any).message), /integrity/);
  }
  // Switching auto-renew on for a key that never had it is caught too.
  const { proxy, token } = store.issueProxy({ credential: 'work', ttlSeconds: TTL });
  rawEdit('UPDATE proxies SET renew_window_s = 600, max_expires_at = ? WHERE id = ?', Date.now() + 86400_000, proxy.id);
  assert.equal(await use({ id: proxy.id, token }), 401);
});

test('each renewal is written to the activity log, apart from real requests', async () => {
  const k = key({ limits: { rpm: 100 } });
  inWindow(k.id);
  assert.equal(await use(k), 200);
  const log = store.recentRequests(k.id, 10);
  const renewed = log.filter((r) => r.event === 'renewed');
  assert.equal(renewed.length, 1);
  assert.equal(renewed[0].renewedTo, expiry(k.id));
  assert.equal(renewed[0].refusedReason, null);
  const requests = log.filter((r) => r.event === null);
  assert.equal(requests.length, 1, 'the forwarded request keeps its own row');
  assert.equal(requests[0].refusedReason, null);

  inWindow(k.id);
  assert.equal(await use(k), 200);
  assert.equal(renewals(k.id).length, 2);
});

test('manual renew of an auto-renew key is clamped to the maximum; rotate keeps the settings', async () => {
  const k = key({ maxLifetime: '2h' });
  const { maxExpiresAt } = store.getProxy(k.id)!.autoRenew!;
  let r = await api('POST', `/api/proxies/${k.id}/renew`, { ttl: '5h', passphrase: PASS });
  assert.equal(r.status, 200);
  assert.equal(r.body.proxy.expiresAt, maxExpiresAt, 'ttl 5h cannot pass a 2h maximum');
  r = await api('POST', `/api/proxies/${k.id}/rotate`, { ttl: '5h', passphrase: PASS });
  assert.equal(r.body.proxy.expiresAt, maxExpiresAt);
  assert.deepEqual(r.body.proxy.autoRenew, { windowSeconds: WINDOW, maxExpiresAt });
  assert.notEqual(r.body.token, k.token);

  r = await api('POST', `/api/proxies/${k.id}/renew`, { ttl: '5m', passphrase: PASS });
  assert.equal(r.status, 400, 'a ttl no longer than the window is refused');

  setTimes(k.id, Date.now() - 1000, Date.now() - 500);
  r = await api('POST', `/api/proxies/${k.id}/renew`, { passphrase: PASS });
  assert.equal(r.status, 400, 'nothing left to renew into once the maximum has passed');
  assert.match(r.body.error.message, /maximum lifetime/);
  assert.ok(!r.body.error.message.includes('—'));
});
