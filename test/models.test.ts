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
import type { Limits } from '../src/store.ts';

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-models-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '0';

const PASS = 'correct horse battery staple';
const REAL = 'sk-REAL-MODELS-KEY-12345';
const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const vault = await import('../src/vault.ts');
const models = await import('../src/models.ts');
session.setUp(PASS);

const dbFile = path.join(home, 'wickey.db');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const servers: http.Server[] = [];
let upstream = '';
let proxyPort = 0;

/** Hits on the mock provider, by "METHOD path" (query stripped). */
const hits: Record<string, number> = {};
const seen: { url: string; headers: http.IncomingHttpHeaders }[] = [];
const hitCount = (key: string) => hits[key] ?? 0;

// What the mock provider lists; tests change it to play "the provider added a model".
let listed = ['gpt-a', 'gpt-b'];
let listDelayMs = 0;
const ANTHROPIC_IDS = ['claude-1', 'claude-2', 'claude-3', 'claude-4', 'claude-5'];

before(async () => {
  const mock = http.createServer(async (req, res) => {
    const url = new URL(req.url!, 'http://x');
    const key = `${req.method} ${url.pathname}`;
    hits[key] = (hits[key] ?? 0) + 1;
    seen.push({ url: req.url!, headers: req.headers });
    const reply = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (url.pathname === '/openai/v1/models') {
      if (listDelayMs) await sleep(listDelayMs);
      if (req.headers.authorization !== `Bearer ${REAL}`) return reply(401, { error: 'bad key' });
      return reply(200, { data: listed.map((id) => ({ id })) });
    }
    if (url.pathname === '/anth/v1/models') {
      if (req.headers['x-api-key'] !== REAL || req.headers['anthropic-version'] !== '2023-06-01') return reply(401, {});
      // Pages of two, to exercise has_more / last_id.
      const after = url.searchParams.get('after_id');
      const start = after ? ANTHROPIC_IDS.indexOf(after) + 1 : 0;
      const page = ANTHROPIC_IDS.slice(start, start + 2);
      return reply(200, { data: page.map((id) => ({ id })), has_more: start + 2 < ANTHROPIC_IDS.length, last_id: page.at(-1) });
    }
    // A broken provider that echoes the key it was given, to prove errors don't repeat it.
    if (url.pathname === '/leaky/models') return reply(500, { error: `bad request for ${req.headers.authorization}` });
    if (url.pathname === '/nolist/models') return reply(404, { error: 'not found' });
    if (url.pathname === '/portal/models') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<html>please sign in</html>'); }
    if (url.pathname === '/junk/models') return reply(200, { foo: 1 });
    if (url.pathname === '/array/models') return reply(200, [{ id: 'arr-a' }, { id: 'arr-b' }]);
    if (url.pathname.endsWith('/chat/completions')) return reply(200, { id: 'c', choices: [], usage: { prompt_tokens: 1, completion_tokens: 1 } });
    return reply(404, {});
  });
  await new Promise<void>((r) => mock.listen(0, '127.0.0.1', () => r()));
  servers.push(mock);
  upstream = `http://127.0.0.1:${(mock.address() as AddressInfo).port}`;

  const proxy = createProxyServer();
  await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', () => r()));
  servers.push(proxy);
  proxyPort = (proxy.address() as AddressInfo).port;
  vault.unlockVault(PASS);
});

after(() => {
  store.closeStore();
  for (const s of servers) s.close();
  fs.rmSync(home, { recursive: true, force: true });
});

async function api(method: string, p: string) {
  const cookie = await sessionCookie();
  return fetch(`http://127.0.0.1:${proxyPort}${p}`, { method, headers: { 'x-wickey': '1', cookie } })
    .then(async (r) => ({ status: r.status, body: await r.json() as any }));
}

/** Ages the cached list so the 60-second refresh throttle no longer applies. */
function ageCache(credentialId: string) {
  const d = new DatabaseSync(dbFile);
  d.prepare('UPDATE credential_models SET fetched_at = 0 WHERE credential_id = ?').run(credentialId);
  d.close();
}

let n = 0;
function setup(opts: { provider?: string; base?: string; limits?: Partial<Limits> | null } = {}) {
  const name = `cred-${++n}`;
  const credential = store.addCredential({ name, provider: opts.provider ?? 'custom', apiKey: REAL, baseUrl: `${upstream}${opts.base ?? '/openai/v1'}` });
  const { proxy, token } = store.issueProxy({ credential: name, ttlSeconds: 600, limits: opts.limits === undefined ? null : opts.limits });
  return { credential, name, id: proxy.id, token };
}

function chat(k: { id: string; token: string }, model: string | null, p = '/chat/completions') {
  const body = model === null ? undefined : JSON.stringify({ model, messages: [] });
  return fetch(`http://127.0.0.1:${proxyPort}/p/${k.id}${p}`, {
    method: body ? 'POST' : 'GET', headers: { authorization: `Bearer ${k.token}`, 'content-type': 'application/json' }, body,
  }).then(async (r) => ({ status: r.status, json: await r.json().catch(() => null) as any }));
}

const noModels = (l: Partial<Limits>): Limits => ({ models: null, rpm: null, tokenCap: null, refuseUncounted: true, ...l });

// ---- Fetching and caching ----

test('openai-style list is fetched with the real key, parsed and cached', async () => {
  listed = ['gpt-a', 'gpt-b'];
  const k = setup();
  const first = await api('GET', `/api/credentials/${k.name}/models`);
  assert.equal(first.status, 200);
  assert.deepEqual(first.body.models, ['gpt-a', 'gpt-b']);
  assert.equal(first.body.unavailable, false);
  assert.ok(first.body.fetchedAt > 0);
  const before = hitCount('GET /openai/v1/models');
  const again = await api('GET', `/api/credentials/${k.name}/models`);
  assert.deepEqual(again.body.models, ['gpt-a', 'gpt-b']);
  assert.equal(hitCount('GET /openai/v1/models'), before, 'second read comes from the cache');
  const forced = await api('POST', `/api/credentials/${k.name}/models/refresh`);
  assert.equal(forced.status, 200);
  assert.equal(hitCount('GET /openai/v1/models'), before + 1, 'refresh always asks the provider');
});

test('anthropic list is paginated with limit=1000 and the anthropic-version header', async () => {
  const k = setup({ provider: 'anthropic', base: '/anth' });
  seen.length = 0;
  const res = await api('GET', `/api/credentials/${k.name}/models`);
  assert.deepEqual(res.body.models, ANTHROPIC_IDS);
  assert.equal(seen.length, 3, 'three pages of two, two and one');
  assert.ok(seen.every((s) => s.url.includes('limit=1000') && s.headers['anthropic-version'] === '2023-06-01'));
  assert.ok(seen[1].url.includes('after_id=claude-2'));
});

test('the API key never appears in a model list error', async () => {
  const leaky = setup({ base: '/leaky' });
  const res = await api('GET', `/api/credentials/${leaky.name}/models`);
  assert.equal(res.status, 200);
  assert.equal(res.body.unavailable, false, 'a server error is a failure, not "no list"');
  assert.ok(res.body.error);
  assert.ok(!JSON.stringify(res.body).includes(REAL));
  // Unreachable server and a wrong key too.
  const dead = store.addCredential({ name: 'dead', provider: 'custom', apiKey: REAL, baseUrl: 'http://127.0.0.1:9/v1' });
  const r2 = await api('GET', `/api/credentials/${dead.name}/models`);
  assert.ok(r2.body.error && !JSON.stringify(r2.body).includes(REAL));
  assert.deepEqual(r2.body.models, []);
  assert.ok(!JSON.stringify(store.getModelCache(leaky.credential.id)).includes(REAL));
});

test('a 404 from /models marks the credential unavailable', async () => {
  const k = setup({ base: '/nolist' });
  const res = await api('GET', `/api/credentials/${k.name}/models`);
  assert.equal(res.body.unavailable, true);
  assert.deepEqual(res.body.models, []);
});

test('the list endpoints need the vault unlocked and a known credential', async () => {
  assert.equal((await api('GET', '/api/credentials/nope/models')).status, 404);
  const k = setup();
  vault.lockVault();
  try {
    const res = await api('GET', `/api/credentials/${k.name}/models`);
    assert.equal(res.status, 409);
    assert.match(res.body.error.message, /locked/);
  } finally {
    vault.unlockVault(PASS);
  }
});

test('editing or removing a credential drops its cached list', async () => {
  const k = setup();
  await api('GET', `/api/credentials/${k.name}/models`);
  assert.ok(store.getModelCache(k.credential.id));
  store.updateCredential(k.name, { name: `${k.name}-renamed` });
  assert.ok(store.getModelCache(k.credential.id), 'a rename keeps the list');
  store.updateCredential(`${k.name}-renamed`, { baseUrl: `${upstream}/alt/v1` });
  assert.equal(store.getModelCache(k.credential.id), null, 'a new base URL drops it');
  await api('GET', `/api/credentials/${k.name}-renamed/models`);
  store.updateCredential(`${k.name}-renamed`, { apiKey: REAL });
  assert.equal(store.getModelCache(k.credential.id), null, 'a new key drops it');
  await api('GET', `/api/credentials/${k.name}-renamed/models`);
  store.removeCredential(`${k.name}-renamed`);
  const d = new DatabaseSync(dbFile);
  assert.equal(d.prepare('SELECT COUNT(*) AS c FROM credential_models WHERE credential_id = ?').get(k.credential.id)!.c, 0);
  d.close();
});

// ---- The three modes, enforced ----

test('None refuses every request, including a bodiless GET /models, and forwards nothing', async () => {
  const k = setup({ limits: { models: [] } });
  const before = { chat: hitCount('POST /openai/v1/chat/completions'), models: hitCount('GET /openai/v1/models') };
  const a = await chat(k, 'gpt-a');
  assert.equal(a.status, 403);
  assert.match(a.json.error.message, /allows no models/);
  assert.equal((await chat(k, null, '/models')).status, 403);
  assert.equal(hitCount('POST /openai/v1/chat/completions'), before.chat);
  assert.equal(hitCount('GET /openai/v1/models'), before.models, 'nothing at all reached the provider');
});

test('Selected refuses a model the provider lists but the key did not select', async () => {
  listed = ['gpt-a', 'gpt-b'];
  const k = setup({ limits: { models: ['gpt-a'] } });
  await api('GET', `/api/credentials/${k.name}/models`);
  assert.equal((await chat(k, 'gpt-a')).status, 200);
  const res = await chat(k, 'gpt-b');
  assert.equal(res.status, 403);
  assert.match(res.json.error.message, /not allowed/);
});

test('All allows a listed model and refuses an unlisted one after exactly one refresh', async () => {
  listed = ['gpt-a', 'gpt-b'];
  const k = setup({ limits: noModels({}) });
  assert.equal((await chat(k, 'gpt-a')).status, 200, 'first use fetches the list');
  assert.equal(hitCount('GET /openai/v1/models') > 0, true);
  ageCache(k.credential.id);
  const before = hitCount('GET /openai/v1/models');
  const res = await chat(k, 'gpt-missing');
  assert.equal(res.status, 403);
  assert.match(res.json.error.message, /not on the provider's model list/);
  assert.match(res.json.error.message, /models .* --refresh/);
  assert.equal(hitCount('GET /openai/v1/models') - before, 1, 'one refresh, then refused');
});

test('All: a model the provider added since the last fetch is picked up by the refresh', async () => {
  listed = ['gpt-a'];
  const k = setup({ limits: noModels({}) });
  assert.equal((await chat(k, 'gpt-a')).status, 200);
  listed = ['gpt-a', 'gpt-new'];
  ageCache(k.credential.id);
  assert.equal((await chat(k, 'gpt-new')).status, 200);
});

test('All: unknown models inside the throttle window do not refetch', async () => {
  listed = ['gpt-a'];
  const k = setup({ limits: noModels({}) });
  await chat(k, 'gpt-a');
  ageCache(k.credential.id);
  await chat(k, 'gpt-x'); // refreshes
  const before = hitCount('GET /openai/v1/models');
  for (const m of ['gpt-y', 'gpt-z', 'gpt-x']) assert.equal((await chat(k, m)).status, 403);
  assert.equal(hitCount('GET /openai/v1/models'), before, 'no new fetch within 60 seconds');
});

test('All: concurrent requests for an unknown model share ONE upstream /models fetch', async () => {
  listed = ['gpt-a'];
  const k = setup({ limits: noModels({}) });
  await chat(k, 'gpt-a');
  ageCache(k.credential.id);
  listDelayMs = 150; // long enough that every request arrives while the first fetch is running
  try {
    const before = hitCount('GET /openai/v1/models');
    const results = await Promise.all(Array.from({ length: 8 }, () => chat(k, 'gpt-unknown')));
    assert.ok(results.every((r) => r.status === 403));
    assert.equal(hitCount('GET /openai/v1/models') - before, 1, 'one fetch for eight callers');
  } finally {
    listDelayMs = 0;
  }
});

test('All: the very first concurrent requests also share one initial fetch', async () => {
  listed = ['gpt-a'];
  listDelayMs = 150;
  try {
    const k = setup({ limits: noModels({}) });
    const before = hitCount('GET /openai/v1/models');
    const results = await Promise.all(Array.from({ length: 6 }, () => chat(k, 'gpt-a')));
    assert.ok(results.every((r) => r.status === 200));
    assert.equal(hitCount('GET /openai/v1/models') - before, 1);
  } finally {
    listDelayMs = 0;
  }
});

test('All: a failing list fetch refuses (fails closed) and says what to do', async () => {
  const k = setup({ base: '/leaky', limits: noModels({}) });
  const res = await chat(k, 'gpt-a');
  assert.equal(res.status, 403);
  assert.match(res.json.error.message, /Could not get the model list/);
  assert.ok(!JSON.stringify(res.json).includes(REAL));
});

test('All: a bodiless GET passes, a URL naming a model is refused, a body without a model is refused', async () => {
  listed = ['gpt-a'];
  const k = setup({ limits: noModels({}) });
  assert.equal((await chat(k, null, '/models')).status, 200, 'forwarded to the provider');
  assert.equal((await chat(k, null, '/models/gpt-a')).status, 403);
  for (const p of ['/engines/davinci/completions', '/model/anthropic.claude-v2/invoke', '/Engines/x/completions', '/%65ngines/x/completions', '/v1/model/x/invoke']) {
    assert.equal((await chat(k, 'gpt-a', p)).status, 403, p);
  }
  const sel = setup({ limits: { models: ['gpt-a'] } });
  assert.equal((await chat(sel, 'gpt-a', '/engines/davinci/completions')).status, 403);
  assert.equal((await chat(sel, 'gpt-a', '/model/x/invoke')).status, 403);
  const noModel = await fetch(`http://127.0.0.1:${proxyPort}/p/${k.id}/chat/completions`, {
    method: 'POST', headers: { authorization: `Bearer ${k.token}`, 'content-type': 'application/json' }, body: '{"messages":[]}',
  });
  assert.equal(noModel.status, 403);
});

test('All: a 200 that is not a model list (HTML, junk JSON) refuses and is never pass-through', async () => {
  for (const base of ['/portal', '/junk']) {
    const k = setup({ base, limits: noModels({}) });
    const res = await chat(k, 'arbitrary-model');
    assert.equal(res.status, 403, base);
    assert.match(res.json.error.message, /could not be read as a model list/, base);
    const list = await api('GET', `/api/credentials/${k.name}/models`);
    assert.equal(list.body.unavailable, false, base);
  }
});

test('a top-level array of models is accepted', async () => {
  const k = setup({ base: '/array', limits: noModels({}) });
  assert.equal((await chat(k, 'arr-a')).status, 200);
  assert.equal((await chat(k, 'arr-zzz')).status, 403);
});

test('forced refresh: 20 rapid calls reach the provider at most once per 10 seconds', async () => {
  listed = ['gpt-a'];
  const k = setup();
  const before = hitCount('GET /openai/v1/models');
  const results = await Promise.all(Array.from({ length: 20 }, () => api('POST', `/api/credentials/${k.name}/models/refresh`)));
  assert.ok(results.every((r) => r.status === 200));
  assert.equal(hitCount('GET /openai/v1/models') - before, 1);
  const again = await api('POST', `/api/credentials/${k.name}/models/refresh`);
  assert.equal(hitCount('GET /openai/v1/models') - before, 1);
  assert.ok(again.body.retryAfter > 0 && again.body.retryAfter <= 10);
  assert.deepEqual(again.body.models, ['gpt-a'], 'the cache is still returned');
});

test('All with a provider that has no model list passes models through, as before', async () => {
  const k = setup({ base: '/nolist', limits: noModels({}) });
  assert.equal((await chat(k, 'anything-goes')).status, 200);
  const selected = setup({ base: '/nolist', limits: { models: ['only-this'] } });
  assert.equal((await chat(selected, 'anything-goes')).status, 403, 'Selected still restricts');
});

// ---- Loosening ----

test('isLoosening ranks None < Selected < All', () => {
  const L = (m: string[] | null): Limits => ({ models: m, rpm: null, tokenCap: null, refuseUncounted: true });
  const loosens = (a: string[] | null, b: string[] | null) => store.isLoosening(L(a), L(b));
  assert.equal(loosens([], ['a']), true, 'None -> Selected');
  assert.equal(loosens([], null), true, 'None -> All');
  assert.equal(loosens(['a'], null), true, 'Selected -> All');
  assert.equal(loosens(['a'], ['a', 'b']), true, 'adding an ID');
  assert.equal(loosens(['a'], ['b']), true, 'swapping in a new ID');
  assert.equal(loosens(null, ['a']), false, 'All -> Selected');
  assert.equal(loosens(null, []), false, 'All -> None');
  assert.equal(loosens(['a'], []), false, 'Selected -> None');
  assert.equal(loosens(['a', 'b'], ['a']), false, 'removing an ID');
  assert.equal(loosens([], []), false);
  assert.equal(loosens(null, null), false);
  assert.equal(loosens(['a'], ['a']), false);
});

test('a malformed stored allowlist still fails closed to None', () => {
  const k = setup({ limits: { models: ['a'] } });
  const d = new DatabaseSync(dbFile);
  d.prepare('UPDATE proxies SET allowed_models = ? WHERE id = ?').run('{not json', k.id);
  d.close();
  // The row signature rejects the edit before limits are even read; either way nothing is forwarded.
  const result = store.authorize(k.id, k.token);
  assert.equal(result.ok, false);
});

// ---- CLI flag parsing ----

test('--models accepts all, none and a list, and rejects mixes', () => {
  assert.equal(models.parseModelsFlag('all'), null);
  assert.equal(models.parseModelsFlag(' ALL '), null);
  assert.deepEqual(models.parseModelsFlag('none'), []);
  assert.deepEqual(models.parseModelsFlag('a, b,c'), ['a', 'b', 'c']);
  assert.throws(() => models.parseModelsFlag('a,all'), /alone/);
  assert.throws(() => models.parseModelsFlag('none,a'), /alone/);
  assert.throws(() => models.parseModelsFlag(' , '), /needs/);
});
