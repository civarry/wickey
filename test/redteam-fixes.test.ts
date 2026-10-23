import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import zlib from 'node:zlib';

// Isolate from the real ~/.wickey before anything opens them.
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';

const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const metering = await import('../src/metering.ts');
const vault = await import('../src/vault.ts');
session.setUp('correct horse battery staple');

const dbFile = path.join(home, 'wickey.db');
interface Received { method: string; url: string; headers: http.IncomingHttpHeaders; body: Buffer }
const received: Received[] = [];
let upstreamBase = '';
let proxyBase = '';
const servers: http.Server[] = [];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---- Mock provider: the x-mock request header picks a scenario ----

const CHAT = { id: 'c1', choices: [], usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } };
const BIG = { id: 'c2', choices: [], usage: { prompt_tokens: 100, completion_tokens: 100, total_tokens: 200 } };
const ev = (o: unknown) => `data: ${JSON.stringify(o)}\n\n`;
const stream = (withUsage: boolean) =>
  ev({ choices: [{ delta: { content: 'a' } }], usage: null }) + (withUsage ? ev({ choices: [], usage: CHAT.usage }) : '') + 'data: [DONE]\n\n';
const json = (res: http.ServerResponse, body: unknown, status = 200) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};
const sse = (res: http.ServerResponse, text: string) => {
  res.writeHead(200, { 'content-type': 'text/event-stream' });
  res.end(text);
};
const includeUsage = (body: Buffer) => JSON.parse(body.toString()).stream_options?.include_usage === true;

type Scenario = (req: http.IncomingMessage, res: http.ServerResponse, body: Buffer) => void | Promise<void>;
const scenarios: Record<string, Scenario> = {
  chat: (_q, res) => json(res, CHAT),
  models: (_q, res) => json(res, { data: [] }),
  big: async (_q, res) => { await sleep(100); json(res, BIG); },
  // Like OpenAI: any stream_options field other than include_usage is an error that names stream_options.
  'strict-stream': (_q, res, body) => {
    const so = JSON.parse(body.toString()).stream_options;
    if (so && Object.keys(so).some((k) => k !== 'include_usage')) {
      return json(res, { error: { message: `Unknown parameter: 'stream_options.${Object.keys(so)[0]}'.`, type: 'invalid_request_error' } }, 400);
    }
    sse(res, stream(includeUsage(body)));
  },
  'stream-nousage': (_q, res) => sse(res, stream(false)),
};

before(async () => {
  const upstream = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      received.push({ method: req.method!, url: req.url!, headers: req.headers, body });
      Promise.resolve(scenarios[String(req.headers['x-mock'] ?? 'chat')](req, res, body)).catch(() => res.destroy());
    });
  });
  upstreamBase = `http://127.0.0.1:${await listen(upstream)}`;
  proxyBase = `http://127.0.0.1:${await listen(createProxyServer())}`;
});

function listen(server: http.Server): Promise<number> {
  servers.push(server);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
}

after(() => {
  for (const c of store.listCredentials()) store.removeCredential(c.id);
  store.closeStore();
  for (const s of servers) s.close();
  fs.rmSync(home, { recursive: true, force: true });
});

// ---- Helpers ----

type Limits = import('../src/store.ts').Limits;
let n = 0;
function key(opts: { limits?: Partial<Limits>; baseUrl?: string; autoRenew?: object; ttl?: number } = {}) {
  const name = `cred-${++n}`;
  const credential = store.addCredential({ name, provider: 'custom', apiKey: 'sk-REAL', baseUrl: opts.baseUrl ?? upstreamBase });
  // These tests predate All-mode model checks: mark the mock provider as having no model list so keys pass through as before.
  store.putModelCache(credential.id, store.modelsEpoch(credential.id), { models: null, fetchedAt: Date.now(), error: 'test', unavailable: true });
  const { proxy, token } = store.issueProxy({ credential: name, ttlSeconds: opts.ttl ?? 600, limits: opts.limits ?? null, autoRenew: opts.autoRenew });
  return { credential, proxy, token, id: proxy.id };
}
/** Another proxy on an existing credential, to show one key can't affect its siblings. */
const sibling = (credentialName: string, limits: Partial<Limits>) => {
  const { proxy, token } = store.issueProxy({ credential: credentialName, ttlSeconds: 600, limits });
  return { id: proxy.id, token };
};

interface Reply { status: number; headers: http.IncomingHttpHeaders; text: string; json: any }
function call(k: { id: string; token: string }, opts: { method?: string; path?: string; body?: string | Buffer | object; mock?: string; headers?: Record<string, string> } = {}): Promise<Reply> {
  const body = opts.body === undefined ? undefined : Buffer.isBuffer(opts.body) || typeof opts.body === 'string' ? Buffer.from(opts.body) : Buffer.from(JSON.stringify(opts.body));
  const headers: Record<string, string> = { 'x-mock': opts.mock ?? 'chat', authorization: `Bearer ${k.token}`, ...opts.headers };
  if (body) { headers['content-type'] ??= 'application/json'; headers['content-length'] = String(body.length); }
  return new Promise((resolve, reject) => {
    const r = http.request(`${proxyBase}/p/${k.id}${opts.path ?? '/chat/completions'}`, { method: opts.method ?? (body ? 'POST' : 'GET'), headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed: any = null;
        try { parsed = JSON.parse(text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode!, headers: res.headers, text, json: parsed });
      });
    });
    r.on('error', reject);
    r.end(body);
  });
}
async function until(cond: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 300; i++) { if (cond()) return; await sleep(10); }
  assert.fail(`timed out waiting for ${what}`);
}
const used = (id: string) => { const u = store.getUsage(id); return u.tokensIn + u.tokensOut; };
const chatBody = (extra: object = {}) => ({ model: 'gpt-ok', messages: [{ role: 'user', content: 'hi' }], ...extra });
const rawRow = (id: string) => { const d = new DatabaseSync(dbFile); const r = d.prepare('SELECT * FROM proxies WHERE id = ?').get(id) as Record<string, any>; d.close(); return r; };
/** Puts an older copy of a proxies row back, as restoring a backup of the file would. */
function restoreRow(row: Record<string, any>) {
  const cols = Object.keys(row).filter((c) => c !== 'id');
  const d = new DatabaseSync(dbFile);
  d.prepare(`UPDATE proxies SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`).run(...cols.map((c) => row[c]), row.id);
  d.close();
}

// ---- B: capped keys forward only what the proxy parsed ----

test('B: UTF-16, non-UTF-8, non-object and empty bodies are refused on capped and allowlisted keys, never forwarded raw', async () => {
  for (const limits of [{ tokenCap: 1000 }, { tokenCap: 1000, refuseUncounted: false }, { models: ['gpt-ok'] }]) {
    const k = key({ limits });
    received.length = 0;
    const bad: [string, Buffer | string][] = [
      ['utf-16le', Buffer.from(JSON.stringify(chatBody({ stream: true })), 'utf16le')],
      ['utf-16le with BOM', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(JSON.stringify(chatBody()), 'utf16le')])],
      ['invalid utf-8', Buffer.concat([Buffer.from('{"model":"gpt-ok","x":"'), Buffer.from([0xff, 0xfe]), Buffer.from('"}')])],
      ['array', '[1]'], ['string', '"gpt-ok"'], ['null', 'null'], ['number', '5'], ['not json', 'model=gpt-ok'], ['empty', ''],
    ];
    for (const [what, body] of bad) {
      const r = await call(k, { method: 'POST', body });
      assert.equal(r.status, 400, `${what}: ${r.text}`);
      assert.equal(r.json.error.code, 'invalid_body', what);
      assert.ok(!r.json.error.message.includes('—'));
    }
    assert.equal(received.length, 0, 'nothing reached the upstream');
    assert.equal(store.recentRequests(k.id, 1)[0].refusedReason, 'invalid_body');
    assert.equal(used(k.id), 0);
  }
  const k = key({ limits: { tokenCap: 1000 } });
  const r = await call(k, { method: 'POST', body: '[1]', path: '/chat/completions', headers: { 'x-api-key': 'x' } });
  assert.equal(r.status, 400);
});

test('B: a BOM body is forwarded as exactly the re-serialized UTF-8 JSON, with a matching content-length and a JSON content-type', async () => {
  const k = key({ limits: { tokenCap: 1000 } });
  received.length = 0;
  const raw = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{ "model" : "m1", "model":"gpt-ok",  "n": 1 }')]);
  const r = await call(k, { body: raw, headers: { 'content-type': 'text/plain', 'content-encoding': 'identity' } });
  assert.equal(r.status, 200, r.text);
  assert.equal(received[0].body.toString('utf8'), '{"model":"gpt-ok","n":1}');
  assert.equal(received[0].headers['content-length'], String(received[0].body.length));
  assert.equal(received[0].headers['content-type'], 'application/json');
  assert.equal(received[0].headers['content-encoding'], undefined);
});

test('B: a truthy non-boolean "stream" is treated as streaming: forwarded as true, usage requested and counted', async () => {
  const k = key({ limits: { tokenCap: 1000 } });
  for (const value of [1, 'yes', 'false']) {
    received.length = 0;
    const r = await call(k, { body: `{"model":"gpt-ok","stream":${JSON.stringify(value)}}`, mock: 'strict-stream' });
    assert.equal(r.status, 200, r.text);
    const sent = JSON.parse(received[0].body.toString());
    assert.equal(sent.stream, true, `stream:${JSON.stringify(value)} normalized`);
    assert.deepEqual(sent.stream_options, { include_usage: true });
    assert.match(r.text, /prompt_tokens/, 'the provider streamed usage because the proxy asked for it');
  }
  await until(() => store.getUsage(k.id).requests === 3, 'accounting');
  assert.equal(used(k.id), 45);
  assert.equal(store.getUsage(k.id).uncounted, 0);
});

// ---- A: client stream_options can't poison the credential ----

test('A: client stream_options are replaced by exactly {include_usage:true}; the credential and its other keys are untouched', async () => {
  const k = key({ limits: { tokenCap: 100000 } });
  const other = sibling(k.credential.name, { tokenCap: 100000 });
  received.length = 0;
  const r = await call(k, { body: chatBody({ stream: true, stream_options: { bogus: 1, include_usage: false } }), mock: 'strict-stream' });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(JSON.parse(received[0].body.toString()).stream_options, { include_usage: true });
  await until(() => store.getUsage(k.id).requests === 1, 'accounting');
  const c = store.getCredential(k.credential.id)!;
  assert.notEqual(c.streamUsage, 'rejects_option');
  assert.notEqual(c.streamUsage, 'missing');
  assert.equal((await call(other, { body: chatBody({ stream: true }), mock: 'strict-stream' })).status, 200, 'sibling key still streams');
  // A non-object stream_options is dropped too.
  for (const so of [5, 'x', [1], null]) {
    received.length = 0;
    assert.equal((await call(k, { body: chatBody({ stream: true, stream_options: so }), mock: 'strict-stream' })).status, 200);
    assert.deepEqual(JSON.parse(received[0].body.toString()).stream_options, { include_usage: true });
  }
});

test('A: a stream to /completions gets include_usage too', async () => {
  const k = key({ limits: { tokenCap: 1000 } });
  received.length = 0;
  const r = await call(k, { path: '/completions', body: { model: 'gpt-ok', prompt: 'hi', stream: true }, mock: 'strict-stream' });
  assert.equal(r.status, 200);
  assert.deepEqual(JSON.parse(received[0].body.toString()).stream_options, { include_usage: true });
  await until(() => store.getUsage(k.id).requests === 1, 'accounting');
  assert.equal(used(k.id), 15, 'usage was reported and counted');
});

test('A: only our own option can mark rejects_option; an unlimited key streaming without usage cannot mark missing', async () => {
  // Unlimited key: the client's body is not ours, so an answer without usage says nothing about the provider.
  const u = key();
  await call(u, { body: chatBody({ stream: true }), mock: 'stream-nousage' });
  await until(() => store.getUsage(u.id).requests === 1, 'accounting');
  assert.equal(store.getCredential(u.credential.id)!.streamUsage, null);
  // Unlimited key sending a bad stream_options: error passes through, nothing is flagged.
  const bad = await call(u, { body: chatBody({ stream: true, stream_options: { bogus: 1 } }), mock: 'strict-stream' });
  assert.equal(bad.status, 400);
  assert.equal(store.getCredential(u.credential.id)!.streamUsage, null);
  // Capped key: the body is ours and the provider really returned no usage, so this is a real finding.
  const c = key({ limits: { tokenCap: 1000, refuseUncounted: false } });
  await call(c, { body: chatBody({ stream: true }), mock: 'stream-nousage' });
  await until(() => store.getUsage(c.id).requests === 1, 'accounting');
  assert.equal(store.getCredential(c.credential.id)!.streamUsage, 'missing');
});

test('A: flags heal when a later request does report usage', async () => {
  const u = key();
  for (const flag of ['missing', 'rejects_option'] as const) {
    store.setUsageReporting(u.credential.id, { streamUsage: flag });
    const r = await call(u, { body: chatBody({ stream: true, stream_options: { include_usage: true } }), mock: 'strict-stream' });
    assert.equal(r.status, 200);
    await until(() => store.getCredential(u.credential.id)!.streamUsage === 'reports', `heal from ${flag}`);
  }
  store.setUsageReporting(u.credential.id, { usage: 'missing' });
  assert.equal((await call(u, { body: chatBody() })).status, 200);
  await until(() => store.getCredential(u.credential.id)!.usageReporting === 'reports', 'non-stream heal');
});

// ---- C: a model in the URL path ----

test('C: with an allowlist, a model or deployment named in the path is refused; GET /models still works', async () => {
  const k = key({ limits: { models: ['gpt-ok'] } });
  received.length = 0;
  for (const p of [
    '/openai/deployments/evil/chat/completions', '/v1beta/models/evil:generateContent', '/openai/Deployments/evil/chat/completions',
    '/openai/%64eployments/evil/chat/completions', '/v1/models/evil', '/x/../openai/deployments/evil/chat/completions',
  ]) {
    const r = await call(k, { path: p, body: chatBody() });
    assert.equal(r.status, 403, p);
    assert.equal(r.json.error.code, 'model_not_allowed', p);
  }
  assert.equal(received.length, 0);
  assert.equal((await call(k, { path: '/models', mock: 'models' })).status, 200);
  assert.equal((await call(k, { body: chatBody() })).status, 200);
  // Without an allowlist the path is the client's business.
  const free = key({ limits: { tokenCap: 1000 } });
  assert.equal((await call(free, { path: '/openai/deployments/x/chat/completions', body: chatBody() })).status, 200);
});

// ---- D: bounded overshoot ----

test('D: at most 8 requests in flight per capped key; the 9th is refused and the slot frees afterwards', async () => {
  const k = key({ limits: { tokenCap: 1_000_000 } });
  const replies = await Promise.all(Array.from({ length: 9 }, () => call(k, { body: chatBody({ max_tokens: 10 }), mock: 'big' })));
  const refused = replies.filter((r) => r.status === 429);
  assert.equal(refused.length, 1);
  assert.equal(refused[0].json.error.code, 'rate_limit_exceeded');
  assert.equal(replies.filter((r) => r.status === 200).length, 8);
  await until(() => store.getUsage(k.id).requests === 8, 'accounting');
  assert.equal((await call(k, { body: chatBody({ max_tokens: 10 }), mock: 'big' })).status, 200, 'reservations were released');
});

test('D: 50 parallel slow requests against a cap of 1000 stay within the cap plus one bounded batch', async () => {
  const k = key({ limits: { tokenCap: 1000 } });
  const replies = await Promise.all(Array.from({ length: 50 }, () => call(k, { body: chatBody({ max_tokens: 100 }), mock: 'big' })));
  await until(() => store.getUsage(k.id).requests === replies.filter((r) => r.status === 200).length, 'accounting');
  assert.ok(replies.some((r) => r.status === 429));
  assert.ok(used(k.id) <= 1000 + 8 * 200, `counted ${used(k.id)}`);
  assert.equal(replies.filter((r) => r.status === 200).length * 200, used(k.id));
});

test('D: budget reserved by requests in flight refuses a new request with token_cap_reached', async () => {
  const k = key({ limits: { tokenCap: 1000 } });
  const first = call(k, { body: chatBody({ max_tokens: 700 }), mock: 'big' });
  await sleep(20);
  const second = call(k, { body: chatBody({ max_tokens: 700 }), mock: 'big' });
  await sleep(20);
  const third = await call(k, { body: chatBody({ max_tokens: 700 }), mock: 'big' });
  assert.equal(third.status, 429);
  assert.equal(third.json.error.code, 'token_cap_reached');
  assert.match(third.json.error.message, /reserved by requests in flight/);
  assert.ok(!third.json.error.message.includes('—'));
  assert.deepEqual((await Promise.all([first, second])).map((r) => r.status), [200, 200]);
  // max_completion_tokens and max_output_tokens reserve too; with none stated the default applies.
  assert.equal(metering.reservationFor({ max_completion_tokens: 50 }), 50);
  assert.equal(metering.reservationFor({ max_output_tokens: 60 }), 60);
  assert.equal(metering.reservationFor({}), metering.DEFAULT_RESERVATION);
  assert.equal(metering.reservationFor({ max_tokens: 'x' }), metering.DEFAULT_RESERVATION);
});

// ---- E / F: older rows and unsigned ttl ----

test('E: an older signed proxies row put back while running is refused with usage_rollback; legitimate edits still work', async () => {
  const k = key({ limits: { tokenCap: 100000 } });
  assert.equal((await call(k, { body: chatBody() })).status, 200);
  const tight = rawRow(k.id);
  store.setLimits(k.id, { tokenCap: 500000, models: ['gpt-ok'] });
  assert.equal((await call(k, { body: chatBody() })).status, 200, 'a legitimate limit edit works');
  restoreRow(tight);
  received.length = 0;
  const r = await call(k, { body: chatBody() });
  assert.equal(r.status, 403, r.text);
  assert.equal(r.json.error.code, 'usage_rollback');
  assert.equal(received.length, 0);
  assert.equal(metering.isRollbackFlagged(k.id), true, 'the dashboard shows it as needing review');
  assert.equal(store.renewIfDue(k.id, 0), null);
});

test('E: restoring a row from before "expire now" does not revive the key (unlimited key too)', async () => {
  const k = key();
  assert.equal((await call(k, { body: chatBody() })).status, 200);
  const live = rawRow(k.id);
  store.expireProxy(k.id);
  assert.equal((await call(k, { body: chatBody() })).status, 401);
  restoreRow(live);
  const r = await call(k, { body: chatBody() });
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, 'usage_rollback');
});

test('E: expire, renew, rotate and limit edits keep working through any number of writes', async () => {
  const k = key({ limits: { tokenCap: 100000 } });
  let token = k.token;
  for (let i = 0; i < 3; i++) {
    store.setLimits(k.id, { tokenCap: 100000 + i });
    store.expireProxy(k.id);
    assert.equal((await call({ id: k.id, token }, { body: chatBody() })).status, 401);
    store.renewProxy(k.id);
    token = store.rotateProxy(k.id).token;
    assert.equal((await call({ id: k.id, token }, { body: chatBody() })).status, 200);
  }
  assert.ok(rawRow(k.id).version >= 10);
});

test('F: ttl_seconds is signed once a row has been written, so editing it breaks the signature', () => {
  const k = key({ ttl: 600 });
  assert.ok(rawRow(k.id).version > 0);
  assert.equal(store.authorize(k.id, k.token).ok, true);
  const d = new DatabaseSync(dbFile);
  d.prepare('UPDATE proxies SET ttl_seconds = 99999999 WHERE id = ?').run(k.id);
  d.close();
  const r = store.authorize(k.id, k.token);
  assert.equal(r.ok, false);
  assert.match((r as any).message, /integrity check/);
  // And so does zeroing the version to strip the segment.
  const d2 = new DatabaseSync(dbFile);
  d2.prepare('UPDATE proxies SET ttl_seconds = 600, version = 0 WHERE id = ?').run(k.id);
  d2.close();
  assert.equal(store.authorize(k.id, k.token).ok, false);
});

// ---- G: only an upstream response renews ----

/** Moves a key's expiry into its renew window and re-signs, as the passphrase holder could. Mirrors proxySigData. */
function intoWindow(id: string) {
  const d = new DatabaseSync(dbFile);
  d.prepare('UPDATE proxies SET expires_at = ? WHERE id = ?').run(Date.now() + 5 * 60_000, id);
  const r = d.prepare('SELECT * FROM proxies WHERE id = ?').get(id) as Record<string, any>;
  const f = (v: unknown) => (v == null ? '' : String(v));
  const data = ['proxy', 'v1', r.id, r.credential_id, r.token_hash, r.expires_at, r.revoked_at ?? '',
    'limits-v2', f(r.allowed_models), f(r.rpm), f(r.token_cap), r.refuse_uncounted === 0 ? 0 : 1, f(r.renew_window_s), f(r.max_expires_at),
    ...(r.version > 0 ? ['version-v1', r.version, r.ttl_seconds] : [])].join('|');
  d.prepare('UPDATE proxies SET sig = ? WHERE id = ?').run(vault.sign(data), id);
  d.close();
}

test('G: an unreachable upstream (502) does not renew a key in its window; a real response does', async () => {
  const closed = http.createServer();
  const deadPort = await listen(closed);
  await new Promise((r) => closed.close(r));
  const autoRenew = { windowSeconds: 600, maxLifetime: '2d' };
  const dead = key({ baseUrl: `http://127.0.0.1:${deadPort}`, autoRenew, ttl: 3600 });
  const live = key({ autoRenew, ttl: 3600 });
  intoWindow(dead.id);
  intoWindow(live.id);
  const before = store.getProxy(dead.id)!.expiresAt;
  const r = await call(dead, { body: chatBody() });
  assert.equal(r.status, 502);
  await until(() => store.getUsage(dead.id).requests === 1, 'accounting');
  assert.equal(store.getProxy(dead.id)!.expiresAt, before, 'not renewed');
  assert.equal(store.recentRequests(dead.id, 20).filter((e) => e.event === 'renewed').length, 0);

  const liveBefore = store.getProxy(live.id)!.expiresAt;
  assert.equal((await call(live, { body: chatBody() })).status, 200);
  await until(() => store.getProxy(live.id)!.expiresAt > liveBefore, 'control: a real response renews');
});

// ---- H: encodings the meter can read ----

test('H: a capped key asks the upstream only for encodings the meter can decode; unlimited keys pass the client header through', async () => {
  const expected = ['gzip', 'deflate', 'br', ...(typeof (zlib as any).createZstdDecompress === 'function' ? ['zstd'] : [])].join(', ');
  const k = key({ limits: { tokenCap: 1000 } });
  received.length = 0;
  assert.equal((await call(k, { body: chatBody(), headers: { 'accept-encoding': 'identity, compress, sdch' } })).status, 200);
  assert.equal(received[0].headers['accept-encoding'], expected);
  assert.equal((await call(k, { body: chatBody() })).status, 200, 'also when the client sent none');
  assert.equal(received[1].headers['accept-encoding'], expected);
  const u = key();
  received.length = 0;
  await call(u, { body: chatBody(), headers: { 'accept-encoding': 'compress' } });
  assert.equal(received[0].headers['accept-encoding'], 'compress');
});

// ---- Log retention ----

test('log: refused requests cannot push out forwarded rows or renewal events', async () => {
  const k = key({ limits: { tokenCap: 100000 } });
  for (let i = 0; i < 4; i++) assert.equal((await call(k, { body: chatBody() })).status, 200);
  const d = new DatabaseSync(dbFile);
  d.prepare("INSERT INTO requests (proxy_id, at, status, duration_ms, event, renewed_to) VALUES (?, ?, 200, 0, 'renewed', ?)").run(k.id, Date.now(), Date.now() + 1000);
  d.close();
  await until(() => store.getUsage(k.id).requests === 4, 'accounting');
  for (let i = 0; i < 600; i++) store.logRequest({ proxyId: k.id, at: Date.now(), status: 429, durationMs: 0, refusedReason: 'rate_limit_exceeded' });
  assert.equal((await call(k, { body: [1] as any })).status, 400, 'a refusal through the proxy is logged the same way');
  const count = (where: string) => {
    const c = new DatabaseSync(dbFile);
    const r = (c.prepare(`SELECT COUNT(*) AS n FROM requests WHERE proxy_id = ? AND ${where}`).get(k.id) as any).n;
    c.close();
    return r;
  };
  assert.equal(count('refused_reason IS NULL AND event IS NULL'), 4, 'forwarded rows kept');
  assert.equal(count("event = 'renewed'"), 1, 'renewal event kept');
  assert.equal(count('refused_reason IS NOT NULL'), 200, 'refused rows are capped at 200');
  // Forwarded rows are still capped at 500 (the renewal event counts toward them).
  for (let i = 0; i < 520; i++) store.logRequest({ proxyId: k.id, at: Date.now(), status: 200, durationMs: 0 });
  assert.equal(count('refused_reason IS NULL'), 500);
  assert.equal(count('refused_reason IS NOT NULL'), 200);
});
