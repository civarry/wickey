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
session.setUp('correct horse battery staple');

interface Received {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

const received: Received[] = [];
let upstreamAborted = 0;
let upstreamBase = '';
let proxyBase = '';
const servers: http.Server[] = [];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---- Mock provider: the x-mock request header picks a scenario ----

const CHAT = { id: 'c1', choices: [{ message: { role: 'assistant', content: 'hi' } }], usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } };
const RESPONSES = { id: 'r1', output: [], usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } };
const ANTHROPIC = { id: 'm1', type: 'message', content: [], usage: { input_tokens: 7, cache_creation_input_tokens: 2, cache_read_input_tokens: 1, output_tokens: 5 } };
const EMBED = { object: 'list', data: [], usage: { prompt_tokens: 8, total_tokens: 8 } };

const ev = (o: unknown, name?: string) => `${name ? `event: ${name}\n` : ''}data: ${JSON.stringify(o)}\n\n`;
const chatStream = (withUsage: boolean) =>
  ev({ choices: [{ delta: { content: 'a' } }], usage: null }) + ev({ choices: [{ delta: { content: 'b' } }], usage: null })
  + (withUsage ? ev({ choices: [], usage: CHAT.usage }) : '') + 'data: [DONE]\n\n';
const responsesStream =
  ev({ type: 'response.created', response: { usage: null } }, 'response.created') + ev({ type: 'response.output_text.delta', delta: 'x' }, 'response.output_text.delta')
  + ev({ type: 'response.completed', response: { usage: RESPONSES.usage } }, 'response.completed');
const anthropicStream =
  ev({ type: 'message_start', message: { usage: { input_tokens: 7, cache_creation_input_tokens: 2, cache_read_input_tokens: 1, output_tokens: 1 } } }, 'message_start')
  + ev({ type: 'content_block_delta', delta: { text: 'x' } }, 'content_block_delta')
  + ev({ type: 'message_delta', usage: { output_tokens: 3 } }, 'message_delta') + ev({ type: 'message_delta', usage: { output_tokens: 5 } }, 'message_delta')
  + ev({ type: 'message_stop' }, 'message_stop');

const json = (res: http.ServerResponse, body: unknown, headers: Record<string, string> = {}, status = 200) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};
const sse = async (res: http.ServerResponse, text: string, pieces = 0, headers: Record<string, string> = {}) => {
  res.writeHead(200, { 'content-type': 'text/event-stream', ...headers });
  if (!pieces) return void res.end(text);
  for (let i = 0; i < text.length; i += pieces) {
    res.write(text.slice(i, i + pieces));
    await sleep(2);
  }
  res.end();
};

type Scenario = (req: http.IncomingMessage, res: http.ServerResponse, body: Buffer) => void | Promise<void>;
const scenarios: Record<string, Scenario> = {
  chat: (_q, res) => json(res, CHAT),
  'chat-gzip': (_q, res) => json(res, zlib.gzipSync(JSON.stringify(CHAT)), { 'content-encoding': 'gzip' }),
  'chat-br': (_q, res) => json(res, zlib.brotliCompressSync(JSON.stringify(CHAT)), { 'content-encoding': 'br' }),
  'chat-weird-encoding': (_q, res) => json(res, JSON.stringify(CHAT), { 'content-encoding': 'compress' }),
  responses: (_q, res) => json(res, RESPONSES),
  anthropic: (_q, res) => json(res, ANTHROPIC),
  embeddings: (_q, res) => json(res, EMBED),
  models: (_q, res) => json(res, { data: [{ id: 'gpt-ok' }] }),
  nousage: (_q, res) => json(res, { id: 'x', choices: [] }),
  slow: async (_q, res) => { await sleep(120); json(res, CHAT); },
  // Behaves like OpenAI: the usage chunk only appears when include_usage was requested.
  'chat-stream': (_q, res, body) => sse(res, chatStream(JSON.parse(body.toString()).stream_options?.include_usage === true)),
  'chat-stream-gzip': async (_q, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'content-encoding': 'gzip' });
    const gz = zlib.createGzip();
    gz.on('data', (c) => res.write(c));
    const done = new Promise((r) => gz.on('end', r));
    for (const part of chatStream(true).match(/[\s\S]{1,40}/g)!) { gz.write(part); gz.flush(); await sleep(2); }
    gz.end();
    await done;
    res.end();
  },
  'chat-stream-split': (_q, res) => sse(res, chatStream(true).replace(/\n/g, '\r\n'), 7),
  'responses-stream': (_q, res) => sse(res, responsesStream, 11),
  'anthropic-stream': (_q, res) => sse(res, anthropicStream, 13),
  'stream-nousage': (_q, res) => sse(res, chatStream(false)),
  'stream-reject': (_q, res, body) => {
    if (JSON.parse(body.toString()).stream_options?.include_usage === true) {
      return json(res, { error: { message: 'Unrecognized request argument supplied: stream_options', type: 'invalid_request_error' } }, {}, 400);
    }
    return sse(res, chatStream(false));
  },
  // Usage only in the last event, after a delay; counts upstream sockets that die early.
  'late-usage': async (_q, res) => {
    res.on('close', () => { if (!res.writableFinished) upstreamAborted++; });
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(ev({ choices: [{ delta: { content: 'a' } }], usage: null }));
    await sleep(150);
    res.write(ev({ choices: [], usage: CHAT.usage }) + 'data: [DONE]\n\n');
    res.end();
  },
  'bad-request': (_q, res) => json(res, { error: { message: 'nope' } }, {}, 400),
};

before(async () => {
  const upstream = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      received.push({ method: req.method!, url: req.url!, headers: req.headers, body });
      const name = String(req.headers['x-mock'] ?? 'chat');
      Promise.resolve(scenarios[name](req, res, body)).catch(() => res.destroy());
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

let n = 0;
function key(opts: { provider?: string; authStyle?: 'bearer' | 'x-api-key'; limits?: Partial<import('../src/store.ts').Limits> } = {}) {
  const name = `cred-${++n}`;
  const credential = store.addCredential({
    name, provider: opts.provider ?? 'custom', apiKey: 'sk-REAL', baseUrl: upstreamBase, authStyle: opts.authStyle,
  });
  // These tests predate All-mode model checks: mark the mock provider as having no model list so keys pass through as before.
  store.putModelCache(credential.id, store.modelsEpoch(credential.id), { models: null, fetchedAt: Date.now(), error: 'test', unavailable: true });
  const { proxy, token } = store.issueProxy({ credential: name, ttlSeconds: 600, limits: opts.limits ?? null });
  return { credential, proxy, token, id: proxy.id };
}

interface Reply { status: number; headers: http.IncomingHttpHeaders; body: Buffer; text: string; json: any }

/** Raw client: no automatic decompression, so response bytes can be compared exactly. */
function call(k: { id: string; token: string }, opts: { method?: string; path?: string; body?: string | Buffer | object; mock?: string; anthropicAuth?: boolean } = {}): Promise<Reply> {
  const body = opts.body === undefined ? undefined : Buffer.isBuffer(opts.body) || typeof opts.body === 'string' ? Buffer.from(opts.body) : Buffer.from(JSON.stringify(opts.body));
  const headers: Record<string, string> = { 'x-mock': opts.mock ?? 'chat' };
  if (opts.anthropicAuth) headers['x-api-key'] = k.token;
  else headers.authorization = `Bearer ${k.token}`;
  if (body) { headers['content-type'] = 'application/json'; headers['content-length'] = String(body.length); }
  return new Promise((resolve, reject) => {
    const r = http.request(`${proxyBase}/p/${k.id}${opts.path ?? '/chat/completions'}`, { method: opts.method ?? (body ? 'POST' : 'GET'), headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        const text = buf.toString('utf8');
        let parsed: any = null;
        try { parsed = JSON.parse(text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode!, headers: res.headers, body: buf, text, json: parsed });
      });
    });
    r.on('error', reject);
    r.end(body);
  });
}

async function until(cond: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (cond()) return;
    await sleep(10);
  }
  assert.fail(`timed out waiting for ${what}`);
}

const totals = (id: string) => { const u = store.getUsage(id); return { in: u.tokensIn, out: u.tokensOut, requests: u.requests, uncounted: u.uncounted }; };
const noEmDash = (s: string) => assert.ok(!s.includes('—'), `no em dash in: ${s}`);
const chatBody = (extra: object = {}) => ({ model: 'gpt-ok', messages: [{ role: 'user', content: 'hi' }], ...extra });

// ---- Tests ----

test('unlimited key: request and response bytes pass through unchanged, usage is still recorded', async () => {
  const k = key();
  received.length = 0;
  // Odd spacing and a duplicate key: an unlimited key must not re-serialize anything.
  const raw = Buffer.from('{ "model" :"m-1",  "model":"m-2", "n": 12345678901234567890 }\n');
  const r = await call(k, { body: raw, mock: 'chat-gzip' });
  assert.equal(r.status, 200);
  assert.deepEqual(received[0].body, raw);
  assert.equal(r.headers['content-encoding'], 'gzip');
  assert.deepEqual(r.body, zlib.gzipSync(JSON.stringify(CHAT)), 'client got the compressed bytes untouched');
  await until(() => store.getUsage(k.id).requests === 1, 'passive usage');
  assert.deepEqual(totals(k.id), { in: 10, out: 5, requests: 1, uncounted: 0 });
  const [row] = store.recentRequests(k.id, 1);
  assert.equal(row.model, 'm-2');
  assert.equal(row.status, 200);
  assert.equal(row.tokensIn, 10);
  assert.equal(row.refusedReason, null);
});

test('unlimited key: streaming is not touched, include_usage is not injected, usage is read from the side copy', async () => {
  const k = key();
  received.length = 0;
  const body = JSON.stringify(chatBody({ stream: true }));
  const r = await call(k, { body, mock: 'chat-stream' });
  assert.equal(r.status, 200);
  assert.equal(received[0].body.toString(), body, 'body unchanged');
  assert.ok(!r.text.includes('"prompt_tokens"'), 'upstream sent no usage chunk because nobody asked');
  await until(() => store.getUsage(k.id).requests === 1, 'passive usage');
  assert.equal(totals(k.id).uncounted, 1, 'no usage found: uncounted');
  // The client's body is not ours, so a stream without usage must not teach the credential anything.
  assert.equal(store.getCredential(k.credential.id)!.streamUsage, null);
});

test('unlimited key: a stream the client reads still arrives with gzip and a Content-Length-less body', async () => {
  const k = key();
  const r = await call(k, { body: chatBody({ stream: true }), mock: 'chat-stream-gzip' });
  assert.equal(r.status, 200);
  assert.equal(zlib.gunzipSync(r.body).toString(), chatStream(true));
  await until(() => store.getUsage(k.id).requests === 1, 'passive usage');
  assert.deepEqual(totals(k.id), { in: 10, out: 5, requests: 1, uncounted: 0 });
});

test('allowlist: disallowed model is refused and never reaches upstream; allowed and bodiless GET pass', async () => {
  const k = key({ limits: { models: ['gpt-ok'] } });
  received.length = 0;
  const bad = await call(k, { body: chatBody({ model: 'gpt-evil' }) });
  assert.equal(bad.status, 403);
  assert.equal(bad.json.error.code, 'model_not_allowed');
  assert.match(bad.json.error.message, /^Wickey: Model "gpt-evil" is not allowed/);
  noEmDash(bad.json.error.message);
  assert.equal(received.length, 0, 'upstream received nothing');

  const ok = await call(k, { body: chatBody() });
  assert.equal(ok.status, 200);
  assert.equal(received.length, 1);

  const models = await call(k, { path: '/models', mock: 'models' });
  assert.equal(models.status, 200, models.text);
  assert.equal(received.length, 2);
  assert.equal(received[1].method, 'GET');

  // Case and prefix variants are different models: exact match only.
  assert.equal((await call(k, { body: chatBody({ model: 'GPT-OK' }) })).status, 403);
  assert.equal((await call(k, { body: chatBody({ model: 'gpt-ok-2' }) })).status, 403);
  assert.equal(received.length, 2);
});

test('allowlist: a model that cannot be determined is refused', async () => {
  const k = key({ limits: { models: ['gpt-ok'] } });
  received.length = 0;
  for (const body of ['{"messages":[]}', '{"model": 5}', '{"model": ["gpt-ok"]}']) {
    const r = await call(k, { body });
    assert.equal(r.status, 403, body);
    assert.equal(r.json.error.code, 'model_not_allowed');
  }
  // Bodies that aren't a JSON object are refused as invalid before any model is looked for.
  for (const body of ['not json', '["gpt-ok"]', 'null']) {
    const r = await call(k, { body });
    assert.equal(r.status, 400, body);
    assert.equal(r.json.error.code, 'invalid_body');
  }
  const noBody = await call(k, { method: 'POST', path: '/chat/completions' });
  assert.equal(noBody.status, 400, 'POST with no body');
  assert.equal((await call(k, { method: 'DELETE', path: '/models/x' })).status, 403, 'only GET may omit the model');
  assert.equal(received.length, 0);
});

test('allowlist: with duplicate "model" keys the upstream sees exactly the model that was checked', async () => {
  const k = key({ limits: { models: ['gpt-ok'] } });
  received.length = 0;
  const first = await call(k, { body: '{"model":"gpt-evil","model":"gpt-ok","x":1}' });
  assert.equal(first.status, 200);
  assert.equal(received[0].body.toString(), '{"model":"gpt-ok","x":1}');
  assert.equal(received[0].headers['content-length'], String(received[0].body.length));
  const second = await call(k, { body: '{"model":"gpt-ok","model":"gpt-evil"}' });
  assert.equal(second.status, 403);
  assert.equal(received.length, 1);
});

test('rate limit: the 4th request in the window gets 429 + Retry-After; refused requests do not count', async () => {
  const k = key({ limits: { rpm: 3, models: ['gpt-ok'] } });
  received.length = 0;
  for (let i = 0; i < 5; i++) assert.equal((await call(k, { body: chatBody({ model: 'gpt-evil' }) })).status, 403);
  for (let i = 0; i < 3; i++) assert.equal((await call(k, { body: chatBody() })).status, 200, `request ${i + 1}`);
  const limited = await call(k, { body: chatBody() });
  assert.equal(limited.status, 429);
  assert.equal(limited.json.error.code, 'rate_limit_exceeded');
  const retry = Number(limited.headers['retry-after']);
  assert.ok(retry >= 1 && retry <= 60, `retry-after ${retry}`);
  assert.match(limited.json.error.message, /3 requests per minute/);
  noEmDash(limited.json.error.message);
  assert.equal(received.length, 3, 'only the 3 allowed requests were forwarded');
  assert.equal(totals(k.id).requests, 3, 'refused requests are not usage');
  const log = store.recentRequests(k.id, 20);
  assert.equal(log.filter((l) => l.refusedReason === 'model_not_allowed').length, 5);
  assert.equal(log.filter((l) => l.refusedReason === 'rate_limit_exceeded').length, 1);
  assert.equal(log.filter((l) => l.refusedReason === null).length, 3);
});

test('token cap, non-streaming: totals are recorded, then 429 once the cap is reached', async () => {
  const cases = [
    { name: 'chat', path: '/chat/completions', mock: 'chat', anth: false, expect: { in: 10, out: 5 } },
    { name: 'responses', path: '/responses', mock: 'responses', anth: false, expect: { in: 10, out: 5 } },
    { name: 'anthropic', path: '/v1/messages', mock: 'anthropic', anth: true, expect: { in: 10, out: 5 } },
    { name: 'embeddings', path: '/embeddings', mock: 'embeddings', anth: false, expect: { in: 8, out: 0 } },
  ];
  for (const c of cases) {
    const k = key({ limits: { tokenCap: 20 }, provider: c.anth ? 'anthropic' : 'custom', authStyle: c.anth ? 'x-api-key' : undefined });
    received.length = 0;
    const opts = { path: c.path, mock: c.mock, body: chatBody(), anthropicAuth: c.anth };
    assert.equal((await call(k, opts)).status, 200, c.name);
    assert.deepEqual({ in: totals(k.id).in, out: totals(k.id).out }, c.expect, `${c.name} totals recorded before the next request`);
    const total = c.expect.in + c.expect.out;
    // Fill past the cap, then the next request is refused without reaching upstream.
    while (store.getUsage(k.id).tokensIn + store.getUsage(k.id).tokensOut < 20) assert.equal((await call(k, opts)).status, 200);
    const before = received.length;
    const r = await call(k, opts);
    assert.equal(r.status, 429, c.name);
    assert.equal(received.length, before, `${c.name}: refused before forwarding`);
    const message = c.anth ? r.json.error.message : r.json.error.message;
    assert.match(message, /Token cap reached: \d+ of 20 tokens used\. Raise the cap in the dashboard/);
    assert.ok(total > 0);
  }
});

test('token cap, streaming OpenAI chat: include_usage is injected for capped keys only and usage is counted', async () => {
  const k = key({ limits: { tokenCap: 100 } });
  received.length = 0;
  const r = await call(k, { body: chatBody({ stream: true, stream_options: { include_obfuscation: false, include_usage: false } }), mock: 'chat-stream' });
  assert.equal(r.status, 200);
  const sent = JSON.parse(received[0].body.toString());
  assert.deepEqual(sent.stream_options, { include_usage: true }, 'the client options are replaced, not merged');
  assert.equal(received[0].headers['content-length'], String(received[0].body.length));
  assert.deepEqual(totals(k.id), { in: 10, out: 5, requests: 1, uncounted: 0 });
  assert.equal(store.getCredential(k.credential.id)!.streamUsage, 'reports');
  assert.match(r.text, /"prompt_tokens":10/, 'the client still gets the stream it asked for');

  // Embeddings / non-chat streams and non-streaming requests are not modified.
  received.length = 0;
  await call(k, { body: chatBody() });
  assert.ok(!('stream_options' in JSON.parse(received[0].body.toString())));
});

test('token cap, streaming: Responses, Anthropic, events split across chunks, CRLF and gzip', async () => {
  const cases: [string, string, boolean, string][] = [
    ['responses', '/responses', false, 'responses-stream'],
    ['anthropic', '/v1/messages', true, 'anthropic-stream'],
    ['chat split + CRLF', '/chat/completions', false, 'chat-stream-split'],
    ['chat gzip', '/chat/completions', false, 'chat-stream-gzip'],
  ];
  for (const [name, p, anth, mock] of cases) {
    const k = key({ limits: { tokenCap: 100 }, provider: anth ? 'anthropic' : 'custom', authStyle: anth ? 'x-api-key' : undefined });
    const r = await call(k, { path: p, body: chatBody({ stream: true }), mock, anthropicAuth: anth });
    assert.equal(r.status, 200, name);
    assert.deepEqual(totals(k.id), { in: 10, out: 5, requests: 1, uncounted: 0 }, name);
  }
});

test('SseParser handles CRLF, CR, events split anywhere, and multi-line data', () => {
  const text = 'event: a\r\ndata: {"x":1}\r\n\r\ndata: one\ndata: two\n\ndata: {"y":2}\r\r';
  for (let size = 1; size <= text.length; size++) {
    const out: string[] = [];
    const p = new metering.SseParser((d: string) => out.push(d));
    for (let i = 0; i < text.length; i += size) p.write(text.slice(i, i + size));
    p.end();
    assert.deepEqual(out, ['{"x":1}', 'one\ntwo', '{"y":2}'], `chunk size ${size}`);
  }
});

test('response metering: brotli is decoded; an unsupported encoding means unknown, not a missing-usage flag', async () => {
  const k = key({ limits: { tokenCap: 100 } });
  assert.equal((await call(k, { body: chatBody(), mock: 'chat-br' })).status, 200);
  assert.deepEqual(totals(k.id), { in: 10, out: 5, requests: 1, uncounted: 0 });
  assert.equal((await call(k, { body: chatBody(), mock: 'chat-weird-encoding' })).status, 200);
  assert.equal(totals(k.id).uncounted, 1);
  assert.equal(store.getCredential(k.credential.id)!.usageReporting, 'reports', 'unreadable is not "missing"');
});

test('D1: upstream rejects stream_options. Without refuseUncounted the agent gets a 200 from one retry', async () => {
  const k = key({ limits: { tokenCap: 100, refuseUncounted: false } });
  received.length = 0;
  const r = await call(k, { body: chatBody({ stream: true, stream_options: { include_obfuscation: true } }), mock: 'stream-reject' });
  assert.equal(r.status, 200);
  assert.ok(!r.text.includes('stream_options'), 'the agent never sees the provider error');
  assert.equal(received.length, 2);
  assert.equal(JSON.parse(received[0].body.toString()).stream_options.include_usage, true);
  assert.equal(JSON.parse(received[1].body.toString()).stream_options, undefined, 'retry drops stream_options entirely');
  assert.equal(store.getCredential(k.credential.id)!.streamUsage, 'rejects_option');
  assert.deepEqual(totals(k.id), { in: 0, out: 0, requests: 1, uncounted: 1 });

  // Known now: the next stream goes out without the option on the first try.
  received.length = 0;
  assert.equal((await call(k, { body: chatBody({ stream: true }), mock: 'stream-reject' })).status, 200);
  assert.equal(received.length, 1);
  assert.ok(!received[0].body.toString().includes('stream_options'));
  assert.equal(store.getCredential(k.credential.id)!.streamUsage, 'rejects_option', 'not overwritten by "missing"');
});

test('D1: upstream rejects stream_options. With refuseUncounted the agent gets a clear 403 and there is no retry', async () => {
  const k = key({ limits: { tokenCap: 100, refuseUncounted: true } });
  received.length = 0;
  const r = await call(k, { body: chatBody({ stream: true }), mock: 'stream-reject' });
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, 'usage_uncountable');
  assert.ok(!r.text.includes('Unrecognized'), 'provider text is hidden');
  assert.match(r.json.error.message, /token cap cannot be enforced/);
  noEmDash(r.json.error.message);
  assert.equal(received.length, 1, 'no retry');
  assert.equal(store.getCredential(k.credential.id)!.streamUsage, 'rejects_option');
  assert.equal(totals(k.id).requests, 0, 'a refusal is not usage');
  // Next stream is refused before it is forwarded.
  const again = await call(k, { body: chatBody({ stream: true }), mock: 'stream-reject' });
  assert.equal(again.status, 403);
  assert.equal(received.length, 1);
  // Non-streaming still works on the same key.
  assert.equal((await call(k, { body: chatBody() })).status, 200);
});

test('D1: other upstream 400s (not about stream_options) reach the agent untouched', async () => {
  const k = key({ limits: { tokenCap: 100 } });
  const r = await call(k, { body: chatBody({ stream: true }), mock: 'bad-request' });
  assert.equal(r.status, 400);
  assert.equal(r.json.error.message, 'nope');
  assert.deepEqual(totals(k.id), { in: 0, out: 0, requests: 1, uncounted: 0 }, 'non-2xx counts with zero tokens');
});

test('D3: a 2xx with no usage is uncounted and marks the credential; refusing keys then block before forwarding', async () => {
  const strict = key({ limits: { tokenCap: 100, refuseUncounted: true } });
  received.length = 0;
  assert.equal((await call(strict, { body: chatBody(), mock: 'nousage' })).status, 200);
  assert.deepEqual(totals(strict.id), { in: 0, out: 0, requests: 1, uncounted: 1 });
  assert.equal(store.getCredential(strict.credential.id)!.usageReporting, 'missing');

  const r = await call(strict, { body: chatBody() });
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, 'usage_uncountable');
  assert.match(r.json.error.message, /cannot be counted/);
  noEmDash(r.json.error.message);
  assert.equal(received.length, 1, 'refused before forwarding');
  // Not a generation endpoint, so nothing to count: still allowed.
  assert.equal((await call(strict, { path: '/models', mock: 'models' })).status, 200);

  // A key that allows uncapped requests on the same credential goes through.
  const { proxy, token } = store.issueProxy({ credential: strict.credential.name, ttlSeconds: 600, limits: { tokenCap: 100, refuseUncounted: false } });
  assert.equal((await call({ id: proxy.id, token }, { body: chatBody(), mock: 'nousage' })).status, 200);
  assert.equal(store.getUsage(proxy.id).uncounted, 1);

  // Streams track their own flag.
  const s = key({ limits: { tokenCap: 100, refuseUncounted: true } });
  assert.equal((await call(s, { body: chatBody({ stream: true }), mock: 'stream-nousage' })).status, 200);
  assert.equal(store.getCredential(s.credential.id)!.streamUsage, 'missing');
  assert.equal((await call(s, { body: chatBody({ stream: true }), mock: 'stream-nousage' })).status, 403);
  assert.equal(store.getCredential(s.credential.id)!.usageReporting, null);
});

test('non-generation requests count with zero tokens; a client that hangs up mid-stream on an uncapped key is uncounted', async () => {
  const k = key({ limits: { rpm: 100 } });
  assert.equal((await call(k, { path: '/models', mock: 'models' })).status, 200);
  assert.deepEqual(totals(k.id), { in: 0, out: 0, requests: 1, uncounted: 0 });

  const abort = new Promise<void>((resolve) => {
    const r = http.request(`${proxyBase}/p/${k.id}/chat/completions`, {
      method: 'POST', headers: { authorization: `Bearer ${k.token}`, 'x-mock': 'chat-stream-split', 'content-type': 'application/json' },
    }, (res) => res.once('data', () => { r.destroy(); resolve(); }));
    r.on('error', () => {});
    r.end(JSON.stringify(chatBody({ stream: true })));
  });
  await abort;
  await until(() => store.getUsage(k.id).requests === 2, 'disconnect accounting');
  assert.deepEqual(totals(k.id), { in: 0, out: 0, requests: 2, uncounted: 1 });
});

test('D7: restoring an older, validly signed usage row while running gets the key refused', async () => {
  const k = key({ limits: { tokenCap: 1000 } });
  const other = key();
  const db = new DatabaseSync(path.join(home, 'wickey.db'));
  try {
    assert.equal((await call(k, { body: chatBody() })).status, 200);
    const old = db.prepare('SELECT * FROM proxy_usage WHERE proxy_id = ?').get(k.id) as Record<string, any>;
    assert.equal(old.tokens_in, 10);
    assert.equal((await call(k, { body: chatBody() })).status, 200);
    assert.equal(store.getUsage(k.id).tokensIn, 20);

    db.prepare('UPDATE proxy_usage SET requests = ?, tokens_in = ?, tokens_out = ?, uncounted = ?, last_used_at = ?, sig = ? WHERE proxy_id = ?')
      .run(old.requests, old.tokens_in, old.tokens_out, old.uncounted, old.last_used_at, old.sig, k.id);
    assert.equal(store.getUsage(k.id).ok, true, 'the restored row verifies; only the high-water mark can catch it');

    received.length = 0;
    const r = await call(k, { body: chatBody() });
    assert.equal(r.status, 403);
    assert.equal(r.json.error.code, 'usage_rollback');
    assert.match(r.json.error.message, /went backwards/);
    noEmDash(r.json.error.message);
    assert.equal(received.length, 0);
    assert.equal(metering.isRollbackFlagged(k.id), true);
    assert.equal(store.recentRequests(k.id, 1)[0].refusedReason, 'usage_rollback');

    // Sticky: even if the newer row comes back, the key stays flagged until restart.
    db.prepare('UPDATE proxy_usage SET tokens_in = 10 WHERE proxy_id = ?').run(k.id);
    assert.equal((await call(k, { body: chatBody() })).status, 403);

    // Unlimited keys are flagged but not refused (nothing to dodge).
    assert.equal((await call(other, { body: chatBody() })).status, 200);
    const o = db.prepare('SELECT * FROM proxy_usage WHERE proxy_id = ?').get(other.id) as Record<string, any>;
    assert.equal(o.requests, 1);
    assert.equal((await call(other, { body: chatBody() })).status, 200);
    db.prepare('UPDATE proxy_usage SET requests = ?, tokens_in = ?, tokens_out = ?, uncounted = ?, last_used_at = ?, sig = ? WHERE proxy_id = ?')
      .run(o.requests, o.tokens_in, o.tokens_out, o.uncounted, o.last_used_at, o.sig, other.id);
    assert.equal((await call(other, { body: chatBody() })).status, 200);
    assert.equal(metering.isRollbackFlagged(other.id), true);
  } finally {
    db.close();
  }
});

test('D7: totals edited outside wickey (bad signature) are refused', async () => {
  const k = key({ limits: { tokenCap: 1000 } });
  const db = new DatabaseSync(path.join(home, 'wickey.db'));
  try {
    db.prepare('UPDATE proxy_usage SET tokens_in = 5 WHERE proxy_id = ?').run(k.id);
    const r = await call(k, { body: chatBody() });
    assert.equal(r.status, 403);
    assert.equal(r.json.error.code, 'usage_rollback');
  } finally {
    db.close();
  }
});

test('D4: requests already in flight when the cap is reached finish, so a key can overshoot (bounded by their reservations)', async () => {
  const k = key({ limits: { tokenCap: 20 } });
  assert.equal((await call(k, { body: chatBody() })).status, 200);
  assert.equal(totals(k.id).in + totals(k.id).out, 15, 'one token-batch below the cap');
  const [a, b] = await Promise.all([
    call(k, { body: chatBody({ max_tokens: 2 }), mock: 'slow' }), call(k, { body: chatBody({ max_tokens: 2 }), mock: 'slow' }),
  ]);
  assert.equal(a.status, 200);
  assert.equal(b.status, 200);
  assert.equal(totals(k.id).in + totals(k.id).out, 45, 'overshoot: 45 of 20');
  assert.equal((await call(k, { body: chatBody() })).status, 429);
});

test('errors use the client format: Anthropic for anthropic credentials and /messages, OpenAI otherwise', async () => {
  const an = key({ provider: 'anthropic', authStyle: 'x-api-key', limits: { models: ['claude-ok'], tokenCap: 5 } });
  const denied = await call(an, { path: '/v1/messages', anthropicAuth: true, body: { model: 'claude-evil' } });
  assert.equal(denied.status, 403);
  assert.equal(denied.json.type, 'error');
  assert.equal(denied.json.error.type, 'permission_error');
  assert.match(denied.json.error.message, /^Wickey: /);
  noEmDash(denied.json.error.message);
  assert.equal((await call(an, { path: '/v1/messages', anthropicAuth: true, body: { model: 'claude-ok' }, mock: 'anthropic' })).status, 200);
  const capped = await call(an, { path: '/v1/messages', anthropicAuth: true, body: { model: 'claude-ok' }, mock: 'anthropic' });
  assert.equal(capped.status, 429);
  assert.equal(capped.json.error.type, 'rate_limit_error');
  assert.equal(capped.json.error.code, undefined);

  const rpm = key({ provider: 'anthropic', authStyle: 'x-api-key', limits: { rpm: 1 } });
  await call(rpm, { path: '/v1/messages', anthropicAuth: true, body: { model: 'x' }, mock: 'anthropic' });
  const slow = await call(rpm, { path: '/v1/messages', anthropicAuth: true, body: { model: 'x' }, mock: 'anthropic' });
  assert.equal(slow.status, 429);
  assert.equal(slow.json.error.type, 'rate_limit_error');
  assert.ok(slow.headers['retry-after']);

  // Path-based: a custom credential hitting /messages still gets Anthropic-shaped errors.
  const custom = key({ limits: { models: ['m'] } });
  const viaPath = await call(custom, { path: '/v1/messages', body: { model: 'other' } });
  assert.equal(viaPath.json.type, 'error');
  assert.equal(viaPath.json.error.type, 'permission_error');

  const oa = key({ limits: { models: ['m'] } });
  const oai = await call(oa, { body: { model: 'other' } });
  assert.equal(oai.json.type, undefined);
  assert.equal(oai.json.error.code, 'model_not_allowed');
  assert.equal(oai.json.error.type, 'invalid_request_error');
});

test('a body over 10 MB is refused with 413 for limited keys and never forwarded', async () => {
  const k = key({ limits: { rpm: 100 } });
  received.length = 0;
  const big = Buffer.from(JSON.stringify({ model: 'm', pad: 'x'.repeat(10 * 1024 * 1024 + 10) }));
  const r = await call(k, { body: big }).catch((e) => ({ status: 0, err: e }) as any);
  // The server may close the socket while the client is still sending; either way nothing is forwarded.
  assert.ok(r.status === 413 || r.status === 0, `status ${r.status}`);
  assert.equal(received.length, 0);
});

test('include_usage is only injected when a token cap is set (a models-only key forwards the stream as sent)', async () => {
  const k = key({ limits: { models: ['gpt-ok'] } });
  received.length = 0;
  const r = await call(k, { body: chatBody({ stream: true }), mock: 'chat-stream' });
  assert.equal(r.status, 200);
  assert.ok(!('stream_options' in JSON.parse(received[0].body.toString())));
});

function abortAfterFirstChunk(k: { id: string; token: string }): Promise<void> {
  return new Promise((resolve) => {
    const r = http.request(`${proxyBase}/p/${k.id}/chat/completions`, {
      method: 'POST', headers: { authorization: `Bearer ${k.token}`, 'x-mock': 'late-usage', 'content-type': 'application/json' },
    }, (res) => res.once('data', () => { r.destroy(); resolve(); }));
    r.on('error', () => {});
    r.end(JSON.stringify(chatBody({ stream: true })));
  });
}

test('disconnect bypass: a capped key that hangs up before the usage chunk is still counted', async () => {
  const k = key({ limits: { tokenCap: 15 } });
  upstreamAborted = 0;
  await abortAfterFirstChunk(k);
  await until(() => store.getUsage(k.id).requests === 1, 'background accounting');
  assert.deepEqual(totals(k.id), { in: 10, out: 5, requests: 1, uncounted: 0 });
  assert.equal(upstreamAborted, 0, 'upstream was left to finish');
  const r = await call(k, { body: chatBody() });
  assert.equal(r.status, 429);
  assert.equal(r.json.error.code, 'token_cap_reached');
});

test('an unlimited key that hangs up has its upstream request destroyed', async () => {
  const k = key();
  upstreamAborted = 0;
  await abortAfterFirstChunk(k);
  await until(() => upstreamAborted === 1, 'upstream destroyed');
});

test('unmetered endpoint: a capped refusing key may not use paths it cannot meter', async () => {
  const k = key({ limits: { tokenCap: 100, refuseUncounted: true } });
  received.length = 0;
  for (const [method, p] of [['POST', '/v1/images/generations'], ['DELETE', '/models/x'], ['POST', '/messages/count_tokens']]) {
    const r = await call(k, { method, path: p, body: method === 'POST' ? chatBody() : undefined });
    assert.equal(r.status, 403, `${method} ${p}`);
    assert.equal(r.json.error.code, 'usage_uncountable');
    assert.match(r.json.error.message, /isn't metered/);
    noEmDash(r.json.error.message);
  }
  assert.equal(received.length, 0);
  assert.equal((await call(k, { path: '/models', mock: 'models' })).status, 200);
  assert.equal(received.length, 1);

  const lax = key({ limits: { tokenCap: 100, refuseUncounted: false } });
  received.length = 0;
  assert.equal((await call(lax, { path: '/v1/images/generations', body: chatBody() })).status, 200);
  assert.equal(received.length, 1);
  assert.deepEqual(totals(lax.id), { in: 0, out: 0, requests: 1, uncounted: 1 });
});
