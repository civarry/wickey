import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';

// Isolate from the real ~/.wickey before anything opens them.
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';

const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
// Every test file starts from a fresh vault; a tiny scrypt cost keeps the suite fast.
session.setUp('correct horse battery staple');

interface Seen {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

let seen: Seen | null = null;
let upstreamBase = '';
let proxyBase = '';
const servers: http.Server[] = [];

function listen(server: http.Server): Promise<number> {
  servers.push(server);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
}

before(async () => {
  // Fake provider: records what it received, and streams SSE on /stream with gaps between events.
  const upstream = http.createServer((req, res) => {
    // No model list, so the default All-mode key passes models through.
    if (req.method === 'GET' && req.url?.endsWith('/models')) { res.writeHead(404); return res.end(); }
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen = { method: req.method!, url: req.url!, headers: req.headers, body };
      if (req.url?.endsWith('/stream')) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        let n = 0;
        const timer = setInterval(() => {
          res.write(`data: chunk-${n}\n\n`);
          if (++n === 3) {
            clearInterval(timer);
            res.end();
          }
        }, 150);
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  upstreamBase = `http://127.0.0.1:${await listen(upstream)}`;
  proxyBase = `http://127.0.0.1:${await listen(createProxyServer())}`;
});

after(() => {
  for (const c of store.listCredentials()) store.removeCredential(c.id);
  store.closeStore();
  for (const s of servers) s.close();
  fs.rmSync(home, { recursive: true, force: true });
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function call(proxyId: string, token: string, opts: { path?: string; header?: 'bearer' | 'x-api-key'; body?: string } = {}) {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (opts.header === 'x-api-key') headers['x-api-key'] = token;
  else headers.authorization = `Bearer ${token}`;
  return fetch(`${proxyBase}/p/${proxyId}${opts.path ?? '/chat/completions'}`, {
    method: 'POST',
    headers,
    body: opts.body ?? '{"model":"x"}',
  });
}

test('swaps the proxy token for the real key and forwards path, query and body', async () => {
  store.addCredential({ name: 'mock-openai', provider: 'custom', apiKey: 'sk-REAL-openai', baseUrl: `${upstreamBase}/v1` });
  const { proxy, token } = store.issueProxy({ credential: 'mock-openai', ttlSeconds: 60 });

  const res = await call(proxy.id, token, { path: '/chat/completions?x=1', body: '{"hello":"world"}' });
  assert.equal(res.status, 200);
  assert.equal(seen!.url, '/v1/chat/completions?x=1');
  assert.equal(seen!.body, '{"hello":"world"}');
  assert.equal(seen!.headers.authorization, 'Bearer sk-REAL-openai');
  assert.ok(!JSON.stringify(seen!.headers).includes(token), 'proxy token must not reach upstream');
});

test('anthropic-style credential sends x-api-key upstream, accepts the token via x-api-key', async () => {
  store.addCredential({
    name: 'mock-anthropic', provider: 'custom', apiKey: 'sk-ant-REAL', baseUrl: upstreamBase, authStyle: 'x-api-key',
  });
  const { proxy, token } = store.issueProxy({ credential: 'mock-anthropic', ttlSeconds: 60 });

  const res = await call(proxy.id, token, { path: '/v1/messages', header: 'x-api-key' });
  assert.equal(res.status, 200);
  assert.equal(seen!.url, '/v1/messages');
  assert.equal(seen!.headers['x-api-key'], 'sk-ant-REAL');
  assert.equal(seen!.headers.authorization, undefined);
});

test('token stops working once the TTL passes; renew brings back the same key, rotate replaces it', async () => {
  const { proxy, token } = store.issueProxy({ credential: 'mock-openai', ttlSeconds: 1 });
  assert.equal((await call(proxy.id, token)).status, 200);

  await sleep(1100);
  seen = null;
  const expired = await call(proxy.id, token);
  assert.equal(expired.status, 401);
  assert.match((await expired.json()).error.message, /expired/);
  assert.equal(seen, null, 'expired request must not reach upstream');
  assert.equal(store.getProxy(proxy.id)!.status, 'expired');

  // Renew: the exact same key works again, so nothing that uses it needs updating.
  const renewed = store.renewProxy(proxy.id, 60);
  assert.equal(renewed.id, proxy.id);
  assert.equal(renewed.status, 'active');
  assert.equal(renewed.maskedKey, `sk-wick-…${token.slice(-5)}`, 'renew keeps the key');
  assert.equal((await call(proxy.id, token)).status, 200, 'same key works after renew');

  // Rotate: new key at the same base URL; the old one dies immediately, even though the proxy is active.
  const rotated = store.rotateProxy(proxy.id);
  assert.equal(rotated.proxy.id, proxy.id);
  assert.notEqual(rotated.token, token);
  assert.equal((await call(proxy.id, rotated.token)).status, 200);
  assert.equal((await call(proxy.id, token)).status, 401, 'old key is dead after rotate');
});

test('expire now blocks immediately; wrong token and wrong proxy id are rejected', async () => {
  const a = store.issueProxy({ credential: 'mock-openai', ttlSeconds: 60 });
  const b = store.issueProxy({ credential: 'mock-openai', ttlSeconds: 60 });

  assert.equal((await call(a.proxy.id, b.token)).status, 401, "one proxy's token must not unlock another");
  assert.equal((await call(a.proxy.id, 'sk-wick-nope')).status, 401);
  assert.equal((await call('deadbeef', a.token)).status, 401);

  const expired = store.expireProxy(a.proxy.id);
  assert.equal(expired.status, 'expired');
  assert.equal((await call(a.proxy.id, a.token)).status, 401);
  assert.equal((await call(b.proxy.id, b.token)).status, 200, 'expiring one proxy leaves others working');
  // Renewing brings it back, same as a proxy whose timer ran out.
  store.renewProxy(a.proxy.id);
  assert.equal((await call(a.proxy.id, a.token)).status, 200);
});

test('streams SSE through without buffering', async () => {
  const { proxy, token } = store.issueProxy({ credential: 'mock-openai', ttlSeconds: 60 });
  const res = await call(proxy.id, token, { path: '/stream' });
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  const arrivals: number[] = [];
  let text = '';
  const start = Date.now();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    text += decoder.decode(value);
    arrivals.push(Date.now() - start);
  }
  assert.equal(text, 'data: chunk-0\n\ndata: chunk-1\n\ndata: chunk-2\n\n');
  assert.ok(arrivals.length >= 3, `expected chunks to arrive separately, got ${arrivals.length} read(s)`);
});

test('unreachable upstream returns a 502 that names the host and the reason', async () => {
  // "localhost" resolves to both ::1 and 127.0.0.1, so Node tries both and fails with an
  // AggregateError, whose own message is empty. The proxy must still say what went wrong.
  const dead = store.addCredential({ name: 'dead', provider: 'custom', apiKey: 'sk-dead', baseUrl: 'http://localhost:9/v1' });
  // This test is about forwarding errors, so mark the credential as having no model list (otherwise an All key would refuse first).
  store.putModelCache(dead.id, store.modelsEpoch(dead.id), { models: null, fetchedAt: Date.now(), error: 'test', unavailable: true });
  const { proxy, token } = store.issueProxy({ credential: 'dead', ttlSeconds: 60 });
  const res = await call(proxy.id, token, { path: '/models' });
  assert.equal(res.status, 502);
  const message = (await res.json()).error.message;
  assert.match(message, /Could not reach localhost:9/);
  assert.match(message, /ECONNREFUSED/);
  store.removeCredential('dead');
});

test('editing a credential keeps its proxies and their keys working, with the new settings', async () => {
  store.addCredential({ name: 'editme', provider: 'custom', apiKey: 'sk-OLD', baseUrl: `${upstreamBase}/old` });
  const { proxy, token } = store.issueProxy({ credential: 'editme', ttlSeconds: 60 });

  store.updateCredential('editme', { name: 'edited', baseUrl: `${upstreamBase}/new/`, apiKey: 'sk-NEW' });
  assert.equal(store.getCredential('editme'), null);
  assert.equal(store.getProxy(proxy.id)!.credentialName, 'edited');

  assert.equal((await call(proxy.id, token, { path: '/models' })).status, 200, 'same proxy key still works');
  assert.equal(seen!.url, '/new/models', 'new base URL is used (trailing slash trimmed)');
  assert.equal(seen!.headers.authorization, 'Bearer sk-NEW', 'replaced real key is sent upstream');

  // Omitted fields stay as they were, including the key.
  store.updateCredential('edited', { authStyle: 'x-api-key' });
  await call(proxy.id, token, { path: '/models' });
  assert.equal(seen!.headers['x-api-key'], 'sk-NEW');
  assert.equal(seen!.headers.authorization, undefined);
  store.removeCredential('edited');
});

test('mintEnvProxy (the `env` command) mints a new key per run and cleans up only expired ones', async () => {
  const first = store.mintEnvProxy({ label: 'zshrc', credential: 'mock-openai', ttlSeconds: 60 });
  const second = store.mintEnvProxy({ label: 'zshrc', credential: 'mock-openai', ttlSeconds: 60 });
  assert.notEqual(second.proxy.id, first.proxy.id, 'every terminal gets its own proxy');
  assert.notEqual(second.token, first.token, 'a key is never handed out twice');
  assert.equal((await call(first.proxy.id, first.token)).status, 200, 'other terminals keep working');
  assert.equal(store.listProxies().filter((p) => p.label === 'zshrc').length, 2);

  store.expireProxy(first.proxy.id);
  const third = store.mintEnvProxy({ label: 'zshrc', credential: 'mock-openai', ttlSeconds: 120 });
  assert.ok(store.getProxy(first.proxy.id)!.cleanedAt, 'the expired one is marked cleaned up, not revived or deleted');
  assert.ok(!store.listProxies().some((p) => p.id === first.proxy.id), 'and hidden from the default list');
  assert.ok(store.getProxy(second.proxy.id), 'the active one stays');
  assert.equal((await call(first.proxy.id, first.token)).status, 401, 'the old key stays dead');
  assert.equal((await call(third.proxy.id, third.token)).status, 200);
  assert.equal(third.proxy.ttlSeconds, 120);

  // A rejected request cleans nothing.
  store.expireProxy(second.proxy.id);
  assert.throws(() => store.mintEnvProxy({ label: 'zshrc', credential: 'mock-openai', ttlSeconds: 60, limits: { rpm: -1 } }));
  assert.equal(store.getProxy(second.proxy.id)!.cleanedAt, null, 'a failed mint does not clean up');
  for (const p of store.listProxies().filter((p) => p.label === 'zshrc')) store.deleteProxy(p.id);
});

test('removing a credential deletes its vault secret and proxies', async () => {
  store.addCredential({ name: 'temp', provider: 'custom', apiKey: 'sk-temp', baseUrl: upstreamBase });
  const { proxy, token } = store.issueProxy({ credential: 'temp', ttlSeconds: 60 });
  const cred = store.getCredential('temp')!;
  store.removeCredential('temp');
  assert.equal(store.getCredentialSecret(cred), null);
  assert.equal(store.getProxy(proxy.id), null);
  assert.equal((await call(proxy.id, token)).status, 401);
});
