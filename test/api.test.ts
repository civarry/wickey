import { sessionCookie } from './helpers.ts';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { checkHighWater, observeUsage } from '../src/metering.ts';

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-api-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
// A stand-in for the built dashboard (web/dist), so these tests don't depend on running the build.
const webDir = path.join(home, 'web-dist');
fs.mkdirSync(path.join(webDir, 'assets'), { recursive: true });
fs.writeFileSync(path.join(webDir, 'index.html'), '<!doctype html><title>wickey</title><script type="module" src="/assets/app-abc123.js"></script>');
fs.writeFileSync(path.join(webDir, 'assets', 'app-abc123.js'), 'console.log("app")');
fs.writeFileSync(path.join(webDir, 'assets', 'font-x1.woff2'), 'woff2');
fs.writeFileSync(path.join(webDir, 'assets', 'notes.txt'), 'not a served type');
// Decoys outside the build with servable extensions, so only the path rule can keep them out.
fs.writeFileSync(path.join(home, 'secret.js'), '{"secret":true}');
fs.writeFileSync(path.join(webDir, 'secret.css'), '{"secret":true}');
process.env.WICKEY_WEB_DIR = webDir;

const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
// Every test file starts from a fresh vault; a tiny scrypt cost keeps the suite fast.
session.setUp('correct horse battery staple');

let server: http.Server;
let port = 0;

before(async () => {
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});

after(() => {
  for (const c of store.listCredentials()) store.removeCredential(c.id);
  store.closeStore();
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
});

/** Raw request so tests can forge Host and Origin, which fetch() won't let us set. */
async function request(opts: { method?: string; path: string; headers?: Record<string, string>; body?: unknown }) {
  const cookie = await sessionCookie();
  return new Promise<{ status: number; body: any }>((resolve, reject) => {
    const payload = opts.body === undefined ? undefined : JSON.stringify(opts.body);
    const req = http.request({
      host: '127.0.0.1', port, method: opts.method ?? 'GET', path: opts.path,
      headers: {
        host: `127.0.0.1:${port}`,
        'x-wickey': '1',
        cookie,
        ...(payload ? { 'content-type': 'application/json' } : {}),
        ...opts.headers,
      },
    }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => {
        let body: any = text;
        try { body = JSON.parse(text); } catch {}
        resolve({ status: res.statusCode!, body });
      });
    });
    req.on('error', reject);
    req.end(payload);
  });
}

test('serves the dashboard on loopback hosts only', async () => {
  const ok = await request({ path: '/' });
  assert.equal(ok.status, 200);
  assert.match(ok.body, /<title>wickey<\/title>/);
  assert.equal((await request({ path: '/', headers: { host: `localhost:${port}` } })).status, 200);
  assert.equal((await request({ path: '/', headers: { host: 'evil.example:80' } })).status, 403);
});

test('the dashboard page carries a strict security policy: no inline scripts or styles', async () => {
  const res = await new Promise<http.IncomingMessage>((resolve) =>
    http.get({ host: '127.0.0.1', port, path: '/', headers: { host: `127.0.0.1:${port}` } }, resolve));
  res.resume();
  const csp = String(res.headers['content-security-policy']);
  assert.match(csp, /script-src 'self'(;|$)/);
  assert.match(csp, /style-src 'self'(;|$)/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  assert.match(csp, /frame-ancestors 'none'/);
});

test('built assets are served with the right types, and nothing else is reachable', async () => {
  const js = await new Promise<http.IncomingMessage>((resolve) =>
    http.get({ host: '127.0.0.1', port, path: '/assets/app-abc123.js', headers: { host: `127.0.0.1:${port}` } }, resolve));
  js.resume();
  assert.equal(js.statusCode, 200);
  assert.match(String(js.headers['content-type']), /^text\/javascript/);
  assert.equal(js.headers['x-content-type-options'], 'nosniff');
  assert.equal((await request({ path: '/assets/font-x1.woff2' })).status, 200);

  for (const p of [
    '/assets/../../secret.js', '/assets/..%2f..%2fsecret.js', '/assets/%2e%2e/%2e%2e/secret.js', '/assets/x/../../../secret.js',
    '/assets/../secret.css', '/assets/..%2fsecret.css', '/assets/%2e%2e%2fsecret.css',
    '/assets/notes.txt', '/assets/missing.js', '/assets/', '/secret.css', '/assets/.hidden.js',
  ]) {
    const res = await request({ path: p });
    assert.ok(res.status === 404, `${p} gave ${res.status}`);
    assert.ok(!String(res.body).includes('"secret":true'), `${p} leaked a file`);
  }
  assert.equal((await request({ path: '/assets/app-abc123.js', headers: { host: 'evil.example:80' } })).status, 403);
});

test('a missing build says how to fix it instead of serving a blank page', async () => {
  const saved = process.env.WICKEY_WEB_DIR;
  process.env.WICKEY_WEB_DIR = path.join(home, 'not-built');
  try {
    const res = await request({ path: '/' });
    assert.equal(res.status, 503);
    assert.match(String(res.body), /npm run build/);
  } finally {
    process.env.WICKEY_WEB_DIR = saved;
  }
});

test('API rejects DNS rebinding, cross-site origins and requests without the header', async () => {
  assert.equal((await request({ path: '/api/state' })).status, 200);
  assert.equal((await request({ path: '/api/state', headers: { host: `attacker.example:${port}` } })).status, 403);
  assert.equal((await request({ path: '/api/state', headers: { origin: 'https://attacker.example' } })).status, 403);
  assert.equal((await request({ path: '/api/state', headers: { 'x-wickey': '' } })).status, 403);
  assert.equal((await request({ path: '/api/state', headers: { origin: `http://127.0.0.1:${port}` } })).status, 200);

  // A cross-site form post can't set custom headers, so it must not be able to create anything.
  const forged = await request({
    method: 'POST', path: '/api/credentials', headers: { 'x-wickey': '', origin: 'null' },
    body: { name: 'x', provider: 'openai', apiKey: 'k' },
  });
  assert.equal(forged.status, 403);
  assert.equal(store.listCredentials().length, 0);
});

test('full lifecycle over the API: add, issue, expire, renew, rotate, delete, remove', async () => {
  const add = await request({
    method: 'POST', path: '/api/credentials',
    body: { name: 'mock', provider: 'custom', baseUrl: 'http://127.0.0.1:9/v1', apiKey: 'sk-REAL' },
  });
  assert.equal(add.status, 201);
  assert.ok(!JSON.stringify(add.body).includes('sk-REAL'), 'API must never echo the real key');

  const state = await request({ path: '/api/state' });
  assert.ok(!JSON.stringify(state.body).includes('sk-REAL'));
  assert.equal(state.body.credentials[0].name, 'mock');

  const issued = await request({ method: 'POST', path: '/api/proxies', body: { credential: 'mock', ttl: '90s', label: 'ui' } });
  assert.equal(issued.status, 201);
  assert.match(issued.body.token, /^sk-wick-/);
  assert.equal(issued.body.baseUrl, `http://127.0.0.1:${port}/p/${issued.body.proxy.id}`);
  assert.equal(issued.body.proxy.ttlSeconds, 90);
  const id = issued.body.proxy.id;

  // State carries only the masked key; the full key is shown once, in the issue response.
  const afterIssue = await request({ path: '/api/state' });
  const row = afterIssue.body.proxies.find((p: any) => p.id === id);
  assert.equal(row.maskedKey, `sk-wick-…${issued.body.token.slice(-5)}`);
  assert.ok(!JSON.stringify(afterIssue.body).includes(issued.body.token));

  // The dashboard's "Needs review" badge reads the in-memory rollback flag from state.
  assert.equal(afterIssue.body.proxies.find((p: any) => p.id === id).rollbackFlagged, false);
  observeUsage(id, { requests: 5, tokensIn: 5, tokensOut: 5, uncounted: 0 });
  assert.equal(checkHighWater(id, { requests: 1, tokensIn: 1, tokensOut: 1, uncounted: 0 }), true);
  assert.equal((await request({ path: '/api/state' })).body.proxies.find((p: any) => p.id === id).rollbackFlagged, true);

  assert.equal((await request({ method: 'POST', path: `/api/proxies/${id}/expire` })).body.proxy.status, 'expired');
  const renewed = await request({ method: 'POST', path: `/api/proxies/${id}/renew`, body: {} });
  assert.equal(renewed.body.proxy.status, 'active');
  assert.equal(renewed.body.proxy.ttlSeconds, 90, 'renew keeps the original TTL by default');
  assert.equal(renewed.body.token, undefined, 'renew keeps the key and has nothing to show');
  assert.equal(renewed.body.proxy.maskedKey, row.maskedKey);

  const rotated = await request({ method: 'POST', path: `/api/proxies/${id}/rotate`, body: { ttl: '5m' } });
  assert.equal(rotated.status, 200);
  assert.notEqual(rotated.body.token, issued.body.token, 'rotate replaces the key');
  assert.equal(rotated.body.proxy.ttlSeconds, 300);
  const afterRotate = await request({ path: '/api/state' });
  assert.equal(afterRotate.body.proxies.find((p: any) => p.id === id).maskedKey, `sk-wick-…${rotated.body.token.slice(-5)}`);

  assert.equal((await request({ method: 'DELETE', path: `/api/proxies/${id}` })).status, 200);
  assert.equal(store.getProxy(id), null);
  assert.equal((await request({ method: 'DELETE', path: '/api/credentials/mock' })).status, 200);
  assert.equal(store.listCredentials().length, 0);
});

test('API validation errors come back as messages', async () => {
  const badTtl = await request({ method: 'POST', path: '/api/proxies', body: { credential: 'nope', ttl: '5x' } });
  assert.equal(badTtl.status, 400);
  assert.match(badTtl.body.error.message, /Invalid TTL/);
  const noCustomUrl = await request({ method: 'POST', path: '/api/credentials', body: { name: 'c', provider: 'custom', apiKey: 'k' } });
  assert.match(noCustomUrl.body.error.message, /base URL/);

  const withEndpoint = await request({
    method: 'POST', path: '/api/credentials',
    body: { name: 'or', provider: 'custom', baseUrl: 'https://openrouter.ai/api/v1/chat/completions', apiKey: 'k' },
  });
  assert.equal(withEndpoint.status, 400);
  assert.match(withEndpoint.body.error.message, /Use https:\/\/openrouter\.ai\/api\/v1 instead/);
  assert.equal(store.listCredentials().length, 0);
});

test('PATCH edits a credential; blank key keeps the old one; bad edits are rejected', async () => {
  store.addCredential({ name: 'a', provider: 'custom', apiKey: 'sk-A', baseUrl: 'https://example.com/v1' });
  store.addCredential({ name: 'b', provider: 'custom', apiKey: 'sk-B', baseUrl: 'https://example.com/v1' });
  const a = store.getCredential('a')!;

  const ok = await request({
    method: 'PATCH', path: `/api/credentials/${a.id}`,
    body: { name: 'a2', baseUrl: 'https://openrouter.ai/api/v1', authStyle: 'bearer', apiKey: '' },
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.credential.name, 'a2');
  assert.equal(ok.body.credential.baseUrl, 'https://openrouter.ai/api/v1');
  assert.equal(store.getCredentialSecret(a), 'sk-A', 'blank key field keeps the current key');
  assert.ok(!JSON.stringify(ok.body).includes('sk-A'), 'API must never echo the real key');

  const endpoint = await request({ method: 'PATCH', path: `/api/credentials/a2`, body: { baseUrl: 'https://openrouter.ai/api/v1/chat/completions' } });
  assert.equal(endpoint.status, 400);
  assert.match(endpoint.body.error.message, /stop before the endpoint/);
  const taken = await request({ method: 'PATCH', path: `/api/credentials/a2`, body: { name: 'b' } });
  assert.match(taken.body.error.message, /already exists/);
  const badUrl = await request({ method: 'PATCH', path: `/api/credentials/a2`, body: { baseUrl: 'not a url' } });
  assert.match(badUrl.body.error.message, /not a valid URL/);
  assert.equal(store.getCredential('a2')!.baseUrl, 'https://openrouter.ai/api/v1', 'failed edits change nothing');

  store.removeCredential('a2');
  store.removeCredential('b');
});
