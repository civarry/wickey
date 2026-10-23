import { sessionCookie } from './helpers.ts';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import type http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, before, test } from 'node:test';

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-netguard-test-'));
const OWN_PORT = 47123;
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '0';
process.env.WICKEY_PORT = String(OWN_PORT);

const PASS = 'correct horse battery staple';
const REAL = 'sk-REAL-NETGUARD-KEY-98765';
const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const vault = await import('../src/vault.ts');
const models = await import('../src/models.ts');
const guard = await import('../src/netguard.ts');
session.setUp(PASS);

const dbFile = path.join(home, 'wickey.db');
let server: http.Server;
let port = 0;
let restoreResolver: (() => void) | null = null;

before(async () => {
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
  vault.unlockVault(PASS);
});

after(() => {
  restoreResolver?.();
  store.closeStore();
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
});

const scope = (url: string) => {
  const c = guard.classifyBaseUrl(url);
  return c.ok ? c.scope : `refused: ${c.reason}`;
};
const refused = (url: string) => assert.equal(guard.classifyBaseUrl(url).ok, false, `${url} should be refused`);

test('cloud metadata and link-local destinations are always refused, in every spelling', () => {
  for (const url of [
    'http://169.254.169.254/latest/meta-data', 'https://169.254.169.254/', 'http://169.254.0.1/',
    // WHATWG URL rewrites these to dotted form; the table proves we rely on that correctly.
    'http://2852039166/', 'http://0xA9FEA9FE/', 'http://0251.0376.0251.0376/', 'http://169.254.169.254./',
    'http://[::ffff:169.254.169.254]/', 'http://[::ffff:a9fe:a9fe]/', 'http://[fe80::1]/', 'https://[febf::1]/',
    'http://[fd00:ec2::254]/', 'http://100.100.100.200/',
    'http://0.0.0.0/', 'http://0.1.2.3:8080/', 'http://[::]/',
    'http://metadata/', 'http://metadata.google.internal/', 'https://METADATA.GOOGLE.INTERNAL/', 'http://metadata.google.internal./',
    'http://metadata.goog/', 'http://instance-data/', 'http://Instance-Data.EC2.Internal./',
  ]) refused(url);
});

test('the proxy cannot be pointed at itself, but other local ports are fine', () => {
  for (const url of [`http://127.0.0.1:${OWN_PORT}/v1`, `http://localhost:${OWN_PORT}`, `http://[::1]:${OWN_PORT}/`, `http://[::ffff:127.0.0.1]:${OWN_PORT}/`]) refused(url);
  assert.equal(scope(`http://127.0.0.1:${OWN_PORT + 1}/v1`), 'loopback');
  assert.equal(scope('http://localhost:11434/v1'), 'loopback');
  assert.equal(scope('http://localhost/v1'), 'loopback');
});

test('private ranges and local names stay allowed and are classified', () => {
  for (const url of ['http://10.0.0.5/v1', 'http://172.16.0.1/', 'http://172.31.255.1/', 'http://192.168.1.5:1234/v1', 'http://100.64.0.1/', 'http://100.127.0.1/', 'http://[fd12::1]/', 'http://[fc00::1]/', 'http://gpu-box/v1', 'http://box.local/v1', 'http://llm.corp.internal/v1']) {
    assert.equal(scope(url), 'private', url);
  }
  for (const url of ['http://127.0.0.1:9/v1', 'http://[::1]:9/v1']) assert.equal(scope(url), 'loopback', url);
  assert.equal(scope('http://172.32.0.1/').startsWith('refused'), true, '172.32 is public, so http is refused');
  assert.equal(scope('http://100.128.0.1/').startsWith('refused'), true);
});

test('public hosts need https, and only http(s) without userinfo is accepted', () => {
  assert.equal(scope('https://api.openai.com/v1'), 'public');
  assert.equal(scope('https://8.8.8.8/v1'), 'public');
  refused('http://api.openai.com/v1');
  refused('http://8.8.8.8/v1');
  refused('ftp://example.com/');
  refused('file:///etc/passwd');
  refused('https://user:pass@api.openai.com/v1');
  refused('https://user@api.openai.com/v1');
  refused('http://user:pass@127.0.0.1:9/v1');
});

test('refusals say what to do next and saving enforces the same rules', () => {
  const c = guard.classifyBaseUrl('http://169.254.169.254/');
  assert.ok(!c.ok && /Use the address of your real provider/.test(c.reason));
  const h = guard.classifyBaseUrl('http://api.example.com/');
  assert.ok(!h.ok && /Change it to https/.test(h.reason));
  for (const baseUrl of ['http://169.254.169.254/v1', 'http://api.example.com/v1', 'https://u:p@api.example.com/v1', `http://127.0.0.1:${OWN_PORT}/v1`]) {
    assert.throws(() => store.addCredential({ name: 'bad', provider: 'custom', apiKey: REAL, baseUrl }), /./, baseUrl);
  }
  assert.equal(store.getCredential('bad'), null);
  store.addCredential({ name: 'local', provider: 'custom', apiKey: REAL, baseUrl: 'http://192.168.1.5:11434/v1' });
  assert.throws(() => store.updateCredential('local', { baseUrl: 'http://metadata.google.internal/' }), /metadata/);
  assert.equal(store.getCredential('local')!.baseUrl, 'http://192.168.1.5:11434/v1', 'a refused edit changes nothing');
  store.removeCredential('local');
});

test('the API reports baseUrlScope so the dashboard can flag private addresses', async () => {
  store.addCredential({ name: 'lan', provider: 'custom', apiKey: REAL, baseUrl: 'http://192.168.1.5:11434/v1' });
  store.addCredential({ name: 'cloud', provider: 'custom', apiKey: REAL, baseUrl: 'https://api.example.com/v1' });
  const res = await fetch(`http://127.0.0.1:${port}/api/state`, { headers: { 'x-wickey': '1', cookie: await sessionCookie() } });
  const state = await res.json() as any;
  const byName = Object.fromEntries(state.credentials.map((c: any) => [c.name, c.baseUrlScope]));
  assert.equal(byName.lan, 'private');
  assert.equal(byName.cloud, 'public');
  store.removeCredential('lan');
  store.removeCredential('cloud');
});

// ---- connect time ----

type Answer = { address: string; family: 4 | 6 };
function stubDns(map: Record<string, Answer[]>) {
  restoreResolver?.();
  restoreResolver = guard.setResolverForTests((host, _opts, cb) => {
    const found = map[host];
    if (!found) return cb(Object.assign(new Error('nx'), { code: 'ENOTFOUND' }) as NodeJS.ErrnoException, []);
    cb(null, found);
  });
}
const call = (lookup: any, host: string, opts: object) =>
  new Promise<any[]>((resolve) => lookup(host, opts, (...args: any[]) => resolve(args)));

test('the lookup wrapper refuses metadata, link-local and unspecified answers in either callback shape', async () => {
  const lookup = guard.guardedLookup(443);
  for (const address of ['169.254.169.254', '169.254.1.1', 'fe80::1', 'fd00:ec2::254', '::ffff:169.254.169.254', '0.0.0.0', '::', '100.100.100.200']) {
    stubDns({ 'rebind.example.com': [{ address, family: address.includes(':') ? 6 : 4 }] });
    for (const opts of [{ all: true }, { all: false }, {}]) {
      const [err] = await call(lookup, 'rebind.example.com', opts);
      assert.ok(guard.isBlockedError(err), `${address} ${JSON.stringify(opts)} should be refused`);
      assert.match(err.message, /resolved to/);
    }
  }
});

test('one bad address among good ones refuses the whole answer', async () => {
  stubDns({ 'mixed.example.com': [{ address: '93.184.216.34', family: 4 }, { address: '169.254.169.254', family: 4 }] });
  const [err] = await call(guard.guardedLookup(443), 'mixed.example.com', { all: true });
  assert.ok(guard.isBlockedError(err));
});

test('the lookup wrapper passes good answers through with the shape Node asked for', async () => {
  stubDns({ 'ok.example.com': [{ address: '93.184.216.34', family: 4 }, { address: '2606:2800::1', family: 6 }], 'lan.example.com': [{ address: '10.1.2.3', family: 4 }], 'me.example.com': [{ address: '127.0.0.1', family: 4 }] });
  const lookup = guard.guardedLookup(443);
  const [e1, list] = await call(lookup, 'ok.example.com', { all: true });
  assert.equal(e1, null);
  assert.deepEqual(list.map((a: Answer) => a.address), ['93.184.216.34', '2606:2800::1']);
  const [e2, address, family] = await call(lookup, 'ok.example.com', {});
  assert.deepEqual([e2, address, family], [null, '93.184.216.34', 4]);
  const [e3] = await call(lookup, 'lan.example.com', { all: true });
  assert.equal(e3, null, 'private resolution is allowed');
  const [e4] = await call(lookup, 'me.example.com', { all: true });
  assert.equal(e4, null, 'loopback on another port is allowed');
  const [e5] = await call(guard.guardedLookup(OWN_PORT), 'me.example.com', { all: true });
  assert.ok(guard.isBlockedError(e5), 'loopback on the proxy port loops back into wickey');
  const [e6] = await call(lookup, 'nope.example.com', { all: true });
  assert.equal(e6.code, 'ENOTFOUND', 'resolver errors pass through');
});

test('forwarding refuses a public name that resolves to the metadata address, and never sends the key', async () => {
  stubDns({ 'rebind.example.com': [{ address: '169.254.169.254', family: 4 }] });
  store.addCredential({ name: 'rebind', provider: 'custom', apiKey: REAL, baseUrl: 'https://rebind.example.com/v1' });
  const { token, proxy } = store.issueProxy({ credential: 'rebind', ttlSeconds: 3600 });
  const res = await fetch(`http://127.0.0.1:${port}/p/${proxy.id}/chat/completions`, {
    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'x', messages: [] }), signal: AbortSignal.timeout(4000),
  });
  const text = await res.text();
  assert.equal(res.status, 403);
  assert.match(text, /resolved to 169\.254\.169\.254/);
  assert.ok(!text.includes(REAL));
});

test('the model list fetch is guarded the same way', async () => {
  stubDns({ 'rebind.example.com': [{ address: '169.254.169.254', family: 4 }] });
  const cred = store.getCredential('rebind')!;
  await assert.rejects(models.fetchModels(cred), (e: Error) => /resolved to 169\.254\.169\.254/.test(e.message) && !e.message.includes(REAL));
  const entry = await models.refreshModels(cred, true);
  assert.match(entry.error ?? '', /resolved to/);
});

test('rows saved before these rules are refused at use time with a fix-it message', async () => {
  const stored = (name: string, url: string) => {
    store.addCredential({ name, provider: 'custom', apiKey: REAL, baseUrl: 'https://placeholder.example.com/v1' });
    const id = store.getCredential(name)!.id;
    const d = new DatabaseSync(dbFile);
    d.prepare('UPDATE credentials SET base_url = ?, sig = ? WHERE id = ?').run(url, vault.sign(['credential', 'v1', id, 'custom', url, 'bearer'].join('|')), id);
    d.close();
    return store.issueProxy({ credential: name, ttlSeconds: 3600 });
  };
  const hit = async (issued: { token: string; proxy: { id: string } }) => {
    const res = await fetch(`http://127.0.0.1:${port}/p/${issued.proxy.id}/chat/completions`, {
      method: 'POST', headers: { authorization: `Bearer ${issued.token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'x', messages: [] }), signal: AbortSignal.timeout(4000),
    });
    return { status: res.status, text: await res.text() };
  };
  const meta = await hit(stored('old-meta', 'http://169.254.169.254/v1'));
  assert.equal(meta.status, 403);
  assert.match(meta.text, /metadata/);
  const plain = await hit(stored('old-http', 'http://api.example.com/v1'));
  assert.equal(plain.status, 403);
  assert.match(plain.text, /Change it to https/);
  assert.match(plain.text, /Edit the credential/);
  assert.ok(!meta.text.includes(REAL) && !plain.text.includes(REAL));
  await assert.rejects(models.fetchModels(store.getCredential('old-http')!), /https/);
});
