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

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-import-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';

const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const PASS = 'correct horse battery staple';
session.setUp(PASS);

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

async function post(body: unknown) {
  const cookie = await sessionCookie();
  return new Promise<{ status: number; text: string; body: any }>((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request({
      host: '127.0.0.1', port, method: 'POST', path: '/api/credentials/import',
      headers: { host: `127.0.0.1:${port}`, 'x-wickey': '1', cookie, 'content-type': 'application/json' },
    }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => resolve({ status: res.statusCode!, text, body: JSON.parse(text) }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

const KEY_A = 'sk-proj-AAAAsecretAAAA1111';
const KEY_B = 'sk-ant-BBBBsecretBBBB2222';
const KEY_C = 'sk-or-CCCCsecretCCCC3333';
const KEY_D = 'sk-proj-DDDDsecretDDDD4444';
const entry = (name: string, apiKey: string, extra: object = {}) => ({ name, provider: 'openai', apiKey, ...extra });

test('both dry run and import need the passphrase once the grace period is over', async () => {
  session.endGrace();
  for (const dryRun of [true, false]) {
    const res = await post({ entries: [entry('needs-auth', KEY_A)], dryRun });
    assert.equal(res.status, 401, `dryRun=${dryRun}`);
    assert.equal(res.body.error.code, 'passphrase_required');
    assert.ok(!res.text.includes(KEY_A));
  }
  assert.equal(store.getCredential('needs-auth'), null);
  const bad = await post({ entries: [entry('needs-auth', KEY_A)], dryRun: true, passphrase: 'not the passphrase' });
  assert.equal(bad.status, 401);
  assert.equal(bad.body.error.code, 'wrong_passphrase');
});

test('dry run reports what would happen and stores nothing', async () => {
  const res = await post({ entries: [entry('d1', KEY_A), { name: 'd2', provider: 'anthropic', apiKey: KEY_B }], dryRun: true, passphrase: PASS });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.results.map((r: any) => [r.name, r.outcome, r.baseUrlScope]), [['d1', 'would_import', 'public'], ['d2', 'would_import', 'public']]);
  assert.equal(store.listCredentials().length, 0);
});

test('import stores each entry, signed, with no proxy keys issued', async () => {
  const res = await post({ entries: [entry('i1', KEY_A), { name: 'i2', provider: 'anthropic', apiKey: KEY_B }], dryRun: false, passphrase: PASS });
  assert.deepEqual(res.body.results.map((r: any) => r.outcome), ['imported', 'imported']);
  const stored = store.getCredential('i2')!;
  assert.equal(stored.authStyle, 'x-api-key');
  assert.equal(store.getCredentialSecret(stored), KEY_B);
  assert.equal(store.listProxies().length, 0);
  // A signed row is what the proxy trusts; list drops rows whose signature fails.
  assert.equal(store.listCredentials().length, 2);
});

test('duplicates: same key under another name, same name, and repeats inside one batch', async () => {
  const res = await post({
    entries: [entry('other-name', KEY_A), entry('i1', KEY_C), entry('new1', KEY_C), entry('new1', 'sk-or-DIFFERENTkey9999'), entry('new2', KEY_C)],
    dryRun: false, passphrase: PASS,
  });
  const out = res.body.results.map((r: any) => r.outcome);
  assert.deepEqual(out, ['duplicate_key', 'duplicate_name', 'imported', 'duplicate_name', 'duplicate_key']);
  assert.match(res.body.results[0].message, /"i1"/);
  assert.match(res.body.results[4].message, /"new1"/);
  assert.ok(!res.text.includes(KEY_A) && !res.text.includes(KEY_C), 'no response contains a key');
  assert.equal(store.getCredential('other-name'), null);
});

test('invalid entries are reported without stopping the rest, and without echoing keys', async () => {
  const res = await post({
    entries: [
      entry('meta', KEY_B, { baseUrl: 'http://169.254.169.254/latest' }),
      entry('bad name!', KEY_B),
      { name: 'noprov', provider: 'nope', apiKey: KEY_B },
      entry('nokey', ''),
      entry('echo', KEY_D, { baseUrl: `not a url ${KEY_D}` }),
      entry('badauth', KEY_B, { authStyle: 'basic' }),
      'not an object',
      entry('fine', 'sk-proj-ZZZZsecretZZZZ9999'),
    ],
    dryRun: false, passphrase: PASS,
  });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.results.map((r: any) => r.outcome), ['invalid', 'invalid', 'invalid', 'invalid', 'invalid', 'invalid', 'invalid', 'imported']);
  assert.match(res.body.results[0].message, /169\.254\.169\.254/);
  assert.match(res.body.results[4].message, /not a valid URL/);
  assert.ok(!res.text.includes(KEY_B) && !res.text.includes(KEY_D), 'error messages never contain the key');
  assert.ok(store.getCredential('fine'));
  assert.equal(store.getCredential('meta'), null);
});

test('private base URLs import with their scope so the dashboard can flag them', async () => {
  const res = await post({ entries: [entry('lan', 'sk-lan-key-0001', { provider: 'custom', baseUrl: 'http://10.0.0.5:8080/v1' })], dryRun: true, passphrase: PASS });
  assert.deepEqual([res.body.results[0].outcome, res.body.results[0].baseUrlScope], ['would_import', 'private']);
});

test('bad bodies and oversized batches are rejected', async () => {
  assert.equal((await post({ dryRun: true, passphrase: PASS })).status, 400);
  assert.equal((await post({ entries: [], dryRun: true, passphrase: PASS })).status, 400);
  assert.equal((await post({ entries: [entry('x', KEY_A)], passphrase: PASS })).status, 400);
  const many = Array.from({ length: 51 }, (_, i) => entry(`n${i}`, `key-${i}-padding`));
  assert.equal((await post({ entries: many, dryRun: true, passphrase: PASS })).status, 400);
});

test('names must start with a letter or digit (add, edit rename, import, proxy label)', async () => {
  for (const bad of ['..', '--help', '-x', '.hidden', '_a']) {
    assert.throws(() => store.addCredential({ name: bad, provider: 'openai', apiKey: 'sk-proj-NAMEtest0001' }), /start with a letter or number/, bad);
  }
  const res = await post({ entries: [entry('-x', 'sk-proj-NAMEtest0002'), entry('..', 'sk-proj-NAMEtest0003')], dryRun: false, passphrase: PASS });
  assert.deepEqual(res.body.results.map((r: any) => r.outcome), ['invalid', 'invalid']);
  store.addCredential({ name: 'ok-name', provider: 'openai', apiKey: 'sk-proj-NAMEtest0004' });
  assert.throws(() => store.updateCredential('ok-name', { name: '--help' }), /start with a letter or number/);
  assert.throws(() => store.issueProxy({ credential: 'ok-name', ttlSeconds: 60, label: '-rf' }), /start with a letter or number/);
  assert.throws(() => store.issueProxy({ credential: 'ok-name', ttlSeconds: 60, label: '..' }), /start with a letter or number/);
  assert.ok(store.issueProxy({ credential: 'ok-name', ttlSeconds: 60, label: 'good.label-1' }));
});

test('a credential stored under an older, looser name still edits; only a rename validates', () => {
  const c = store.addCredential({ name: 'legacy', provider: 'openai', apiKey: 'sk-proj-NAMEtest0005' });
  // Simulate a row from before the rule, then re-sign it through a normal edit path.
  const db = new DatabaseSync(path.join(home, 'wickey.db'));
  db.prepare('UPDATE credentials SET name = ? WHERE id = ?').run('-old', c.id);
  db.close();
  assert.throws(() => store.updateCredential('-old', { name: '-new' }), /start with a letter or number/);
  assert.equal(store.updateCredential(c.id, { authStyle: 'x-api-key' }).authStyle, 'x-api-key');
  assert.equal(store.updateCredential(c.id, { name: 'renamed' }).name, 'renamed');
});

test('an sk-wick proxy key is refused as a provider key on add, edit and import', async () => {
  const proxyKey = 'sk-wick-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG';
  assert.throws(() => store.addCredential({ name: 'selfkey', provider: 'openai', apiKey: proxyKey }), /Wickey proxy key, not a provider key/);
  store.addCredential({ name: 'editme', provider: 'openai', apiKey: 'sk-proj-NAMEtest0006' });
  assert.throws(() => store.updateCredential('editme', { apiKey: proxyKey }), /Wickey proxy key, not a provider key/);
  const res = await post({ entries: [entry('imp', proxyKey)], dryRun: false, passphrase: PASS });
  assert.equal(res.body.results[0].outcome, 'invalid');
  assert.match(res.body.results[0].message, /proxy key, not a provider key/);
  assert.equal(store.getCredential('imp'), null);
  assert.equal(store.getCredential('selfkey'), null);
});
