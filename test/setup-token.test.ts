import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';

// A fresh install: no vault yet. Any local program can reach /api/setup, so it must need the
// one-time token that `start` prints, or a program could set the passphrase before the user does.
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-setup-token-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';

const { createProxyServer } = await import('../src/proxy.ts');
const session = await import('../src/session.ts');
const { vaultExists } = await import('../src/vault.ts');
const store = await import('../src/store.ts');

const PASS = 'correct horse battery staple';
let server: http.Server;
let port = 0;

before(async () => {
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});

after(() => {
  store.closeStore();
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
});

function setup(body: unknown): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request({
      host: '127.0.0.1', port, method: 'POST', path: '/api/setup',
      headers: { host: `127.0.0.1:${port}`, 'x-wickey': '1', 'content-type': 'application/json' },
    }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => resolve({ status: res.statusCode!, body: JSON.parse(text || '{}') }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

test('before start opens setup, no token works', async () => {
  for (const body of [{ passphrase: PASS }, { passphrase: PASS, token: '' }, { passphrase: PASS, token: 'guess' }]) {
    const res = await setup(body);
    assert.equal(res.status, 403, JSON.stringify(body));
    assert.match(res.body.error.message, /setup link printed by `wickey start`/);
  }
  assert.equal(vaultExists(), false);
});

test('setup needs the token, keeps it through a fixable mistake, and works once', async () => {
  const token = session.openSetup();

  const missing = await setup({ passphrase: PASS });
  assert.equal(missing.status, 403);
  const wrong = await setup({ passphrase: PASS, token: token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A') });
  assert.equal(wrong.status, 403, 'a token that differs in one character fails');
  const wrongLength = await setup({ passphrase: PASS, token: token + 'x' });
  assert.equal(wrongLength.status, 403);
  assert.equal((await setup({ passphrase: PASS, token: 42 })).status, 403, 'a non-string token fails');
  assert.equal(vaultExists(), false, 'no failed attempt creates a vault');

  // A too-short passphrase is the user's typo, not an attack: the link must keep working.
  const short = await setup({ passphrase: 'short', token });
  assert.equal(short.status, 400);
  assert.equal(vaultExists(), false);

  const ok = await setup({ passphrase: PASS, token });
  assert.equal(ok.status, 201);
  assert.equal(vaultExists(), true);

  const again = await setup({ passphrase: 'someone else entirely', token });
  assert.equal(again.status, 409, 'the same link cannot set a second passphrase');
  assert.equal(session.setupTokenMatches(token), false, 'setup consumed the token');
});

test('setup from the terminal also retires an open link', () => {
  // Simulates a later run: vault gone, a link open, then the terminal path sets it up instead.
  fs.rmSync(path.join(home, 'vault.json'));
  const token = session.openSetup();
  session.setUp(PASS);
  assert.equal(session.setupTokenMatches(token), false);
});
