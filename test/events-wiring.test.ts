import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, mock, test } from 'node:test';

// Every security-relevant action leaves exactly one event of its type, with ids and limits only.
// The scan at the end reads the whole log file for anything that looks like a key or passphrase.

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-wiring-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '300';

const { createProxyServer } = await import('../src/proxy.ts');
const ev = await import('../src/events.ts');
const vault = await import('../src/vault.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const { performReset } = await import('../src/reset.ts');

const PASS = 'correct horse battery staple';
const PASS2 = 'a completely different passphrase';
const logFile = path.join(home, 'events.log');
const script = fileURLToPath(new URL('../bin/wickey.js', import.meta.url));
const issuedTokens: string[] = [];
let server: http.Server;
let port = 0;
let pass = PASS;

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

interface Res { status: number; body: any; cookie: string | null }

async function api(method: string, p: string, opts: { body?: unknown; cookie?: string | null; via?: string } = {}): Promise<Res> {
  const res = await fetch(`http://127.0.0.1:${port}${p}`, {
    method,
    headers: {
      'x-wickey': '1',
      ...(opts.via ? { 'x-wickey-via': opts.via } : {}),
      ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...(opts.cookie ? { cookie: opts.cookie } : {}),
    },
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
  const body = await res.json().catch(() => ({}));
  if (typeof body?.token === 'string') issuedTokens.push(body.token);
  return { status: res.status, body, cookie: res.headers.get('set-cookie')?.split(';')[0] ?? null };
}

const lastSeq = (): number => ev.listEvents({ limit: 1 }).events[0]?.seq ?? 0;
/** Events written after `seq`, oldest first, without the checkpoints the log adds by itself. */
const since = (seq: number) =>
  ev.listEvents({ limit: 200 }).events.filter((e) => e.seq > seq && e.type !== 'checkpoint').sort((a, b) => a.seq - b.seq);
const types = (seq: number) => since(seq).map((e) => e.type);
const ok = () => assert.equal(ev.verifyLog().ok, true, JSON.stringify(ev.verifyLog()));

/** Signs in over HTTP (starts the grace period) and returns the cookie. */
async function login(): Promise<string> {
  const r = await api('POST', '/api/signin', { body: { passphrase: pass } });
  assert.equal(r.status, 200);
  return r.cookie!;
}

function runCli(args: string[]): Promise<{ code: number | null; err: string }> {
  // detached = its own session, so there is no controlling terminal for /dev/tty.
  const child = spawn(process.execPath, [script, ...args], {
    env: { ...process.env, WICKEY_HOME: home, WICKEY_PORT: String(port) }, stdio: ['ignore', 'ignore', 'pipe'], detached: true,
  });
  let err = '';
  child.stderr.on('data', (d) => (err += d));
  const timer = setTimeout(() => child.kill(), 20_000);
  return new Promise((resolve) => child.on('close', (code) => { clearTimeout(timer); resolve({ code, err }); }));
}

const CRED = { name: 'work', provider: 'custom', apiKey: 'sk-REAL-work-key', baseUrl: 'http://127.0.0.1:9/v1' };

// ---- vault and passphrase events (order matters: they share module state) ----

test('vault_created: terminal setup, then the one-time setup link', async () => {
  let seq = lastSeq();
  session.setUp(PASS);
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['vault_created', { via: 'terminal' }]]);

  vault.lockVault();
  store.closeStore();
  performReset();
  seq = lastSeq();
  const token = session.openSetup();
  const r = await api('POST', '/api/setup', { body: { passphrase: PASS, token } });
  assert.equal(r.status, 201);
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['vault_created', { via: 'setup_link' }]]);
  ok();
});

test('signed_in: dashboard sign-in while unlocked', async () => {
  const seq = lastSeq();
  await login();
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['signed_in', { via: 'dashboard' }]]);
  ok();
});

test('locked: dashboard Lock and `wickey lock` in a child process', async () => {
  let seq = lastSeq();
  assert.equal((await api('POST', '/api/lock', { body: {} })).status, 200);
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['locked', { via: 'dashboard' }]]);

  seq = lastSeq();
  const r = await runCli(['lock']);
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['locked', { via: 'cli' }]]);
  ok();
});

test('unlocked: locked to unlocked, once; an already-unlocked vault is a sign-in instead', async () => {
  vault.lockVault();
  let seq = lastSeq();
  const r = await api('POST', '/api/unlock', { body: { passphrase: pass } });
  assert.equal(r.status, 200);
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['unlocked', { via: 'dashboard' }]]);

  seq = lastSeq();
  await api('POST', '/api/unlock', { body: { passphrase: pass }, via: 'cli' });
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['signed_in', { via: 'cli' }]]);
  ok();
});

test('unlock_failed: wrong passphrase on unlock, sign-in, passphrase change and a gated action', async () => {
  const cookie = await login();
  store.addCredential(CRED);
  let seq = lastSeq();
  vault.lockVault();
  assert.equal((await api('POST', '/api/unlock', { body: { passphrase: 'wrong wrong wrong' } })).body.error.code, 'wrong_passphrase');
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['unlock_failed', { via: 'dashboard' }]]);
  vault.unlockVault(pass);

  seq = lastSeq();
  await api('POST', '/api/signin', { body: { passphrase: 'wrong wrong wrong' }, via: 'cli' });
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['unlock_failed', { via: 'cli' }]]);

  seq = lastSeq();
  await api('POST', '/api/passphrase', { cookie, body: { current: 'wrong wrong wrong', next: 'another new passphrase' } });
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['unlock_failed', { via: 'dashboard' }]]);

  seq = lastSeq();
  const r = await api('POST', '/api/proxies', { cookie, body: { credential: 'work', passphrase: 'wrong wrong wrong' } });
  assert.equal(r.status, 401);
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['unlock_failed', { via: 'dashboard' }]]);
  ok();
});

test('passphrase_throttled: once per throttle window, not per refused attempt', async () => {
  // Four wrong guesses happened above; the fifth starts the window.
  let seq = lastSeq();
  await api('POST', '/api/signin', { body: { passphrase: 'wrong wrong wrong' } });
  assert.deepEqual(types(seq), ['unlock_failed']);
  seq = lastSeq();
  for (let i = 0; i < 4; i++) {
    const r = await api('POST', '/api/signin', { body: { passphrase: 'wrong wrong wrong' } });
    assert.equal(r.status, 429);
  }
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['passphrase_throttled', {}]]);
  await new Promise((r) => setTimeout(r, 1200));
  await login(); // the right passphrase clears the counter
  ok();
});

test('passphrase_changed: via the label the request carries', async () => {
  const cookie = await login();
  const seq = lastSeq();
  const r = await api('POST', '/api/passphrase', { cookie, via: 'cli', body: { current: pass, next: PASS2 } });
  assert.equal(r.status, 200);
  pass = PASS2;
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['passphrase_changed', { via: 'cli' }]]);
  ok();
});

// ---- keys ----

test('key_issued: models/limits summary, `unlimited` only when all three limits are absent; grace-period mints count', async () => {
  const cookie = await login(); // grace is running: no passphrase in these bodies
  const issue = async (limits: unknown, extra: Record<string, unknown> = {}) => {
    const seq = lastSeq();
    const r = await api('POST', '/api/proxies', { cookie, body: { credential: 'work', label: 'agent', limits, ...extra } });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    const evs = since(seq);
    assert.equal(evs.filter((e) => e.type === 'key_issued').length, 1);
    return { proxyId: r.body.proxy.id as string, evs };
  };

  let { proxyId, evs } = await issue(undefined);
  assert.deepEqual(evs.map((e) => e.data), [{
    proxyId, credential: 'work', label: 'agent', via: 'dashboard', op: 'issue', models: 'all', rpm: null, tokenCap: null, autoRenew: false, unlimited: true,
  }]);

  for (const [limits, expect] of [
    [{ rpm: 10 }, { models: 'all', rpm: 10, tokenCap: null, unlimited: false }],
    [{ tokenCap: 5000 }, { models: 'all', rpm: null, tokenCap: 5000, unlimited: false }],
    [{ models: ['a', 'b'] }, { models: 2, rpm: null, tokenCap: null, unlimited: false }],
    [{ models: [] }, { models: 'none', rpm: null, tokenCap: null, unlimited: false }],
  ] as const) {
    ({ evs } = await issue(limits));
    assert.deepEqual({ models: evs[0].data.models, rpm: evs[0].data.rpm, tokenCap: evs[0].data.tokenCap, unlimited: evs[0].data.unlimited }, expect);
  }

  // From `wickey issue`: the label the CLI sends. Rotate and env mint too.
  const seq = lastSeq();
  const cli = await api('POST', '/api/proxies', { cookie, via: 'cli', body: { credential: 'work' } });
  assert.equal(since(seq)[0].data.via, 'cli');
  assert.equal(since(seq)[0].data.label, null);

  let s = lastSeq();
  await api('POST', `/api/proxies/${cli.body.proxy.id}/rotate`, { cookie, body: {} });
  assert.deepEqual(since(s).map((e) => [e.type, e.data.op, e.data.proxyId]), [['key_issued', 'rotate', cli.body.proxy.id]]);

  s = lastSeq();
  const env = await api('POST', '/api/env', { cookie, body: { credential: 'work', label: 'term1' } });
  assert.equal(env.status, 200);
  assert.deepEqual(since(s).map((e) => [e.type, e.data.op, e.data.label, e.data.proxyId]), [['key_issued', 'env', 'term1', env.body.proxy.id]]);
  ok();
});

test('a mint with the passphrase after Lock logs key_issued and nothing else', async () => {
  await login();
  await api('POST', '/api/lock', { body: {} });
  const cookie = await login(); // sign-in restarts grace, so end it again without dropping the session
  session.endGrace();
  const seq = lastSeq();
  const refused = await api('POST', '/api/proxies', { cookie, body: { credential: 'work' } });
  assert.equal(refused.status, 401);
  assert.deepEqual(types(seq), [], 'a refused mint leaves no key_issued');
  const r = await api('POST', '/api/proxies', { cookie, body: { credential: 'work', passphrase: pass } });
  assert.equal(r.status, 201);
  assert.deepEqual(types(seq), ['key_issued']);
  ok();
});

test('key_renewed: renew logs key_renewed, not key_issued', async () => {
  const cookie = await login();
  const p = await api('POST', '/api/proxies', { cookie, body: { credential: 'work' } });
  const seq = lastSeq();
  const r = await api('POST', `/api/proxies/${p.body.proxy.id}/renew`, { cookie, via: 'cli', body: {} });
  assert.equal(r.status, 200);
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['key_renewed', { proxyId: p.body.proxy.id, via: 'cli' }]]);
  ok();
});

test('limits_tightened, limits_loosened and auto_renew_enabled', async () => {
  const cookie = await login();
  const p = await api('POST', '/api/proxies', { cookie, body: { credential: 'work', ttl: '10m', limits: { rpm: 10 } } });
  const id = p.body.proxy.id as string;
  const patch = async (body: Record<string, unknown>, via?: string) => {
    const seq = lastSeq();
    const r = await api('PATCH', `/api/proxies/${id}/limits`, { cookie, via, body });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    return since(seq);
  };

  let evs = await patch({ limits: { rpm: 5 } });
  assert.deepEqual(evs.map((e) => e.type), ['limits_tightened']);
  assert.equal(evs[0].data.proxyId, id);
  assert.equal(evs[0].data.via, 'dashboard');
  assert.match(String(evs[0].data.before), /rpm 10/);
  assert.match(String(evs[0].data.after), /rpm 5/);

  assert.deepEqual((await patch({ limits: { rpm: 5 } })).map((e) => e.type), [], 'no change, no event');

  evs = await patch({ limits: { rpm: 20, tokenCap: 100 } }, 'cli');
  assert.deepEqual(evs.map((e) => e.type), ['limits_loosened'], 'grace period lets a loosening through, and it is logged');
  assert.equal(evs[0].data.via, 'cli');

  evs = await patch({ autoRenew: { windowSeconds: 60, maxLifetime: '2h' } });
  assert.deepEqual(evs.map((e) => e.type), ['limits_loosened', 'auto_renew_enabled']);
  assert.equal(evs[1].data.window, 60);
  assert.ok(Math.abs((evs[1].data.maxLifetime as number) - 7200) < 60);

  assert.deepEqual((await patch({ autoRenew: null })).map((e) => e.type), ['limits_tightened'], 'turning it off is a tightening and not "enabled"');

  // Issue with auto-renew: one key_issued plus auto_renew_enabled.
  const seq = lastSeq();
  await api('POST', '/api/proxies', { cookie, body: { credential: 'work', ttl: '10m', autoRenew: { windowSeconds: 60, maxLifetime: '2h' } } });
  const issued = since(seq);
  assert.deepEqual(issued.map((e) => e.type), ['key_issued', 'auto_renew_enabled']);
  assert.equal(issued[0].data.autoRenew, true);
  ok();
});

// ---- credentials ----

test('credential_added, credential_changed, credential_removed', async () => {
  const cookie = await login();
  let seq = lastSeq();
  const add = await api('POST', '/api/credentials', { cookie, body: { name: 'other', provider: 'custom', apiKey: 'sk-REAL-other', baseUrl: 'http://127.0.0.1:9/v1' } });
  assert.equal(add.status, 201);
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['credential_added', { name: 'other', provider: 'custom', baseUrlHost: '127.0.0.1:9', via: 'dashboard' }]]);

  seq = lastSeq();
  await api('PATCH', '/api/credentials/other', { cookie, body: { baseUrl: 'http://127.0.0.1:10/v1', apiKey: 'sk-REAL-new' } });
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['credential_changed', {
    name: 'other', provider: 'custom', baseUrlHost: '127.0.0.1:10', fields: ['baseUrl', 'apiKey'], keyReplaced: true, baseUrlChanged: true, via: 'dashboard',
  }]]);

  seq = lastSeq();
  await api('PATCH', '/api/credentials/other', { cookie, body: { name: 'renamed' } });
  const renamed = since(seq);
  assert.deepEqual(renamed.map((e) => [e.type, e.data.fields, e.data.keyReplaced, e.data.baseUrlChanged]), [['credential_changed', ['name'], false, false]]);

  seq = lastSeq();
  await api('PATCH', '/api/credentials/renamed', { cookie, body: { name: 'renamed' } });
  assert.deepEqual(types(seq), [], 'an edit that changes nothing logs nothing');

  seq = lastSeq();
  const del = await api('DELETE', '/api/credentials/renamed', { cookie, via: 'cli' });
  assert.equal(del.status, 200);
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['credential_removed', { name: 'renamed', provider: 'custom', baseUrlHost: '127.0.0.1:10', via: 'cli' }]]);
  ok();
});

test('credentials_imported: one event with the count; a dry run and a failed import log nothing', async () => {
  const cookie = await login();
  const entries = [
    { name: 'imp1', provider: 'custom', apiKey: 'sk-IMP-1', baseUrl: 'http://127.0.0.1:9/v1' },
    { name: 'imp2', provider: 'custom', apiKey: 'sk-IMP-2', baseUrl: 'http://127.0.0.1:9/v1' },
    { name: '-bad', provider: 'custom', apiKey: 'sk-IMP-3', baseUrl: 'http://127.0.0.1:9/v1' },
  ];
  let seq = lastSeq();
  await api('POST', '/api/credentials/import', { cookie, body: { entries, dryRun: true } });
  assert.deepEqual(types(seq), []);

  await api('POST', '/api/credentials/import', { cookie, body: { entries, dryRun: false } });
  assert.deepEqual(since(seq).map((e) => [e.type, e.data]), [['credentials_imported', { count: 2, via: 'dashboard' }]]);

  seq = lastSeq();
  await api('POST', '/api/credentials/import', { cookie, body: { entries, dryRun: false } });
  assert.deepEqual(types(seq), [], 'everything was a duplicate: nothing imported');
  ok();
});

// ---- no secrets, and logging never blocks ----

test('no event holds a key, token or passphrase', () => {
  const text = fs.readFileSync(logFile, 'utf8');
  assert.ok(text.length > 500);
  assert.ok(!/sk-/.test(text), 'no sk- string anywhere in the log');
  for (const secret of [PASS, PASS2, 'wrong wrong wrong', 'another new passphrase', ...issuedTokens]) assert.ok(!text.includes(secret));
  assert.ok(issuedTokens.length > 5);
  ok();
});

test('a log that cannot be written never blocks unlock, sign-in or lock; mints warn on stderr', async () => {
  // A directory where the file should be makes every append fail.
  fs.rmSync(logFile, { force: true });
  fs.mkdirSync(logFile);
  const stderr = mock.method(process.stderr, 'write', () => true);
  try {
    vault.lockVault();
    assert.equal((await api('POST', '/api/unlock', { body: { passphrase: pass } })).status, 200);
    const signin = await api('POST', '/api/signin', { body: { passphrase: pass } });
    assert.equal(signin.status, 200);
    const wrong = await api('POST', '/api/signin', { body: { passphrase: 'wrong wrong wrong' } });
    assert.equal(wrong.status, 401, 'a failed attempt is still a plain wrong-passphrase answer');
    assert.equal((await api('POST', '/api/lock', { body: {} })).status, 200);
    assert.equal(stderr.mock.calls.length, 0, 'unlock, sign-in and lock fail silently');

    const cookie = await login();
    stderr.mock.resetCalls();
    const minted = await api('POST', '/api/proxies', { cookie, body: { credential: 'work' } });
    assert.equal(minted.status, 201);
    const lines = stderr.mock.calls.map((c) => String(c.arguments[0]));
    assert.equal(lines.length, 1);
    assert.match(lines[0], /security event log could not be written \(key_issued\)/);
    assert.ok(!lines[0].includes(minted.body.token));
  } finally {
    stderr.mock.restore();
    fs.rmSync(logFile, { recursive: true, force: true });
  }
});
