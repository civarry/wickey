import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, mock, test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';

// Proxy keys are shown once and kept only as a hash; every /api route needs a session that only the
// passphrase can create. A local program holding key A (but not the passphrase) must not get key B.

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-tokens-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '300';
const PASS = 'correct horse battery staple';

const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
session.setUp(PASS);

let server: http.Server;
let port = 0;
const dbFile = path.join(home, 'wickey.db');
const script = fileURLToPath(new URL('../bin/wickey.js', import.meta.url));
const cleanups: (() => void)[] = [];

before(async () => {
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as net.AddressInfo).port;
  store.addCredential({ name: 'work', provider: 'custom', apiKey: 'sk-REAL-work-key', baseUrl: 'http://127.0.0.1:9/v1' });
});

after(() => {
  for (const c of store.listCredentials()) store.removeCredential(c.id);
  store.closeStore();
  server.close();
  for (const fn of cleanups) fn();
  fs.rmSync(home, { recursive: true, force: true });
});

interface Res { status: number; body: any; text: string; headers: http.IncomingHttpHeaders }

/** Raw request against `targetPort` so tests can forge Host and Origin or drop the custom header. */
function raw(opts: { method?: string; path: string; headers?: Record<string, string | undefined>; body?: unknown; port?: number }): Promise<Res> {
  const p = opts.port ?? port;
  return new Promise((resolve, reject) => {
    const payload = opts.body === undefined ? undefined : JSON.stringify(opts.body);
    const headers: Record<string, string> = { host: `127.0.0.1:${p}`, 'x-wickey': '1', ...(payload ? { 'content-type': 'application/json' } : {}) };
    for (const [k, v] of Object.entries(opts.headers ?? {})) {
      if (v === undefined) delete headers[k];
      else headers[k] = v;
    }
    const req = http.request({ host: '127.0.0.1', port: p, method: opts.method ?? 'GET', path: opts.path, headers }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => {
        let body: any = text;
        try { body = JSON.parse(text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode!, body, text, headers: res.headers });
      });
    });
    req.on('error', reject);
    req.end(payload);
  });
}

const cookieOf = (res: Res): string => String(res.headers['set-cookie']?.[0] ?? '').split(';')[0];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Signs in with the passphrase, like the dashboard or CLI does, and returns the cookie. */
async function signIn(): Promise<string> {
  const res = await raw({ method: 'POST', path: '/api/signin', body: { passphrase: PASS } });
  assert.equal(res.status, 200);
  return cookieOf(res);
}

function allTables(file: string): string {
  const d = new DatabaseSync(file);
  const out: string[] = [];
  for (const { name } of d.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[]) {
    out.push(JSON.stringify(d.prepare(`SELECT * FROM ${name}`).all()));
  }
  d.close();
  return out.join('\n');
}

/** Everything on disk that belongs to the database, including the write-ahead log. */
function rawDbBytes(file: string): string {
  return ['', '-wal', '-shm'].map((ext) => (fs.existsSync(file + ext) ? fs.readFileSync(file + ext).toString('latin1') : '')).join('\n');
}

const mint = () => store.issueProxy({ credential: 'work', ttlSeconds: 3600 });

// ---- sessions ----

// Every route in the table of src/api.ts. The guard below fails when a route is added without being listed here.
const ROUTES: [string, string][] = [
  ['GET', '/api/state'],
  ['POST', '/api/passphrase'],
  ['POST', '/api/signout'],
  ['POST', '/api/env'],
  ['POST', '/api/credentials'],
  ['POST', '/api/credentials/import'],
  ['PATCH', '/api/credentials/work'],
  ['DELETE', '/api/credentials/nope'],
  ['GET', '/api/credentials/work/models'],
  ['POST', '/api/credentials/work/models/refresh'],
  ['POST', '/api/proxies'],
  ['PATCH', '/api/proxies/abcd1234/limits'],
  ['GET', '/api/events'],
  ['GET', '/api/requests'],
  ['GET', '/api/proxies/abcd1234/requests'],
  ['POST', '/api/proxies/abcd1234/renew'],
  ['POST', '/api/proxies/abcd1234/rotate'],
  ['POST', '/api/proxies/abcd1234/expire'],
  ['DELETE', '/api/proxies/abcd1234'],
  ['GET', '/api/nothing-here'],
];
// /api/lock is open on purpose (it only ends the grace period); see PUBLIC_ROUTES in src/api.ts.
const OPEN_ROUTES = ['/api/session-status', '/api/setup', '/api/unlock', '/api/signin', '/api/lock'];

test('the route table in this test covers every /api path in src/api.ts', () => {
  const source = fs.readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8');
  const found = new Set<string>();
  for (const m of source.matchAll(/['`\/^]\/?api\/([a-z-]+)/g)) found.add(m[1]);
  const covered = new Set([...ROUTES.map(([, p]) => p.split('/')[2]), ...OPEN_ROUTES.map((p) => p.split('/')[2])]);
  for (const first of found) assert.ok(covered.has(first), `/api/${first} is not covered by ROUTES`);
  // Each method+path handled in route() is listed (sessions are checked for all of them).
  for (const m of source.matchAll(/method === '([A-Z]+)' && path === '(\/api\/[a-z\/]+)'/g)) {
    assert.ok([...ROUTES, ...OPEN_ROUTES.map((p) => ['', p])].some(([, p]) => p === m[2]), `${m[1]} ${m[2]} is not in ROUTES`);
  }
});

test('every /api route answers 401 session_required without a session, and works with one', async () => {
  const cookie = await signIn();
  for (const [method, p] of ROUTES) {
    const bare = await raw({ method, path: p, body: method === 'GET' || method === 'DELETE' ? undefined : {} });
    assert.equal(bare.status, 401, `${method} ${p} without a session`);
    assert.equal(bare.body.error.code, 'session_required', `${method} ${p}`);
    // A made-up cookie is no better than none.
    const forged = await raw({ method, path: p, headers: { cookie: 'wickey_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, body: method === 'GET' || method === 'DELETE' ? undefined : {} });
    assert.equal(forged.body?.error?.code, 'session_required', `${method} ${p} with a forged cookie`);
  }
  for (const [method, p] of ROUTES.filter(([m, p]) => m === 'GET' && !p.includes('nothing') && !p.includes('/models'))) {
    const ok = await raw({ method, path: p.replace('abcd1234', mint().proxy.id), headers: { cookie } });
    assert.equal(ok.status, 200, `${method} ${p} with a session`);
  }
  const status = await raw({ path: '/api/session-status' });
  assert.deepEqual(status.body, { vault: true, unlocked: true, signedIn: false }, 'the open status route carries no proxy or credential data');
  assert.equal((await raw({ path: '/api/session-status', headers: { cookie } })).body.signedIn, true);
  for (const p of store.listProxies()) store.deleteProxy(p.id);
});

test('the session cookie is HttpOnly, SameSite=Strict and Path=/ (setup, unlock and signin)', async () => {
  const res = await raw({ method: 'POST', path: '/api/signin', body: { passphrase: PASS } });
  const set = String(res.headers['set-cookie']?.[0]);
  assert.match(set, /^wickey_session=[A-Za-z0-9_-]{43};/);
  assert.match(set, /; HttpOnly/);
  assert.match(set, /; SameSite=Strict/);
  assert.match(set, /; Path=\//);
  assert.doesNotMatch(set, /Secure/, 'the dashboard is http on loopback, where a Secure cookie would be dropped');
  const unlock = await raw({ method: 'POST', path: '/api/unlock', body: { passphrase: PASS } });
  assert.match(String(unlock.headers['set-cookie']?.[0]), /HttpOnly; SameSite=Strict; Path=\//);
  // Two sign-ins never share an id.
  assert.notEqual(cookieOf(res), cookieOf(unlock));
});

test('signout ends only that session', async () => {
  const a = await signIn();
  const b = await signIn();
  const out = await raw({ method: 'POST', path: '/api/signout', headers: { cookie: a } });
  assert.equal(out.status, 200);
  assert.match(String(out.headers['set-cookie']?.[0]), /Max-Age=0/);
  assert.equal((await raw({ path: '/api/state', headers: { cookie: a } })).status, 401);
  assert.equal((await raw({ path: '/api/state', headers: { cookie: b } })).status, 200);
});

test('Lock signs every session out; signing in again works', async () => {
  const a = await signIn();
  const b = await signIn();
  assert.equal((await raw({ method: 'POST', path: '/api/lock', headers: { cookie: a }, body: {} })).status, 200);
  for (const c of [a, b]) {
    const res = await raw({ path: '/api/state', headers: { cookie: c } });
    assert.equal(res.status, 401);
    assert.equal(res.body.error.code, 'session_required');
  }
  assert.equal((await raw({ path: '/api/state', headers: { cookie: await signIn() } })).status, 200);
});

test('a session idle for 12 hours expires; activity keeps it alive', async () => {
  const cookie = await signIn();
  const start = Date.now();
  mock.timers.enable({ apis: ['Date'], now: start });
  try {
    mock.timers.setTime(start + 11 * 3600_000);
    assert.equal((await raw({ path: '/api/state', headers: { cookie } })).status, 200, 'used at 11h, so the clock restarts');
    mock.timers.setTime(start + 22 * 3600_000);
    assert.equal((await raw({ path: '/api/state', headers: { cookie } })).status, 200, 'still inside 12h of the last use');
    mock.timers.setTime(start + 35 * 3600_000);
    assert.equal((await raw({ path: '/api/state', headers: { cookie } })).status, 401, 'idle for 13h');
  } finally {
    mock.timers.reset();
  }
});

test('Host, Origin and the x-wickey header are still enforced, even with a valid session', async () => {
  const cookie = await signIn();
  for (const p of ['/api/state', '/api/session-status']) {
    assert.equal((await raw({ path: p, headers: { cookie, host: `attacker.example:${port}` } })).status, 403, `${p}: other host`);
    assert.equal((await raw({ path: p, headers: { cookie, host: `127.0.0.1:${port + 1}` } })).status, 403, `${p}: other port in Host`);
    assert.equal((await raw({ path: p, headers: { cookie, origin: 'https://attacker.example' } })).status, 403, `${p}: foreign Origin`);
    assert.equal((await raw({ path: p, headers: { cookie, origin: `http://127.0.0.1:${port + 1}` } })).status, 403, `${p}: Origin from another local port`);
    assert.equal((await raw({ path: p, headers: { cookie, 'x-wickey': undefined } })).status, 403, `${p}: header missing`);
  }
  assert.equal((await raw({ method: 'POST', path: '/api/signin', headers: { origin: 'http://127.0.0.1:9' }, body: { passphrase: PASS } })).status, 403, 'a local web page cannot sign in');
  assert.equal((await raw({ path: '/api/state', headers: { cookie, origin: `http://127.0.0.1:${port}` } })).status, 200);
});

test('signing in is throttled like unlock: 5 wrong passphrases, then a wait', async () => {
  for (let i = 0; i < 5; i++) {
    const res = await raw({ method: 'POST', path: '/api/signin', body: { passphrase: `wrong passphrase ${i}` } });
    assert.equal(res.status, 401);
    assert.equal(res.body.error.code, 'wrong_passphrase');
  }
  const blocked = await raw({ method: 'POST', path: '/api/signin', body: { passphrase: PASS } });
  assert.equal(blocked.status, 429, 'even the right passphrase waits');
  assert.equal(blocked.headers['set-cookie'], undefined);
  await sleep(1100);
  assert.equal((await raw({ method: 'POST', path: '/api/signin', body: { passphrase: PASS } })).status, 200);
});

test('signing in with the wrong passphrase gives no session', async () => {
  const res = await raw({ method: 'POST', path: '/api/signin', body: { passphrase: 'not the one at all' } });
  assert.equal(res.status, 401);
  assert.equal(res.headers['set-cookie'], undefined);
  const empty = await raw({ method: 'POST', path: '/api/signin', body: {} });
  assert.equal(empty.headers['set-cookie'], undefined);
  // Sign-in is not a back door to a locked vault: that is what unlock is for.
  assert.equal((await raw({ method: 'POST', path: '/api/signin', body: { passphrase: PASS } })).status, 200);
});

test('grace only helps inside a session: no session, no minting', async () => {
  const cookie = await signIn(); // starts the grace period
  const withSession = await raw({ method: 'POST', path: '/api/proxies', headers: { cookie }, body: { credential: 'work', ttl: '1h' } });
  assert.equal(withSession.status, 201, 'a signed-in session mints during grace without retyping');
  const without = await raw({ method: 'POST', path: '/api/proxies', body: { credential: 'work', ttl: '1h' } });
  assert.equal(without.status, 401);
  assert.equal(without.body.error.code, 'session_required');
  const withPassphrase = await raw({ method: 'POST', path: '/api/proxies', body: { credential: 'work', ttl: '1h', passphrase: PASS } });
  assert.equal(withPassphrase.body.error.code, 'session_required', 'the passphrase in a body is not a session either');
  for (const p of store.listProxies()) store.deleteProxy(p.id);
});

// ---- no key in any list ----

test('state, activity and per-proxy logs never contain a full key or a token field', async () => {
  const cookie = await signIn();
  const issued = await raw({ method: 'POST', path: '/api/proxies', headers: { cookie }, body: { credential: 'work', ttl: '1h', label: 'a' } });
  assert.equal(issued.status, 201);
  const { token } = issued.body;
  assert.match(token, /^sk-wick-/, 'the issue response is the one place the key appears');
  const id = issued.body.proxy.id;
  store.logRequest({ proxyId: id, at: Date.now(), model: 'm', status: 200, tokensIn: 1, tokensOut: 1, durationMs: 5 });
  const rotated = await raw({ method: 'POST', path: `/api/proxies/${id}/rotate`, headers: { cookie }, body: {} });
  assert.match(rotated.body.token, /^sk-wick-/);
  const renewed = await raw({ method: 'POST', path: `/api/proxies/${id}/renew`, headers: { cookie }, body: {} });
  assert.equal(renewed.body.token, undefined);

  for (const p of ['/api/state', '/api/requests', `/api/proxies/${id}/requests`]) {
    const res = await raw({ path: p, headers: { cookie } });
    assert.equal(res.status, 200);
    for (const secret of [token, rotated.body.token]) assert.ok(!res.text.includes(secret), `${p} contains a full key`);
    assert.ok(!/"token"\s*:/.test(res.text), `${p} has a token field`);
    assert.ok(!res.text.includes(rotated.body.token.slice(10)), `${p} shows more than the suffix`);
  }
  const state = (await raw({ path: '/api/state', headers: { cookie } })).body;
  assert.equal(state.proxies[0].maskedKey, `sk-wick-…${rotated.body.token.slice(-5)}`);
  for (const p of store.listProxies()) store.deleteProxy(p.id);
});

// ---- at rest ----

test('after issue, the database holds a hash and a suffix, never the key', async () => {
  const { proxy, token } = mint();
  const rotated = store.rotateProxy(proxy.id);
  const d = new DatabaseSync(dbFile);
  const columns = (d.prepare('PRAGMA table_info(proxies)').all() as { name: string }[]).map((c) => c.name);
  const row = d.prepare('SELECT * FROM proxies WHERE id = ?').get(proxy.id) as Record<string, any>;
  d.close();
  assert.ok(!columns.includes('token'), 'no plaintext column');
  assert.equal(row.token_hash, createHash('sha256').update(rotated.token).digest('hex'));
  assert.equal(row.token_tail, rotated.token.slice(-5));
  for (const t of [token, rotated.token]) {
    assert.ok(!allTables(dbFile).includes(t), 'no table has the key');
    assert.ok(!rawDbBytes(dbFile).includes(t), 'neither do the file or its log');
  }
  assert.equal(store.authorize(proxy.id, rotated.token).ok, true);
  assert.equal(store.authorize(proxy.id, token).ok, false, 'the old key is dead');
  store.deleteProxy(proxy.id);
});

test('a database from before this change is scrubbed on open, and old keys keep working', async () => {
  const { proxy, token } = mint();
  const other = mint();
  store.closeStore();
  // Put the old plaintext column back, as the previous version left it (rows and signatures untouched).
  const old = new DatabaseSync(dbFile);
  old.exec('ALTER TABLE proxies ADD COLUMN token TEXT');
  old.prepare('UPDATE proxies SET token = ?, token_tail = NULL WHERE id = ?').run(token, proxy.id);
  old.prepare('UPDATE proxies SET token = ?, token_tail = NULL WHERE id = ?').run(other.token, other.proxy.id);
  old.close();
  assert.ok(rawDbBytes(dbFile).includes(token), 'precondition: the old file has the key in plain text');

  const migrated = store.getProxy(proxy.id)!; // opening the store runs the migration
  assert.equal(migrated.maskedKey, `sk-wick-…${token.slice(-5)}`, 'the suffix survives');
  const d = new DatabaseSync(dbFile);
  assert.ok(!(d.prepare('PRAGMA table_info(proxies)').all() as { name: string }[]).some((c) => c.name === 'token'));
  d.close();
  assert.ok(!allTables(dbFile).includes(token));
  assert.ok(!rawDbBytes(dbFile).includes(token), 'not in free pages or the write-ahead log either');
  assert.ok(!rawDbBytes(dbFile).includes(other.token));

  assert.equal(store.authorize(proxy.id, token).ok, true, 'the existing key still authenticates');
  // Authenticated: the 403 is the network guard refusing the loopback test upstream, not a bad key.
  assert.notEqual((await rawProxy(proxy.id, token)).status, 401, 'the old key still gets through authentication');
  // Rows still verify, and a later write re-signs them.
  store.expireProxy(proxy.id);
  store.renewProxy(proxy.id, 60);
  assert.equal(store.authorize(proxy.id, token).ok, true);
  store.deleteProxy(proxy.id);
  store.deleteProxy(other.proxy.id);
});

function rawProxy(id: string, token: string): Promise<Res> {
  return raw({ method: 'POST', path: `/p/${id}/chat/completions`, headers: { authorization: `Bearer ${token}` }, body: { model: 'm' } });
}

test('changing the stored hash breaks the row signature', async () => {
  const { proxy } = mint();
  const mine = 'sk-wick-chosen-by-the-attacker';
  const d = new DatabaseSync(dbFile);
  d.prepare('UPDATE proxies SET token_hash = ? WHERE id = ?').run(createHash('sha256').update(mine).digest('hex'), proxy.id);
  d.close();
  const result = store.authorize(proxy.id, mine);
  assert.equal(result.ok, false);
  assert.match((result as { message: string }).message, /integrity check/);
  store.deleteProxy(proxy.id);
});

// ---- the red-team case: an agent with key A wants key B ----

function runCli(args: string[]): Promise<{ code: number | null; out: string; err: string }> {
  // detached = its own session, so there is no controlling terminal for /dev/tty: like an agent's subprocess.
  const child = spawn(process.execPath, [script, ...args], {
    env: { ...process.env, WICKEY_HOME: home, WICKEY_PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe'], detached: true,
  });
  let out = '';
  let err = '';
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (err += d));
  const timer = setTimeout(() => child.kill(), 20_000);
  return new Promise((resolve) => child.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err }); }));
}

test('an agent holding key A and no passphrase cannot get key B', async () => {
  const a = mint();
  const b = mint();
  const cookie = await signIn();
  const issuedB = b.token;

  // The management API: no session, with or without the header, from a bare client.
  for (const headers of [{}, { 'x-wickey': undefined }, { authorization: `Bearer ${a.token}` }, { 'x-api-key': a.token }, { cookie: `wickey_session=${a.token}` }]) {
    for (const p of ['/api/state', '/api/requests', `/api/proxies/${b.proxy.id}/requests`]) {
      const res = await raw({ path: p, headers });
      assert.ok(res.status === 401 || res.status === 403, `${p} ${JSON.stringify(Object.keys(headers))} -> ${res.status}`);
      assert.ok(!res.text.includes(issuedB));
    }
  }
  for (const p of [`/api/proxies/${b.proxy.id}/rotate`, '/api/env']) {
    const res = await raw({ method: 'POST', path: p, headers: { authorization: `Bearer ${a.token}` }, body: { label: 'x', credential: 'work', passphrase: PASS } });
    assert.equal(res.body.error.code, 'session_required', 'not even the right passphrase works without a session in the cookie');
  }
  // Through the proxy path key A is only key A.
  assert.equal((await rawProxy(b.proxy.id, a.token)).status, 401);

  // The database file and its log.
  assert.ok(!allTables(dbFile).includes(issuedB));
  assert.ok(!rawDbBytes(dbFile).includes(issuedB));
  // A reader of the file cannot sign a row either: the signing key lives only in the unlocked vault.
  assert.ok(!fs.readFileSync(path.join(home, 'vault.json'), 'utf8').includes(issuedB));

  // The CLI, from a process with no terminal.
  for (const args of [['show', b.proxy.id], ['show', b.proxy.id, '--json'], ['list'], ['creds']]) {
    const r = await runCli(args);
    assert.ok(!r.out.includes(issuedB) && !r.err.includes(issuedB), `wickey ${args.join(' ')}`);
  }
  const show = await runCli(['show', b.proxy.id]);
  assert.equal(show.code, 0);
  assert.match(show.out, new RegExp(`sk-wick-…${issuedB.slice(-5)}`));
  assert.match(show.out, /Shown only once/);
  for (const args of [['show', b.proxy.id, '--env'], ['rotate', b.proxy.id, '--env'], ['issue', 'work'], ['env', 'agent', '--credential', 'work']]) {
    const r = await runCli(args);
    assert.notEqual(r.code, 0, `wickey ${args.join(' ')} must refuse`);
    assert.ok(!/sk-wick-[A-Za-z0-9_-]{43}/.test(r.out + r.err), `wickey ${args.join(' ')} printed a key`);
  }
  assert.match((await runCli(['env', 'agent', '--credential', 'work'])).err, /This must be done by a human/);
  // Key B is untouched by all of that.
  assert.equal(store.authorize(b.proxy.id, issuedB).ok, true);
  assert.equal(store.listProxies().length, 2, 'nothing was minted');
  assert.equal(cookie.length > 20, true);
  for (const p of store.listProxies()) store.deleteProxy(p.id);
});

// ---- restart ----

test('a restart signs everyone out: an old cookie is dead, and unlock starts a new session', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-restart-'));
  const childPort = await new Promise<number>((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => resolve(p)); });
  });
  // Plain `start` with no terminal: the first run prints the one-time setup link, the second
  // starts locked. stdout is captured so the test can follow the link like a user would.
  let output = '';
  const start = async () => {
    output = '';
    const child = spawn(process.execPath, [script, 'start'], {
      env: { ...process.env, WICKEY_HOME: dir, WICKEY_PORT: String(childPort), WICKEY_SCRYPT_N: '1024' },
      stdio: ['ignore', 'pipe', 'ignore'], detached: true,
    });
    child.stdout!.on('data', (d) => (output += d));
    cleanups.push(() => { try { child.kill(); } catch { /* gone */ } });
    for (let i = 0; i < 100; i++) {
      try { if ((await fetch(`http://127.0.0.1:${childPort}/health`)).ok) return child; } catch { /* not up yet */ }
      await sleep(100);
    }
    throw new Error('child proxy did not start');
  };
  const stop = (child: ReturnType<typeof spawn>) => new Promise<void>((r) => { child.once('exit', () => r()); child.kill(); });
  try {
    const first = await start();
    let token = '';
    for (let i = 0; i < 50 && !token; i++, await sleep(50)) token = /#setup=([A-Za-z0-9_-]+)/.exec(output)?.[1] ?? '';
    assert.ok(token, 'start prints a setup link when there is no terminal');
    const setup = await raw({ method: 'POST', path: '/api/setup', port: childPort, body: { passphrase: PASS, token } });
    assert.equal(setup.status, 201);
    const cookie = cookieOf(setup);
    assert.equal((await raw({ path: '/api/state', port: childPort, headers: { cookie } })).status, 200, 'setup signs the browser in');
    await stop(first);

    const second = await start();
    const res = await raw({ path: '/api/state', port: childPort, headers: { cookie } });
    assert.equal(res.status, 401);
    assert.equal(res.body.error.code, 'session_required');
    assert.deepEqual((await raw({ path: '/api/session-status', port: childPort, headers: { cookie } })).body, { vault: true, unlocked: false, signedIn: false });
    const unlocked = await raw({ method: 'POST', path: '/api/unlock', port: childPort, body: { passphrase: PASS } });
    assert.equal(unlocked.status, 200);
    assert.equal((await raw({ path: '/api/state', port: childPort, headers: { cookie: cookieOf(unlocked) } })).status, 200);
    assert.equal((await raw({ path: '/api/state', port: childPort, headers: { cookie } })).status, 401, 'the old cookie stays dead');
    await stop(second);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('pasting the masked form of a key gets a message saying so, not just "invalid"', async () => {
  const { authorize } = await import('../src/store.ts');
  // As a header value: Node hands over the UTF-8 bytes of "…" as Latin-1 characters.
  const fromHeader = Buffer.from('sk-wick-…D5JKw', 'utf8').toString('latin1');
  for (const token of ['sk-wick-…D5JKw', fromHeader, 'sk-wick-...D5JKw']) {
    const r = authorize('nosuchid', token);
    assert.equal(r.ok, false);
    assert.match((r as { message: string }).message, /masked form of the key/, JSON.stringify(token));
  }
});
