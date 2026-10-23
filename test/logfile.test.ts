import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-log-test-'));
process.env.WICKEY_HOME = path.join(tmp, 'home');
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const { RotatingLog, redact, hardenDataDir, redirectOutput } = await import('../src/logfile.ts');
const mode = (p: string) => fs.statSync(p).mode & 0o777;
const posix = process.platform !== 'win32';

test('rotation: caps each file, keeps exactly three, files are 0600 and the dir 0700', () => {
  const file = path.join(tmp, 'logs', 'a.log');
  const log = new RotatingLog(file, 100, 3);
  for (let i = 0; i < 40; i++) log.write(`line ${String(i).padStart(2, '0')} ${'x'.repeat(20)}\n`);
  log.close();
  assert.deepEqual(fs.readdirSync(path.dirname(file)).sort(), ['a.log', 'a.log.1', 'a.log.2']);
  for (const f of ['a.log', 'a.log.1', 'a.log.2']) {
    const full = path.join(path.dirname(file), f);
    assert.ok(fs.statSync(full).size <= 100, `${f} within the cap`);
    if (posix) assert.equal(mode(full), 0o600, f);
  }
  if (posix) assert.equal(mode(path.dirname(file)), 0o700);
  // Newest lines are in the live file, older ones in .1 then .2.
  assert.match(fs.readFileSync(file, 'utf8'), /line 39/);
  assert.doesNotMatch(fs.readFileSync(`${file}.2`, 'utf8'), /line 39/);
});

test('an existing loose log file and data dir are tightened on open and on start', { skip: !posix }, () => {
  const logs = path.join(process.env.WICKEY_HOME!, 'logs');
  fs.mkdirSync(logs, { recursive: true, mode: 0o755 });
  fs.chmodSync(logs, 0o755);
  const loose = path.join(logs, 'wickey.log');
  fs.writeFileSync(loose, 'old\n', { mode: 0o644 });
  fs.chmodSync(loose, 0o644);
  const vault = path.join(process.env.WICKEY_HOME!, 'vault.json');
  fs.writeFileSync(vault, '{}', { mode: 0o644 });
  fs.chmodSync(vault, 0o644);
  fs.chmodSync(process.env.WICKEY_HOME!, 0o755);
  hardenDataDir();
  assert.equal(mode(process.env.WICKEY_HOME!), 0o700);
  assert.equal(mode(logs), 0o700);
  assert.equal(mode(loose), 0o600);
  assert.equal(mode(vault), 0o600);
  fs.chmodSync(loose, 0o644);
  new RotatingLog(loose).close();
  assert.equal(mode(loose), 0o600);
});

test('redact hides keys, bearer values and auth headers', () => {
  const key = 'sk-proj-abcdefghijklmnop1234';
  assert.equal(redact(`failed with ${key}`), 'failed with sk-[hidden]');
  assert.equal(redact('Authorization: Bearer abc.def-ghi'), 'Authorization: [hidden]');
  assert.equal(redact('{"x-api-key":"zzz999"}'), '{"x-api-key":"[hidden]"}');
  assert.equal(redact('header authorization=Bearer tok123 end'), 'header authorization=[hidden] end');
  assert.equal(redact('sk-wick-0123456789abcdef'), 'sk-[hidden]');
  assert.equal(redact('plain line, proxy 3f9a1c2e'), 'plain line, proxy 3f9a1c2e');
});

test('redirectOutput sends writes (with a timestamp, redacted) to the log, and restores', () => {
  const file = path.join(tmp, 'redir', 'r.log');
  const log = new RotatingLog(file);
  const restore = redirectOutput(log);
  try {
    process.stderr.write('oops sk-proj-abcdefghijklmnop1234\n');
    process.stdout.write('hello\n');
  } finally {
    restore();
  }
  log.close();
  const text = fs.readFileSync(file, 'utf8');
  assert.match(text, /^\d{4}-\d\d-\d\dT[\d:.]+Z err oops sk-\[hidden\]\n/);
  assert.match(text, / out hello\n/);
  assert.doesNotMatch(text, /abcdefghijklmnop/);
});

const freePort = () => new Promise<number>((resolve) => {
  const s = net.createServer().listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => resolve(p)); });
});

test('service-mode proxy never logs keys, tokens or auth headers, even when upstream errors', async () => {
  const REAL = 'sk-proj-REALKEYabcdefghijklmnopqrstuv0123456789';
  const home = path.join(tmp, 'e2e-home');
  const port = await freePort();
  const upstream = http.createServer((req, res) => {
    if (req.url?.includes('boom')) return void req.socket.destroy();
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'bad', authorization: req.headers.authorization }));
  });
  await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', () => r()));
  const up = (upstream.address() as net.AddressInfo).port;

  const script = fileURLToPath(new URL('../bin/wickey.js', import.meta.url));
  const child = spawn(process.execPath, [script, 'start', '--service'], {
    env: { ...process.env, WICKEY_HOME: home, WICKEY_PORT: String(port), WICKEY_SCRYPT_N: '1024' },
  });
  let captured = '';
  child.stdout.on('data', (d) => (captured += d));
  child.stderr.on('data', (d) => (captured += d));
  try {
    const base = `http://127.0.0.1:${port}`;
    for (let i = 0; i < 100; i++) {
      try { if ((await fetch(`${base}/health`)).ok) break; } catch { /* not up yet */ }
      await new Promise((r) => setTimeout(r, 100));
    }
    let cookie = '';
    const api = (p: string, body: unknown) => fetch(`${base}${p}`, { method: 'POST', headers: { 'x-wickey': '1', 'content-type': 'application/json', cookie }, body: JSON.stringify(body) }).then((r) => {
      cookie = r.headers.get('set-cookie')?.split(';')[0] ?? cookie;
      return r.json();
    });
    await api('/api/setup', { passphrase: 'correct horse battery staple' });
    await api('/api/credentials', { name: 'mock', provider: 'custom', apiKey: REAL, baseUrl: `http://127.0.0.1:${up}/v1` });
    const { proxy, token } = await api('/api/proxies', { credential: 'mock', ttl: '10m', limits: { models: ['x'], rpm: null, tokenCap: null, refuseUncounted: false } });
    assert.ok(token?.startsWith('sk-wick-'), 'got a proxy token');

    const hit = (p: string, t = token) => fetch(`${base}/p/${proxy.id}${p}`, { method: 'POST', headers: { authorization: `Bearer ${t}`, 'x-api-key': t, 'content-type': 'application/json' }, body: '{"model":"x"}' }).then((r) => r.status);
    assert.equal(await hit('/chat/completions'), 500, 'upstream error is passed through');
    await hit('/boom'); // upstream drops the connection
    await hit('/chat/completions', 'sk-wick-wrongwrongwrongwrong'); // bad token
    await new Promise((r) => setTimeout(r, 300));

    const logFile = path.join(home, 'logs', 'wickey.log');
    const log = fs.readFileSync(logFile, 'utf8');
    assert.match(log, /Starting locked|No passphrase/, 'service start is logged');
    for (const text of [log, captured]) {
      assert.ok(!text.includes(REAL), 'real key');
      assert.ok(!text.includes(token), 'proxy token');
      assert.ok(!/authorization/i.test(text), 'auth header name');
      assert.ok(!/bearer/i.test(text), 'bearer value');
    }
    assert.equal(captured.trim(), '', 'nothing reaches the OS-level streams');
    if (posix) {
      assert.equal(mode(logFile), 0o600);
      assert.equal(mode(path.dirname(logFile)), 0o700);
      assert.equal(mode(home), 0o700);
      assert.equal(mode(path.join(home, 'vault.json')), 0o600);
      assert.equal(mode(path.join(home, 'wickey.db')), 0o600);
    }
  } finally {
    child.kill();
    await new Promise((r) => (child.exitCode !== null ? r(null) : child.once('exit', r)));
    upstream.close();
  }
});
