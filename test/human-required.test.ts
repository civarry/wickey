import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, test } from 'node:test';

// Refusals that exist because no human is present must tell an AI agent to stop and ask its user.
// A nudge for cooperating agents, not a control: the passphrase and setup token are the controls.
// Everything runs against throwaway instances (own home, own port), as real child processes.

const script = fileURLToPath(new URL('../bin/wickey.js', import.meta.url));
const PASS = 'correct horse battery staple';
const PREFIX = 'This must be done by a human. If you are an AI agent, stop and ask the user to ';

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-human-'));
const children: ChildProcess[] = [];

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const p = (s.address() as net.AddressInfo).port; s.close(() => resolve(p)); });
  });
}

const env = (port: number) => ({ ...process.env, WICKEY_HOME: home, WICKEY_PORT: String(port), WICKEY_SCRYPT_N: '1024', WICKEY_GRACE: '0' });

/** `wickey start` with no terminal (detached = own session, so /dev/tty cannot open). Resolves with its stdout so far. */
async function startServer(port: number): Promise<{ child: ChildProcess; stdout: () => string }> {
  const child = spawn(process.execPath, [script, 'start'], { env: env(port), detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  children.push(child);
  let out = '';
  child.stdout!.on('data', (d) => (out += d));
  for (let i = 0; i < 100 && !/Dashboard: /.test(out); i++) await new Promise((r) => setTimeout(r, 100));
  assert.match(out, /Dashboard: /, 'server did not start');
  return { child, stdout: () => out };
}

async function stopServer(child: ChildProcess): Promise<void> {
  const exited = new Promise((r) => child.once('exit', r));
  child.kill();
  await exited;
}

function runCli(port: number, args: string[]): Promise<{ code: number | null; err: string }> {
  const child = spawn(process.execPath, [script, ...args], { env: env(port), stdio: ['ignore', 'pipe', 'pipe'], detached: true });
  let err = '';
  child.stderr.on('data', (d) => (err += d));
  const timer = setTimeout(() => child.kill(), 20_000);
  return new Promise((resolve) => child.on('close', (code) => { clearTimeout(timer); resolve({ code, err }); }));
}

interface Res { status: number; body: any; cookie: string | null }
function api(port: number, method: string, p: string, body?: unknown, cookie?: string | null): Promise<Res> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request({
      host: '127.0.0.1', port, method, path: p,
      headers: { host: `127.0.0.1:${port}`, 'x-wickey': '1', ...(payload ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) },
    }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => resolve({ status: res.statusCode!, body: JSON.parse(text || '{}'), cookie: res.headers['set-cookie']?.[0]?.split(';')[0] ?? null }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

after(() => {
  for (const c of children) if (c.exitCode === null) c.kill();
  fs.rmSync(home, { recursive: true, force: true });
});

const skip = process.platform === 'win32';

test('API refusals for a missing human keep their code and set humanRequired', { skip }, async () => {
  const port = await freePort();
  let srv = await startServer(port);
  const refusals: { name: string; res: Res; code: string | undefined; next: RegExp }[] = [];

  // Fresh install: no vault, no session.
  refusals.push({ name: 'session_required', res: await api(port, 'GET', '/api/state'), code: 'session_required', next: /sign in to the dashboard/ });
  refusals.push({ name: 'setup_required (signin)', res: await api(port, 'POST', '/api/signin', { passphrase: PASS }), code: 'setup_required', next: /one-time setup link printed by `wickey start`, or run `wickey setup` in their own terminal/ });
  refusals.push({ name: 'setup_required (unlock)', res: await api(port, 'POST', '/api/unlock', { passphrase: PASS }), code: 'setup_required', next: /`wickey setup`/ });
  const noToken = await api(port, 'POST', '/api/setup', { passphrase: PASS, token: 'guess' });
  refusals.push({ name: 'setup token 403', res: noToken, code: undefined, next: /one-time setup link printed by `wickey start`, or run `wickey setup` in their own terminal/ });
  assert.equal(noToken.status, 403);

  // Set the passphrase with the real link; the grace period is 0, so minting needs the passphrase every time.
  const token = /#setup=([\w-]+)/.exec(srv.stdout())?.[1];
  assert.ok(token, 'start prints the setup link');
  const setup = await api(port, 'POST', '/api/setup', { passphrase: PASS, token });
  assert.equal(setup.status, 201);
  const mint = await api(port, 'POST', '/api/proxies', { credential: 'x', ttl: '10m' }, setup.cookie);
  refusals.push({ name: 'passphrase_required (grace over)', res: mint, code: 'passphrase_required', next: /enter their passphrase in the dashboard/ });

  // Restart: the proxy comes back locked.
  await stopServer(srv.child);
  srv = await startServer(port);
  refusals.push({ name: 'passphrase_required (locked)', res: await api(port, 'POST', '/api/signin', { passphrase: PASS }), code: 'passphrase_required', next: /unlock Wickey in the dashboard with their passphrase, or run `wickey unlock` in their own terminal/ });

  for (const r of refusals) {
    const e = r.res.body.error;
    assert.ok(r.res.status === 401 || r.res.status === 403, `${r.name}: status ${r.res.status}`);
    assert.ok(typeof e?.message === 'string' && e.message.startsWith(PREFIX), `${r.name}: ${e?.message}`);
    assert.match(e.message, r.next, r.name);
    assert.ok(e.message.endsWith('.') && !e.message.endsWith('..'), r.name);
    assert.equal(e.code, r.code, `${r.name}: code`);
    assert.equal(e.humanRequired, true, `${r.name}: humanRequired`);
  }

  // A human typing the wrong passphrase is not a missing human.
  const wrong = await api(port, 'POST', '/api/unlock', { passphrase: 'not the passphrase at all' });
  assert.equal(wrong.body.error.code, 'wrong_passphrase');
  assert.equal(wrong.body.error.humanRequired, undefined);
  assert.ok(!wrong.body.error.message.startsWith(PREFIX));
  // Neither is a validation error.
  const unlocked = await api(port, 'POST', '/api/unlock', { passphrase: PASS });
  const bad = await api(port, 'POST', '/api/proxies', { credential: '', ttl: 'nope', passphrase: PASS }, unlocked.cookie);
  assert.ok(bad.status >= 400 && bad.body.error.humanRequired === undefined);
  assert.ok(!String(bad.body.error.message).startsWith(PREFIX));

  await stopServer(srv.child);
});

test('CLI refusals with no terminal name the exact command the agent ran', { skip }, async () => {
  const port = await freePort();
  const table: { args: string[]; echo: string }[] = [
    { args: ['issue', 'openai', '--ttl', '10m'], echo: 'wickey issue openai --ttl 10m' },
    { args: ['issue', 'my cred'], echo: "wickey issue 'my cred'" },
    { args: ['env', 'agent', '--credential', 'work', '--ttl', '1h'], echo: 'wickey env agent --credential work --ttl 1h' },
    { args: ['unlock'], echo: 'wickey unlock' },
    { args: ['passphrase'], echo: 'wickey passphrase' },
    { args: ['reset'], echo: 'wickey reset' },
    { args: ['setup'], echo: 'wickey setup' },
    { args: ['add', 'openai', '--provider', 'openai'], echo: 'wickey add openai --provider openai' },
    { args: ['edit', 'openai', '--key'], echo: 'wickey edit openai --key' },
    { args: ['remove', 'openai'], echo: 'wickey remove openai' },
  ];
  for (const { args, echo } of table) {
    const r = await runCli(port, args);
    assert.equal(r.code, 1, `${echo}: exit code`);
    assert.ok(r.err.startsWith(`error: ${PREFIX}run \`${echo}\` in their own terminal, or do it in the dashboard at http://127.0.0.1:${port}/.`), `${echo}: ${r.err}`);
  }
});
