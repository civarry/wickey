import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { sessionCookie } from './helpers.ts';

// The security event log must show tampering by a same-user program that lacks the passphrase.
// Each detection test edits the file the way such a program would and expects verifyLog to say so.

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-events-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';

const { createProxyServer } = await import('../src/proxy.ts');
const ev = await import('../src/events.ts');
const vault = await import('../src/vault.ts');
const store = await import('../src/store.ts');
const { performReset } = await import('../src/reset.ts');
const { createHash } = await import('node:crypto');

const PASS = 'correct horse battery staple';
const PASS2 = 'a completely different passphrase';
const logFile = path.join(home, 'events.log');
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

const readLines = () => fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean);
const writeLines = (l: string[]) => fs.writeFileSync(logFile, l.join('\n') + '\n');
const edit = (i: number, fn: (e: any) => void) => {
  const l = readLines();
  const e = JSON.parse(l[i]);
  fn(e);
  l[i] = JSON.stringify(e);
  writeLines(l);
};
/** What a forger can do without the key: recompute a valid hash for an edited entry. */
function rehash(e: any): void {
  const canon = (v: any): string => Array.isArray(v) ? `[${v.map(canon).join(',')}]` : v && typeof v === 'object'
    ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}` : JSON.stringify(v);
  e.hash = createHash('sha256').update(canon({ seq: e.seq, ts: e.ts, type: e.type, data: e.data, prev: e.prev })).digest('hex');
}
function fresh(unlocked = true): void {
  fs.rmSync(logFile, { force: true });
  fs.rmSync(path.join(home, 'events.anchor'), { force: true });
  if (!vault.vaultExists()) vault.createVault(PASS);
  if (unlocked) vault.unlockVault(PASS);
  else vault.lockVault();
}
function five(): void {
  fresh();
  for (let i = 1; i <= 5; i++) ev.appendEvent('note', { n: i, name: `k${i}` });
}

test('appends chain correctly, are signed, and verify ok; file is 0600', () => {
  five();
  const s = ev.verifyLog();
  assert.equal(s.ok, true);
  assert.equal(s.entries, 5);
  assert.equal(s.macsChecked, true);
  const l = readLines().map((x) => JSON.parse(x));
  assert.deepEqual(l.map((e) => e.seq), [1, 2, 3, 4, 5]);
  assert.equal(l[1].prev, l[0].hash);
  assert.ok(l.every((e) => typeof e.mac === 'string'));
  assert.equal(fs.statSync(logFile).mode & 0o777, 0o600);
});

test('two appends in the same tick both land, in order', () => {
  fresh();
  ev.appendEvent('a');
  ev.appendEvent('b');
  assert.deepEqual(readLines().map((x) => JSON.parse(x).type), ['a', 'b']);
  assert.equal(ev.verifyLog().ok, true);
});

test('secrets are refused as event data', () => {
  fresh();
  assert.throws(() => ev.appendEvent('x', { passphrase: 'hunter2hunter2' }), /must not carry/);
  assert.throws(() => ev.appendEvent('x', { apiKey: 'abc' }), /must not carry/);
  assert.throws(() => ev.appendEvent('x', { note: 'sk-wick-abcdef' }), /proxy key/);
  assert.equal(fs.existsSync(logFile), false);
});

test('an edited entry is detected', () => {
  five();
  edit(2, (e) => { e.data.name = 'evil'; });
  const s = ev.verifyLog();
  assert.equal(s.ok, false);
  assert.equal(s.firstBadSeq, 3);
  assert.match(s.reason!, /edited/);
});

test('a deleted middle entry is detected', () => {
  five();
  const l = readLines();
  l.splice(2, 1);
  writeLines(l);
  const s = ev.verifyLog();
  assert.equal(s.ok, false);
  assert.equal(s.firstBadSeq, 4);
});

test('swapped entries are detected', () => {
  five();
  const l = readLines();
  [l[1], l[2]] = [l[2], l[1]];
  writeLines(l);
  const s = ev.verifyLog();
  assert.equal(s.ok, false);
  assert.equal(s.firstBadSeq, 3);
});

test('a garbage line is detected', () => {
  five();
  const l = readLines();
  l.splice(3, 0, '{not json');
  writeLines(l);
  const s = ev.verifyLog();
  assert.equal(s.ok, false);
  assert.match(s.reason!, /not a valid entry/);
});

test('a forged entry with a recomputed hash but no key is detected by its MAC', () => {
  five();
  // Replace the newest entry with a valid-looking one that keeps the old (now wrong) MAC.
  edit(4, (e) => { e.data.name = 'forged'; rehash(e); });
  let s = ev.verifyLog();
  assert.equal(s.ok, false);
  assert.equal(s.firstBadSeq, 5);
  assert.match(s.reason!, /MAC/);
  // A MAC made up out of thin air fails the same way.
  five();
  edit(4, (e) => { e.mac = 'ab'.repeat(32); });
  s = ev.verifyLog();
  assert.equal(s.ok, false);
  assert.match(s.reason!, /MAC/);
});

test('rewriting the middle of the chain without the key is detected by the later MACs', () => {
  five();
  const l = readLines().map((x) => JSON.parse(x));
  l[1].data.name = 'evil';
  for (let i = 1; i < l.length; i++) {
    if (i > 1) l[i].prev = l[i - 1].hash;
    rehash(l[i]);
  }
  writeLines(l.map((e) => JSON.stringify(e)));
  const s = ev.verifyLog();
  assert.equal(s.ok, false);
  assert.match(s.reason!, /MAC/);
});

test('a checkpoint with no MAC is detected', () => {
  fresh(false);
  ev.appendEvent('unlock_failed', { reason: 'wrong' });
  vault.unlockVault(PASS);
  ev.checkpoint();
  edit(1, (e) => { e.mac = null; });
  const s = ev.verifyLog();
  assert.equal(s.ok, false);
  assert.match(s.reason!, /checkpoint/);
});

test('entries written while locked have no MAC, get a checkpoint on unlock, and stay flagged', () => {
  fresh(false);
  ev.appendEvent('unlock_failed', { source: 'api' });
  ev.appendEvent('unlock_failed', { source: 'cli' });
  assert.ok(readLines().every((x) => JSON.parse(x).mac === null));
  let s = ev.verifyLog();
  assert.equal(s.ok, true);
  assert.equal(s.macsChecked, false);
  assert.match(s.notes.join(' '), /locked/);

  vault.unlockVault(PASS);
  const cp = ev.checkpoint();
  assert.equal(cp?.type, 'checkpoint');
  assert.equal(ev.checkpoint(), null, 'no second checkpoint when the head is already signed');
  s = ev.verifyLog();
  assert.equal(s.ok, true);
  assert.equal(s.macsChecked, true);
  assert.equal(s.whileLocked, 2);
  const { events } = ev.listEvents();
  assert.equal(events[0].trust, 'verified');
  assert.deepEqual(events.slice(1).map((e) => e.trust), ['recorded_while_locked', 'recorded_while_locked']);

  // Tampering with a locked-time entry still breaks the chain under the checkpoint.
  edit(0, (e) => { e.data.source = 'edited'; });
  assert.equal(ev.verifyLog().ok, false);
});

test('an event after unlocked-head with an unsigned head auto-checkpoints first', () => {
  fresh(false);
  ev.appendEvent('unlock_failed');
  vault.unlockVault(PASS);
  ev.appendEvent('setup');
  assert.deepEqual(readLines().map((x) => JSON.parse(x).type), ['unlock_failed', 'checkpoint', 'setup']);
});

test('reset keeps the file, appends reset, and older entries are "not verifiable", not tampered', () => {
  five();
  vault.lockVault();
  performReset();
  assert.equal(vault.vaultExists(), false);
  assert.equal(fs.existsSync(logFile), true, 'reset must not delete events.log');
  const l = readLines().map((x) => JSON.parse(x));
  assert.equal(l.length, 6);
  assert.equal(l[5].type, 'reset');
  assert.equal(l[5].mac, null);

  vault.createVault(PASS2); // new setup: new data key, so the old MACs cannot be checked
  const cp = ev.checkpoint();
  assert.equal(cp?.type, 'checkpoint');
  const s = ev.verifyLog();
  assert.equal(s.ok, true, s.reason);
  assert.equal(s.beforeReset, 5);
  const { events } = ev.listEvents();
  assert.equal(events[0].trust, 'verified');
  assert.deepEqual(events.slice(2).map((e) => e.trust), Array(5).fill('before_reset'));
  // The hash chain still covers the old part.
  edit(1, (e) => { e.data.name = 'evil'; });
  assert.equal(ev.verifyLog().ok, false);

  // Leave a usable vault for the next tests.
  fs.rmSync(path.join(home, 'vault.json'));
  vault.createVault(PASS);
});

test('a fake reset inserted to hide edits is caught: a real reset fails ALL old MACs', () => {
  five();
  edit(1, (e) => { e.data.name = 'evil'; rehash(e); });
  // Re-link the rest, keeping their MACs (most now fail, but entry 1 and 2 etc. differ).
  const l = readLines().map((x) => JSON.parse(x));
  for (let i = 2; i < l.length; i++) { l[i].prev = l[i - 1].hash; rehash(l[i]); }
  writeLines(l.map((e) => JSON.stringify(e)));
  vault.lockVault();
  vault.unlockVault(PASS);
  // Append a reset entry by hand, as an attacker could (no key needed).
  ev.appendEvent('reset', {}, { signed: false });
  const s = ev.verifyLog();
  assert.equal(s.ok, false);
  assert.match(s.reason!, /real reset cannot cause/);
});

test('the log is not deleted or truncated by listing, and a broken last line does not stop logging', () => {
  five();
  fs.appendFileSync(logFile, '{broken');
  const e = ev.appendEvent('after_garbage');
  assert.equal(e.seq, 7, 'checkpoint is #6, this event #7');
  assert.equal(ev.verifyLog().ok, false, 'the garbage line is still reported');
});

// ---- API ----

function get(p: string, cookie?: string): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, method: 'GET', path: p,
      headers: { host: `127.0.0.1:${port}`, 'x-wickey': '1', ...(cookie ? { cookie } : {}) },
    }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => resolve({ status: res.statusCode!, body: JSON.parse(text || '{}') }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('GET /api/events needs a session, pages newest first, caps limit, returns the summary', async () => {
  five();
  assert.equal((await get('/api/events')).status, 401);
  const cookie = await sessionCookie();

  const all = await get('/api/events', cookie);
  assert.equal(all.status, 200);
  assert.deepEqual(all.body.events.map((e: any) => e.seq), [5, 4, 3, 2, 1]);
  assert.equal(all.body.summary.ok, true);
  assert.equal(all.body.summary.entries, 5);
  assert.equal(all.body.events[0].trust, 'verified');

  const page = await get('/api/events?before=4&limit=2', cookie);
  assert.deepEqual(page.body.events.map((e: any) => e.seq), [3, 2]);

  assert.equal((await get('/api/events?limit=0', cookie)).status, 400);
  assert.equal((await get('/api/events?limit=201', cookie)).status, 400);
  assert.equal((await get('/api/events?before=abc', cookie)).status, 400);

  edit(2, (e) => { e.data.name = 'evil'; });
  const bad = await get('/api/events', cookie);
  assert.equal(bad.body.summary.ok, false);
  assert.equal(bad.body.summary.firstBadSeq, 3);
});
