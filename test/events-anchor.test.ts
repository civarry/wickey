import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';

// The anchor (events.anchor + a Keychain copy) must catch what the chain and MACs cannot:
// truncation, and rewriting the whole log as unsigned entries that the next checkpoint would sign.

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-anchor-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';

const ev = await import('../src/events.ts');
const vault = await import('../src/vault.ts');
const { performReset } = await import('../src/reset.ts');
const { MacKeychain } = await import('../src/keychain.ts');

const PASS = 'correct horse battery staple';
const PASS2 = 'a completely different passphrase';
const logFile = path.join(home, 'events.log');
const anchorFile = path.join(home, 'events.anchor');

/** In-memory Keychain; `store` is what a program running `security` could read or rewrite. */
const store = new Map<string, string>();
const fakeKeychain = {
  get: (a: string) => (store.has(a) ? { state: 'ok' as const, value: store.get(a)! } : { state: 'none' as const }),
  set: (a: string, v: string) => { store.set(a, v); return true; },
};
const kcValue = () => [...store.values()][0];
ev.setKeychain(fakeKeychain);

after(() => fs.rmSync(home, { recursive: true, force: true }));

const readLines = () => fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean);
const writeLines = (l: string[]) => fs.writeFileSync(logFile, l.join('\n') + '\n');
const types = () => readLines().map((x) => JSON.parse(x).type);
const canon = (v: any): string => Array.isArray(v) ? `[${v.map(canon).join(',')}]` : v && typeof v === 'object'
  ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}` : JSON.stringify(v);
const hashOf = (e: any) => createHash('sha256').update(canon({ seq: e.seq, ts: e.ts, type: e.type, data: e.data, prev: e.prev })).digest('hex');

function fresh(): void {
  fs.rmSync(logFile, { force: true });
  fs.rmSync(anchorFile, { force: true });
  store.clear();
  if (!vault.vaultExists()) vault.createVault(PASS);
  vault.unlockVault(PASS);
}
function signed(n: number): void {
  for (let i = 1; i <= n; i++) ev.appendEvent('note', { n: i });
}
/** Mute the one-line stderr warning so test output stays readable. */
function quiet<T>(fn: () => T): T {
  const w = process.stderr.write;
  process.stderr.write = (() => true) as any;
  try { return fn(); } finally { process.stderr.write = w; }
}
const tampered = () => readLines().map((x) => JSON.parse(x)).filter((e) => e.type === 'tamper_detected');

test('first start with no log and no anchor is ok; appends write the anchor (0600)', () => {
  fresh();
  assert.equal(ev.checkAnchor(), 'ok');
  signed(3);
  const a = JSON.parse(fs.readFileSync(anchorFile, 'utf8'));
  assert.equal(a.seq, 3);
  assert.equal(a.hash, JSON.parse(readLines()[2]).hash);
  assert.equal(fs.statSync(anchorFile).mode & 0o777, 0o600);
  assert.equal(kcValue(), `3:${a.hash}`);
  assert.equal(ev.checkAnchor(), 'ok');
  assert.equal(ev.verifyLog().anchor, 'ok');
});

test('locked: the anchor is unchecked and is not a failure', () => {
  fresh();
  signed(2);
  vault.lockVault();
  assert.equal(ev.checkAnchor(), 'unchecked');
  const s = ev.verifyLog();
  assert.equal(s.anchor, 'unchecked');
  assert.equal(s.ok, true);
  vault.unlockVault(PASS);
});

test('truncating the newest entries is caught and recorded', () => {
  fresh();
  signed(6);
  writeLines(readLines().slice(0, 3));
  assert.equal(ev.checkAnchor(), 'truncated');
  const s = ev.verifyLog();
  assert.equal(s.ok, false);
  assert.equal(s.anchor, 'truncated');

  quiet(() => ev.appendEvent('after'));
  const t = tampered();
  assert.equal(t.length, 1);
  assert.equal(t[0].data.anchor, 'truncated');
  assert.equal(t[0].data.expectedSeq, 6);
  assert.equal(t[0].data.foundSeq, 3);
  assert.ok(t[0].mac, 'the tamper record is signed');
  assert.equal(ev.checkAnchor(), 'ok', 'recorded once, then the anchor follows the new head');
  assert.match(ev.verifyLog().notes.join(' '), /1 tamper detection/);
});

test('LAUNDERING: a log rewritten as unsigned entries is a mismatch, not folded in at unlock', () => {
  fresh();
  signed(4);
  vault.lockVault();
  // A program without the passphrase writes a self-consistent chain of unsigned entries.
  let prev = 'wickey-events-genesis';
  const forged = [1, 2, 3, 4, 5].map((seq) => {
    const e: any = { seq, ts: new Date().toISOString(), type: 'note', data: { forged: seq }, prev };
    e.hash = hashOf(e);
    e.mac = null;
    prev = e.hash;
    return JSON.stringify(e);
  });
  writeLines(forged);
  assert.equal(ev.verifyLog().ok, true, 'locked, the forgery is a consistent chain (that is the attack)');

  vault.unlockVault(PASS);
  assert.equal(ev.checkAnchor(), 'mismatch');
  assert.equal(ev.verifyLog().ok, false);

  quiet(() => ev.appendEvent('unlocked'));
  const t = tampered();
  assert.equal(t.length, 1);
  assert.equal(t[0].data.anchor, 'mismatch');
  assert.equal(types().indexOf('tamper_detected'), 5, 'recorded right after the forged entries, before anything else');
  const { events } = ev.listEvents({ limit: 200 });
  for (const e of events.filter((x) => x.data.forged !== undefined)) {
    assert.notEqual(e.trust, 'verified');
    assert.equal(e.trust, 'recorded_while_locked');
  }
});

test('deleting events.anchor is reported as missing', () => {
  fresh();
  signed(3);
  fs.rmSync(anchorFile);
  assert.equal(ev.checkAnchor(), 'missing');
  assert.equal(ev.verifyLog().ok, false);
  quiet(() => ev.appendEvent('after'));
  assert.equal(tampered()[0].data.anchor, 'missing');
  assert.ok(fs.existsSync(anchorFile), 'a fresh anchor is written after the record');
  assert.equal(ev.checkAnchor(), 'ok');
});

test('a forged anchor file (valid shape, no key) is a mismatch', () => {
  fresh();
  signed(3);
  const a = JSON.parse(fs.readFileSync(anchorFile, 'utf8'));
  fs.writeFileSync(anchorFile, JSON.stringify({ ...a, seq: 2, hash: JSON.parse(readLines()[1]).hash }));
  assert.equal(ev.checkAnchor(), 'mismatch');
  fs.writeFileSync(anchorFile, 'garbage');
  assert.equal(ev.checkAnchor(), 'mismatch');
});

test('rolling back the anchor file and the log together is caught by the Keychain', () => {
  fresh();
  signed(2);
  const oldAnchor = fs.readFileSync(anchorFile, 'utf8');
  const oldLog = readLines().slice();
  signed(4);
  fs.writeFileSync(anchorFile, oldAnchor);
  writeLines(oldLog);
  assert.equal(ev.checkAnchor(), 'rolled_back');
  assert.equal(ev.verifyLog().ok, false);
  quiet(() => ev.appendEvent('after'));
  assert.equal(tampered()[0].data.anchor, 'rolled_back');
});

test('ACCEPTED LIMIT: rolling back the log, the file AND the Keychain together is not detected', () => {
  fresh();
  signed(2);
  const oldAnchor = fs.readFileSync(anchorFile, 'utf8');
  const oldLog = readLines().slice();
  const oldKc = kcValue();
  signed(4);
  fs.writeFileSync(anchorFile, oldAnchor);
  writeLines(oldLog);
  for (const k of store.keys()) store.set(k, oldKc);
  assert.equal(ev.checkAnchor(), 'ok');
});

test('reset, then truncating the old entries, is still caught through the Keychain', () => {
  fresh();
  signed(5);
  vault.lockVault();
  performReset();
  assert.equal(fs.existsSync(anchorFile), false, 'reset deletes the anchor file (its key is gone)');
  assert.equal(store.size, 1, 'reset keeps the Keychain copy');
  fs.rmSync(path.join(home, 'vault.json'), { force: true });
  vault.createVault(PASS2);
  assert.equal(ev.checkAnchor(), 'ok', 'untouched: a legitimate reset is not an alarm');
  quiet(() => ev.appendEvent('after_reset'));
  assert.equal(tampered().length, 0);
  assert.equal(ev.checkAnchor(), 'ok');
  assert.ok(fs.existsSync(anchorFile), 'first signed append after setup writes a fresh anchor');

  // Second reset, then an attacker cuts the old part off the log.
  vault.lockVault();
  performReset();
  fs.rmSync(path.join(home, 'vault.json'), { force: true });
  vault.createVault(PASS);
  writeLines(readLines().slice(-1)); // keep only the final `reset` line
  const c = ev.checkAnchor();
  assert.ok(c === 'truncated' || c === 'mismatch', c);
  quiet(() => ev.appendEvent('after'));
  assert.equal(tampered().length, 1);
});

test('normal operation: many events, lock/unlock cycles, failed unlocks, always ok', () => {
  fresh();
  for (let round = 0; round < 5; round++) {
    signed(10);
    vault.lockVault();
    ev.appendEvent('unlock_failed', { round });
    ev.appendEvent('unlock_failed', { round });
    assert.equal(ev.checkAnchor(), 'unchecked');
    vault.unlockVault(PASS);
    quiet(() => ev.appendEvent('unlocked'));
    assert.equal(ev.checkAnchor(), 'ok');
  }
  assert.equal(tampered().length, 0);
  const s = ev.verifyLog();
  assert.equal(s.ok, true, s.reason);
  assert.equal(s.anchor, 'ok');
});

test('a Keychain that is unavailable never blocks or alarms', () => {
  fresh();
  const none = { get: () => ({ state: 'unavailable' as const }), set: () => false };
  ev.setKeychain(none);
  try {
    signed(3);
    assert.equal(ev.checkAnchor(), 'ok');
    writeLines(readLines().slice(0, 2));
    assert.equal(ev.checkAnchor(), 'truncated', 'the file copy alone still catches truncation');
  } finally {
    ev.setKeychain(fakeKeychain);
  }
});

test('real macOS Keychain: set, get, update, delete under a test-only service', { skip: process.platform !== 'darwin' }, () => {
  const service = 'dev.wickey.events.test';
  const account = randomBytes(8).toString('hex');
  const k = new MacKeychain(service);
  try {
    assert.deepEqual(k.get(account), { state: 'none' });
    assert.equal(k.set(account, `1:${'a'.repeat(64)}`), true);
    assert.deepEqual(k.get(account), { state: 'ok', value: `1:${'a'.repeat(64)}` });
    assert.equal(k.set(account, `2:${'b'.repeat(64)}`), true, '-U updates in place');
    assert.deepEqual(k.get(account), { state: 'ok', value: `2:${'b'.repeat(64)}` });
  } finally {
    k.remove(account);
    assert.deepEqual(k.get(account), { state: 'none' });
    try { execFileSync('/usr/bin/security', ['delete-generic-password', '-s', service, '-a', account], { stdio: 'ignore' }); } catch { /* already gone */ }
  }
});
