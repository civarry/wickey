import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, before, test } from 'node:test';

// The "since your last visit" marker: signed row, moves only on POST /api/events/seen.

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-seen-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '300';

const { createProxyServer } = await import('../src/proxy.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const ev = await import('../src/events.ts');

const PASS = 'correct horse battery staple';
let server: http.Server;
let port = 0;
let cookie = '';

before(async () => {
  session.setUp(PASS);
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
  const { sessionCookie } = await import('./helpers.ts');
  cookie = await sessionCookie();
});

after(() => {
  store.closeStore();
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
});

async function api(method: string, p: string, body?: unknown, cookieHeader: string | null = cookie) {
  const res = await fetch(`http://127.0.0.1:${port}${p}`, {
    method,
    headers: { 'x-wickey': '1', ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(cookieHeader ? { cookie: cookieHeader } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
}

test('POST /api/events/seen needs a session, and GET /api/events returns the marker', async () => {
  assert.equal((await api('POST', '/api/events/seen', { seq: 0 }, null)).status, 401);
  assert.equal((await api('GET', '/api/events', undefined, null)).status, 401);

  const first = await api('GET', '/api/events?limit=1');
  assert.equal(first.status, 200);
  assert.equal(first.body.seen, 0);
  assert.equal(first.body.seenState, 'missing');
  assert.ok(first.body.head >= 1);
  assert.equal(first.body.unseen.vault_created, 1);
});

test('the marker moves only on POST, is signed, and survives sign-in', async () => {
  // A key with no limits is banner-worthy; one with limits and a sign-in are routine.
  const cred = await api('POST', '/api/credentials', { name: 'work', provider: 'custom', apiKey: 'sk-REAL-1', baseUrl: 'http://127.0.0.1:9/v1' });
  assert.equal(cred.status, 201, JSON.stringify(cred.body));
  assert.equal((await api('POST', '/api/proxies', { credential: 'work', label: 'open' })).status, 201);
  assert.equal((await api('POST', '/api/proxies', { credential: 'work', label: 'capped', limits: { models: ['m'], rpm: 5, tokenCap: null, refuseUncounted: false } })).status, 201);

  let r = await api('GET', '/api/events');
  assert.equal(r.body.unseen.key_unrestricted, 1, 'only the key without limits counts');
  assert.equal(r.body.unseen.signed_in, undefined);
  const head = r.body.head;

  assert.equal((await api('POST', '/api/events/seen', { seq: head })).status, 200);
  const row = store.readEventsSeen();
  assert.equal(row.state, 'ok', 'stored in a signed row');
  assert.equal(row.state === 'ok' && row.seq, head);
  assert.equal(row.state === 'ok' && row.hash, ev.listEvents({ limit: 1 }).events[0].hash, 'pinned to that entry');
  r = await api('GET', '/api/events');
  assert.equal(r.body.seen, head);
  assert.equal(r.body.seenState, 'ok');
  assert.deepEqual(r.body.unseen, {});

  // The CLI signs in on every command: that must not touch the marker.
  const signedIn = await api('POST', '/api/signin', { passphrase: PASS }, null);
  assert.equal(signedIn.status, 200);
  const seenAfter = (await api('GET', '/api/events')).body;
  assert.equal(seenAfter.seen, head);
  assert.equal(seenAfter.unseen.signed_in, undefined);

  // New events bring the banner back.
  assert.equal((await api('POST', '/api/proxies', { credential: 'work', label: 'open2' })).status, 201);
  assert.equal((await api('GET', '/api/events')).body.unseen.key_unrestricted, 1);

  // Never backwards, never past the newest event, whole numbers only.
  const now = (await api('GET', '/api/events')).body.head;
  assert.equal((await api('POST', '/api/events/seen', { seq: 1 })).body.seen, head, 'a lower seq leaves the marker where it was');
  for (const seq of [now + 1, -1, 1.5, '3', null]) assert.equal((await api('POST', '/api/events/seen', { seq })).status, 400, String(seq));
  assert.equal((await api('GET', '/api/events')).body.seen, head);
});

test('a marker row that fails its signature counts as no marker, and is recorded once', async () => {
  const before = (await api('GET', '/api/events')).body;
  assert.ok(before.seen > 0);
  const db = new DatabaseSync(path.join(home, 'wickey.db'));
  db.prepare('UPDATE event_settings SET seen_seq = ? WHERE id = 1').run(before.head + 1000); // edit without re-signing
  db.close();

  const r = (await api('GET', '/api/events')).body;
  assert.equal(r.seenState, 'tampered');
  assert.equal(r.seen, 0, 'an edited marker must not hide anything');
  assert.ok(r.unseen.vault_created >= 1);
  assert.equal(r.unseen.tamper_detected, 1);
  await api('GET', '/api/events');
  assert.equal((await api('GET', '/api/events?type=tamper_detected')).body.events.length, 1, 'recorded once, not on every read');

  // Marking as seen writes a fresh signed row.
  const head = (await api('GET', '/api/events')).body.head;
  assert.equal((await api('POST', '/api/events/seen', { seq: head })).status, 200);
  assert.equal(store.readEventsSeen().state, 'ok');
  assert.equal((await api('GET', '/api/events')).body.seenState, 'ok');
});

test('GET /api/events filters by type and rejects a bad one', async () => {
  const r = await api('GET', '/api/events?type=key_issued');
  assert.equal(r.status, 200);
  assert.ok(r.body.events.length >= 3);
  assert.ok(r.body.events.every((e: any) => e.type === 'key_issued'));
  assert.equal((await api('GET', '/api/events?type=a%20b')).status, 400);
});

test('a log cut back under the marker invalidates it, so the tamper record is not hidden behind it', async () => {
  const head = (await api('GET', '/api/events')).body.head;
  assert.equal((await api('POST', '/api/events/seen', { seq: head })).status, 200);
  const logFile = path.join(home, 'events.log');
  const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
  fs.writeFileSync(logFile, `${lines.slice(0, -3).join('\n')}\n`);

  // The next signed write notices the missing tail and records tamper_detected, with a seq below the old marker.
  assert.equal((await api('POST', '/api/proxies', { credential: 'work', label: 'after-cut' })).status, 201);
  const r = (await api('GET', '/api/events')).body;
  assert.ok(r.head < head + 1);
  assert.equal(r.seenState, 'mismatch');
  assert.equal(r.seen, 0);
  assert.equal(r.unseen.tamper_detected, 1);
  assert.equal(r.unseen.key_unrestricted >= 1, true);

  // Acknowledging pins a new marker to the log as it is now.
  assert.equal((await api('POST', '/api/events/seen', { seq: r.head })).body.seen, r.head);
  const after = (await api('GET', '/api/events')).body;
  assert.equal(after.seenState, 'ok');
  assert.deepEqual(after.unseen, {});
});
