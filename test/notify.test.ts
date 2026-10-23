import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { sessionCookie } from './helpers.ts';

// Desktop notifications for security events. Every test injects a recording notifier: nothing here
// may ever show a real notification (the default backend is off under `node --test` anyway).

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-notify-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
process.env.WICKEY_GRACE = '300';
const PASS = 'correct horse battery staple';

const notify = await import('../src/notify.ts');
const { logEvent } = await import('../src/audit.ts');
const ev = await import('../src/events.ts');
const store = await import('../src/store.ts');
const session = await import('../src/session.ts');
const { createProxyServer } = await import('../src/proxy.ts');
const { performReset } = await import('../src/reset.ts');

interface Sent { title: string; body: string }
const sent: Sent[] = [];
const recorder: import('../src/notify.ts').Notifier = {
  name: 'recorder',
  available: true,
  send: (title, body) => { sent.push({ title, body }); },
};
notify.setNotifier(recorder);

/** Clears what was recorded and forgets coalescing windows, so each test starts clean. */
function fresh(): void {
  sent.length = 0;
  notify.resetNotifyState();
  notify.setCoalesceWindow(null);
  notify.setNotifier(recorder);
}

let server: http.Server;
let port = 0;
const dbFile = path.join(home, 'wickey.db');

before(async () => {
  session.setUp(PASS, 'setup_link');
  server = createProxyServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});

after(() => {
  store.closeStore();
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
});

async function api(method: string, p: string, body?: unknown): Promise<{ status: number; body: any }> {
  const res = await fetch(`http://127.0.0.1:${port}${p}`, {
    method,
    headers: { 'x-wickey': '1', cookie: await sessionCookie(), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

const eventsOf = (type: string) => ev.listEvents({ limit: 200 }).events.filter((e) => e.type === type);

test('setting a passphrase through the setup link notifies once (this ran in before())', () => {
  // `before` ran setUp before any test, with the recorder installed at import time.
  assert.equal(sent.length, 1);
  assert.equal(sent[0].title, 'Wickey');
  assert.match(sent[0].body, /^A passphrase was set through the setup link\. If this wasn't you: stop Wickey, run `wickey reset`/);
});

test('a passphrase set in a terminal says so', () => {
  fresh();
  logEvent('vault_created', { via: 'terminal' });
  assert.equal(sent.length, 1);
  assert.match(sent[0].body, /^A passphrase was set in a terminal\./);
});

// [type, data, text that must appear in the one notification]
const NOTIFYING: [string, Record<string, string | number | boolean | null>, string[]][] = [
  ['unlocked', { via: 'dashboard' }, ['Wickey was unlocked from the dashboard.', 'If this wasn\'t you: run `wickey lock`']],
  ['passphrase_changed', { via: 'cli' }, ['The passphrase was changed from the command line.', '`wickey reset`']],
  ['reset', { credentials: 2, proxies: 3 }, ['Wickey was reset', 'rotate your real provider keys']],
  ['passphrase_throttled', {}, ['Several wrong passphrases', '`wickey lock`']],
  ['key_issued', { proxyId: 'ab12cd34', credential: 'work', label: 'ci-runner', via: 'cli', op: 'issue', models: 3, unlimited: true }, ['A key with no limits was issued: "ci-runner" (proxy ab12cd34, from the command line).', 'run `wickey expire ab12cd34`']],
  ['key_issued', { proxyId: 'ef56ab78', credential: 'work', label: 'agent', via: 'dashboard', op: 'env', models: 'all', unlimited: false }, ['A key for all models was issued: "agent" (proxy ef56ab78, from the dashboard).', 'run `wickey expire ef56ab78`']],
  ['limits_loosened', { proxyId: 'ab12cd34', via: 'dashboard', before: 'x', after: 'y' }, ['Limits were loosened on proxy ab12cd34', 'run `wickey expire ab12cd34`']],
  ['auto_renew_enabled', { proxyId: 'ab12cd34', via: 'cli', window: 60, maxLifetime: 600 }, ['Auto-renew was turned on for proxy ab12cd34', '`wickey limits ab12cd34 --no-auto-renew`']],
  ['tamper_detected', { anchor: 'truncated', foundSeq: 3 }, ['signs of tampering', 'the event log failed its anchor check (truncated)', 'check the security event log', 'rotate your keys']],
  ['tamper_detected', { what: 'notification settings' }, ['signs of tampering: notification settings.']],
  ['notifications_changed', { type: 'unlocked', enabled: false, via: 'cli' }, ['Notifications for "unlocked" were turned off from the command line.', '`wickey notifications on unlocked`']],
];

for (const [type, data, expected] of NOTIFYING) {
  test(`${type} ${JSON.stringify(data).slice(0, 40)} sends exactly one notification with a next step`, () => {
    fresh();
    logEvent(type, data);
    assert.equal(sent.length, 1, JSON.stringify(sent));
    assert.equal(sent[0].title, 'Wickey');
    for (const text of expected) assert.ok(sent[0].body.includes(text), `"${text}" not in: ${sent[0].body}`);
    assert.match(sent[0].body, /If this wasn't you: .+\.$/);
    assert.ok(!sent[0].body.includes('—'), 'no em dash in user-facing copy');
  });
}

test('events that are not alerts, and keys with limits, send nothing', () => {
  fresh();
  logEvent('signed_in', { via: 'dashboard' });
  logEvent('locked', { via: 'dashboard' });
  logEvent('unlock_failed', { via: 'dashboard' });
  logEvent('key_renewed', { proxyId: 'ab12cd34', via: 'cli' });
  logEvent('limits_tightened', { proxyId: 'ab12cd34', via: 'cli' });
  logEvent('credential_added', { name: 'work', via: 'cli' });
  logEvent('credential_changed', { name: 'work', via: 'cli' });
  logEvent('credential_removed', { name: 'work', via: 'cli' });
  logEvent('credentials_imported', { count: 2, via: 'cli' });
  logEvent('key_issued', { proxyId: 'ab12cd34', credential: 'work', label: 'x', via: 'cli', op: 'issue', models: 2, rpm: 10, tokenCap: null, unlimited: false });
  logEvent('key_issued', { proxyId: 'ab12cd34', credential: 'work', label: 'x', via: 'cli', op: 'issue', models: 'none', unlimited: false });
  assert.deepEqual(sent, []);
});

test('a label with control characters is flattened to one bounded line', () => {
  fresh();
  logEvent('key_issued', { proxyId: 'ab12cd34', credential: 'work', label: `a\nb\u0007${'z'.repeat(100)}`, via: 'cli', op: 'issue', models: 'all', unlimited: true });
  assert.equal(sent.length, 1);
  assert.ok(!/[\u0000-\u001f]/.test(sent[0].body));
  assert.ok(sent[0].body.length < 300);
});

// ---- Coalescing ----

test('five identical events: one notification now and one summary when the window ends', () => {
  fresh();
  for (let i = 0; i < 5; i++) logEvent('limits_loosened', { proxyId: 'aaaa1111', via: 'cli', before: 'a', after: 'b' });
  assert.equal(sent.length, 1);
  notify.flushSummaries();
  assert.equal(sent.length, 2);
  assert.match(sent[1].body, /^4 more limit loosenings in the last minute\. If this wasn't you: run `wickey expire aaaa1111`\.$/);
  notify.flushSummaries();
  assert.equal(sent.length, 2, 'a summary is sent once');
});

test('different subjects are not merged, and a lone event gets no summary', () => {
  fresh();
  logEvent('limits_loosened', { proxyId: 'aaaa1111', via: 'cli' });
  logEvent('limits_loosened', { proxyId: 'bbbb2222', via: 'cli' });
  logEvent('auto_renew_enabled', { proxyId: 'aaaa1111', via: 'cli' });
  assert.equal(sent.length, 3);
  notify.flushSummaries();
  assert.equal(sent.length, 3);
});

test('the summary arrives by itself when the window ends', async () => {
  fresh();
  notify.setCoalesceWindow(40);
  for (let i = 0; i < 3; i++) logEvent('unlocked', { via: 'cli' });
  assert.equal(sent.length, 1);
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(sent.length, 2);
  assert.match(sent[1].body, /^2 more unlocks in the last minute\./);
  // The window closed: the next event notifies again.
  logEvent('unlocked', { via: 'cli' });
  assert.equal(sent.length, 3);
});

test('a settings change is never merged into an earlier one', () => {
  fresh();
  for (let i = 0; i < 3; i++) logEvent('notifications_changed', { type: 'unlocked', enabled: true, via: 'cli' });
  assert.equal(sent.length, 3);
});

// ---- Settings: OFF needs the passphrase, ON does not ----

test('GET /api/notifications lists every type, which are locked on, and the backend', async () => {
  fresh();
  const r = await api('GET', '/api/notifications');
  assert.equal(r.status, 200);
  const byType = Object.fromEntries(r.body.types.map((t: any) => [t.type, t]));
  for (const t of ['vault_created', 'unlocked', 'passphrase_changed', 'reset', 'passphrase_throttled', 'key_issued', 'limits_loosened', 'auto_renew_enabled', 'tamper_detected', 'notifications_changed']) {
    assert.equal(byType[t]?.enabled, true, t);
  }
  assert.equal(byType.tamper_detected.locked, true);
  assert.equal(byType.notifications_changed.locked, true);
  assert.equal(byType.unlocked.locked, false);
  assert.deepEqual(r.body.backend, { name: 'recorder', available: true });
});

test('turning a type OFF without the passphrase is refused, even inside the grace period', async () => {
  fresh();
  assert.ok(session.graceRemaining() > 0, 'the grace period is running');
  const before = eventsOf('notifications_changed').length;
  const r = await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: false });
  assert.equal(r.status, 401);
  assert.equal(r.body.error.code, 'passphrase_required');
  assert.equal(r.body.error.humanRequired, true);
  assert.equal((await api('GET', '/api/notifications')).body.types.find((t: any) => t.type === 'unlocked').enabled, true);
  assert.equal(eventsOf('notifications_changed').length, before);
  assert.deepEqual(sent, []);
});

test('a wrong passphrase is refused, counted as a failed attempt, and changes nothing', async () => {
  fresh();
  const failed = eventsOf('unlock_failed').length;
  const r = await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: false, passphrase: 'not the passphrase at all' });
  assert.equal(r.status, 401);
  assert.equal(r.body.error.code, 'wrong_passphrase');
  assert.equal(eventsOf('unlock_failed').length, failed + 1);
  assert.equal((await api('GET', '/api/notifications')).body.types.find((t: any) => t.type === 'unlocked').enabled, true);
  assert.deepEqual(sent, [], 'a failed attempt is not an alert');
});

test('types that cannot be turned off, unknown types, bad bodies', async () => {
  fresh();
  for (const type of ['tamper_detected', 'notifications_changed']) {
    const r = await api('PATCH', '/api/notifications', { type, enabled: false, passphrase: PASS });
    assert.equal(r.status, 400, type);
    assert.match(r.body.error.message, /cannot be turned off/);
  }
  assert.equal((await api('PATCH', '/api/notifications', { type: 'nope', enabled: false, passphrase: PASS })).status, 400);
  assert.equal((await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: 'no', passphrase: PASS })).status, 400);
  assert.equal((await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: false, passphrase: PASS, extra: 1 })).status, 400);
  assert.deepEqual(sent, []);
});

test('the right passphrase turns a type off: signed row, logged, alerted, and that type goes quiet', async () => {
  fresh();
  const r = await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: false, passphrase: PASS });
  assert.equal(r.status, 200);
  assert.equal(r.body.types.find((t: any) => t.type === 'unlocked').enabled, false);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body, /^Notifications for "unlocked" were turned off from the dashboard\. If this wasn't you: run `wickey notifications on unlocked`/);
  const logged = eventsOf('notifications_changed')[0];
  assert.deepEqual(logged.data, { type: 'unlocked', enabled: false, via: 'dashboard' });
  const d = new DatabaseSync(dbFile);
  const row = d.prepare('SELECT * FROM notification_settings').get() as any;
  d.close();
  assert.equal(row.disabled, 'unlocked');
  assert.match(String(row.sig), /^[0-9a-f]{64}$/, 'the row is signed');

  sent.length = 0;
  logEvent('unlocked', { via: 'cli' });
  assert.deepEqual(sent, [], 'a type that is off is silent');
  logEvent('passphrase_changed', { via: 'cli' });
  assert.equal(sent.length, 1, 'other types still notify');
});

test('turning a type back ON needs only the session, and still alerts', async () => {
  fresh();
  const r = await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: true });
  assert.equal(r.status, 200);
  assert.equal(r.body.types.find((t: any) => t.type === 'unlocked').enabled, true);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body, /turned on from the dashboard/);
  assert.deepEqual(eventsOf('notifications_changed')[0].data, { type: 'unlocked', enabled: true, via: 'dashboard' });
  sent.length = 0;
  logEvent('unlocked', { via: 'cli' });
  assert.equal(sent.length, 1);
});

test('real actions notify: an unlimited key over the API, then loosening limits', async () => {
  fresh();
  store.addCredential({ name: 'work', provider: 'custom', apiKey: 'sk-REAL-work-key', baseUrl: 'http://127.0.0.1:9/v1' });
  const issued = await api('POST', '/api/proxies', { credential: 'work', ttl: '10m', label: 'agent', limits: { models: null } });
  assert.equal(issued.status, 201, JSON.stringify(issued.body));
  const id = issued.body.proxy.id;
  assert.equal(sent.length, 1, JSON.stringify(sent));
  assert.ok(sent[0].body.includes(`proxy ${id}`) && sent[0].body.includes(`run \`wickey expire ${id}\``));
  assert.ok(!JSON.stringify(sent).includes(issued.body.token), 'the proxy key is never in a notification');

  sent.length = 0;
  const tight = await api('POST', '/api/proxies', { credential: 'work', ttl: '10m', label: 'safe', limits: { models: ['m1'], rpm: 5, tokenCap: 100 } });
  assert.equal(sent.length, 0, 'a limited key is not an alert');
  const tid = tight.body.proxy.id;
  const loosen = await api('PATCH', `/api/proxies/${tid}/limits`, { limits: { models: ['m1'], rpm: 50, tokenCap: 100 } });
  assert.equal(loosen.status, 200, JSON.stringify(loosen.body));
  assert.equal(sent.length, 1);
  assert.match(sent[0].body, new RegExp(`^Limits were loosened on proxy ${tid}`));
});

// ---- Tampered settings row ----

test('a settings row that fails its signature means all on, and one tamper_detected per process start', async () => {
  fresh();
  await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: false, passphrase: PASS });
  sent.length = 0;
  const d = new DatabaseSync(dbFile);
  d.prepare("UPDATE notification_settings SET disabled = 'unlocked,key_issued,reset'").run(); // sig now wrong
  d.close();
  notify.resetNotifyState(); // as a fresh process start
  const before = eventsOf('tamper_detected').filter((e) => e.data.what === 'notification settings').length;

  logEvent('unlocked', { via: 'cli' });
  assert.equal(eventsOf('tamper_detected').filter((e) => e.data.what === 'notification settings').length, before + 1);
  assert.ok(sent.some((s) => s.body.includes('signs of tampering: notification settings')), 'the tamper alert is sent');
  assert.ok(sent.some((s) => s.body.startsWith('Wickey was unlocked')), 'the type the forged row tried to silence still notifies');
  logEvent('key_issued', { proxyId: 'ab12cd34', label: 'q', via: 'cli', models: 'all', unlimited: true });
  logEvent('reset', {});
  assert.equal(eventsOf('tamper_detected').filter((e) => e.data.what === 'notification settings').length, before + 1, 'reported once');
  assert.equal(sent.filter((s) => /Wickey was unlocked|no limits|Wickey was reset/.test(s.body)).length, 3);

  // A legitimate change replaces the bad row with a valid one.
  const r = await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: true });
  assert.equal(r.status, 200);
  assert.ok(r.body.types.every((t: any) => t.enabled));
  notify.resetNotifyState();
  const n = eventsOf('tamper_detected').length;
  logEvent('unlocked', { via: 'cli' });
  assert.equal(eventsOf('tamper_detected').length, n);
});

// ---- A notifier can never hurt the action or the log ----

test('a notifier that throws, rejects or never finishes does not block the action or the log', async () => {
  const notifiers: import('../src/notify.ts').Notifier[] = [
    { name: 'throws', available: true, send: () => { throw new Error('boom'); } },
    { name: 'rejects', available: true, send: (() => Promise.reject(new Error('nope'))) as any },
    { name: 'hangs', available: true, send: (() => new Promise(() => {})) as any },
  ];
  for (const n of notifiers) {
    fresh();
    notify.setNotifier(n);
    const seq = ev.listEvents({ limit: 1 }).events[0].seq;
    const started = Date.now();
    logEvent('passphrase_changed', { via: 'cli' });
    assert.ok(Date.now() - started < 1000, `${n.name} did not block`);
    assert.ok(ev.listEvents({ limit: 1 }).events[0].seq > seq, `${n.name}: the event is in the log`);
    const r = await api('PATCH', '/api/notifications', { type: 'reset', enabled: true });
    assert.equal(r.status, 200, `${n.name}: the action succeeded`);
  }
  assert.equal(ev.verifyLog().ok, true);
  await new Promise((r) => setTimeout(r, 20)); // let a rejection surface; the run would fail on an unhandled one
});

// ---- Backends ----

const EVIL = 'a"\\" & do shell script "touch /tmp/pwned" & "\\';

test('macOS: title and body go as argv after the script, never into the AppleScript source', () => {
  const calls: { file: string; args: readonly string[]; options: any }[] = [];
  const mac = notify.macNotifier((file, args, options, cb) => { calls.push({ file, args, options }); cb(null); });
  fresh();
  notify.setNotifier(mac);
  logEvent('key_issued', { proxyId: 'ab12cd34', credential: 'work', label: EVIL, via: 'cli', op: 'issue', models: 'all', unlimited: true });
  assert.equal(calls.length, 1);
  const { file, args, options } = calls[0];
  assert.equal(file, '/usr/bin/osascript');
  assert.equal(options.timeout, 3000);
  const dash = args.indexOf('--');
  assert.equal(dash, args.length - 3, 'title and body are the last two args, after --');
  const script = args.slice(0, dash).join('\n');
  assert.ok(!script.includes('pwned') && !script.includes(EVIL) && !script.includes('Wickey'), 'the script source holds no event text');
  assert.deepEqual(args.slice(0, dash), ['-e', 'on run argv', '-e', 'display notification (item 2 of argv) with title (item 1 of argv)', '-e', 'end run']);
  assert.equal(args[dash + 1], 'Wickey');
  assert.ok(args[dash + 2].includes(`"${EVIL}"`), `the label arrives unchanged: ${args[dash + 2]}`);
});

test('macOS: osascript really hands argv back unchanged (no notification is shown)', { skip: process.platform !== 'darwin' }, () => {
  for (const text of [EVIL, '-e quoted --', 'plain']) {
    const out = execFileSync('/usr/bin/osascript', ['-e', 'on run argv', '-e', 'return item 2 of argv', '-e', 'end run', '--', 'title', text], { encoding: 'utf8', timeout: 10000 });
    assert.equal(out.replace(/\n$/, ''), text);
  }
});

test('Linux: notify-send gets the text as plain args after --', () => {
  const calls: { file: string; args: readonly string[] }[] = [];
  const linux = notify.linuxNotifier((file, args, _o, cb) => { calls.push({ file, args }); cb(null); }, '/usr/bin/notify-send');
  linux.send('Wickey', '--hint=evil');
  assert.deepEqual(calls, [{ file: '/usr/bin/notify-send', args: ['--app-name', 'Wickey', '--', 'Wickey', '--hint=evil'] }]);
});

test('the default backend is off under node --test and with WICKEY_NOTIFY=0', () => {
  const saved = process.env.WICKEY_NOTIFY;
  try {
    delete process.env.WICKEY_NOTIFY;
    assert.equal(notify.defaultNotifier().available, false);
    process.env.WICKEY_NOTIFY = '0';
    const n = notify.defaultNotifier();
    assert.equal(n.available, false);
    assert.match(n.reason ?? '', /WICKEY_NOTIFY=0/);
    n.send('x', 'y'); // does nothing
  } finally {
    if (saved === undefined) delete process.env.WICKEY_NOTIFY;
    else process.env.WICKEY_NOTIFY = saved;
  }
});

// ---- Throttle and reset (last: they leave the process in a throttled / reset state) ----

test('repeated wrong passphrases notify once when the throttle starts', async () => {
  fresh();
  for (let i = 0; i < 5; i++) {
    const r = await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: false, passphrase: `wrong guess number ${i}` });
    assert.equal(r.status, 401);
  }
  assert.equal(sent.length, 0);
  const blocked = await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: false, passphrase: PASS });
  assert.equal(blocked.status, 429);
  await api('PATCH', '/api/notifications', { type: 'unlocked', enabled: false, passphrase: PASS });
  assert.equal(sent.length, 1);
  assert.match(sent[0].body, /^Several wrong passphrases were entered/);
});

test('reset notifies from its own process, without recreating the database', () => {
  fresh();
  store.closeStore();
  performReset();
  assert.equal(sent.length, 1);
  assert.match(sent[0].body, /^Wickey was reset/);
  assert.equal(fs.existsSync(dbFile), false, 'reading the settings did not recreate the database');
});
