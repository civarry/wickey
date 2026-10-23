import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.ts';
import { defaultKeychain, type Keychain } from './keychain.ts';
import { bannerKey, type Trust } from './eventtext.ts';
import { notifyEvent } from './notify.ts';
import { eventMac, isUnlocked, verifyEventMac } from './vault.ts';

// Security event log: an append-only JSON Lines file (`events.log`) that a same-user program
// cannot quietly rewrite. Each entry carries the hash of the previous one (a chain), and, when the
// vault was unlocked, an HMAC of its own hash under a key only the passphrase can produce. Editing,
// deleting or reordering entries breaks the chain; forging entries breaks the MACs. Entries written
// while locked (failed unlocks) have no MAC: the next unlock appends a `checkpoint` whose MAC
// covers the head, which authenticates the chain up to it.
//
// The anchor (`{seq, hash}` of the newest entry that has a MAC) is kept outside the log: in
// `events.anchor` (with a MAC, so it cannot be forged without the passphrase) and, on macOS, in the
// Keychain (plain, so it survives a reset). It is rewritten after every signed append and checked
// before anything is appended or checkpointed once the vault is unlocked. That catches truncation
// (the log ends before the anchor), laundering (the log was rewritten as unsigned entries that a
// checkpoint would otherwise sign) and rolling back only some of the copies. Rolling back the log,
// the file AND the Keychain item together is not detected.
//
// `data` must hold ids, names and limits only. Never a key, token, passphrase or provider secret.

export type EventData = Record<string, string | number | boolean | null | string[] | number[]>;

export interface EventEntry {
  seq: number;
  ts: string;
  type: string;
  data: EventData;
  prev: string;
  hash: string;
  mac: string | null;
}

/** How far an entry can be believed, for display (defined in eventtext.ts, shared with the dashboard). */
export type { Trust };

export interface LogSummary {
  ok: boolean;
  entries: number;
  firstBadSeq?: number;
  reason?: string;
  macsChecked: boolean;
  beforeReset: number;
  whileLocked: number;
  notes: string[];
  anchor: AnchorStatus;
}

export type AnchorStatus = 'ok' | 'missing' | 'truncated' | 'mismatch' | 'rolled_back' | 'unchecked';

export interface AnchorCheck {
  status: AnchorStatus;
  expectedSeq?: number;
  expectedHash?: string;
  /** Newest seq actually present in the log. */
  foundSeq: number;
}

export interface LoggedEvent extends EventEntry { trust: Trust }

const GENESIS = 'wickey-events-genesis';
const KEYS = ['seq', 'ts', 'type', 'data', 'prev', 'hash', 'mac'];
// Cheap guard against a caller handing over a secret by mistake; the real rule is in the header comment.
const SECRET_KEY = /pass(word|phrase)?|secret|api_?key|^token$|^key$/i;

function file(): string {
  return config().eventsFile;
}

/** Stable key order at every level, so a hash does not depend on how an object was built. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

function hashOf(e: Pick<EventEntry, 'seq' | 'ts' | 'type' | 'data' | 'prev'>): string {
  return createHash('sha256').update(canonical({ seq: e.seq, ts: e.ts, type: e.type, data: e.data, prev: e.prev })).digest('hex');
}

function parse(line: string): EventEntry | null {
  try {
    const e = JSON.parse(line);
    if (!e || typeof e !== 'object' || Array.isArray(e)) return null;
    const keys = Object.keys(e);
    if (keys.length !== KEYS.length || !KEYS.every((k) => keys.includes(k))) return null;
    if (!Number.isInteger(e.seq) || e.seq < 1 || typeof e.ts !== 'string' || typeof e.type !== 'string') return null;
    if (!e.data || typeof e.data !== 'object' || Array.isArray(e.data)) return null;
    if (typeof e.prev !== 'string' || typeof e.hash !== 'string' || !(e.mac === null || typeof e.mac === 'string')) return null;
    return e;
  } catch {
    return null;
  }
}

// ---- anchor ----

let keychain: Keychain | null = null;
/** Tests inject a fake; pass null to go back to the default. */
export function setKeychain(k: Keychain | null): void {
  keychain = k;
}
function kc(): Keychain {
  return (keychain ??= defaultKeychain());
}
/** Account = hash of the data directory, so a test home never collides with the real one. */
function kcAccount(): string {
  return createHash('sha256').update(config().home).digest('hex').slice(0, 32);
}

const anchorMessage = (seq: number, hash: string) => `wickey-anchor:${seq}:${hash}`;

function readAnchorFile(): { seq: number; hash: string; mac: string } | 'bad' | null {
  let text: string;
  try {
    text = fs.readFileSync(config().anchorFile, 'utf8');
  } catch {
    return null;
  }
  try {
    const a = JSON.parse(text);
    if (Number.isInteger(a?.seq) && a.seq >= 1 && typeof a.hash === 'string' && typeof a.mac === 'string') return a;
  } catch { /* fall through */ }
  return 'bad';
}

function readKeychainAnchor(): { seq: number; hash: string } | null {
  const r = kc().get(kcAccount());
  if (r.state !== 'ok') return null;
  const m = /^(\d+):([0-9a-f]{64})$/.exec(r.value);
  return m ? { seq: Number(m[1]), hash: m[2] } : null;
}

/** Both copies, after a signed append. Never throws: logging is a record, not a gate. */
function writeAnchor(e: EventEntry): void {
  if (e.mac === null) return;
  try {
    const f = config().anchorFile;
    const tmp = `${f}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ seq: e.seq, hash: e.hash, mac: eventMac(anchorMessage(e.seq, e.hash)) }) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, f);
  } catch {
    process.stderr.write('wickey: the event log anchor file could not be written.\n');
  }
  try {
    kc().set(kcAccount(), `${e.seq}:${e.hash}`);
  } catch { /* unavailable: the file copy still stands */ }
}

function anchorCheck(): AnchorCheck {
  if (!isUnlocked()) return { status: 'unchecked', foundSeq: 0 };
  const entries = lines(rawText()).map(parse).filter((e): e is EventEntry => e !== null);
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const foundSeq = entries.reduce((n, e) => Math.max(n, e.seq), 0);
  const resetSeq = entries.reduce((n, e) => (e.type === 'reset' ? Math.max(n, e.seq) : n), 0);
  const out = (status: AnchorStatus, a?: { seq: number; hash: string }): AnchorCheck =>
    ({ status, foundSeq, ...(a ? { expectedSeq: a.seq, expectedHash: a.hash } : {}) });
  /** Does the log hold this entry? */
  const against = (a: { seq: number; hash: string }, checkMac: boolean): AnchorStatus => {
    const e = bySeq.get(a.seq);
    if (!e) return 'truncated';
    if (e.hash !== a.hash) return 'mismatch';
    if (checkMac && !verifyEventMac(e.hash, e.mac)) return 'mismatch';
    return 'ok';
  };

  const file = readAnchorFile();
  let fileAnchor: { seq: number; hash: string } | null = null;
  if (file === 'bad') return out('mismatch');
  if (file) {
    if (!verifyEventMac(anchorMessage(file.seq, file.hash), file.mac)) return out('mismatch', file);
    fileAnchor = file;
    const s = against(file, true);
    if (s !== 'ok') return out(s, file);
  }

  const k = readKeychainAnchor();
  if (k) {
    const s = against(k, false);
    if (s !== 'ok') {
      // The file is older than the Keychain and the log matches the file: both were rolled back.
      if (fileAnchor && fileAnchor.seq < k.seq && s === 'truncated') return out('rolled_back', k);
      return out(s, k);
    }
  }
  if (!fileAnchor) {
    // Signed entries from after the newest reset must have an anchor; ones before it were
    // signed with a key that no longer exists, and the anchor was deleted with it.
    if (entries.some((e) => e.mac !== null && e.seq > resetSeq)) return out('missing');
  }
  return out('ok', fileAnchor ?? undefined);
}

export function checkAnchor(): AnchorStatus {
  return anchorCheck().status;
}

let guarding = false;
/**
 * Checks the anchor and, if it fails, records a signed `tamper_detected` entry and warns once on
 * stderr. The entry's own signed append rewrites the anchor to the new head, so the next check is
 * clean; the record stays in the log for good. Call before a checkpoint or any signed append.
 */
export function guardAnchor(): AnchorStatus {
  if (guarding) return 'ok';
  const c = anchorCheck();
  if (c.status === 'ok' || c.status === 'unchecked') return c.status;
  guarding = true;
  try {
    appendEvent('tamper_detected', {
      anchor: c.status,
      expectedSeq: c.expectedSeq ?? null,
      expectedHash: c.expectedHash ? c.expectedHash.slice(0, 12) : null,
      foundSeq: c.foundSeq,
    });
    // Only once the record exists: if the log itself cannot be written, the caller's own failure
    // handling speaks, and an unlock must stay silent about it.
    process.stderr.write(`wickey: the security event log failed its anchor check (${c.status}). It was recorded as a tamper_detected event.\n`);
  } catch { /* unwritable log: nothing more can be recorded */ } finally {
    guarding = false;
  }
  return c.status;
}

function rawText(): string {
  try {
    return fs.readFileSync(file(), 'utf8');
  } catch {
    return '';
  }
}

function lines(text: string): string[] {
  return text.split('\n').filter((l) => l.trim() !== '');
}

/**
 * Appends one entry (O_APPEND, mode 0600; the file is never rewritten). Synchronous on purpose:
 * this is one process, so two calls in the same tick cannot interleave and each sees the last head.
 * `signed: false` forces mac null (reset: the key it would use is gone).
 */
export function appendEvent(type: string, data: EventData = {}, opts: { signed?: boolean } = {}): EventEntry {
  for (const [k, v] of Object.entries(data)) {
    if (SECRET_KEY.test(k)) throw new Error(`Event data must not carry "${k}": log ids and names only.`);
    if (typeof v === 'string' && v.startsWith('sk-wick-')) throw new Error('Event data must not carry a proxy key.');
  }
  const canSign = opts.signed !== false && isUnlocked();
  // Anchor first: a checkpoint would sign whatever unsigned chain is there. tamper_detected skips
  // the checkpoint because its own MAC covers the chain and it must come right after the tamper.
  if (canSign && type !== 'checkpoint' && type !== 'tamper_detected') {
    guardAnchor();
    checkpoint(false);
  }

  const text = rawText();
  const all = lines(text);
  // Chain to the newest entry that parses, so one garbage line (reported by verifyLog) cannot stop logging.
  let head: EventEntry | null = null;
  for (let i = all.length - 1; i >= 0 && !head; i--) head = parse(all[i]);
  const seq = head ? head.seq + 1 : 1;
  const prev = head ? head.hash : GENESIS;
  const body = { seq, ts: new Date().toISOString(), type, data, prev };
  const hash = hashOf(body);
  const entry: EventEntry = { ...body, hash, mac: canSign ? eventMac(hash) : null };

  fs.mkdirSync(path.dirname(file()), { recursive: true, mode: 0o700 });
  // If the file does not end in a newline (cut off mid-write, or tampered), start a fresh line.
  const line = `${text && !text.endsWith('\n') ? '\n' : ''}${JSON.stringify(entry)}\n`;
  const fd = fs.openSync(file(), 'a', 0o600);
  try {
    fs.fchmodSync(fd, 0o600);
    fs.writeSync(fd, line);
  } finally {
    fs.closeSync(fd);
  }
  writeAnchor(entry);
  // After the entry is safely on disk. Never throws and never waits: the log is the record,
  // the notification is only the alert (and also covers the CLI's `reset`, which has no proxy).
  notifyEvent(entry);
  return entry;
}

/**
 * Call after an unlock or a new setup. If the newest entry has no MAC (written while locked, or a
 * `reset`), appends a `checkpoint` whose MAC covers it. Returns the entry, or null if nothing to do.
 */
export function checkpoint(guard = true): EventEntry | null {
  if (!isUnlocked()) return null;
  if (guard) guardAnchor();
  const all = lines(rawText());
  if (all.length === 0) return null;
  const last = parse(all[all.length - 1]);
  if (last && last.mac !== null) return null;
  return appendEvent('checkpoint');
}

interface Analysis { summary: LogSummary; trust: Map<number, Trust>; entries: EventEntry[] }

function analyze(): Analysis {
  const raw = lines(rawText());
  const parsed = raw.map(parse);
  const entries = parsed.filter((e): e is EventEntry => e !== null);
  const unlocked = isUnlocked();
  const trust = new Map<number, Trust>();
  const notes: string[] = [];
  let bad: { seq: number; reason: string } | undefined;
  const fail = (seq: number, reason: string) => { bad ??= { seq, reason }; };

  // The newest `reset` splits the log: older MACs were made with a key that no longer exists.
  const resetSeq = entries.reduce((n, e) => (e.type === 'reset' ? Math.max(n, e.seq) : n), 0);
  let preOk = 0;
  let preBadSeq: number | undefined;

  let expectSeq = 1;
  let expectPrev = GENESIS;
  parsed.forEach((e, i) => {
    if (!e) {
      fail(expectSeq, `line ${i + 1} is not a valid entry`);
      return;
    }
    if (hashOf(e) !== e.hash) fail(e.seq, 'an entry was edited (its content does not match its hash)');
    else if (e.seq !== expectSeq) fail(e.seq, `entries are missing or out of order (expected #${expectSeq}, found #${e.seq})`);
    else if (e.prev !== expectPrev) fail(e.seq, 'the chain is broken here (an entry was removed, moved or replaced)');
    // Resync on what the file says, so one bad spot is reported once instead of cascading.
    expectSeq = e.seq + 1;
    expectPrev = e.hash;

    if (e.mac === null) {
      if (e.type === 'checkpoint') fail(e.seq, 'a checkpoint without a MAC (checkpoints are always signed)');
      trust.set(e.seq, e.seq < resetSeq ? 'before_reset' : 'recorded_while_locked');
    } else if (e.seq < resetSeq) {
      trust.set(e.seq, 'before_reset');
      if (unlocked) {
        if (verifyEventMac(e.hash, e.mac)) { preOk++; trust.set(e.seq, 'verified'); }
        else preBadSeq ??= e.seq;
      }
    } else if (!unlocked) {
      trust.set(e.seq, 'unchecked');
    } else if (verifyEventMac(e.hash, e.mac)) {
      trust.set(e.seq, 'verified');
    } else {
      fail(e.seq, 'the MAC does not match: this entry was not written by an unlocked Wickey');
    }
  });

  // A real reset replaces the key, so EVERY older MAC fails. Some passing and some failing means
  // someone edited entries and inserted a fake `reset` to hide it.
  if (preOk > 0 && preBadSeq !== undefined) fail(preBadSeq, 'entries before a reset: some MACs verify and some do not, which a real reset cannot cause');

  if (!unlocked) notes.push('Wickey is locked, so MACs were not checked (hashes and links only).');
  const values = [...trust.values()];
  const summary: LogSummary = {
    ok: !bad,
    entries: entries.length,
    ...(bad ? { firstBadSeq: bad.seq, reason: bad.reason } : {}),
    macsChecked: unlocked,
    beforeReset: values.filter((t) => t === 'before_reset').length,
    whileLocked: values.filter((t) => t === 'recorded_while_locked').length,
    notes,
    anchor: 'unchecked',
  };
  return { summary, trust, entries };
}

/** Folds the anchor check into a summary. Any tamper status makes it not ok. */
function withAnchor(a: Analysis): Analysis {
  const c = anchorCheck();
  const s = a.summary;
  s.anchor = c.status;
  if (c.status === 'unchecked') s.notes.push('The anchor was not checked because Wickey is locked.');
  else if (c.status !== 'ok' && s.ok) {
    s.ok = false;
    s.reason = `the log does not match its anchor (${c.status}): entries were removed, rewritten or rolled back`;
    if (c.expectedSeq !== undefined) s.firstBadSeq = c.expectedSeq;
  }
  const detected = a.entries.filter((e) => e.type === 'tamper_detected').length;
  if (detected > 0) s.notes.push(`${detected} tamper detection${detected === 1 ? '' : 's'} recorded in this log.`);
  return a;
}

export function verifyLog(): LogSummary {
  return withAnchor(analyze()).summary;
}

export interface EventsPage {
  events: LoggedEvent[];
  summary: LogSummary;
  /** Newest seq in the log (0 when empty). */
  head: number;
  /** The marker that applies: 0 when none was given or the log no longer matches it. */
  seen: number;
  /** The given marker pointed at an entry that is gone or different: the log was cut back or rewritten. */
  seenMismatch: boolean;
  /** Banner buckets (see `bannerKey`) for entries newer than `seen`, over the whole log, not just this page. */
  unseen: Record<string, number>;
}

/**
 * Newest first. `before` is exclusive (pass the last seq of the previous page). `type` keeps one
 * event type. `seen` is the "last seen" marker (an entry's seq and hash) used to count `unseen`. It only counts
 * while that very entry is still in the log: a log cut back or rewritten under it makes every entry new again.
 */
export function listEvents(opts: { before?: number; limit?: number; type?: string; seen?: { seq: number; hash: string } } = {}): EventsPage {
  const { summary, trust, entries } = withAnchor(analyze());
  const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
  const head = entries.reduce((n, e) => Math.max(n, e.seq), 0);
  const events = entries
    .filter((e) => (opts.before === undefined || e.seq < opts.before) && (opts.type === undefined || e.type === opts.type))
    .sort((a, b) => b.seq - a.seq)
    .slice(0, limit)
    .map((e) => ({ ...e, trust: trust.get(e.seq) ?? 'recorded_while_locked' as Trust }));
  const unseen: Record<string, number> = {};
  const m = opts.seen;
  const mismatch = !!m && m.seq > 0 && entries.find((e) => e.seq === m.seq)?.hash !== m.hash;
  const after = m && !mismatch ? m.seq : 0;
  for (const e of entries) {
    if (e.seq <= after) continue;
    const k = bannerKey(e);
    if (k) unseen[k] = (unseen[k] ?? 0) + 1;
  }
  return { events, summary, head, seen: after, seenMismatch: mismatch, unseen };
}

/** Hash of the entry with this seq, '' for 0, null when there is none. For the "last seen" marker. */
export function entryHash(seq: number): string | null {
  if (seq === 0) return '';
  return analyze().entries.find((e) => e.seq === seq)?.hash ?? null;
}
