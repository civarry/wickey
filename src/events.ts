import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.ts';
import { eventMac, isUnlocked, verifyEventMac } from './vault.ts';

// Security event log: an append-only JSON Lines file (`events.log`) that a same-user program
// cannot quietly rewrite. Each entry carries the hash of the previous one (a chain), and, when the
// vault was unlocked, an HMAC of its own hash under a key only the passphrase can produce. Editing,
// deleting or reordering entries breaks the chain; forging entries breaks the MACs. Entries written
// while locked (failed unlocks) have no MAC: the next unlock appends a `checkpoint` whose MAC
// covers the head, which authenticates the chain up to it.
//
// Known limit: dropping entries off the END of the file is not detectable from the file alone
// (the shorter chain is still consistent). The planned anchor outside the data directory fixes it.
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

/** How far an entry can be believed, for display. */
export type Trust =
  | 'verified' // hash chain intact and MAC checked
  | 'recorded_while_locked' // no MAC: a local program could have added it
  | 'before_reset' // from before a reset: the old key is gone, so integrity cannot be verified
  | 'unchecked'; // has a MAC, but the vault is locked so it was not checked

export interface LogSummary {
  ok: boolean;
  entries: number;
  firstBadSeq?: number;
  reason?: string;
  macsChecked: boolean;
  beforeReset: number;
  whileLocked: number;
  notes: string[];
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
  if (canSign && type !== 'checkpoint') checkpoint();

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
  return entry;
}

/**
 * Call after an unlock or a new setup. If the newest entry has no MAC (written while locked, or a
 * `reset`), appends a `checkpoint` whose MAC covers it. Returns the entry, or null if nothing to do.
 */
export function checkpoint(): EventEntry | null {
  if (!isUnlocked()) return null;
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
  };
  return { summary, trust, entries };
}

export function verifyLog(): LogSummary {
  return analyze().summary;
}

/** Newest first. `before` is exclusive (pass the last seq of the previous page). */
export function listEvents(opts: { before?: number; limit?: number } = {}): { events: LoggedEvent[]; summary: LogSummary } {
  const { summary, trust, entries } = analyze();
  const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
  const events = entries
    .filter((e) => opts.before === undefined || e.seq < opts.before)
    .sort((a, b) => b.seq - a.seq)
    .slice(0, limit)
    .map((e) => ({ ...e, trust: trust.get(e.seq) ?? 'recorded_while_locked' }));
  return { events, summary };
}
