import { BRAND } from './brand.ts';
import type { IncomingHttpHeaders } from 'node:http';
import { StringDecoder } from 'node:string_decoder';
import zlib from 'node:zlib';
import type { Transform } from 'node:stream';
import type { UsageTotals } from './store.ts';

// ---- Usage parsing ----

export interface Usage {
  tokensIn: number;
  tokensOut: number;
}

/**
 * 'found': the provider reported usage. 'none': the whole response was read and carried none.
 * 'unknown': we could not read it (unsupported encoding, too large, malformed), which says
 * nothing about whether the provider reports usage, so callers must not flag the credential.
 */
export type MeterResult = ({ kind: 'found' } & Usage) | { kind: 'none' } | { kind: 'unknown' };

const nat = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : null);

/** One `usage` object in any supported shape: OpenAI chat/embeddings, OpenAI Responses, Anthropic. */
export function usageFromObject(u: any): Usage | null {
  if (!u || typeof u !== 'object') return null;
  const prompt = nat(u.prompt_tokens);
  if (prompt !== null) return { tokensIn: prompt, tokensOut: nat(u.completion_tokens) ?? 0 };
  const input = nat(u.input_tokens);
  if (input !== null) {
    // Anthropic bills cache writes and reads separately from input_tokens; they count toward the cap.
    const cache = (nat(u.cache_creation_input_tokens) ?? 0) + (nat(u.cache_read_input_tokens) ?? 0);
    return { tokensIn: input + cache, tokensOut: nat(u.output_tokens) ?? 0 };
  }
  return null;
}

/** Folds SSE event payloads into one usage figure. */
export class StreamUsage {
  private tin: number | null = null;
  private tout: number | null = null;
  private found = false;

  feed(ev: any): void {
    if (!ev || typeof ev !== 'object') return;
    if (ev.type === 'message_start') {
      const x = usageFromObject(ev.message?.usage);
      if (x) { this.tin = x.tokensIn; this.tout = x.tokensOut; this.found = true; }
    } else if (ev.type === 'message_delta') {
      const out = nat(ev.usage?.output_tokens);
      if (out !== null) { this.tout = out; this.found = true; }
      const x = usageFromObject(ev.usage);
      if (x && (this.tin === null || x.tokensIn > this.tin)) this.tin = x.tokensIn;
    } else if (typeof ev.type === 'string' && ev.type.startsWith('response.')) {
      // Responses API: usage rides on response.completed (also incomplete/failed); other events carry null.
      const x = usageFromObject(ev.response?.usage);
      if (x) { this.tin = x.tokensIn; this.tout = x.tokensOut; this.found = true; }
    } else {
      // Chat completions: the usage chunk is the last one before [DONE]; earlier chunks have usage:null.
      const x = usageFromObject(ev.usage);
      if (x) { this.tin = x.tokensIn; this.tout = x.tokensOut; this.found = true; }
    }
  }

  result(): Usage | null {
    return this.found ? { tokensIn: this.tin ?? 0, tokensOut: this.tout ?? 0 } : null;
  }
}

const MAX_EVENT_BYTES = 8 * 1024 * 1024;

/** Incremental SSE reader: events may be split across chunks, and lines end in LF, CRLF or CR. */
export class SseParser {
  private buf = '';
  private data: string[] = [];
  overflowed = false;
  private onData: (data: string) => void;

  constructor(onData: (data: string) => void) {
    this.onData = onData;
  }

  write(text: string): void {
    this.buf += text;
    // A trailing CR may be the first half of a CRLF split across chunks; wait for the next one.
    const hold = this.buf.endsWith('\r') ? 1 : 0;
    this.consume(this.buf.length - hold);
    if (this.buf.length > MAX_EVENT_BYTES) {
      this.buf = '';
      this.data = [];
      this.overflowed = true;
    }
  }

  end(tail = ''): void {
    this.buf += tail;
    this.consume(this.buf.length);
    if (this.buf) this.line(this.buf);
    this.buf = '';
    this.dispatch();
  }

  private consume(limit: number): void {
    let start = 0;
    const re = /\r\n|\r|\n/g;
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(this.buf)) && m.index < limit) {
      this.line(this.buf.slice(start, m.index));
      start = m.index + m[0].length;
    }
    this.buf = this.buf.slice(start);
  }

  private line(line: string): void {
    if (line === '') return this.dispatch();
    if (!line.startsWith('data:')) return;
    const v = line.slice(5);
    this.data.push(v.startsWith(' ') ? v.slice(1) : v);
  }

  private dispatch(): void {
    if (!this.data.length) return;
    const joined = this.data.join('\n');
    this.data = [];
    this.onData(joined);
  }
}

// ---- Response side copy ----

const JSON_LIMIT = 20 * 1024 * 1024;
// A stream is parsed as it goes and never kept, but a decompression bomb could still burn CPU.
const STREAM_DECODE_LIMIT = 512 * 1024 * 1024;

/** What a capped key's upstream request may ask for: exactly the encodings decoderFor can undo. */
export const SUPPORTED_ENCODINGS = ['gzip', 'deflate', 'br', ...(typeof (zlib as any).createZstdDecompress === 'function' ? ['zstd'] : [])].join(', ');

function decoderFor(name: string): Transform | null {
  const flush = { finishFlush: zlib.constants.Z_SYNC_FLUSH };
  switch (name) {
    case 'gzip': case 'x-gzip': return zlib.createGunzip(flush);
    case 'deflate': return zlib.createInflate(flush);
    case 'br': return zlib.createBrotliDecompress();
    case 'zstd': return typeof (zlib as any).createZstdDecompress === 'function' ? (zlib as any).createZstdDecompress() : null;
    default: return null;
  }
}

/**
 * Reads a decoded side copy of a response. The client always gets the original bytes; nothing
 * here can throw into the forwarding path or hold it up.
 */
export class ResponseMeter {
  readonly sse: boolean;
  private decoders: Transform[] = [];
  private unknown = false;
  private chunks: Buffer[] = [];
  private size = 0;
  private decoded = 0;
  private stream = new StreamUsage();
  private parser: SseParser;
  private sd = new StringDecoder('utf8');
  private finished: Promise<void>;
  private settle!: () => void;

  constructor(headers: IncomingHttpHeaders) {
    this.sse = String(headers['content-type'] ?? '').toLowerCase().includes('text/event-stream');
    this.parser = new SseParser((d) => {
      if (d === '[DONE]') return;
      try { this.stream.feed(JSON.parse(d)); } catch { /* not JSON; ignore the event */ }
    });
    this.finished = new Promise((r) => (this.settle = r));

    const names = String(headers['content-encoding'] ?? '').split(',').map((s) => s.trim().toLowerCase()).filter((s) => s && s !== 'identity');
    // Encodings were applied in listed order, so undo them in reverse.
    for (const name of names.reverse()) {
      const d = decoderFor(name);
      if (!d) { this.unknown = true; this.decoders = []; break; }
      this.decoders.push(d);
    }
    if (this.unknown || !this.decoders.length) {
      this.decoders = [];
      this.settle();
      return;
    }
    this.decoders.forEach((d, i) => {
      d.on('error', () => this.fail());
      if (i < this.decoders.length - 1) d.pipe(this.decoders[i + 1]);
    });
    const last = this.decoders[this.decoders.length - 1];
    last.on('data', (c: Buffer) => this.sink(c));
    last.on('end', () => this.settle());
    last.on('close', () => this.settle());
  }

  private fail(): void {
    this.unknown = true;
    this.chunks = [];
    for (const d of this.decoders) d.destroy();
    this.settle();
  }

  private sink(buf: Buffer): void {
    if (this.unknown) return;
    this.decoded += buf.length;
    if (this.sse) {
      if (this.decoded > STREAM_DECODE_LIMIT) { this.unknown = true; return; }
      this.parser.write(this.sd.write(buf));
    } else {
      this.size += buf.length;
      if (this.size > JSON_LIMIT) { this.unknown = true; this.chunks = []; return; }
      this.chunks.push(buf);
    }
  }

  write(chunk: Buffer): void {
    try {
      if (this.unknown) return;
      if (this.decoders.length) this.decoders[0].write(chunk);
      else this.sink(chunk);
    } catch {
      this.fail();
    }
  }

  /** Call once the upstream body has ended. */
  async finish(): Promise<MeterResult> {
    try {
      if (this.decoders.length && !this.unknown) this.decoders[0].end();
      await this.finished;
      if (this.unknown) return { kind: 'unknown' };
      if (this.sse) {
        this.parser.end(this.sd.end());
        const u = this.stream.result();
        if (u) return { kind: 'found', ...u };
        return this.parser.overflowed ? { kind: 'unknown' } : { kind: 'none' };
      }
      const obj = JSON.parse(Buffer.concat(this.chunks).toString('utf8'));
      const u = usageFromObject(obj?.usage);
      return u ? { kind: 'found', ...u } : { kind: 'none' };
    } catch {
      return { kind: 'unknown' };
    }
  }

  /** Decoded body text (non-stream only); used to read a small upstream error message. */
  bodyText(): string {
    return this.unknown ? '' : Buffer.concat(this.chunks).toString('utf8');
  }
}

// ---- Which requests generate usage ----

const GENERATION_SUFFIXES = ['/chat/completions', '/completions', '/responses', '/messages', '/embeddings'];

export function isGenerationPath(path: string): boolean {
  return GENERATION_SUFFIXES.some((s) => path.endsWith(s));
}

// ---- Rate limit (D9) ----

const WINDOW_MS = 60_000;

/** In-memory sliding one-minute window per proxy. Resets on restart, which needs the passphrase. */
export class RateLimiter {
  private hits = new Map<string, number[]>();

  private prune(id: string, now: number): number[] {
    const list = (this.hits.get(id) ?? []).filter((t) => t > now - WINDOW_MS);
    this.hits.set(id, list);
    return list;
  }

  /** Seconds to wait if the window is full, else 0. Does not count the request. */
  peek(id: string, limit: number, now: number): number {
    const list = this.prune(id, now);
    return list.length < limit ? 0 : Math.max(1, Math.ceil((list[0] + WINDOW_MS - now) / 1000));
  }

  /** Checks and counts in one synchronous step, so concurrent requests can't all slip through. */
  take(id: string, limit: number, now: number): number {
    const wait = this.peek(id, limit, now);
    if (wait === 0) this.hits.get(id)!.push(now);
    return wait;
  }
}

export const rateLimiter = new RateLimiter();

// ---- In-flight reservations (D4/D) ----

/** Assumed output size of a request that doesn't state max_tokens. */
export const DEFAULT_RESERVATION = 4096;
/** Concurrent in-flight requests allowed per capped key. */
export const MAX_INFLIGHT = 8;

/** The most output tokens a request says it may produce, else the default. Always positive. */
export function reservationFor(body: any): number {
  for (const k of ['max_tokens', 'max_completion_tokens', 'max_output_tokens']) {
    const v = body?.[k];
    if (typeof v === 'number' && Number.isFinite(v) && v >= 1) return Math.floor(v);
  }
  return DEFAULT_RESERVATION;
}

/**
 * In-memory budget held back for requests still running. A cap is only checked against recorded
 * usage, so without this a burst of parallel requests would all pass it. Resets on restart, which
 * also drops every in-flight request.
 */
export class Reservations {
  private held = new Map<string, { tokens: number; count: number }>();

  state(id: string): { tokens: number; count: number } {
    return this.held.get(id) ?? { tokens: 0, count: 0 };
  }

  reserve(id: string, tokens: number): void {
    const cur = this.state(id);
    this.held.set(id, { tokens: cur.tokens + tokens, count: cur.count + 1 });
  }

  release(id: string, tokens: number): void {
    const cur = this.state(id);
    if (cur.count <= 1) this.held.delete(id);
    else this.held.set(id, { tokens: Math.max(0, cur.tokens - tokens), count: cur.count - 1 });
  }
}

export const reservations = new Reservations();

// ---- High-water mark (D7) ----

type Counters = Pick<UsageTotals, 'requests' | 'tokensIn' | 'tokensOut' | 'uncounted'>;
const highWater = new Map<string, Counters>();
const flagged = new Set<string>();

/** Marks a key as rolled back (sticks until restart). Used when a restored proxies row is detected. */
export function flagRollback(proxyId: string): void {
  flagged.add(proxyId);
}

/** True if the key is flagged "usage counters went backwards" (sticks until the process restarts). */
export function isRollbackFlagged(proxyId: string): boolean {
  return flagged.has(proxyId);
}

/** Compares stored totals with the highest this process has seen. Returns true if newly flagged. */
export function checkHighWater(proxyId: string, t: Counters): boolean {
  const hw = highWater.get(proxyId);
  if (!hw || flagged.has(proxyId)) return false;
  if (t.requests < hw.requests || t.tokensIn < hw.tokensIn || t.tokensOut < hw.tokensOut || t.uncounted < hw.uncounted) {
    flagged.add(proxyId);
    return true;
  }
  return false;
}

/** Raise the mark to the totals just read or written. Never lowers it. */
export function observeUsage(proxyId: string, t: Counters): void {
  const hw = highWater.get(proxyId) ?? { requests: 0, tokensIn: 0, tokensOut: 0, uncounted: 0 };
  highWater.set(proxyId, {
    requests: Math.max(hw.requests, t.requests), tokensIn: Math.max(hw.tokensIn, t.tokensIn),
    tokensOut: Math.max(hw.tokensOut, t.tokensOut), uncounted: Math.max(hw.uncounted, t.uncounted),
  });
}

// ---- Error bodies in the client's own format ----

export type ErrorKind = 'rate_limit' | 'permission' | 'invalid_request';
export type RefusalCode = 'model_not_allowed' | 'rate_limit_exceeded' | 'token_cap_reached' | 'usage_uncountable' | 'usage_rollback' | 'request_too_large' | 'invalid_body';

export function formatError(anthropic: boolean, kind: ErrorKind, code: RefusalCode, message: string): string {
  const text = `${BRAND.errorPrefix}${message}`;
  if (anthropic) {
    const type = kind === 'rate_limit' ? 'rate_limit_error' : kind === 'permission' ? 'permission_error' : 'invalid_request_error';
    return JSON.stringify({ type: 'error', error: { type, message: text } });
  }
  const type = kind === 'rate_limit' ? 'rate_limit_error' : 'invalid_request_error';
  return JSON.stringify({ error: { message: text, type, code } });
}
