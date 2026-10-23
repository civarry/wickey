import dns from 'node:dns';
import net from 'node:net';
import { config } from './config.ts';

// A credential is a real API key plus a URL the proxy sends it to. This file decides which URLs
// are safe to send it to. Cloud metadata and link-local addresses are always refused (they hand
// out cloud credentials), as is the proxy itself (a loop). Loopback and private ranges stay
// allowed on purpose: Ollama, LM Studio and corporate gateways live there. The checks run when a
// URL is saved (names and literal IPs) and again at connect time (what the name really resolves
// to), which is what stops DNS rebinding.

export type Scope = 'public' | 'private' | 'loopback';
export type Classification = { ok: true; scope: Scope } | { ok: false; reason: string };

const METADATA_NAMES = new Set(['metadata', 'metadata.google.internal', 'metadata.goog', 'instance-data', 'instance-data.ec2.internal']);

type Verdict = { blocked: string } | { scope: Scope };

/** 4 bytes for IPv4, 16 for IPv6. IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::/96) collapse to their IPv4 bytes. */
function ipBytes(input: string): number[] | null {
  const addr = input.split('%')[0];
  const family = net.isIP(addr);
  if (family === 4) return addr.split('.').map(Number);
  if (family !== 6) return null;
  let head = addr;
  let tail: number[] = [];
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(addr);
  if (dotted) {
    const v4 = dotted[1].split('.').map(Number);
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    head = addr.slice(0, -dotted[1].length) + '0:0';
  }
  const [left, right] = head.split('::');
  const groups = (s: string | undefined) => (s ? s.split(':').map((g) => parseInt(g || '0', 16)) : []);
  const l = groups(left);
  const r = head.includes('::') ? groups(right) : [];
  const all = head.includes('::') ? [...l, ...Array(8 - l.length - r.length).fill(0), ...r] : l;
  if (all.length !== 8) return null;
  if (tail.length) all.splice(6, 2, ...tail);
  const bytes = all.flatMap((g) => [g >> 8, g & 255]);
  const zeros10 = bytes.slice(0, 10).every((b) => b === 0);
  if (zeros10 && bytes[10] === 255 && bytes[11] === 255) return bytes.slice(12);
  const nat64 = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
  if (nat64.every((b, i) => bytes[i] === b)) return bytes.slice(12);
  return bytes;
}

function classifyBytes(b: number[]): Verdict {
  if (b.length === 4) {
    const [a, c, d, e] = b;
    if (a === 0) return { blocked: 'is an unspecified address (0.0.0.0/8)' };
    if (a === 169 && c === 254) return { blocked: 'is a link-local or cloud metadata address (169.254.0.0/16)' };
    if (a === 100 && c === 100 && d === 100 && e === 200) return { blocked: 'is the Alibaba Cloud metadata address' };
    if (a === 127) return { scope: 'loopback' };
    if (a === 10 || (a === 172 && c >= 16 && c <= 31) || (a === 192 && c === 168) || (a === 100 && c >= 64 && c <= 127)) return { scope: 'private' };
    return { scope: 'public' };
  }
  if (b.every((x) => x === 0)) return { blocked: 'is the unspecified address (::)' };
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return { scope: 'loopback' };
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return { blocked: 'is a link-local address (fe80::/10)' };
  const ec2 = [0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54];
  if (ec2.every((x, i) => b[i] === x)) return { blocked: 'is the AWS metadata address (fd00:ec2::254)' };
  if ((b[0] & 0xfe) === 0xfc) return { scope: 'private' };
  return { scope: 'public' };
}

function classifyHost(rawHost: string): Verdict {
  const host = rawHost.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  const bytes = ipBytes(host);
  if (bytes) return classifyBytes(bytes);
  if (METADATA_NAMES.has(host)) return { blocked: 'is a cloud metadata host name' };
  if (host === 'localhost' || host.endsWith('.localhost')) return { scope: 'loopback' };
  if (!host.includes('.') || host.endsWith('.local') || host.endsWith('.internal')) return { scope: 'private' };
  return { scope: 'public' };
}

function portOf(url: URL): number {
  return Number(url.port) || (url.protocol === 'https:' ? 443 : 80);
}

const FIX = 'Use the address of your real provider or gateway.';

/** Save-time and pre-connect check of a base URL (names and literal IPs only; DNS is checked at connect time). */
export function classifyBaseUrl(input: string | URL): Classification {
  let url: URL;
  try {
    url = typeof input === 'string' ? new URL(input) : input;
  } catch {
    return { ok: false, reason: `"${String(input)}" is not a valid URL.` };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return { ok: false, reason: 'Base URL must be http or https.' };
  if (url.username || url.password) return { ok: false, reason: 'Base URL must not contain a username or password. Put the key in the credential instead.' };
  const verdict = classifyHost(url.hostname);
  if ('blocked' in verdict) return { ok: false, reason: `Base URL host ${url.hostname} ${verdict.blocked}, so a key must never be sent there. ${FIX}` };
  if (verdict.scope === 'loopback' && portOf(url) === config().port) {
    return { ok: false, reason: `Base URL points at Wickey itself (port ${config().port}), which would loop. Point it at the real provider instead.` };
  }
  if (url.protocol === 'http:' && verdict.scope === 'public') {
    return { ok: false, reason: `Base URL ${url.origin} is plain http to a public host, which would send the key unencrypted. Change it to https://.` };
  }
  return { ok: true, scope: verdict.scope };
}

export const BLOCKED_CODE = 'EWICKEY_BLOCKED';

function blockedError(message: string): NodeJS.ErrnoException {
  const err: NodeJS.ErrnoException = new Error(message);
  err.code = BLOCKED_CODE;
  return err;
}

export function isBlockedError(err: unknown): boolean {
  return !!err && (err as NodeJS.ErrnoException).code === BLOCKED_CODE;
}

/** Judges addresses a name resolved to. Metadata and link-local always; the proxy's own port on loopback. */
export function checkResolved(hostname: string, addresses: string[], port: number): string | null {
  for (const address of addresses) {
    const bytes = ipBytes(address);
    const verdict: Verdict = bytes ? classifyBytes(bytes) : { blocked: 'is not a valid address' };
    if ('blocked' in verdict) {
      return `${hostname} resolved to ${address}, which ${verdict.blocked}, so the key was not sent. Check the credential's base URL and your DNS.`;
    }
    if (verdict.scope === 'loopback' && port === config().port) {
      return `${hostname} resolved to ${address}:${port}, which is Wickey itself, so the request was refused. Point the credential at the real provider.`;
    }
  }
  return null;
}

type Resolver = (hostname: string, options: dns.LookupAllOptions, cb: (err: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => void) => void;
let resolver: Resolver = (host, options, cb) => dns.lookup(host, options, cb);

/** Tests only: swap the DNS resolver. Returns a function that restores the real one. */
export function setResolverForTests(fn: Resolver): () => void {
  const prev = resolver;
  resolver = fn;
  return () => { resolver = prev; };
}

/**
 * A `lookup` option for http(s).request that validates every resolved address before a socket is
 * opened, and connects to exactly those addresses (so nothing can change between check and use).
 * Always asks the resolver for all addresses, then answers in whichever shape the caller asked
 * for: Node's autoSelectFamily calls with `all: true`, older paths with a single address.
 */
export function guardedLookup(port: number): net.LookupFunction {
  return ((hostname: string, options: dns.LookupOptions | number, cb: (...args: any[]) => void) => {
    const opts: dns.LookupOptions = typeof options === 'number' ? { family: options } : (options ?? {});
    resolver(hostname, { ...opts, all: true }, (err, addresses) => {
      if (err) return cb(err);
      const problem = checkResolved(hostname, addresses.map((a) => a.address), port);
      if (problem) return cb(blockedError(problem));
      if (opts.all) return cb(null, addresses);
      const first = addresses[0];
      if (!first) return cb(Object.assign(new Error(`${hostname} did not resolve`), { code: 'ENOTFOUND' }));
      cb(null, first.address, first.family);
    });
  }) as net.LookupFunction;
}

/** Request options that carry the connect-time guard for `url`. */
export function guardOptions(url: URL): { lookup: net.LookupFunction } {
  return { lookup: guardedLookup(portOf(url)) };
}
