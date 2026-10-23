import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.ts';

// The service manager (launchd, systemd) would append stdout to a file forever, so a service-mode
// process writes its own log through this rotating writer and the OS-level streams go to /dev/null.

export const LOG_MAX_BYTES = 1024 * 1024;
export const LOG_FILES = 3; // name, name.1, name.2
/** One log line never exceeds this, so a hostile or runaway message can't fill the cap by itself. */
const MAX_LINE = 4096;

const isWindows = () => process.platform === 'win32';

/** chmod that is a quiet no-op on Windows (no POSIX modes there) and for files that don't exist. */
export function chmodQuiet(target: string, mode: number): void {
  if (isWindows()) return;
  try { fs.chmodSync(target, mode); } catch { /* missing or not ours: nothing to tighten */ }
}

export function ensurePrivateDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodQuiet(dir, 0o700); // mkdir's mode doesn't apply to a directory that already existed
}

/** Tightens an existing data directory: dirs 0700, vault, database and logs 0600. */
export function hardenDataDir(): void {
  const { home, dbPath, logsDir } = config();
  if (!fs.existsSync(home)) return;
  chmodQuiet(home, 0o700);
  for (const f of [path.join(home, 'vault.json'), dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) chmodQuiet(f, 0o600);
  if (!fs.existsSync(logsDir)) return;
  chmodQuiet(logsDir, 0o700);
  for (const f of fs.readdirSync(logsDir)) chmodQuiet(path.join(logsDir, f), 0o600);
}

export class RotatingLog {
  private fd: number | null = null;
  private size = 0;
  private readonly file: string;
  private readonly maxBytes: number;
  private readonly keep: number;

  constructor(file: string, maxBytes = LOG_MAX_BYTES, keep = LOG_FILES) {
    this.file = file;
    this.maxBytes = maxBytes;
    this.keep = keep;
    ensurePrivateDir(path.dirname(file));
    this.open();
  }

  private open(): void {
    this.fd = fs.openSync(this.file, 'a', 0o600);
    if (!isWindows()) fs.fchmodSync(this.fd, 0o600); // an older file may have looser permissions
    this.size = fs.fstatSync(this.fd).size;
  }

  private rotate(): void {
    if (this.fd !== null) fs.closeSync(this.fd);
    this.fd = null;
    // name.(keep-1) is overwritten by the rename below, so at most `keep` files ever exist.
    for (let i = this.keep - 1; i >= 1; i--) {
      const from = i === 1 ? this.file : `${this.file}.${i - 1}`;
      try { fs.renameSync(from, `${this.file}.${i}`); } catch { /* that generation doesn't exist yet */ }
    }
    this.open();
    for (let i = 1; i < this.keep; i++) chmodQuiet(`${this.file}.${i}`, 0o600);
  }

  write(text: string): void {
    const data = Buffer.from(text);
    if (this.fd === null) return;
    if (this.size > 0 && this.size + data.length > this.maxBytes) this.rotate();
    try {
      fs.writeSync(this.fd!, data);
      this.size += data.length;
    } catch {
      // A full disk must not take the proxy down with it.
    }
  }

  close(): void {
    if (this.fd !== null) fs.closeSync(this.fd);
    this.fd = null;
  }
}

/**
 * Last line of defense: nothing in src/ logs a key or header on purpose, but an error message from
 * a library could one day carry one. Patterns are broad on purpose (provider keys, proxy tokens,
 * bearer values, auth headers); this is not a guarantee for unknown key formats.
 */
export function redact(line: string): string {
  return line
    .replace(/\b(authorization|proxy-authorization|x-api-key|api-key)\b(["']?\s*[:=]\s*["']?)[^\s"',;]*(?:\s+[^\s"',;]+)?/gi, '$1$2[hidden]')
    .replace(/\bBearer\s+[^\s"',;]+/gi, 'Bearer [hidden]')
    .replace(/\bsk-[A-Za-z0-9_-]{6,}/g, 'sk-[hidden]');
}

// Redact first, then cut: truncating first could leave half a key in view.
const cap = (l: string) => (l.length > MAX_LINE ? `${l.slice(0, MAX_LINE)}...` : l);

function lineFormatter(tag: string): (chunk: string) => string {
  return (chunk) => chunk.split(/\r?\n/).filter((l, i, all) => l !== '' || i < all.length - 1)
    .map((l) => `${new Date().toISOString()} ${tag} ${cap(redact(l))}\n`).join('');
}

/**
 * Sends everything the process prints to the log instead. Returns a restore function (tests).
 * Uncaught errors are logged too, then the process exits non-zero so the service manager restarts it.
 */
export function redirectOutput(log: RotatingLog): () => void {
  const out = process.stdout.write.bind(process.stdout);
  const err = process.stderr.write.bind(process.stderr);
  const fmtOut = lineFormatter('out');
  const fmtErr = lineFormatter('err');
  const patch = (fmt: (c: string) => string) => ((chunk: string | Uint8Array, ...rest: unknown[]) => {
    log.write(fmt(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')));
    const cb = rest.find((r) => typeof r === 'function') as (() => void) | undefined;
    cb?.();
    return true;
  }) as typeof process.stdout.write;
  process.stdout.write = patch(fmtOut);
  process.stderr.write = patch(fmtErr);
  const onFatal = (e: unknown) => {
    // Message only: a stack can include argument values.
    log.write(fmtErr(`fatal: ${e instanceof Error ? e.message : String(e)}`));
    process.exit(1);
  };
  process.on('uncaughtException', onFatal);
  process.on('unhandledRejection', onFatal);
  return () => {
    process.stdout.write = out as typeof process.stdout.write;
    process.stderr.write = err as typeof process.stderr.write;
    process.off('uncaughtException', onFatal);
    process.off('unhandledRejection', onFatal);
  };
}
