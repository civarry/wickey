import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BRAND } from './brand.ts';
import { config } from './config.ts';

// Node side of the native presence helper (native/presence.swift, macOS Secure Enclave). The
// helper's stdout carries the secret, so it is parsed in memory and never logged, put in an error
// or echoed. Everything runs through execFile with an argument array, never a shell.

const COMPILE_MS = 120_000;
const HUMAN_MS = 90_000;
const QUICK_MS = 5_000;

export const NO_SECURE_ENCLAVE =
  "Presence mode needs a Mac with a Secure Enclave (Apple silicon or a Mac with a T2 chip). This Mac doesn't have one.";
export const NOT_MACOS = 'Presence mode is only available on macOS for now.';
export const NO_SWIFTC = 'Install the Xcode Command Line Tools: run `xcode-select --install`, then try again.';

/** Never rejects on a non-zero exit: the helper reports failures as JSON with exit 1. */
export type ExecResult = { code: number; stdout: string; stderr: string; spawnError?: string };
export type Exec = (file: string, args: string[], opts: { timeout: number }) => Promise<ExecResult>;

export const defaultExec: Exec = (file, args, opts) =>
  new Promise((resolve) => {
    execFile(file, args, { timeout: opts.timeout, windowsHide: true, maxBuffer: 1 << 20 }, (err, stdout, stderr) => {
      if (!err) return resolve({ code: 0, stdout, stderr });
      const e = err as NodeJS.ErrnoException & { killed?: boolean };
      const code = typeof e.code === 'number' ? e.code : 1;
      resolve({ code, stdout: stdout ?? '', stderr: stderr ?? '', spawnError: typeof e.code === 'string' ? e.code : e.killed ? 'TIMEOUT' : undefined });
    });
  });

export type PresenceDeps = { exec?: Exec; platform?: NodeJS.Platform };

// Process-wide defaults for the flows built on top (presencemode.ts). Tests and the dashboard check
// install a fake helper here so no real system prompt is ever shown; production leaves it empty.
let injected: PresenceDeps = {};
export function setPresenceDeps(d: PresenceDeps | null): void {
  injected = d ?? {};
}
const withDefaults = <T extends PresenceDeps>(d: T): T => ({ ...injected, ...d, exec: d.exec ?? injected.exec, platform: d.platform ?? injected.platform });

export class PresenceError extends Error {}
export class PresenceHelperMismatch extends PresenceError {
  constructor() {
    super(`The presence helper is missing or has changed since it was built. Run \`${BRAND.command} presence repair\`.`);
    this.name = 'PresenceHelperMismatch';
  }
}

export function helperPath(): string {
  return path.join(config().home, 'bin', 'wickey-presence');
}

function sourcePath(): string {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'native', 'presence.swift');
}

function sha256File(p: string): string {
  return createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

function firstLines(s: string, n = 5): string {
  return s.trim().split('\n').slice(0, n).join('\n');
}

/** Compile and ad-hoc sign the helper under the data directory. Returns the binary's SHA-256 (hex). */
export async function buildHelper(given: PresenceDeps = {}): Promise<string> {
  const deps = withDefaults(given);
  const exec = deps.exec ?? defaultExec;
  if ((deps.platform ?? process.platform) !== 'darwin') throw new PresenceError(NOT_MACOS);
  const found = await exec('xcrun', ['--find', 'swiftc'], { timeout: QUICK_MS });
  if (found.code !== 0 || found.spawnError) throw new PresenceError(NO_SWIFTC);

  const out = helperPath();
  const binDir = path.dirname(out);
  fs.mkdirSync(binDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(binDir, 0o700);
  fs.rmSync(out, { force: true });

  const compiled = await exec('xcrun', ['swiftc', '-O', sourcePath(), '-o', out], { timeout: COMPILE_MS });
  if (compiled.code !== 0) {
    throw new PresenceError(`Could not compile the presence helper:\n${firstLines(compiled.stderr || compiled.stdout)}`);
  }
  const signed = await exec('codesign', ['-s', '-', '-f', out], { timeout: QUICK_MS * 6 });
  if (signed.code !== 0) {
    throw new PresenceError(`Could not sign the presence helper:\n${firstLines(signed.stderr || signed.stdout)}`);
  }
  fs.chmodSync(out, 0o700);
  return sha256File(out);
}

function parse(stdout: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(stdout);
    return v && typeof v === 'object' ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Injectable for tests: lets a test simulate a Mac without a Secure Enclave. */
export async function probe(given: PresenceDeps = {}): Promise<{ available: boolean; reason?: string }> {
  const deps = withDefaults(given);
  if ((deps.platform ?? process.platform) !== 'darwin') return { available: false, reason: NOT_MACOS };
  const r = await (deps.exec ?? defaultExec)(helperPath(), ['probe'], { timeout: QUICK_MS });
  const j = parse(r.stdout);
  if (j?.available === true) return { available: true };
  if (j && j.available === false) return { available: false, reason: NO_SECURE_ENCLAVE };
  return { available: false, reason: `The presence helper did not answer. Run \`${BRAND.command} presence repair\`.` };
}

/** Hash the binary on disk. Call before EVERY use of the helper. */
export function verifyHelper(expectedSha256: string): void {
  let actual: string;
  try {
    actual = sha256File(helperPath());
  } catch {
    throw new PresenceHelperMismatch();
  }
  if (actual !== expectedSha256) throw new PresenceHelperMismatch();
}

export type PresenceAction =
  | 'turn on presence'
  | 'unlock vault'
  | 'change passphrase'
  | 'turn off presence'
  | 'turn off a notification'
  | 'repair presence';

/** Exact wording of the system prompt, e.g. "Wickey: unlock vault (dashboard)". */
export function presenceReason(action: PresenceAction, trigger?: string): string {
  return `${BRAND.displayName}: ${action}${trigger ? ` (${trigger})` : ''}`;
}

async function runQuick(args: string[], given: PresenceDeps, expectedSha256?: string): Promise<void> {
  const deps = withDefaults(given);
  if (expectedSha256) verifyHelper(expectedSha256);
  const r = await (deps.exec ?? defaultExec)(helperPath(), args, { timeout: QUICK_MS });
  const j = parse(r.stdout);
  if (r.code !== 0 || j?.ok !== true) {
    throw new PresenceError(`The presence helper failed: ${typeof j?.message === 'string' ? j.message : 'no answer'}`);
  }
}

export async function createKey(dir: string, deps: PresenceDeps & { expectedSha256?: string } = {}): Promise<void> {
  await runQuick(['create', dir], deps, deps.expectedSha256);
}

export async function deleteKey(dir: string, deps: PresenceDeps & { expectedSha256?: string } = {}): Promise<void> {
  await runQuick(['delete', dir], deps, deps.expectedSha256);
}

export type UseResult =
  | { ok: true; secret: Buffer }
  | { ok: false; reason: 'cancelled' | 'not-interactive' | 'error'; code?: number; message: string };

export async function useKey(
  dir: string,
  reason: string,
  given: PresenceDeps & { expectedSha256: string; noUi?: boolean },
): Promise<UseResult> {
  const opts = withDefaults(given);
  verifyHelper(opts.expectedSha256);
  const args = ['use', dir, '--reason', reason];
  if (opts.noUi) args.push('--no-ui');
  const r = await (opts.exec ?? defaultExec)(helperPath(), args, { timeout: HUMAN_MS });
  const j = parse(r.stdout);
  if (j?.ok === true && typeof j.secret === 'string') {
    const secret = Buffer.from(j.secret, 'base64');
    if (secret.length === 32) return { ok: true, secret };
  }
  const code = typeof j?.code === 'number' ? j.code : undefined;
  if (code === -2) return { ok: false, reason: 'cancelled', code, message: 'Approval was cancelled.' };
  if (code === -1004) return { ok: false, reason: 'not-interactive', code, message: 'The system prompt cannot be shown right now.' };
  if (r.spawnError === 'TIMEOUT') return { ok: false, reason: 'error', message: 'Nobody approved the prompt in time.' };
  // Message comes from the OS error text, never from the helper's secret field.
  const message = typeof j?.message === 'string' ? j.message : 'The presence helper gave no usable answer.';
  return { ok: false, reason: 'error', code, message };
}
