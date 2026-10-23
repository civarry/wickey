import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { BRAND, envVar } from './brand.ts';
import { config } from './config.ts';

// The vault holds the real provider keys, encrypted, in one JSON file that works the same on
// every OS. A random data key (DK) encrypts everything; the DK itself is stored encrypted under a
// key derived from the user's passphrase with scrypt, so changing the passphrase later only means
// re-wrapping the DK. Three subkeys come from the DK: one encrypts secrets, one signs database rows, one authenticates the security event log.

interface Box { iv: string; tag: string; data: string }
interface Kdf { name: 'scrypt'; salt: string; N: number; r: number; p: number }
/** Presence mode (macOS): the data key is wrapped under passphrase + a Secure Enclave secret, and the passphrase-only `dk` wrap is gone. */
interface PresenceBlock {
  helperSha256: string;
  keyDir: string;
  dk: Box;
  recovery: { kdf: Kdf; dk: Box };
}
interface VaultFile {
  version: 1;
  kdf: Kdf;
  /** Absent while presence mode is on: the passphrase alone must not open the vault then. */
  dk?: Box;
  presence?: PresenceBlock;
  secrets: Record<string, Box>;
}
interface Keys { dk: Buffer; enc: Buffer; mac: Buffer; events: Buffer }

export const MIN_PASSPHRASE = 12;

/** Only lives in the memory of the process that unlocked it (normally the running proxy). */
let keys: Keys | null = null;

// Presence mode: after an approved unlock, a sign-in (a new browser tab, every CLI command) is checked
// against this instead of asking the Secure Enclave again. It is an HMAC of the scrypt output under a
// random per-process key, so it exists only in memory and says nothing to anyone who reads the heap
// less than the vault keys already do. Nothing like it is stored on disk: that would let anyone with
// a copy of vault.json guess the passphrase offline without the Secure Enclave.
const processKey = randomBytes(32);
let verifier: Buffer | null = null;

/** Presence mode is on but this process cannot check a passphrase without an approval. */
export class PresenceRequiredError extends Error {
  constructor() {
    super('Presence mode is on: unlocking needs your passphrase and an approval on this Mac.');
  }
}

export class WrongPassphraseError extends Error {
  constructor() {
    super('Wrong passphrase.');
  }
}

function vaultPath(): string {
  return path.join(config().home, 'vault.json');
}

function seal(key: Buffer, plaintext: Buffer, aad: string): Box {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
}

/** Throws if the key is wrong or the box was tampered with (GCM authentication). */
function open(key: Buffer, box: Box, aad: string): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(box.iv, 'base64'));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(box.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(box.data, 'base64')), decipher.final()]);
}

function kek(passphrase: string, kdf: Kdf): Buffer {
  return scryptSync(passphrase.normalize('NFC'), Buffer.from(kdf.salt, 'base64'), 32, {
    N: kdf.N, r: kdf.r, p: kdf.p, maxmem: 256 * kdf.N * kdf.r + 1024 * 1024,
  });
}

function subkeys(dk: Buffer): Keys {
  const derive = (info: string) => Buffer.from(hkdfSync('sha256', dk, Buffer.alloc(0), info, 32));
  return { dk, enc: derive(`${BRAND.cryptoContext}/secrets`), mac: derive(`${BRAND.cryptoContext}/records`), events: derive(`${BRAND.cryptoContext}/events`) };
}

function read(): VaultFile {
  return JSON.parse(fs.readFileSync(vaultPath(), 'utf8'));
}

/** Atomic replace, so a crash mid-write never leaves a half-written vault. */
function write(file: VaultFile): void {
  const target = vaultPath();
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const tmp = `${target}.${process.pid}.tmp`;
  // fsync before the rename: otherwise a power cut can leave a renamed but empty vault, and for
  // a passphrase change that would destroy the only copy of the wrapped data key.
  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    fs.fchmodSync(fd, 0o600); // a leftover temp file from a crash may have looser permissions
    fs.writeSync(fd, JSON.stringify(file, null, 2));
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, target);
}

/**
 * Every change is read-modify-write of the whole file, and both the proxy and the CLI (presence
 * enable/disable/repair) write it, so two writers at the same moment would lose one change: a
 * credential key, or the presence wrap. A lock file serialises them across processes. A lock left
 * by a crashed process is taken over after 30 s.
 */
function withVaultLock<T>(fn: () => T): T {
  const lock = `${vaultPath()}.lock`;
  fs.mkdirSync(path.dirname(lock), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      fs.closeSync(fs.openSync(lock, 'wx', 0o600));
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      try {
        if (Date.now() - fs.statSync(lock).mtimeMs > 30_000) { fs.rmSync(lock, { force: true }); continue; }
      } catch { continue; }
      if (Date.now() > deadline) throw new Error('The vault is busy (another Wickey process is changing it). Try again in a moment.');
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
  try {
    return fn();
  } finally {
    fs.rmSync(lock, { force: true });
  }
}

export function vaultExists(): boolean {
  return fs.existsSync(vaultPath());
}

export function isUnlocked(): boolean {
  return keys !== null;
}

// N = 2^17 costs ~128 MB and a few hundred ms per unlock; tests lower it via the SCRYPT_N env var (see brand.ts for the prefix).
function freshKdf(): Kdf {
  return { name: 'scrypt', salt: randomBytes(16).toString('base64'), N: Number(envVar('SCRYPT_N') ?? 2 ** 17), r: 8, p: 1 };
}

export function createVault(passphrase: string): void {
  if (passphrase.length < MIN_PASSPHRASE) throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE} characters.`);
  const kdf = freshKdf();
  const dk = randomBytes(32);
  const kekBuf = kek(passphrase, kdf);
  // Checked under the lock, so two setups at once can't both create a vault.
  withVaultLock(() => {
    if (vaultExists()) throw new Error('A vault already exists.');
    write({ version: 1, kdf, dk: seal(kekBuf, dk, `${BRAND.cryptoContext}/dk`), secrets: {} });
  });
  keys = subkeys(dk);
  verifier = verifierFor(kekBuf);
}

/** Passphrase-only unwrap. With presence on there is no such wrap, so this never succeeds then. */
function unwrap(passphrase: string): Buffer {
  const file = read();
  if (!file.dk) throw new PresenceRequiredError();
  try {
    return open(kek(passphrase, file.kdf), file.dk, `${BRAND.cryptoContext}/dk`);
  } catch {
    throw new WrongPassphraseError();
  }
}

export function unlockVault(passphrase: string): void {
  const kekBuf = kek(passphrase, read().kdf);
  keys = subkeys(unwrap(passphrase));
  verifier = verifierFor(kekBuf);
}

/**
 * Confirms the passphrase without changing what is unlocked. With presence on it uses the in-memory
 * verifier and throws PresenceRequiredError when this process has none (it was unlocked by a recovery code).
 */
export function verifyPassphrase(passphrase: string): void {
  if (read().presence) {
    if (!verifier) throw new PresenceRequiredError();
    if (!verifierMatches(passphrase)) throw new WrongPassphraseError();
    return;
  }
  const dk = unwrap(passphrase);
  if (keys && !timingSafeEqual(dk, keys.dk)) throw new WrongPassphraseError();
}

function verifierFor(kekBuf: Buffer): Buffer {
  return createHmac('sha256', processKey).update(kekBuf).digest();
}

function verifierMatches(passphrase: string): boolean {
  return verifier !== null && timingSafeEqual(verifierFor(kek(passphrase, read().kdf)), verifier);
}

// ---- Presence mode ----

const PRESENCE_KEY_DIR = 'presence';
const RECOVERY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function presenceConfig(): { helperSha256: string; keyDir: string } | null {
  if (!vaultExists()) return null;
  const p = read().presence;
  return p ? { helperSha256: p.helperSha256, keyDir: p.keyDir } : null;
}

/** Where the Secure Enclave key handle lives. Fixed, so an edited vault.json cannot point the helper elsewhere. */
export function presenceKeyDir(): string {
  return path.join(config().home, PRESENCE_KEY_DIR);
}

/** The scrypt output for `passphrase` under the vault's current KDF settings. Compute it BEFORE asking for the approval. */
export function deriveKek(passphrase: string): Buffer {
  return kek(passphrase, read().kdf);
}

function presenceKek(kekBuf: Buffer, secret: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', Buffer.concat([kekBuf, secret]), Buffer.alloc(0), `${BRAND.cryptoContext}/presence-kek`, 32));
}

// The helper's hash is in the AAD: editing helperSha256 in vault.json (to match a swapped helper) makes this unwrap fail.
const presenceAad = (helperSha256: string) => `${BRAND.cryptoContext}/dk-presence/${helperSha256}`;
const recoveryAad = `${BRAND.cryptoContext}/dk-recovery`;

/** Data key from passphrase KEK + approval secret. WrongPassphraseError for a wrong passphrase OR a mismatched helper hash (GCM cannot tell which). */
export function openWithPresence(kekBuf: Buffer, secret: Buffer): Buffer {
  const p = read().presence;
  if (!p) throw new Error('Presence mode is off.');
  try {
    return open(presenceKek(kekBuf, secret), p.dk, presenceAad(p.helperSha256));
  } catch {
    throw new WrongPassphraseError();
  }
}

/** Unlock with a data key obtained through openWithPresence. When already unlocked it must be the same key. */
export function adoptDataKey(dk: Buffer, kekBuf: Buffer): void {
  if (keys && !timingSafeEqual(dk, keys.dk)) throw new WrongPassphraseError();
  if (!keys) keys = subkeys(dk);
  verifier = verifierFor(kekBuf);
}

/** Recovery codes are 160 random bits, shown in groups of four. Never stored. */
export function newRecoveryCode(): string {
  const bytes = randomBytes(20);
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += RECOVERY_ALPHABET[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  return out.match(/.{4}/g)!.join('-');
}

function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z2-7]/g, '');
}

export class WrongRecoveryCodeError extends WrongPassphraseError {
  constructor() {
    super();
    this.message = 'Wrong recovery code.';
  }
}

function recoveryKek(code: string, kdf: Kdf): Buffer {
  return kek(normalizeRecoveryCode(code), kdf);
}

function presenceBlock(dk: Buffer, kekBuf: Buffer, secret: Buffer, helperSha256: string, code: string): PresenceBlock {
  const kdf = freshKdf();
  return {
    helperSha256,
    keyDir: PRESENCE_KEY_DIR,
    dk: seal(presenceKek(kekBuf, secret), dk, presenceAad(helperSha256)),
    recovery: { kdf, dk: seal(recoveryKek(code, kdf), dk, recoveryAad) },
  };
}

/** Turns presence on: needs the passphrase (wrong one: WrongPassphraseError) and removes the passphrase-only wrap in the same atomic write. */
export function enablePresence(passphrase: string, secret: Buffer, helperSha256: string, recoveryCode: string): void {
  withVaultLock(() => {
    const file = read();
    if (file.presence) throw new Error('Presence mode is already on.');
    const dk = unwrap(passphrase);
    file.presence = presenceBlock(dk, kek(passphrase, file.kdf), secret, helperSha256, recoveryCode);
    delete file.dk;
    write(file);
  });
}

/** Back to passphrase-only. `secret` is the current approval secret. */
export function disablePresence(passphrase: string, secret: Buffer): void {
  withVaultLock(() => {
    const file = read();
    if (!file.presence) throw new Error('Presence mode is already off.');
    const kekBuf = kek(passphrase, file.kdf);
    const dk = openWithPresence(kekBuf, secret);
    file.dk = seal(kekBuf, dk, `${BRAND.cryptoContext}/dk`);
    delete file.presence;
    write(file);
  });
}

/**
 * Re-records the helper hash (and a fresh recovery code) after a rebuild. `from` is the old key's
 * secret, or the recovery code when the key is gone (the passphrase then cannot be checked, which
 * is why the caller asks for it twice).
 */
export function repairPresence(
  passphrase: string,
  from: { secret: Buffer } | { recoveryCode: string },
  to: { secret: Buffer; helperSha256: string; recoveryCode: string },
): void {
  withVaultLock(() => {
    const file = read();
    if (!file.presence) throw new Error('Presence mode is off.');
    const kekBuf = kek(passphrase, file.kdf);
    const dk = 'secret' in from ? openWithPresence(kekBuf, from.secret) : dkFromRecovery(file, from.recoveryCode);
    file.presence = presenceBlock(dk, kekBuf, to.secret, to.helperSha256, to.recoveryCode);
    write(file);
  });
}

function dkFromRecovery(file: VaultFile, code: string): Buffer {
  if (!file.presence) throw new Error('Presence mode is off.');
  try {
    return open(recoveryKek(code, file.presence.recovery.kdf), file.presence.recovery.dk, recoveryAad);
  } catch {
    throw new WrongRecoveryCodeError();
  }
}

/** Throws WrongRecoveryCodeError unless `code` opens this vault's recovery wrap. */
export function verifyRecoveryCode(code: string): void {
  dkFromRecovery(read(), code);
}

/** Unlocks with the recovery code alone. This process then has no passphrase verifier (see PresenceRequiredError). */
export function unlockWithRecovery(code: string): void {
  const dk = dkFromRecovery(read(), code);
  keys = subkeys(dk);
  verifier = null;
}

/**
 * Re-wraps the same data key under a new passphrase and a fresh salt. The data key doesn't change,
 * so stored secrets and row signatures stay valid. Unlocks nothing: it only verifies `current`.
 */
export function assertNewPassphrase(current: string, next: string): void {
  if (next.length < MIN_PASSPHRASE) throw new Error(`The new passphrase must be at least ${MIN_PASSPHRASE} characters.`);
  if (current.normalize('NFC') === next.normalize('NFC')) throw new Error('The new passphrase must be different from the current one.');
}

export function changePassphrase(current: string, next: string, secret?: Buffer): void {
  assertNewPassphrase(current, next);
  const kdf = freshKdf();
  const nextKek = kek(next, kdf);
  withVaultLock(() => {
    const file = read();
    if (file.presence) {
      if (!secret) throw new PresenceRequiredError();
      // The same approval secret and recovery wrap carry over; only the passphrase half of the key changes.
      const dk = openWithPresence(kek(current, file.kdf), secret);
      file.presence.dk = seal(presenceKek(nextKek, secret), dk, presenceAad(file.presence.helperSha256));
    } else {
      file.dk = seal(nextKek, unwrap(current), `${BRAND.cryptoContext}/dk`);
    }
    file.kdf = kdf;
    write(file);
  });
  if (keys) verifier = verifierFor(nextKek);
}

export function lockVault(): void {
  keys = null;
  verifier = null;
}

function requireKeys(): Keys {
  if (!keys) throw new Error('Wickey is locked. Unlock it with your passphrase first.');
  return keys;
}

export function setSecret(id: string, secret: string): void {
  const k = requireKeys();
  withVaultLock(() => {
    const file = read();
    file.secrets[id] = seal(k.enc, Buffer.from(secret, 'utf8'), `${BRAND.cryptoContext}/secret/${id}`);
    write(file);
  });
}

/** Null if missing; throws if the entry was tampered with or moved to another credential's id. */
export function getSecret(id: string): string | null {
  const k = requireKeys();
  const box = read().secrets[id];
  return box ? open(k.enc, box, `${BRAND.cryptoContext}/secret/${id}`).toString('utf8') : null;
}

/** Needs no passphrase: removing a secret only takes access away. */
export function deleteSecret(id: string): void {
  if (!vaultExists()) return;
  withVaultLock(() => {
    const file = read();
    if (!(id in file.secrets)) return;
    delete file.secrets[id];
    write(file);
  });
}

/** HMAC for database rows, so rows written behind the proxy's back are rejected. */
export function sign(data: string): string {
  return createHmac('sha256', requireKeys().mac).update(data).digest('hex');
}

export function verifySignature(data: string, signature: string | null): boolean {
  if (!signature) return false;
  const expected = Buffer.from(sign(data), 'hex');
  const given = Buffer.from(signature, 'hex');
  return given.length === expected.length && timingSafeEqual(given, expected);
}

/** HMAC over an event-log entry hash. Its own subkey, so a row signature can never pass as an event MAC. */
export function eventMac(hash: string): string {
  return createHmac('sha256', requireKeys().events).update(hash).digest('hex');
}

export function verifyEventMac(hash: string, mac: string | null): boolean {
  if (!mac) return false;
  const expected = Buffer.from(eventMac(hash), 'hex');
  const given = Buffer.from(mac, 'hex');
  return given.length === expected.length && timingSafeEqual(given, expected);
}
