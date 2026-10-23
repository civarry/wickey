import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { BRAND, envVar } from './brand.ts';
import { config } from './config.ts';

// The vault holds the real provider keys, encrypted, in one JSON file that works the same on
// every OS. A random data key (DK) encrypts everything; the DK itself is stored encrypted under a
// key derived from the user's passphrase with scrypt, so changing the passphrase later only means
// re-wrapping the DK. Two subkeys come from the DK: one encrypts secrets, one signs database rows.

interface Box { iv: string; tag: string; data: string }
interface VaultFile {
  version: 1;
  kdf: { name: 'scrypt'; salt: string; N: number; r: number; p: number };
  dk: Box;
  secrets: Record<string, Box>;
}
interface Keys { dk: Buffer; enc: Buffer; mac: Buffer }

export const MIN_PASSPHRASE = 12;

/** Only lives in the memory of the process that unlocked it (normally the running proxy). */
let keys: Keys | null = null;

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

function kek(passphrase: string, kdf: VaultFile['kdf']): Buffer {
  return scryptSync(passphrase.normalize('NFC'), Buffer.from(kdf.salt, 'base64'), 32, {
    N: kdf.N, r: kdf.r, p: kdf.p, maxmem: 256 * kdf.N * kdf.r + 1024 * 1024,
  });
}

function subkeys(dk: Buffer): Keys {
  const derive = (info: string) => Buffer.from(hkdfSync('sha256', dk, Buffer.alloc(0), info, 32));
  return { dk, enc: derive(`${BRAND.cryptoContext}/secrets`), mac: derive(`${BRAND.cryptoContext}/records`) };
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

export function vaultExists(): boolean {
  return fs.existsSync(vaultPath());
}

export function isUnlocked(): boolean {
  return keys !== null;
}

// N = 2^17 costs ~128 MB and a few hundred ms per unlock; tests lower it via the SCRYPT_N env var (see brand.ts for the prefix).
function freshKdf(): VaultFile['kdf'] {
  return { name: 'scrypt', salt: randomBytes(16).toString('base64'), N: Number(envVar('SCRYPT_N') ?? 2 ** 17), r: 8, p: 1 };
}

export function createVault(passphrase: string): void {
  if (vaultExists()) throw new Error('A vault already exists.');
  if (passphrase.length < MIN_PASSPHRASE) throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE} characters.`);
  const kdf = freshKdf();
  const dk = randomBytes(32);
  write({ version: 1, kdf, dk: seal(kek(passphrase, kdf), dk, `${BRAND.cryptoContext}/dk`), secrets: {} });
  keys = subkeys(dk);
}

function unwrap(passphrase: string): Buffer {
  const file = read();
  try {
    return open(kek(passphrase, file.kdf), file.dk, `${BRAND.cryptoContext}/dk`);
  } catch {
    throw new WrongPassphraseError();
  }
}

export function unlockVault(passphrase: string): void {
  keys = subkeys(unwrap(passphrase));
}

/** Confirms the passphrase against the vault without changing what is unlocked. */
export function verifyPassphrase(passphrase: string): void {
  const dk = unwrap(passphrase);
  if (keys && !timingSafeEqual(dk, keys.dk)) throw new WrongPassphraseError();
}

/**
 * Re-wraps the same data key under a new passphrase and a fresh salt. The data key doesn't change,
 * so stored secrets and row signatures stay valid. Unlocks nothing: it only verifies `current`.
 */
export function changePassphrase(current: string, next: string): void {
  if (next.length < MIN_PASSPHRASE) throw new Error(`The new passphrase must be at least ${MIN_PASSPHRASE} characters.`);
  if (current.normalize('NFC') === next.normalize('NFC')) throw new Error('The new passphrase must be different from the current one.');
  const dk = unwrap(current);
  const file = read();
  const kdf = freshKdf();
  file.kdf = kdf;
  file.dk = seal(kek(next, kdf), dk, `${BRAND.cryptoContext}/dk`);
  write(file);
}

export function lockVault(): void {
  keys = null;
}

function requireKeys(): Keys {
  if (!keys) throw new Error('Wickey is locked. Unlock it with your passphrase first.');
  return keys;
}

export function setSecret(id: string, secret: string): void {
  const k = requireKeys();
  const file = read();
  file.secrets[id] = seal(k.enc, Buffer.from(secret, 'utf8'), `${BRAND.cryptoContext}/secret/${id}`);
  write(file);
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
  const file = read();
  if (!(id in file.secrets)) return;
  delete file.secrets[id];
  write(file);
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
