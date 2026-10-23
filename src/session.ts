import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { BRAND, envVar } from './brand.ts';
import { signExistingRows, listCredentials } from './store.ts';
import { WrongPassphraseError, changePassphrase as rewrapVault, createVault, getSecret, isUnlocked, unlockVault, vaultExists, verifyPassphrase } from './vault.ts';

// Sudo-style grace: after the passphrase is entered, minting keys works without it for a few
// minutes. During that window ANY program on this computer can mint keys through the running
// proxy, which is why the dashboard shows the countdown and a "Lock now" button.

const DEFAULT_GRACE_SECONDS = 300;
let graceUntil = 0;

// Online guessing through the API is throttled: after 5 wrong passphrases, each further attempt
// waits twice as long as the last (up to 5 minutes). Offline guessing against vault.json is slowed
// only by scrypt, so a long passphrase still matters.
let failures = 0;
let blockedUntil = 0;

export class TooManyAttemptsError extends Error {
  constructor(seconds: number) {
    super(`Too many wrong passphrases. Try again in ${seconds}s.`);
  }
}

function checkThrottle(): void {
  const wait = Math.ceil((blockedUntil - Date.now()) / 1000);
  if (wait > 0) throw new TooManyAttemptsError(wait);
}

function recordAttempt<T>(fn: () => T): T {
  checkThrottle();
  try {
    const result = fn();
    failures = 0;
    return result;
  } catch (err) {
    if (err instanceof WrongPassphraseError) {
      failures++;
      if (failures >= 5) blockedUntil = Date.now() + Math.min(300, 2 ** (failures - 5)) * 1000;
    }
    throw err;
  }
}

export class AuthRequiredError extends Error {
  code: 'passphrase_required' | 'setup_required' | 'session_required';
  constructor(code: 'passphrase_required' | 'setup_required' | 'session_required', message: string) {
    super(message);
    this.code = code;
  }
}

/** WICKEY_GRACE accepts seconds; 0 turns the grace period off. Read at call time. */
export function graceSeconds(): number {
  const raw = envVar('GRACE');
  const n = raw === undefined ? DEFAULT_GRACE_SECONDS : Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_GRACE_SECONDS;
}

export function graceRemaining(): number {
  return Math.max(0, Math.ceil((graceUntil - Date.now()) / 1000));
}

function startGrace(): void {
  graceUntil = Date.now() + graceSeconds() * 1000;
}

export function endGrace(): void {
  graceUntil = 0;
}

// ---- Sessions ----
// Every /api call except the sign-in ones needs a session. A session is created only by proving the
// passphrase, lives in this process's memory (a restart signs everyone out) and travels in an
// HttpOnly cookie. The Host/Origin/header checks in api.ts stay on top: browsers treat every port
// on 127.0.0.1 as one site, so the cookie alone would not stop another local web page.

export const SESSION_COOKIE = BRAND.sessionCookie;
const SESSION_IDLE_MS = 12 * 60 * 60 * 1000;
const MAX_SESSIONS = 100;
// Keyed by a hash of the id so the map never holds a usable cookie value.
const sessions = new Map<string, number>();

function sessionKey(id: string): string {
  return createHash('sha256').update(id).digest('hex');
}

export function createSession(): string {
  const now = Date.now();
  for (const [k, seen] of sessions) if (now - seen > SESSION_IDLE_MS) sessions.delete(k);
  // Oldest first (Map keeps insertion order, and touching re-inserts).
  while (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value!);
  const id = randomBytes(32).toString('base64url');
  sessions.set(sessionKey(id), now);
  return id;
}

export function sessionIdFromCookie(header: string | undefined): string | null {
  for (const part of (header ?? '').split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === SESSION_COOKIE) return rest.join('=') || null;
  }
  return null;
}

/** True for a live session; each use pushes its idle expiry back. */
export function touchSession(id: string | null): boolean {
  if (!id) return false;
  const key = sessionKey(id);
  const seen = sessions.get(key);
  if (seen === undefined) return false;
  sessions.delete(key);
  if (Date.now() - seen > SESSION_IDLE_MS) return false;
  sessions.set(key, Date.now());
  return true;
}

export function endSession(id: string | null): void {
  if (id) sessions.delete(sessionKey(id));
}

export function clearSessions(): void {
  sessions.clear();
}

/** Lock: ends the grace period and signs every browser and CLI session out. */
export function lock(): void {
  endGrace();
  clearSessions();
}

// Setup over HTTP needs a one-time token that `start` prints as a link. Without it, any local
// program could set the first passphrase before the user does and know it forever. Memory only:
// it dies with the process, and any setup (dashboard or terminal) clears it.
let setupToken: string | null = null;

/** Starts accepting setup over HTTP and returns the token for the setup link. */
export function openSetup(): string {
  setupToken = randomBytes(32).toString('base64url');
  return setupToken;
}

export function setupTokenMatches(given: unknown): boolean {
  if (!setupToken || typeof given !== 'string') return false;
  const a = Buffer.from(given);
  const b = Buffer.from(setupToken);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Creates the vault, signs any rows that predate it, and starts the grace period. */
export function setUp(passphrase: string): void {
  createVault(passphrase);
  setupToken = null;
  signExistingRows();
  startGrace();
}

/** Unlocks the vault (if it isn't already) and starts the grace period. */
export function unlock(passphrase: string): void {
  if (!vaultExists()) throw new AuthRequiredError('setup_required', 'Set a passphrase first.');
  recordAttempt(() => (isUnlocked() ? verifyPassphrase(passphrase) : unlockVault(passphrase)));
  startGrace();
}

/** Passphrase check for a sign-in when the vault is already unlocked (a new browser, or the CLI). */
export function signIn(passphrase: string): void {
  if (!vaultExists()) throw new AuthRequiredError('setup_required', 'Set a passphrase first.');
  if (!isUnlocked()) throw new AuthRequiredError('passphrase_required', 'Wickey is locked. Unlock it with your passphrase first.');
  recordAttempt(() => verifyPassphrase(passphrase));
  startGrace();
}

/**
 * Always asks for the current passphrase, even inside the grace period: otherwise any local
 * program could take over the vault during the window. Wrong guesses count toward the throttle.
 * Ends the grace period, so the next mint asks for the new passphrase.
 */
export function changePassphrase(current: string, next: string): void {
  if (!vaultExists()) throw new AuthRequiredError('setup_required', 'Set a passphrase first.');
  if (!isUnlocked()) throw new Error('Wickey is locked. Unlock it with your passphrase first.');
  recordAttempt(() => rewrapVault(current, next));
  endGrace();
}

/**
 * Gate for anything that mints a key or could redirect a real key: passes with the right
 * passphrase, or without one while the grace period is running.
 */
export function requireAuth(passphrase?: string): void {
  if (!vaultExists()) throw new AuthRequiredError('setup_required', 'Set a passphrase first.');
  if (passphrase) return unlock(passphrase);
  if (isUnlocked() && Date.now() < graceUntil) return;
  throw new AuthRequiredError('passphrase_required', 'Enter your passphrase to continue.');
}

/** All that is safe to tell a caller who has no session: what the sign-in screen needs. */
export function publicStatus(signedIn: boolean) {
  return { vault: vaultExists(), unlocked: isUnlocked(), signedIn };
}

export function sessionState() {
  return {
    vault: vaultExists(),
    unlocked: isUnlocked(),
    graceSeconds: graceSeconds(),
    graceRemaining: isUnlocked() ? graceRemaining() : 0,
    credentialsWithoutVault: vaultExists() ? 0 : listCredentials().length,
  };
}
