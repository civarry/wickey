import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { BRAND, envVar } from './brand.ts';
import { logEvent, type Via } from './audit.ts';
import { humanRequired } from './human.ts';
import { signExistingRows, listCredentials } from './store.ts';
import { noteUnwrapFailure, presenceOn, usePresence } from './presencemode.ts';
import type { PresenceAction } from './presence.ts';
import {
  PresenceRequiredError, WrongPassphraseError, adoptDataKey, assertNewPassphrase, changePassphrase as rewrapVault, createVault, deriveKek,
  isUnlocked, openWithPresence, unlockVault, unlockWithRecovery, vaultExists, verifyPassphrase,
} from './vault.ts';

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

// The throttle window (identified by its end time) already reported to the event log.
let throttleLogged = 0;

function checkThrottle(): void {
  const wait = Math.ceil((blockedUntil - Date.now()) / 1000);
  if (wait <= 0) return;
  // Once per window, not per refused attempt: a guessing loop must not flood the log.
  if (throttleLogged !== blockedUntil) {
    throttleLogged = blockedUntil;
    logEvent('passphrase_throttled', {});
  }
  throw new TooManyAttemptsError(wait);
}

function noteFailure(err: unknown, via: Via): void {
  if (err instanceof WrongPassphraseError) {
    logEvent('unlock_failed', { via });
    failures++;
    if (failures >= 5) blockedUntil = Date.now() + Math.min(300, 2 ** (failures - 5)) * 1000;
  }
  // A cancelled or failed approval is not a guess: it counts for nothing here (it has its own event).
}

function recordAttempt<T>(via: Via, fn: () => T): T {
  checkThrottle();
  try {
    const result = fn();
    failures = 0;
    return result;
  } catch (err) {
    noteFailure(err, via);
    throw err;
  }
}

/** For attempts that wait for an approval. Only one approval can be open at a time (presencemode.ts), so attempts cannot pile up behind the same stale throttle check. */
async function recordAttemptAsync<T>(via: Via, fn: () => Promise<T>): Promise<T> {
  checkThrottle();
  try {
    const result = await fn();
    failures = 0;
    return result;
  } catch (err) {
    noteFailure(err, via);
    throw err;
  }
}

/** Every one of these means a human has to supply something, so the message addresses agents (see human.ts). */
export class AuthRequiredError extends Error {
  code: 'passphrase_required' | 'setup_required' | 'session_required';
  readonly humanRequired = true;
  constructor(code: 'passphrase_required' | 'setup_required' | 'session_required', nextStep: string) {
    super(humanRequired(nextStep));
    this.code = code;
  }
}

const SET_PASSPHRASE = `set a passphrase: open the one-time setup link printed by \`${BRAND.command} start\`, or run \`${BRAND.command} setup\` in their own terminal`;
export const SIGN_IN_STEP = `sign in to the dashboard with their passphrase, or run the ${BRAND.command} command themselves in their own terminal`;
const UNLOCK_STEP = `unlock Wickey in the dashboard with their passphrase, or run \`${BRAND.command} unlock\` in their own terminal`;
const PASSPHRASE_STEP = `enter their passphrase in the dashboard, or run the ${BRAND.command} command themselves in their own terminal`;

/** Presence mode is on, but this process has no way to check a passphrase until someone signs in once with an approval. */
function needsApprovalSignIn(): AuthRequiredError {
  return new AuthRequiredError('passphrase_required', `sign in to the dashboard or run any ${BRAND.command} command themselves, and approve the system prompt (this Wickey was unlocked with a recovery code, so it cannot check the passphrase yet)`);
}

/** Runs a synchronous passphrase check, turning "needs an approval first" into the sign-in message. */
function guardApproval<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    if (err instanceof PresenceRequiredError) throw needsApprovalSignIn();
    throw err;
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
export function lock(via: Via = 'dashboard'): void {
  endGrace();
  clearSessions();
  logEvent('locked', { via });
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
export function setUp(passphrase: string, via: Via = 'terminal'): void {
  createVault(passphrase);
  logEvent('vault_created', { via });
  setupToken = null;
  signExistingRows();
  startGrace();
}

/**
 * Unlocks the vault (if it isn't already) and starts the grace period. `session` is true when the
 * caller goes on to create a session (dashboard or CLI): then an already-unlocked vault is a sign-in.
 */
export function unlock(passphrase: string, via: Via = 'terminal', session = false): void | Promise<void> {
  if (!vaultExists()) throw new AuthRequiredError('setup_required', SET_PASSPHRASE);
  // With presence mode on the unlock waits for a human to approve a system prompt, so it is async;
  // without it nothing changes and the call completes before returning.
  if (presenceOn()) return unlockWithApproval(passphrase, via, session);
  unlockPlain(passphrase, via, session);
}

function unlockPlain(passphrase: string, via: Via, session: boolean): void {
  const wasUnlocked = isUnlocked();
  recordAttempt(via, () => (wasUnlocked ? verifyPassphrase(passphrase) : unlockVault(passphrase)));
  startGrace();
  if (!wasUnlocked) logEvent('unlocked', { via });
  else if (session) logEvent('signed_in', { via });
}

/**
 * Presence mode: scrypt first (so the prompt appears only once the passphrase work is done), then the
 * approval, then the unwrap. An unwrap that fails after an approval counts as a wrong passphrase:
 * there is deliberately no passphrase-only check on disk, because it would allow offline guessing.
 * A sign-in while unlocked is checked against the in-memory verifier and asks for nothing.
 */
async function checkWithApproval(passphrase: string, via: Via, wasUnlocked: boolean, action: PresenceAction = 'unlock vault'): Promise<void> {
  if (wasUnlocked) {
    try {
      return verifyPassphrase(passphrase);
    } catch (err) {
      if (!(err instanceof PresenceRequiredError)) throw err;
    }
  }
  const kekBuf = deriveKek(passphrase);
  const secret = await usePresence(action, via);
  let dk: Buffer;
  try {
    dk = openWithPresence(kekBuf, secret);
  } catch (err) {
    if (err instanceof WrongPassphraseError) noteUnwrapFailure(action, via);
    throw err;
  }
  adoptDataKey(dk, kekBuf);
}

async function unlockWithApproval(passphrase: string, via: Via, session: boolean): Promise<void> {
  const wasUnlocked = isUnlocked();
  await recordAttemptAsync(via, () => checkWithApproval(passphrase, via, wasUnlocked));
  startGrace();
  if (!wasUnlocked) logEvent('unlocked', { via });
  else if (session) logEvent('signed_in', { via });
}

/** Terminal only (the CLI refuses without one). Opens the vault with the recovery code when the Secure Enclave key cannot be used. */
export function unlockWithRecoveryCode(code: string, via: Via = 'cli'): void {
  if (!vaultExists()) throw new AuthRequiredError('setup_required', SET_PASSPHRASE);
  if (!presenceOn()) throw new Error(`Presence mode is off, so there is no recovery code. Unlock with your passphrase (\`${BRAND.command} unlock\`).`);
  if (isUnlocked()) throw new Error('Wickey is already unlocked. Nothing to recover.');
  recordAttempt(via, () => unlockWithRecovery(code));
  startGrace();
  logEvent('recovery_used', { via, purpose: 'unlock' }, 'warn');
  logEvent('unlocked', { via });
}

/** Passphrase check for a sign-in when the vault is already unlocked (a new browser, or the CLI). */
export function signIn(passphrase: string, via: Via = 'dashboard'): void | Promise<void> {
  if (!vaultExists()) throw new AuthRequiredError('setup_required', SET_PASSPHRASE);
  if (!isUnlocked()) throw new AuthRequiredError('passphrase_required', UNLOCK_STEP);
  if (presenceOn()) return signInWithApproval(passphrase, via);
  recordAttempt(via, () => verifyPassphrase(passphrase));
  startGrace();
  logEvent('signed_in', { via });
}

/** No prompt while this process holds the verifier from the approved unlock; one prompt if it has none (unlocked by recovery code, or presence turned on elsewhere before any unlock here). */
async function signInWithApproval(passphrase: string, via: Via): Promise<void> {
  await recordAttemptAsync(via, () => checkWithApproval(passphrase, via, true));
  startGrace();
  logEvent('signed_in', { via });
}

/**
 * Always asks for the current passphrase, even inside the grace period: otherwise any local
 * program could take over the vault during the window. Wrong guesses count toward the throttle.
 * Ends the grace period, so the next mint asks for the new passphrase.
 */
export function changePassphrase(current: string, next: string, via: Via = 'dashboard'): void | Promise<void> {
  if (!vaultExists()) throw new AuthRequiredError('setup_required', SET_PASSPHRASE);
  if (!isUnlocked()) throw new Error('Wickey is locked. Unlock it with your passphrase first.');
  if (presenceOn()) return changeWithApproval(current, next, via);
  recordAttempt(via, () => rewrapVault(current, next));
  endGrace();
  logEvent('passphrase_changed', { via });
}

async function changeWithApproval(current: string, next: string, via: Via): Promise<void> {
  assertNewPassphrase(current, next); // before the prompt: no approval for a change that cannot happen
  await recordAttemptAsync(via, async () => {
    // A wrong current passphrase is refused before anyone is asked to approve anything.
    try { verifyPassphrase(current); } catch (err) { if (!(err instanceof PresenceRequiredError)) throw err; }
    const secret = await usePresence('change passphrase', via);
    try {
      rewrapVault(current, next, secret);
    } catch (err) {
      if (err instanceof WrongPassphraseError) noteUnwrapFailure('change passphrase', via);
      throw err;
    }
  });
  endGrace();
  logEvent('passphrase_changed', { via });
}

/**
 * Checks the passphrase for an action that must never ride on the grace period (like
 * changePassphrase). Wrong guesses count toward the throttle. Starts nothing: no grace, no session.
 */
export function confirmPassphrase(passphrase: string | undefined, via: Via = 'dashboard'): void {
  if (!vaultExists()) throw new AuthRequiredError('setup_required', SET_PASSPHRASE);
  if (!isUnlocked()) throw new AuthRequiredError('passphrase_required', UNLOCK_STEP);
  if (!passphrase) throw new AuthRequiredError('passphrase_required', PASSPHRASE_STEP);
  recordAttempt(via, () => guardApproval(() => verifyPassphrase(passphrase)));
}

/** confirmPassphrase, plus an approval when presence mode is on: for actions that must not ride on a stolen passphrase alone (turning an alert off). */
export async function confirmWithApproval(passphrase: string | undefined, action: PresenceAction, via: Via = 'dashboard'): Promise<void> {
  confirmPassphrase(passphrase, via);
  if (presenceOn()) await usePresence(action, via);
}

/**
 * Gate for anything that mints a key or could redirect a real key: passes with the right
 * passphrase, or without one while the grace period is running.
 */
export function requireAuth(passphrase?: string, via: Via = 'dashboard'): void {
  if (!vaultExists()) throw new AuthRequiredError('setup_required', SET_PASSPHRASE);
  // Not a sign-in (no session is created here), so only a failure or a real unlock is logged.
  if (passphrase) {
    if (!presenceOn()) return unlockPlain(passphrase, via, false);
    // Unlocking needs an approval, which these synchronous gates cannot wait for; a session implies an earlier unlock anyway.
    if (!isUnlocked()) throw new AuthRequiredError('passphrase_required', UNLOCK_STEP);
    recordAttempt(via, () => guardApproval(() => verifyPassphrase(passphrase)));
    startGrace();
    return;
  }
  if (isUnlocked() && Date.now() < graceUntil) return;
  throw new AuthRequiredError('passphrase_required', PASSPHRASE_STEP);
}

/** All that is safe to tell a caller who has no session: what the sign-in screen needs. */
export function publicStatus(signedIn: boolean) {
  return { vault: vaultExists(), unlocked: isUnlocked(), signedIn, presence: presenceOn() };
}

export function sessionState() {
  return {
    vault: vaultExists(),
    unlocked: isUnlocked(),
    graceSeconds: graceSeconds(),
    graceRemaining: isUnlocked() ? graceRemaining() : 0,
    credentialsWithoutVault: vaultExists() ? 0 : listCredentials().length,
    presence: presenceOn(),
  };
}
