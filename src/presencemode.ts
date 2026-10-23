import fs from 'node:fs';
import path from 'node:path';
import { BRAND } from './brand.ts';
import { logEvent, type Via } from './audit.ts';
import { listEvents } from './events.ts';
import {
  PresenceError, PresenceHelperMismatch, buildHelper, createKey, deleteKey, helperPath, presenceReason, probe, useKey, verifyHelper,
  type PresenceAction,
} from './presence.ts';
import {
  WrongPassphraseError, deriveKek, disablePresence, enablePresence, newRecoveryCode, presenceConfig, presenceKeyDir, repairPresence,
  vaultExists, verifyPassphrase, verifyRecoveryCode,
} from './vault.ts';

// Flows around the Secure Enclave approval (presence mode). vault.ts holds the cryptography,
// presence.ts talks to the native helper; this file decides what is logged and what the person is told.
// The approval proves a human said yes to a genuine system prompt. It does not prove Wickey asked:
// any program of the same user can raise the same prompt with its own wording.

/** The approval did not happen (cancelled, impossible right now, or failed). Nothing was changed. */
export class PresenceRefused extends Error {
  kind: 'cancelled' | 'busy' | 'unavailable' | 'failed';
  constructor(kind: PresenceRefused['kind'], message: string) {
    super(message);
    this.kind = kind;
  }
}

export type UseResultWord = 'approved' | 'cancelled' | 'failed' | 'not available';

// One approval at a time: a second request while a prompt is open would stack prompts on the screen.
let waiting = false;

interface KeyRef { helperSha256: string; keyDir: string }

function logMismatch(action: PresenceAction, via: Via, stage: 'use' | 'unwrap'): void {
  logEvent('presence_helper_mismatch', { action, via, stage }, 'warn');
}

/** Asks for the approval with an explicit helper hash and key directory (enable and repair, before the vault records them). */
async function useRef(ref: KeyRef, action: PresenceAction, via: Via): Promise<Buffer> {
  if (waiting) throw new PresenceRefused('busy', 'Another approval is already waiting on this Mac. Approve or cancel that prompt first, then try again.');
  waiting = true;
  try {
    let r;
    try {
      r = await useKey(ref.keyDir, presenceReason(action, via), { expectedSha256: ref.helperSha256 });
    } catch (err) {
      if (err instanceof PresenceHelperMismatch) logMismatch(action, via, 'use');
      throw err;
    }
    const result: UseResultWord = r.ok ? 'approved' : r.reason === 'cancelled' ? 'cancelled' : r.reason === 'not-interactive' ? 'not available' : 'failed';
    logEvent('presence_used', { action, result, via });
    if (r.ok) return r.secret;
    if (r.reason === 'cancelled') throw new PresenceRefused('cancelled', 'You cancelled the approval, so nothing was changed. Try again and approve the system prompt when you are ready.');
    if (r.reason === 'not-interactive') throw new PresenceRefused('unavailable', 'The system prompt cannot be shown right now (is the screen locked?). Unlock this Mac and try again.');
    throw new PresenceRefused('failed', `${r.message} If the Secure Enclave key is gone, run \`${BRAND.command} unlock --recovery\` with your recovery code, then \`${BRAND.command} presence repair\`.`);
  } finally {
    waiting = false;
  }
}

/** Approval for the key the vault records. Verifies the helper's hash first, every time. */
export async function usePresence(action: PresenceAction, via: Via): Promise<Buffer> {
  const cfg = presenceConfig();
  if (!cfg) throw new Error('Presence mode is off.');
  return useRef({ helperSha256: cfg.helperSha256, keyDir: presenceKeyDir() }, action, via);
}

export function presenceOn(): boolean {
  try {
    return vaultExists() && presenceConfig() !== null;
  } catch {
    return false;
  }
}

/** The helper hash recorded by the newest presence_enabled / presence_repaired event, or null. */
function recordedHelperSha(): string | null {
  try {
    let best: { seq: number; sha: string } | null = null;
    for (const type of ['presence_enabled', 'presence_repaired']) {
      const e = listEvents({ type, limit: 1 }).events[0];
      const sha = e?.data.helperSha256;
      if (e && typeof sha === 'string' && (!best || e.seq > best.seq)) best = { seq: e.seq, sha };
    }
    return best?.sha ?? null;
  } catch {
    return null;
  }
}

/**
 * Call when the data key would not unwrap after an approved prompt. A wrong passphrase and an edited
 * helper hash fail identically (GCM authentication), so the difference is looked up in the event
 * log: if vault.json names another hash than the one Wickey last recorded, it was edited.
 */
export function noteUnwrapFailure(action: PresenceAction, via: Via): void {
  const cfg = presenceConfig();
  const recorded = recordedHelperSha();
  if (cfg && recorded && cfg.helperSha256 !== recorded) logMismatch(action, via, 'unwrap');
}

// ---- Status ----

export interface PresenceStatus {
  enabled: boolean;
  helperOk: boolean;
  keyPresent: boolean;
  /** Secure Enclave available per the helper; null when there is no usable helper to ask. */
  available: boolean | null;
  availableReason?: string;
}

export function keyPresent(): boolean {
  return fs.existsSync(path.join(presenceKeyDir(), 'key.handle'));
}

export async function presenceStatus(withProbe: boolean): Promise<PresenceStatus> {
  const cfg = vaultExists() ? presenceConfig() : null;
  let helperOk = false;
  if (cfg) {
    try { verifyHelper(cfg.helperSha256); helperOk = true; } catch { /* reported as not ok */ }
  } else {
    helperOk = fs.existsSync(helperPath());
  }
  const status: PresenceStatus = { enabled: cfg !== null, helperOk, keyPresent: keyPresent(), available: null };
  if (withProbe && helperOk) {
    const p = await probe();
    status.available = p.available;
    if (p.reason) status.availableReason = p.reason;
  }
  return status;
}

// ---- Enable / disable / repair (CLI, terminal only) ----

function wrongPassphrase(via: Via): never {
  logEvent('unlock_failed', { via });
  throw new WrongPassphraseError();
}

/** Turns presence on. Returns the recovery code, to be shown once by the caller and never kept. Nothing changes on failure. */
export async function enablePresenceMode(passphrase: string, via: Via = 'terminal'): Promise<{ recoveryCode: string }> {
  if (!vaultExists()) throw new Error(`There is no vault yet. Run \`${BRAND.command} setup\` first.`);
  if (presenceConfig()) throw new Error(`Presence mode is already on. \`${BRAND.command} presence status\` shows its state.`);
  try { verifyPassphrase(passphrase); } catch (err) { if (err instanceof WrongPassphraseError) wrongPassphrase(via); throw err; }

  const helperExisted = fs.existsSync(helperPath());
  let hash: string;
  try {
    hash = await buildHelper();
    const p = await probe();
    if (!p.available) throw new PresenceError(p.reason ?? 'The Secure Enclave is not available.');
  } catch (err) {
    if (!helperExisted) fs.rmSync(helperPath(), { force: true });
    throw err;
  }

  const keyDir = presenceKeyDir();
  const undo = async () => { await deleteKey(keyDir, { expectedSha256: hash }).catch(() => {}); };
  try {
    await createKey(keyDir, { expectedSha256: hash });
    const secret = await useRef({ helperSha256: hash, keyDir }, 'turn on presence', via);
    const recoveryCode = newRecoveryCode();
    try {
      enablePresence(passphrase, secret, hash, recoveryCode);
    } catch (err) {
      if (err instanceof WrongPassphraseError) wrongPassphrase(via);
      throw err;
    }
    logEvent('presence_enabled', { via, helperSha256: hash }, 'warn');
    return { recoveryCode };
  } catch (err) {
    await undo();
    throw err;
  }
}

/** Back to passphrase-only. Needs the passphrase and an approval. */
export async function disablePresenceMode(passphrase: string, via: Via = 'terminal'): Promise<void> {
  const cfg = vaultExists() ? presenceConfig() : null;
  if (!cfg) throw new Error('Presence mode is already off.');
  deriveKek(passphrase); // scrypt first, then the prompt, as for an unlock
  const secret = await usePresence('turn off presence', via);
  try {
    disablePresence(passphrase, secret);
  } catch (err) {
    if (err instanceof WrongPassphraseError) {
      noteUnwrapFailure('turn off presence', via);
      wrongPassphrase(via);
    }
    throw err;
  }
  logEvent('presence_disabled', { via }, 'warn');
  // The wrap no longer needs the key; removing it is housekeeping and must not undo the disable.
  await deleteKey(presenceKeyDir(), { expectedSha256: cfg.helperSha256 }).catch(() => {});
}

export type RecoveryAnswer = { passphrase: string; recoveryCode: string };

/**
 * Rebuilds the helper from the package's source and records its hash. When the Secure Enclave key
 * still works, one approval re-wraps the vault. When it is gone, `askRecovery` supplies the recovery
 * code (and the passphrase twice, since it cannot be checked without the key) and a new key is made.
 * Either way a new recovery code comes back; the old one stops working.
 */
export async function repairPresenceMode(
  passphrase: string,
  askRecovery: () => Promise<RecoveryAnswer>,
  via: Via = 'terminal',
): Promise<{ recoveryCode: string; usedRecovery: boolean }> {
  const cfg = vaultExists() ? presenceConfig() : null;
  if (!cfg) throw new Error('Presence mode is off, so there is nothing to repair.');
  const keyDir = presenceKeyDir();
  const hash = await buildHelper();
  const p = await probe();
  if (!p.available) throw new PresenceError(p.reason ?? 'The Secure Enclave is not available.');

  const recoveryCode = newRecoveryCode();
  let secret: Buffer | null = null;
  if (keyPresent()) {
    try {
      secret = await useRef({ helperSha256: hash, keyDir }, 'repair presence', via);
    } catch (err) {
      // A cancelled prompt is an answer; only a key that cannot be used at all leads to the recovery path.
      if (!(err instanceof PresenceRefused) || err.kind !== 'failed') throw err;
    }
  }
  if (secret) {
    try {
      repairPresence(passphrase, { secret }, { secret, helperSha256: hash, recoveryCode });
    } catch (err) {
      if (err instanceof WrongPassphraseError) { noteUnwrapFailure('repair presence', via); wrongPassphrase(via); }
      throw err;
    }
    logEvent('presence_repaired', { via, helperSha256: hash, newKey: false }, 'warn');
    return { recoveryCode, usedRecovery: false };
  }

  const answer = await askRecovery();
  verifyRecoveryCode(answer.recoveryCode); // before the old key is touched: a typo must not cost the key
  await deleteKey(keyDir, { expectedSha256: hash }).catch(() => {});
  await createKey(keyDir, { expectedSha256: hash });
  const fresh = await useRef({ helperSha256: hash, keyDir }, 'repair presence', via);
  try {
    repairPresence(answer.passphrase, { recoveryCode: answer.recoveryCode }, { secret: fresh, helperSha256: hash, recoveryCode });
  } catch (err) {
    if (err instanceof WrongPassphraseError) wrongPassphrase(via);
    throw err;
  }
  logEvent('recovery_used', { via, purpose: 'repair' }, 'warn');
  logEvent('presence_repaired', { via, helperSha256: hash, newKey: true }, 'warn');
  return { recoveryCode, usedRecovery: true };
}
