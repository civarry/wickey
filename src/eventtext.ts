// Plain words for security events. Pure (no Node imports) because the CLI, the server and the
// dashboard all use it: one place decides what "key_issued" is called, so they cannot disagree.

export type Trust = 'verified' | 'recorded_while_locked' | 'before_reset' | 'unchecked';

interface EventLike {
  type: string;
  data: Record<string, unknown>;
}

/** Labels are user text and end up on screens and terminals: one line, no control characters, bounded. */
export function clipText(v: unknown, max = 48): string {
  const s = (typeof v === 'string' ? v : '').replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}...` : s;
}

const VIA: Record<string, string> = { dashboard: 'Dashboard', cli: 'Command line', terminal: 'Terminal', setup_link: 'Setup link' };

/** Where the action came from. A display label only: a local program can send any value for it. */
export function viaLabel(data: Record<string, unknown>): string | null {
  const v = data.via;
  if (typeof v !== 'string') return null;
  return VIA[v] ?? 'Unknown source';
}

export const TRUST_LABEL: Record<Trust, string> = {
  verified: 'Verified',
  recorded_while_locked: 'Recorded while locked',
  before_reset: 'Before reset',
  unchecked: 'Unchecked',
};

export const TRUST_HELP: Record<Trust, string> = {
  verified: 'The chain is intact and the signature checks out: Wickey wrote this while unlocked.',
  recorded_while_locked: 'Written while Wickey was locked, so it carries no signature. A program on this computer could have added it.',
  before_reset: 'From before a reset. The old signing key is gone, so this entry cannot be checked.',
  unchecked: 'Signed, but Wickey is locked, so the signature was not checked. Unlock to verify it.',
};

const ANCHOR_WORDS: Record<string, string> = {
  missing: 'the record of the newest signed entry is missing',
  truncated: 'entries were cut off the end of the log',
  mismatch: 'the log does not match its anchor record',
  rolled_back: 'the log and its anchor file were put back to an older state',
};

function limitsPhrase(d: Record<string, unknown>): string {
  return d.unlimited === true ? ', with no limits' : d.models === 'all' ? ', for all models' : '';
}

const quoted = (v: unknown): string => {
  const s = clipText(v);
  return s ? ` "${s}"` : '';
};

/** One sentence, no source (shown separately) and no raw JSON. Unknown types are still readable. */
export function describeEvent(e: EventLike): string {
  const d = e.data ?? {};
  switch (e.type) {
    case 'vault_created': return 'A passphrase was set for the first time.';
    case 'unlocked': return 'Wickey was unlocked.';
    case 'unlock_failed': return 'A wrong passphrase was entered.';
    case 'signed_in': return 'Someone signed in.';
    case 'locked': return 'Wickey was locked and every session signed out.';
    case 'passphrase_changed': return 'The passphrase was changed.';
    case 'passphrase_throttled': return 'Several wrong passphrases were entered, so further attempts were paused.';
    case 'reset': return 'Wickey was reset: the vault and its data were deleted.';
    case 'checkpoint': return 'Earlier entries recorded while locked were signed.';
    case 'key_issued': {
      const what = d.op === 'rotate' ? 'A key was rotated' : d.op === 'env' ? 'A key was minted for a shell profile' : 'A key was issued';
      const cred = clipText(d.credential);
      return `${what}${cred ? ` for credential "${cred}"` : ''}${quoted(d.label) ? ` named${quoted(d.label)}` : ''}${limitsPhrase(d)}.`;
    }
    case 'key_renewed': return `A key was renewed (proxy ${clipText(d.proxyId, 32)}).`;
    case 'limits_loosened': return `Limits were loosened on proxy ${clipText(d.proxyId, 32)}${d.after ? `: ${clipText(d.after, 80)}` : ''}.`;
    case 'limits_tightened': return `Limits were tightened on proxy ${clipText(d.proxyId, 32)}${d.after ? `: ${clipText(d.after, 80)}` : ''}.`;
    case 'auto_renew_enabled': return `Auto-renew was turned on for proxy ${clipText(d.proxyId, 32)}.`;
    case 'credential_added': return `A credential${quoted(d.name)} was added.`;
    case 'credential_changed': return `The credential${quoted(d.name)} was changed${d.keyReplaced === true ? ' (its key was replaced)' : d.baseUrlChanged === true ? ' (its base URL was changed)' : ''}.`;
    case 'credential_removed': return `The credential${quoted(d.name)} was removed.`;
    case 'credentials_imported': return `${typeof d.count === 'number' ? d.count : 'Some'} credential${d.count === 1 ? ' was' : 's were'} imported.`;
    case 'notifications_changed': return `Notifications for "${clipText(d.type, 32)}" were turned ${d.enabled === true ? 'on' : 'off'}.`;
    case 'presence_used': {
      const result = clipText(d.result, 16);
      const what = clipText(d.action, 40) || 'something';
      return `Wickey asked for a system approval to ${what}: ${result || 'unknown result'}.`;
    }
    case 'presence_enabled': return 'Presence mode was turned on: unlocking needs the passphrase and a system approval.';
    case 'presence_disabled': return 'Presence mode was turned off: the passphrase alone unlocks the vault.';
    case 'presence_repaired': return `Presence mode was repaired: the helper was rebuilt${d.newKey === true ? ' and a new Secure Enclave key was made' : ''}.`;
    case 'recovery_used': return 'The presence recovery code was used.';
    case 'presence_helper_mismatch': return `The presence helper did not match what was recorded, so the approval was refused${d.stage === 'unwrap' ? ' (the vault would not open after the approval)' : ''}.`;
    case 'tamper_detected': {
      if (typeof d.what === 'string') return `Signs of tampering: the stored ${clipText(d.what, 48)} failed its signature check.`;
      const why = ANCHOR_WORDS[clipText(d.anchor, 24)];
      return `Signs of tampering: ${why ?? 'the event log failed its anchor check'}.`;
    }
    default: return `An event this version does not recognise ("${clipText(e.type, 40) || 'unnamed'}").`;
  }
}

/** Short names for the filter and the CLI's --type list. */
export const TYPE_LABEL: Record<string, string> = {
  vault_created: 'Passphrase set',
  unlocked: 'Unlocked',
  unlock_failed: 'Wrong passphrase',
  signed_in: 'Signed in',
  locked: 'Locked',
  passphrase_changed: 'Passphrase changed',
  passphrase_throttled: 'Attempts paused',
  reset: 'Reset',
  checkpoint: 'Checkpoint',
  key_issued: 'Key issued',
  key_renewed: 'Key renewed',
  limits_loosened: 'Limits loosened',
  limits_tightened: 'Limits tightened',
  auto_renew_enabled: 'Auto-renew on',
  credential_added: 'Credential added',
  credential_changed: 'Credential changed',
  credential_removed: 'Credential removed',
  credentials_imported: 'Credentials imported',
  notifications_changed: 'Notifications changed',
  presence_used: 'Approval asked',
  presence_enabled: 'Presence on',
  presence_disabled: 'Presence off',
  presence_repaired: 'Presence repaired',
  recovery_used: 'Recovery code used',
  presence_helper_mismatch: 'Presence helper mismatch',
  tamper_detected: 'Tampering detected',
};

// ---- "since your last visit" ----

/** Events that are routine and would only bury the ones that matter. */
const ROUTINE = new Set(['signed_in', 'locked', 'checkpoint', 'limits_tightened']);

/**
 * The bucket an event counts in for the banner, or null when it stays out of it (still in the
 * Events view). A key with limits is routine (`env` mints one every run); one without is not.
 */
export function bannerKey(e: EventLike): string | null {
  if (ROUTINE.has(e.type)) return null;
  if (e.type === 'key_issued') return e.data?.unlimited === true || e.data?.models === 'all' ? 'key_unrestricted' : null;
  if (e.type === 'key_renewed') return null;
  // An approved approval is routine (every unlock has one); a cancelled or failed one may be a program asking.
  if (e.type === 'presence_used') return e.data?.result === 'approved' ? null : 'presence_used';
  return e.type;
}

const PHRASE: Record<string, [string, string]> = {
  vault_created: ['passphrase set', 'passphrases set'],
  unlocked: ['unlock', 'unlocks'],
  unlock_failed: ['failed passphrase', 'failed passphrases'],
  passphrase_changed: ['passphrase change', 'passphrase changes'],
  passphrase_throttled: ['paused attempt run', 'paused attempt runs'],
  reset: ['reset', 'resets'],
  key_unrestricted: ['key with no limits', 'keys with no limits'],
  limits_loosened: ['loosened limit', 'loosened limits'],
  auto_renew_enabled: ['auto-renew turned on', 'auto-renews turned on'],
  credential_added: ['credential added', 'credentials added'],
  credential_changed: ['credential changed', 'credentials changed'],
  credential_removed: ['credential removed', 'credentials removed'],
  credentials_imported: ['import', 'imports'],
  notifications_changed: ['notification change', 'notification changes'],
  presence_used: ['approval that was not given', 'approvals that were not given'],
  presence_enabled: ['presence mode turned on', 'presence mode turned on'],
  presence_disabled: ['presence mode turned off', 'presence mode turned off'],
  presence_repaired: ['presence repair', 'presence repairs'],
  recovery_used: ['recovery code use', 'recovery code uses'],
  presence_helper_mismatch: ['presence helper mismatch', 'presence helper mismatches'],
  tamper_detected: ['tamper detection', 'tamper detections'],
};

/** "2 unlocks, 1 key with no limits, 1 failed passphrase" (most worrying first). */
export function summarizeUnseen(unseen: Record<string, number>): string {
  const order = Object.keys(PHRASE);
  const keys = Object.keys(unseen).filter((k) => unseen[k] > 0);
  keys.sort((a, b) => (order.indexOf(a) + 1 || 99) - (order.indexOf(b) + 1 || 99));
  return keys.map((k) => {
    const n = unseen[k];
    const p = PHRASE[k];
    return `${n} ${p ? (n === 1 ? p[0] : p[1]) : n === 1 ? 'other event' : 'other events'}`;
  }).join(', ');
}

// ---- Integrity summary and CLI lines ----

export interface SummaryLike {
  ok: boolean;
  reason?: string;
  macsChecked: boolean;
}

/** The integrity summary in plain words, with a next step when something is wrong. */
export function integrityText(s: SummaryLike): { ok: boolean; text: string; next: string | null } {
  if (!s.ok) {
    return {
      ok: false,
      text: `The event log failed its integrity check: ${s.reason ?? 'it does not match what Wickey wrote'}.`,
      next: 'If this was not you, rotate your proxy keys and your real provider keys at the provider, and change your passphrase.',
    };
  }
  return {
    ok: true,
    text: s.macsChecked
      ? 'The event log is intact: every link and signature checks out.'
      : 'The event log links are intact. Wickey is locked, so signatures were not checked.',
    next: null,
  };
}

const pad = (n: number) => String(n).padStart(2, '0');
/** Local `YYYY-MM-DD HH:MM:SS`. */
export function stamp(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return clipText(ts, 24);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** One terminal line for `wickey events`. */
export function eventLine(e: EventLike & { seq: number; ts: string; trust: Trust }): string {
  const via = viaLabel(e.data);
  const trust = TRUST_LABEL[e.trust] ?? 'Unchecked';
  return `#${e.seq}  ${stamp(e.ts)}  ${describeEvent(e)}${via ? `  [via ${via.toLowerCase()}]` : ''}  (${trust.toLowerCase()})`;
}
