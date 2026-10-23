import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { BRAND, envVar } from './brand.ts';
import { logEvent, type Via } from './audit.ts';
import type { EventEntry } from './events.ts';
import { readNotificationSettings, writeNotificationSettings } from './store.ts';
import { isUnlocked } from './vault.ts';

// Desktop notifications for security events. The event log is the record; this is the alert, so a
// person (or the agent's owner) sees right away that something security-relevant happened, with
// what to do if it was not them. Local only: no network, no sound, nothing sent anywhere.
//
// Best effort by design: every failure here (no backend, Focus mode, a hung helper, a bad settings
// row) is swallowed. A notification must never block, slow down or fail the action or its log entry.

const TIMEOUT_MS = 3000;
const OSASCRIPT = '/usr/bin/osascript';

export interface Notifier {
  readonly name: string;
  /** False when nothing can be shown here (unsupported OS, helper missing, switched off by env). */
  readonly available: boolean;
  /** Why not, in words for the person who asks. */
  readonly reason?: string;
  /** Fire and forget. Must not throw or block; callers also guard against both. */
  send(title: string, body: string): void;
}

type ExecFile = (file: string, args: readonly string[], options: { timeout: number; windowsHide: boolean }, callback: (err: Error | null) => void) => unknown;

/**
 * Title and body travel as argv to an `on run argv` script, never inside the AppleScript source,
 * so a label like `" & do shell script "…` is just text. `--` keeps a body that starts with a dash
 * from being read as an option.
 */
export function macNotifier(exec: ExecFile = execFile as unknown as ExecFile): Notifier {
  return {
    name: 'macOS Notification Center',
    available: true,
    send(title, body) {
      exec(OSASCRIPT, [
        '-e', 'on run argv',
        '-e', 'display notification (item 2 of argv) with title (item 1 of argv)',
        '-e', 'end run',
        '--', title, body,
      ], { timeout: TIMEOUT_MS, windowsHide: true }, () => {});
    },
  };
}

export function linuxNotifier(exec: ExecFile = execFile as unknown as ExecFile, binary = 'notify-send'): Notifier {
  return {
    name: 'notify-send',
    available: true,
    send(title, body) {
      exec(binary, ['--app-name', BRAND.displayName, '--', title, body], { timeout: TIMEOUT_MS, windowsHide: true }, () => {});
    },
  };
}

export function unavailableNotifier(reason: string): Notifier {
  return { name: 'none', available: false, reason, send: () => {} };
}

function onPath(name: string): string | null {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch { /* keep looking */ }
  }
  return null;
}

/**
 * The real backend for this OS. Off under `node --test` (Node sets NODE_TEST_CONTEXT in test
 * processes and their children) unless WICKEY_NOTIFY=1, and off with WICKEY_NOTIFY=0 for manual
 * throwaway runs, so a test or a trial run never pops a real notification.
 */
export function defaultNotifier(): Notifier {
  const opt = envVar('NOTIFY');
  if (opt === '0') return unavailableNotifier(`Switched off by ${BRAND.envPrefix}NOTIFY=0.`);
  if (process.env.NODE_TEST_CONTEXT !== undefined && opt !== '1') return unavailableNotifier('Switched off while running tests.');
  if (process.platform === 'darwin') {
    return fs.existsSync(OSASCRIPT) ? macNotifier() : unavailableNotifier(`${OSASCRIPT} was not found.`);
  }
  if (process.platform === 'linux') {
    const bin = onPath('notify-send');
    return bin ? linuxNotifier(undefined, bin) : unavailableNotifier('Install notify-send (the libnotify package) to get desktop notifications.');
  }
  return unavailableNotifier('Desktop notifications are not supported on this system yet.');
}

let notifier: Notifier | null = null;
/** Tests inject a recording notifier; pass null to go back to the default. */
export function setNotifier(n: Notifier | null): void {
  notifier = n;
}
export function currentNotifier(): Notifier {
  return (notifier ??= defaultNotifier());
}

/** Never throws, never waits. A notifier that throws, or returns a promise that rejects or never settles, changes nothing. */
function deliver(title: string, body: string): void {
  try {
    const out = currentNotifier().send(title, body) as unknown;
    if (out && typeof (out as PromiseLike<unknown>).then === 'function') (out as PromiseLike<unknown>).then(undefined, () => {});
  } catch { /* best effort */ }
}

// ---- What notifies ----

interface Message {
  /** What happened, one sentence. */
  text: string;
  /** Completes "If this wasn't you: ...". */
  next: string;
  /** Events of one type about the same subject within a window are coalesced. */
  subject: string;
}

interface Spec {
  /** Short description for settings screens. */
  label: string;
  /** Plural noun for the "N more ..." summary. */
  noun: string;
  /** Cannot be switched off. */
  locked?: boolean;
  describe(e: EventEntry): Message | null;
}

const cmd = (rest: string) => `\`${BRAND.command} ${rest}\``;
const str = (v: unknown): string => (typeof v === 'string' ? v : '');
/** Labels are user text and end up on the desktop: one line, no control characters, bounded. */
const clip = (v: unknown, max = 48): string => {
  const s = str(v).replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}...` : s;
};
const VIA_TEXT: Record<string, string> = { dashboard: 'the dashboard', cli: 'the command line', terminal: 'a terminal', setup_link: 'the setup link' };
const from = (e: EventEntry): string => VIA_TEXT[str(e.data.via)] ?? 'an unknown source';
const proxyId = (e: EventEntry): string => clip(e.data.proxyId, 32);
const REVIEW = `review what happened with ${cmd('events')} or the Events page of the dashboard`;

const SPECS: Record<string, Spec> = {
  vault_created: {
    label: 'A passphrase was set for the first time',
    noun: 'passphrases set',
    describe: (e) => ({
      text: e.data.via === 'setup_link' ? 'A passphrase was set through the setup link.' : 'A passphrase was set in a terminal.',
      next: `stop Wickey, run ${cmd('reset')}, and set your own passphrase`,
      subject: 'global',
    }),
  },
  unlocked: {
    label: 'Wickey was unlocked',
    noun: 'unlocks',
    describe: (e) => ({
      text: `Wickey was unlocked from ${from(e)}.`,
      next: `run ${cmd('lock')}, then change the passphrase with ${cmd('passphrase')}`,
      subject: 'global',
    }),
  },
  passphrase_changed: {
    label: 'The passphrase was changed',
    noun: 'passphrase changes',
    describe: (e) => ({
      text: `The passphrase was changed from ${from(e)}.`,
      next: `stop Wickey, run ${cmd('reset')}, and rotate your real provider keys at the provider`,
      subject: 'global',
    }),
  },
  reset: {
    label: 'Wickey was reset (vault and data deleted)',
    noun: 'resets',
    describe: () => ({
      text: 'Wickey was reset: the vault and its data were deleted.',
      next: `rotate your real provider keys at the provider (a reset does not revoke them), and ${REVIEW}`,
      subject: 'global',
    }),
  },
  passphrase_throttled: {
    label: 'Repeated wrong passphrases',
    noun: 'throttled passphrase attempts',
    describe: () => ({
      text: 'Several wrong passphrases were entered, so further attempts are paused.',
      next: `run ${cmd('lock')} and look for the program on this computer that is guessing`,
      subject: 'global',
    }),
  },
  key_issued: {
    label: 'A key with no limits, or for all models, was issued',
    noun: 'unrestricted keys issued',
    describe: (e) => {
      if (e.data.unlimited !== true && e.data.models !== 'all') return null;
      const id = proxyId(e);
      const label = clip(e.data.label) || clip(e.data.credential);
      return {
        text: `A key ${e.data.unlimited === true ? 'with no limits' : 'for all models'} was issued${label ? `: "${label}"` : ''} (proxy ${id}, from ${from(e)}).`,
        next: `run ${cmd(`expire ${id}`)}`,
        subject: label || id,
      };
    },
  },
  limits_loosened: {
    label: 'A key got looser limits',
    noun: 'limit loosenings',
    describe: (e) => ({
      text: `Limits were loosened on proxy ${proxyId(e)} (from ${from(e)}).`,
      next: `run ${cmd(`expire ${proxyId(e)}`)}`,
      subject: proxyId(e),
    }),
  },
  auto_renew_enabled: {
    label: 'Auto-renew was turned on for a key',
    noun: 'auto-renew activations',
    describe: (e) => ({
      text: `Auto-renew was turned on for proxy ${proxyId(e)} (from ${from(e)}).`,
      next: `run ${cmd(`limits ${proxyId(e)} --no-auto-renew`)} or ${cmd(`expire ${proxyId(e)}`)}`,
      subject: proxyId(e),
    }),
  },
  tamper_detected: {
    label: 'Signs of tampering were found',
    noun: 'tamper detections',
    locked: true,
    describe: (e) => ({
      text: `Wickey found signs of tampering: ${clip(e.data.what) || `the event log failed its anchor check (${clip(e.data.anchor, 24) || 'unknown'})`}.`,
      next: `${REVIEW}, then rotate your keys: ${cmd('rotate <id>')} for proxy keys and the provider's dashboard for real ones`,
      subject: 'global',
    }),
  },
  notifications_changed: {
    label: 'A notification setting was changed',
    noun: 'notification changes',
    locked: true,
    describe: (e) => ({
      text: `Notifications for "${clip(e.data.type, 32)}" were turned ${e.data.enabled === true ? 'on' : 'off'} from ${from(e)}.`,
      next: `run ${cmd(`notifications on ${clip(e.data.type, 32)}`)} and change your passphrase with ${cmd('passphrase')}`,
      subject: clip(e.data.type, 32),
    }),
  },
};

export const NOTIFY_TYPES: readonly string[] = Object.keys(SPECS);
export function isNotifyType(t: unknown): t is string {
  return typeof t === 'string' && Object.hasOwn(SPECS, t);
}
export function isLockedOn(type: string): boolean {
  return SPECS[type]?.locked === true;
}

// ---- Settings ----

// Last verified list of switched-off types. While the vault is locked the signature cannot be
// checked, so the last verified list is used (or all on if there never was one).
let cachedDisabled: Set<string> | null = null;
let tamperReported = false;

function disabledTypes(): Set<string> {
  let read;
  try {
    read = readNotificationSettings();
  } catch {
    return cachedDisabled ?? new Set();
  }
  switch (read.state) {
    case 'ok':
      return (cachedDisabled = new Set(read.disabled.filter(isNotifyType)));
    case 'missing':
      return (cachedDisabled = new Set());
    case 'tampered':
      // An edited row must never silence anything: everything is on, and the edit is recorded once.
      if (!tamperReported) {
        tamperReported = true;
        logEvent('tamper_detected', { what: 'notification settings' });
      }
      return (cachedDisabled = new Set());
    default:
      return cachedDisabled ?? new Set();
  }
}

export function notificationSettings() {
  const off = disabledTypes();
  const n = currentNotifier();
  return {
    types: NOTIFY_TYPES.map((type) => ({ type, label: SPECS[type].label, enabled: !off.has(type), locked: isLockedOn(type) })),
    backend: { name: n.name, available: n.available, ...(n.reason ? { reason: n.reason } : {}) },
  };
}

/** The caller has already checked the passphrase for turning a type off. Logs `notifications_changed`, which always notifies. */
export function setNotificationEnabled(type: string, enabled: boolean, via: Via): void {
  if (!isNotifyType(type)) throw new Error(`Unknown notification type "${type}".`);
  if (!enabled && isLockedOn(type)) throw new Error(`"${type}" notifications cannot be turned off.`);
  if (!isUnlocked()) throw new Error('Wickey is locked. Unlock it with your passphrase first.');
  const off = new Set(disabledTypes());
  if (enabled) off.delete(type);
  else off.add(type);
  writeNotificationSettings([...off]);
  cachedDisabled = off;
  logEvent('notifications_changed', { type, enabled, via }, 'warn');
}

// ---- Coalescing ----

// One message per (type, subject) per window; the rest are counted and summed up when the window
// ends. The proxy is long-running so the summary arrives; a short-lived CLI process (reset, setup)
// may exit first and drop a pending summary, which is acceptable: the first message was sent and
// every event is in the log.
let windowMs = 60_000;
interface Window { count: number; timer: NodeJS.Timeout; noun: string; next: string }
const windows = new Map<string, Window>();

export function setCoalesceWindow(ms: number | null): void {
  windowMs = ms ?? 60_000;
}

function closeWindow(key: string): void {
  const w = windows.get(key);
  if (!w) return;
  windows.delete(key);
  clearTimeout(w.timer);
  if (w.count > 0) deliver(BRAND.displayName, `${w.count} more ${w.noun} in the last minute. If this wasn't you: ${w.next}.`);
}

/** Ends every open window now (sending the pending summaries). For tests and shutdown. */
export function flushSummaries(): void {
  for (const key of [...windows.keys()]) closeWindow(key);
}

/** Forgets windows, the settings cache and the once-per-process tamper flag. For tests. */
export function resetNotifyState(): void {
  for (const w of windows.values()) clearTimeout(w.timer);
  windows.clear();
  cachedDisabled = null;
  tamperReported = false;
}

/** Called after every successful event-log append. Never throws, never waits. */
export function notifyEvent(entry: EventEntry): void {
  try {
    const spec = Object.hasOwn(SPECS, entry.type) ? SPECS[entry.type] : undefined;
    const msg = spec?.describe(entry);
    if (!spec || !msg) return;
    if (!spec.locked && disabledTypes().has(entry.type)) return;

    const body = `${msg.text} If this wasn't you: ${msg.next}.`;
    // A settings change is never merged into another: switching off needs the passphrase, so it is rare.
    if (entry.type === 'notifications_changed') return deliver(BRAND.displayName, body);

    const key = `${entry.type}\u0000${msg.subject}`;
    const open = windows.get(key);
    if (open) {
      open.count++;
      return;
    }
    deliver(BRAND.displayName, body);
    // unref: a pending summary must not keep a short-lived process alive.
    const timer = setTimeout(() => closeWindow(key), windowMs);
    timer.unref();
    windows.set(key, { count: 0, timer, noun: spec.noun, next: msg.next });
  } catch { /* the action and its log entry stand regardless */ }
}
