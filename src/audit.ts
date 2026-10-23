import { appendEvent, type EventData } from './events.ts';

// Call-site helper for the security event log. Logging is a record, not a gate: a failed write
// (disk full, permissions) must never stop the action it describes.
//  - 'quiet': unlock, sign-in, lock, failed attempts. Failing silently is deliberate: if logging
//    could block these, a broken log file would lock the user out of their own vault.
//  - 'warn': minting and credential changes. Also not blocked, but one line goes to stderr so the
//    gap in the trail is visible to whoever runs the proxy.

/** Where an action came from. A display label only: a local program can send any value for it. */
export type Via = 'dashboard' | 'cli' | 'terminal' | 'setup_link';

/** Request header the CLI sets so the server can label its actions `cli`. Not proof of anything. */
export const VIA_HEADER = 'x-wickey-via';

export function viaFromHeader(value: string | string[] | undefined): Via {
  return value === 'cli' ? 'cli' : 'dashboard';
}

export function logEvent(type: string, data: EventData = {}, mode: 'quiet' | 'warn' = 'quiet'): void {
  try {
    appendEvent(type, data);
  } catch {
    if (mode === 'warn') process.stderr.write(`wickey: the security event log could not be written (${type}). The action itself went ahead.\n`);
  }
}
