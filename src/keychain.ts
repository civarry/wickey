import { execFileSync } from 'node:child_process';
import { BRAND, envVar } from './brand.ts';

// Second home for the event-log anchor (see events.ts), outside the data directory so that a
// program which rewrites ~/.wickey cannot also rewrite this without running `security` itself.
// The value is plain `<seq>:<hash>`: no MAC, because it must stay readable after a reset, when
// the key that would verify a MAC is gone. The item has no access control; `security` can rewrite it.
//
// This must never raise a dialog or block: we only create and read items through /usr/bin/security
// (its own items, so macOS has no reason to ask), through execFile with an argument array (no
// shell), under a 2 s timeout. Any failure means "unavailable", which callers treat as a missing
// second copy, never as tampering.

export type KeychainRead = { state: 'ok'; value: string } | { state: 'none' } | { state: 'unavailable' };

export interface Keychain {
  get(account: string): KeychainRead;
  /** True when the value was stored. */
  set(account: string, value: string): boolean;
}

const SECURITY = '/usr/bin/security';
const TIMEOUT_MS = 2000;
const NOT_FOUND = 44; // errSecItemNotFound, as `security` exits

export class MacKeychain implements Keychain {
  readonly service: string;
  constructor(service: string = BRAND.keychainService) {
    this.service = service;
  }

  private run(args: string[]): { code: number; out: string } {
    try {
      const out = execFileSync(SECURITY, args, { timeout: TIMEOUT_MS, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
      return { code: 0, out };
    } catch (e) {
      const status = (e as { status?: number | null }).status;
      return { code: typeof status === 'number' ? status : -1, out: '' };
    }
  }

  get(account: string): KeychainRead {
    const r = this.run(['find-generic-password', '-s', this.service, '-a', account, '-w']);
    if (r.code === 0) return { state: 'ok', value: r.out.trim() };
    return r.code === NOT_FOUND ? { state: 'none' } : { state: 'unavailable' };
  }

  set(account: string, value: string): boolean {
    return this.run(['add-generic-password', '-U', '-s', this.service, '-a', account, '-w', value]).code === 0;
  }

  remove(account: string): boolean {
    return this.run(['delete-generic-password', '-s', this.service, '-a', account]).code === 0;
  }
}

export const unavailableKeychain: Keychain = {
  get: () => ({ state: 'unavailable' }),
  set: () => false,
};

/**
 * The real Keychain on macOS only. Off under `node --test` (Node sets NODE_TEST_CONTEXT in test
 * processes and their children), so test homes never leave items in a real Keychain; tests opt in
 * with WICKEY_KEYCHAIN=1. WICKEY_KEYCHAIN=0 turns it off for a manual throwaway run. Not keyed on
 * WICKEY_HOME: real users set it too, and they must keep the anchor.
 */
export function defaultKeychain(): Keychain {
  if (process.platform !== 'darwin') return unavailableKeychain;
  const opt = envVar('KEYCHAIN');
  if (opt === '0' || (process.env.NODE_TEST_CONTEXT !== undefined && opt !== '1')) return unavailableKeychain;
  return new MacKeychain();
}
