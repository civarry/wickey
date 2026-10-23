import { createHash, timingSafeEqual } from 'node:crypto';
import { classifyBaseUrl } from './netguard.ts';
import { isProvider, type AuthStyle } from './providers.ts';
import { addCredential, checkNewCredential, getCredential, getCredentialSecret, listCredentials } from './store.ts';

export const MAX_IMPORT_ENTRIES = 50;

export type ImportOutcome = 'imported' | 'would_import' | 'duplicate_key' | 'duplicate_name' | 'invalid';

export interface ImportResult {
  name: string;
  outcome: ImportOutcome;
  message?: string;
  baseUrlScope?: string;
}

const digest = (secret: string): Buffer => createHash('sha256').update(secret, 'utf8').digest();

/** Digests of every stored key, so the comparison never needs the plaintext past this call. */
function storedDigests(): { name: string; digest: Buffer }[] {
  const out: { name: string; digest: Buffer }[] = [];
  for (const c of listCredentials()) {
    try {
      const secret = getCredentialSecret(c);
      if (secret) out.push({ name: c.name, digest: digest(secret) });
    } catch {
      // A tampered or unreadable entry can't match anything; the proxy refuses it anyway.
    }
  }
  return out;
}

/**
 * Validates (and, unless dryRun, stores) each entry on its own, so one bad entry never blocks the rest.
 * Never contacts a provider and never issues proxy keys. Caller must have passed requireAuth.
 */
export function importCredentials(entries: unknown[], dryRun: boolean): ImportResult[] {
  const known = storedDigests();
  const batchNames = new Set<string>();
  const results: ImportResult[] = [];

  for (const raw of entries) {
    const e = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
    const name = typeof e.name === 'string' ? e.name.trim() : '';
    const provider = String(e.provider ?? '');
    const apiKey = typeof e.apiKey === 'string' ? e.apiKey.trim() : '';
    const baseUrl = typeof e.baseUrl === 'string' && e.baseUrl.trim() ? e.baseUrl.trim() : undefined;
    const authStyle = e.authStyle ? (String(e.authStyle) as AuthStyle) : undefined;
    // Error text can echo user input (e.g. a URL), so a pasted key must never survive into a message.
    const clean = (m: string) => (apiKey.length >= 4 ? m.split(apiKey).join('[key hidden]') : m);
    const done = (outcome: ImportOutcome, message?: string, baseUrlScope?: string) => {
      results.push({ name, outcome, ...(message ? { message: clean(message) } : {}), ...(baseUrlScope ? { baseUrlScope } : {}) });
    };

    try {
      if (!isProvider(provider)) throw new Error('Unknown provider.');
      if (authStyle && authStyle !== 'bearer' && authStyle !== 'x-api-key') throw new Error('Invalid auth style.');
      const checked = checkNewCredential({ name, provider, apiKey, baseUrl });
      if (batchNames.has(name) || getCredential(name)) {
        done('duplicate_name', `A credential named "${name}" already exists. Rename it to import.`);
        continue;
      }
      const d = digest(apiKey);
      const same = known.find((k) => timingSafeEqual(k.digest, d));
      if (same) {
        done('duplicate_key', `This key is already stored as "${same.name}".`);
        continue;
      }
      const verdict = classifyBaseUrl(checked.baseUrl);
      const scope = verdict.ok ? verdict.scope : undefined;
      if (!dryRun) addCredential({ name, provider, apiKey, baseUrl, authStyle });
      batchNames.add(name);
      known.push({ name, digest: d });
      done(dryRun ? 'would_import' : 'imported', undefined, scope);
    } catch (err) {
      done('invalid', (err as Error).message);
    }
  }
  return results;
}
