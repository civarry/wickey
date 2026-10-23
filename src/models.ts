import http from 'node:http';
import https from 'node:https';
import { classifyBaseUrl, guardOptions, isBlockedError } from './netguard.ts';
import { PROVIDERS, applyUpstreamAuth, upstreamUrl } from './providers.ts';
import {
  getCredentialSecret, getModelCache, modelsEpoch, putModelCache,
  type Credential, type ModelCache,
} from './store.ts';

// Per-key "Allowed models" has three modes: Selected (an exact list), None ([]) and All (null).
// All means "any model the credential's provider lists", checked against a cache of the provider's
// own /models answer. This file fetches and caches that list.

export const MAX_LISTED_MODELS = 5000;
const MAX_ID_LENGTH = 200;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 10_000;
const CONNECT_ATTEMPT_TIMEOUT_MS = 2000;
const PAGE_SIZE = 1000;
/** An unknown model triggers a refresh at most this often per credential. */
export const REFRESH_MIN_MS = 60_000;
/** A credential whose provider has no list is looked at again this often, so a later /models is picked up. */
const UNAVAILABLE_RECHECK_MS = 60 * 60 * 1000;

/** `--models` value: all -> null, none -> [], else a comma list. Throws with a message for a bad mix. */
export function parseModelsFlag(value: string): string[] | null {
  const parts = value.split(',').map((m) => m.trim()).filter(Boolean);
  const words = parts.map((p) => p.toLowerCase());
  if (words.length === 1 && words[0] === 'all') return null;
  if (words.length === 1 && words[0] === 'none') return [];
  if (!parts.length) throw new Error('--models needs "all", "none" or a comma-separated list of model IDs.');
  if (words.includes('all') || words.includes('none')) {
    throw new Error('"all" and "none" must be used alone. For a list, give only model IDs, e.g. --models gpt-4o,gpt-4o-mini.');
  }
  return parts;
}

class ListError extends Error {
  /** The provider definitively has no usable list (as opposed to a failure that may pass). */
  unavailable: boolean;
  constructor(message: string, unavailable = false) {
    super(message);
    this.unavailable = unavailable;
  }
}

interface Page { status: number; body: any }

function getJson(url: URL, headers: http.OutgoingHttpHeaders): Promise<Page> {
  return new Promise((resolve, reject) => {
    // Saved rows can predate the rules, and literal IPs skip DNS, so check the URL itself as well.
    const verdict = classifyBaseUrl(url);
    if (!verdict.ok) return reject(new ListError(verdict.reason));
    const client = url.protocol === 'https:' ? https : http;
    const options = { method: 'GET', headers, agent: false, autoSelectFamilyAttemptTimeout: CONNECT_ATTEMPT_TIMEOUT_MS, ...guardOptions(url) };
    const req = client.request(url, options, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (c: Buffer) => {
        size += c.length;
        if (size > MAX_RESPONSE_BYTES) {
          reject(new ListError('the provider\'s model list is larger than 5 MB'));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        const status = res.statusCode ?? 0;
        if (status < 200 || status >= 300) return resolve({ status, body: null });
        try {
          resolve({ status, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
        } catch {
          resolve({ status, body: undefined });
        }
      });
      res.on('error', (e) => reject(new ListError(`network error (${(e as NodeJS.ErrnoException).code ?? 'read failed'})`)));
    });
    // Whole-request deadline, not an idle timeout: a server that trickles bytes must not hold the fetch open.
    const timer = setTimeout(() => { reject(new ListError('timed out after 10 seconds')); req.destroy(); }, FETCH_TIMEOUT_MS);
    req.on('close', () => clearTimeout(timer));
    req.on('error', (e: NodeJS.ErrnoException & { errors?: NodeJS.ErrnoException[] }) => {
      if (isBlockedError(e)) return reject(new ListError(e.message));
      const code = e.code ?? e.errors?.[0]?.code ?? 'connection failed';
      reject(new ListError(`could not connect (${code})`));
    });
    req.end();
  });
}

function idsOf(body: any): string[] {
  // A 2xx that is not a readable list (captive portal, gateway page, junk) is an error, never
  // "unavailable": unavailable means pass-through, so it must be reserved for a real 404/405/501.
  // Some OpenAI-compatible servers answer with a bare array.
  const list = Array.isArray(body) ? body : body && typeof body === 'object' && Array.isArray(body.data) ? body.data : null;
  if (!list) throw new ListError('the provider\'s /models answer could not be read as a model list');
  const ids: string[] = [];
  for (const m of list) {
    // Entries we can't read as a plain ID are left out, which for an allow check means refused.
    if (m && typeof m.id === 'string' && m.id.length > 0 && m.id.length <= MAX_ID_LENGTH) ids.push(m.id);
  }
  return ids;
}

/**
 * Asks the credential's provider which models it serves, with the real key from the vault.
 * Throws a ListError whose message never contains the key.
 */
export async function fetchModels(credential: Credential): Promise<string[]> {
  const secret = getCredentialSecret(credential);
  if (!secret) throw new Error(`The key for "${credential.name}" is missing from the vault. Add it again from the dashboard.`);
  const spec = (PROVIDERS[credential.provider] ?? PROVIDERS.custom).models;
  const headers: http.OutgoingHttpHeaders = { accept: 'application/json', ...spec.headers };
  applyUpstreamAuth(headers, credential.authStyle, secret);
  try {
    const all = new Set<string>();
    let after: string | null = null;
    for (let page = 0; page < MAX_LISTED_MODELS / PAGE_SIZE + 2; page++) {
      const search: string = spec.paginated ? `?limit=${PAGE_SIZE}${after ? `&after_id=${encodeURIComponent(after)}` : ''}` : '';
      const res = await getJson(upstreamUrl(credential.baseUrl, spec.path, search), headers);
      if (res.status === 404 || res.status === 405 || res.status === 501) throw new ListError('the provider has no model list endpoint', true);
      if (res.status < 200 || res.status >= 300) throw new ListError(`the provider answered HTTP ${res.status} to the model list request`);
      for (const id of idsOf(res.body)) all.add(id);
      if (all.size > MAX_LISTED_MODELS) throw new ListError(`the provider lists more than ${MAX_LISTED_MODELS} models`);
      const more = spec.paginated && !Array.isArray(res.body) && res.body.has_more === true && typeof res.body.last_id === 'string';
      if (!more) return [...all];
      after = res.body.last_id;
    }
    throw new ListError('the provider\'s model list has too many pages');
  } catch (err) {
    // Belt and braces: our messages are built from status codes and error codes only.
    if (err instanceof ListError) {
      const clean = new ListError(err.message.split(secret).join('[key]'), err.unavailable);
      throw clean;
    }
    throw err;
  }
}

// Single-flight: callers that arrive while a fetch runs share its promise instead of starting
// their own. The map entry is set synchronously with the decision to fetch, so there is no gap
// (check-then-act across an await) for a second fetch to slip into.
const inflight = new Map<string, Promise<ModelCache>>();

/**
 * Fetches and caches the list. Without `force` it returns the cache instead when the last attempt
 * was under REFRESH_MIN_MS ago, which bounds how often unknown model names can cause upstream calls.
 */
export function refreshModels(credential: Credential, force = false): Promise<ModelCache> {
  const epoch = modelsEpoch(credential.id);
  const key = `${credential.id}:${epoch}`;
  const running = inflight.get(key);
  if (running) return running;
  const cached = getModelCache(credential.id);
  if (!force && cached && Date.now() - cached.fetchedAt < REFRESH_MIN_MS) return Promise.resolve(cached);

  const run = (async (): Promise<ModelCache> => {
    let entry: ModelCache;
    try {
      const models = await fetchModels(credential);
      entry = { models, fetchedAt: Date.now(), error: null, unavailable: false };
    } catch (err) {
      if (!(err instanceof ListError)) throw err;
      // A failed refresh keeps the last good list; "unavailable" is only for a credential that never had one.
      entry = { models: cached?.models ?? null, fetchedAt: Date.now(), error: err.message, unavailable: err.unavailable && !cached?.models };
    }
    putModelCache(credential.id, epoch, entry);
    return entry;
  })().finally(() => inflight.delete(key));
  inflight.set(key, run);
  return run;
}

/** A forced refresh (dashboard button) goes upstream at most this often per credential. */
export const FORCED_REFRESH_MIN_MS = 10_000;
const lastForced = new Map<string, number>();

/**
 * Dashboard "Refresh list". Needs no passphrase, so it must not be a way to make unlimited
 * upstream calls with the real key: inside the window it returns the cache and `retryAfter` seconds.
 */
export async function forceRefreshModels(credential: Credential): Promise<{ entry: ModelCache; retryAfter?: number }> {
  const last = lastForced.get(credential.id);
  const now = Date.now();
  if (last !== undefined && now - last < FORCED_REFRESH_MIN_MS) {
    return { entry: await ensureModels(credential), retryAfter: Math.ceil((FORCED_REFRESH_MIN_MS - (now - last)) / 1000) };
  }
  // Set before the await so concurrent callers see it (single-flight in refreshModels covers the rest).
  lastForced.set(credential.id, now);
  return { entry: await refreshModels(credential, true) };
}

/** The cached list, fetching first if it was never fetched or a previous attempt is old enough to retry. */
export async function ensureModels(credential: Credential): Promise<ModelCache> {
  const cached = getModelCache(credential.id);
  if (!cached) return refreshModels(credential);
  const age = Date.now() - cached.fetchedAt;
  if (cached.unavailable && age > UNAVAILABLE_RECHECK_MS) return refreshModels(credential);
  if (!cached.models && !cached.unavailable && age >= REFRESH_MIN_MS) return refreshModels(credential);
  return cached;
}

export type ModelVerdict =
  | { allowed: true; passthrough: boolean }
  | { allowed: false; entry: ModelCache };

/** All-mode check: is `model` in the provider's list? An unknown name triggers one throttled, shared refresh. */
export async function checkModel(credential: Credential, model: string): Promise<ModelVerdict> {
  let entry = await ensureModels(credential);
  for (let attempt = 0; attempt < 2; attempt++) {
    if (entry.unavailable) return { allowed: true, passthrough: true };
    if (entry.models?.includes(model)) return { allowed: true, passthrough: false };
    if (attempt === 0) entry = await refreshModels(credential);
  }
  return { allowed: false, entry };
}
