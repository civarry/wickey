export type AuthStyle = 'bearer' | 'x-api-key';
export type ProxyStatus = 'active' | 'expired';

export interface Credential {
  id: string;
  name: string;
  provider: string;
  baseUrl: string;
  authStyle: AuthStyle;
  createdAt: number;
  /** Whether the provider reported token usage last time; null = not seen yet. */
  usageReporting: 'reports' | 'missing' | null;
  streamUsage: 'reports' | 'missing' | 'rejects_option' | null;
  /** Null when the saved URL is no longer allowed. */
  baseUrlScope?: 'public' | 'private' | 'loopback' | null;
}

export interface Limits {
  /** Exact model IDs (Selected); [] = none (every request refused); null = all (any model the provider lists). */
  models: string[] | null;
  rpm: number | null;
  tokenCap: number | null;
  refuseUncounted: boolean;
}

/** A credential's model list. `unavailable` = the provider has no list; `error` = the fetch failed. */
export interface ModelList {
  models: string[] | null;
  fetchedAt: number;
  unavailable: boolean;
  error?: string;
}

export interface Usage {
  requests: number;
  tokensIn: number;
  tokensOut: number;
  uncounted: number;
  lastUsedAt: number | null;
  ok: boolean;
}

export interface AutoRenew {
  windowSeconds: number;
  /** Hard maximum, ms. */
  maxExpiresAt: number;
}

/** What the issue and edit forms send. */
export interface AutoRenewInput {
  windowSeconds: number;
  maxLifetime?: string;
  maxExpiresAt?: number;
}

export interface RequestLogEntry {
  id: number;
  at: number;
  model: string | null;
  status: number;
  tokensIn: number | null;
  tokensOut: number | null;
  durationMs: number;
  /** Null = forwarded upstream. */
  refusedReason: string | null;
  /** 'renewed' marks a key event rather than a request. */
  event: string | null;
  renewedTo: number | null;
}

/** A log entry from the cross-proxy endpoint. */
export interface ActivityEntry extends RequestLogEntry {
  proxyId: string;
  proxyLabel: string | null;
}

export interface ActivityPage {
  requests: ActivityEntry[];
  /** Pass as `before` for the next page; null = no older rows. */
  nextBefore: number | null;
}

export interface Proxy {
  id: string;
  label: string | null;
  credentialId: string;
  credentialName: string;
  provider: string;
  ttlSeconds: number;
  createdAt: number;
  expiresAt: number;
  status: ProxyStatus;
  /** `sk-wick-…` and the last 5 characters. The full key exists only in the issue/rotate response. */
  maskedKey: string;
  limits: Limits;
  usage: Usage;
  autoRenew: AutoRenew | null;
  /** Usage counters went backwards since the proxy started (in-memory flag). */
  rollbackFlagged: boolean;
  /** When `env` retired this expired proxy (ms), else null. Its activity is kept. */
  cleanedAt: number | null;
  /** Marked and its signed expiry has passed: hidden unless "Show cleaned up" is on. */
  cleanedUp: boolean;
  /** Marked while still active: the DB was edited. Shown with a warning; the proxy refuses it. */
  cleanedTampered: boolean;
}

/** What the sign-in screen may know before there is a session: nothing about proxies or credentials. */
export interface SessionStatus {
  vault: boolean;
  unlocked: boolean;
  signedIn: boolean;
}

export interface SessionState {
  vault: boolean;
  unlocked: boolean;
  graceSeconds: number;
  graceRemaining: number;
  credentialsWithoutVault: number;
}

export interface ProviderPreset {
  baseUrl: string | null;
  auth: AuthStyle;
  envPrefix: string;
  /** Detection hints for the .env import. */
  envNames: string[];
  baseUrlEnvNames: string[];
  keyPrefixes: string[];
  hosts: string[];
}
export type Providers = Record<string, ProviderPreset>;

export interface AppState {
  credentials: Credential[];
  proxies: Proxy[];
  providers: Providers;
  defaultTtlSeconds: number;
  proxyOrigin: string;
  session: SessionState;
}

/** The only response that carries a full key (issue and rotate). Keep it in component state, never in app state. */
export interface IssuedProxyResponse {
  proxy: Proxy;
  token: string;
  baseUrl: string;
}

/** Renew keeps the same key, which is not stored, so there is nothing to show. */
export interface RenewedProxyResponse {
  proxy: Proxy;
  baseUrl: string;
}

export interface SetupResponse {
  ok: true;
}

export interface CredentialInput {
  name: string;
  provider: string;
  apiKey: string;
  baseUrl?: string;
  authStyle?: AuthStyle;
}

export interface CredentialPatch {
  name?: string;
  baseUrl?: string;
  authStyle?: AuthStyle;
  /** Blank keeps the current key. */
  apiKey?: string;
}

export type ImportOutcome = 'imported' | 'would_import' | 'duplicate_key' | 'duplicate_name' | 'invalid';

export interface ImportEntryInput {
  name: string;
  provider: string;
  baseUrl?: string;
  apiKey: string;
  authStyle?: AuthStyle;
}

export interface ImportResult {
  name: string;
  outcome: ImportOutcome;
  message?: string;
  baseUrlScope?: 'public' | 'private' | 'loopback';
}

export class Cancelled extends Error {
  constructor() {
    super('Cancelled.');
    this.name = 'Cancelled';
  }
}

/** HTTP failure; `code` is the server's error.code when it sent one. */
export class ApiError extends Error {
  status: number;
  code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

/** Resolves with the passphrase, or null if the user cancelled. `reason` is shown after a wrong try. */
export type PassphraseAsker = (reason: string) => Promise<string | null>;
let asker: PassphraseAsker | null = null;
let onSettled: (() => void) | null = null;
/** Requests currently waiting on or retrying with the passphrase prompt. */
let askers = 0;
let onSessionLost: (() => void) | null = null;

/** The app registers here to switch to the sign-in screen when the server says the session is gone. */
export function setSessionLostHandler(fn: (() => void) | null): void {
  onSessionLost = fn;
}

/** PassphraseDialog registers itself here. `settled` runs when a request is done with the prompt. */
export function setPassphraseAsker(ask: PassphraseAsker | null, settled?: () => void): void {
  asker = ask;
  onSettled = settled ?? null;
}

interface Raw {
  res: Response;
  data: any;
}

async function raw(method: string, path: string, body?: object): Promise<Raw> {
  // The session cookie is HttpOnly: the browser sends it with same-origin requests, this code never sees it.
  const res = await fetch(path, {
    credentials: 'same-origin',
    method,
    headers: { 'x-wickey': '1', ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && data.error?.code === 'session_required') onSessionLost?.();
  return { res, data };
}

function fail({ res, data }: Raw): never {
  throw new ApiError(res.status, data.error?.message || `Request failed (${res.status})`, data.error?.code);
}

/** Without the passphrase flow: setup and unlock carry their own passphrase. */
async function plain<T>(method: string, path: string, body?: object): Promise<T> {
  const r = await raw(method, path, body);
  if (!r.res.ok) fail(r);
  return r.data as T;
}

/** When the server wants the passphrase, ask for it and retry; the prompt stays open on a wrong one. */
async function request<T>(method: string, path: string, body?: object): Promise<T> {
  let r = await raw(method, path, body);
  let reason = '';
  let asked = false;
  try {
    while (r.res.status === 401 && ['passphrase_required', 'wrong_passphrase'].includes(r.data.error?.code)) {
      if (!asker) fail(r);
      if (!asked) {
        asked = true;
        askers++;
      }
      const passphrase = await asker(reason);
      if (passphrase === null) throw new Cancelled();
      r = await raw(method, path, { ...(body ?? {}), passphrase });
      reason = r.data.error?.code === 'wrong_passphrase' ? 'Wrong passphrase. Try again.' : '';
    }
  } finally {
    // Only the last request that used the prompt closes it. Closing on every request let the
    // background poll shut the dialog mid-typing and leave the asking request waiting forever.
    if (asked && --askers === 0) onSettled?.();
  }
  if (!r.res.ok) fail(r);
  return r.data as T;
}

export const sessionStatus = () => plain<SessionStatus>('GET', '/api/session-status');
/** The vault is already unlocked (another browser, the CLI): prove the passphrase to get a session here. */
export const signIn = (passphrase: string) => plain<{ session: SessionState }>('POST', '/api/signin', { passphrase });
export const getState = () => request<AppState>('GET', '/api/state');
/** `token` is the one-time setup token from the link `start` printed (see app.takeSetupToken). */
export const setup = (passphrase: string, token: string) => plain<SetupResponse>('POST', '/api/setup', { passphrase, token });
export const unlock = (passphrase: string) => plain<{ session: SessionState }>('POST', '/api/unlock', { passphrase });
/** Carries its own passphrases (plain), so a wrong current one is an inline error, not the shared prompt. */
export const changePassphrase = (current: string, next: string) =>
  plain<{ session: SessionState; message: string }>('POST', '/api/passphrase', { current, next });
export const lock = () => request<{ session: SessionState }>('POST', '/api/lock');

export const addCredential = (input: CredentialInput) => request<{ credential: Credential }>('POST', '/api/credentials', input);
/** dryRun checks without storing. Both modes ask for the passphrase, since a preview reveals which keys are already stored. */
export const importCredentials = (entries: ImportEntryInput[], dryRun: boolean) =>
  request<{ dryRun: boolean; results: ImportResult[] }>('POST', '/api/credentials/import', { entries, dryRun });
export const updateCredential = (name: string, patch: CredentialPatch) =>
  request<{ credential: Credential }>('PATCH', `/api/credentials/${encodeURIComponent(name)}`, patch);
export const removeCredential = (name: string) =>
  request<{ credential: Credential }>('DELETE', `/api/credentials/${encodeURIComponent(name)}`);

export const issueProxy = (input: { credential: string; ttl: string; label?: string; limits?: Limits; autoRenew?: AutoRenewInput }) =>
  request<IssuedProxyResponse>('POST', '/api/proxies', input);
/** Tightening needs no passphrase; loosening does (the retry in `request` asks). `autoRenew: null` turns it off. */
export const setProxyLimits = (id: string, patch: { limits?: Limits; autoRenew?: AutoRenewInput | null }) =>
  request<{ proxy: Proxy }>('PATCH', `/api/proxies/${id}/limits`, patch);
export const getActivity = (q: { proxy?: string; status?: 'ok' | 'refused'; before?: number; limit?: number }) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v !== undefined) p.set(k, String(v));
  return request<ActivityPage>('GET', `/api/requests?${p}`);
};
export const renewProxy = (id: string, ttl?: string) =>
  request<RenewedProxyResponse>('POST', `/api/proxies/${id}/renew`, ttl ? { ttl } : {});
export const rotateProxy = (id: string, ttl?: string) =>
  request<IssuedProxyResponse>('POST', `/api/proxies/${id}/rotate`, ttl ? { ttl } : {});
export const expireProxy = (id: string) => request<{ proxy: Proxy }>('POST', `/api/proxies/${id}/expire`, {});
export const deleteProxy = (id: string) => request<{ ok: true }>('DELETE', `/api/proxies/${id}`);

/** Uses the stored key upstream, so it can answer 409 when locked. Never mints anything. */
export const getModels = (name: string) => request<ModelList>('GET', `/api/credentials/${encodeURIComponent(name)}/models`);
export const refreshModels = (name: string) => request<ModelList>('POST', `/api/credentials/${encodeURIComponent(name)}/models/refresh`, {});
