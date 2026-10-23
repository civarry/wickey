import { BRAND } from './brand.ts';
import { classifyBaseUrl } from './netguard.ts';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { config } from './config.ts';
import { PROVIDERS, type AuthStyle, type ProviderPreset } from './providers.ts';
import { parseTtl } from './ttl.ts';
import { flagRollback } from './metering.ts';
import { chmodQuiet } from './logfile.ts';
import { deleteSecret, getSecret, isUnlocked, setSecret, sign, verifySignature } from './vault.ts';

export interface Credential {
  id: string;
  name: string;
  provider: string;
  baseUrl: string;
  authStyle: AuthStyle;
  createdAt: number;
  /** UX hints only (see setUsageReporting); enforcement never trusts them. */
  usageReporting: UsageFlag | null;
  streamUsage: StreamUsageFlag | null;
}

export type UsageFlag = 'reports' | 'missing';
export type StreamUsageFlag = 'reports' | 'missing' | 'rejects_option';

export interface Limits {
  /**
   * null = All: any model the credential's provider lists (see models.ts); [] = None: every request
   * refused; otherwise Selected: exactly these IDs.
   */
  models: string[] | null;
  rpm: number | null;
  tokenCap: number | null;
  /** With a token cap, refuse requests whose usage can't be counted. */
  refuseUncounted: boolean;
}

export interface UsageTotals {
  requests: number;
  tokensIn: number;
  tokensOut: number;
  /** Requests whose usage was unknown. */
  uncounted: number;
  lastUsedAt: number | null;
  /** False when the stored totals fail their signature (edited outside Wickey). */
  ok: boolean;
}

export interface RequestLogEntry {
  id: number;
  proxyId: string;
  at: number;
  model: string | null;
  status: number;
  tokensIn: number | null;
  tokensOut: number | null;
  durationMs: number;
  /** Set when the proxy refused the request itself (nothing was forwarded); null for forwarded requests. */
  refusedReason: string | null;
  /**
   * Non-null marks a key event, not a request ('renewed'): it was never sent upstream and carries
   * no tokens. Real requests (forwarded or refused) always have event null.
   */
  event: string | null;
  /** For event 'renewed': the new expiry in ms. */
  renewedTo: number | null;
}

/** Opt-in auto-renew (D10): the key extends itself by one TTL when used inside the window, never past the maximum. */
export interface AutoRenew {
  windowSeconds: number;
  /** Hard maximum, ms. Fixed when approved with the passphrase; the real lifetime being granted. */
  maxExpiresAt: number;
}

export type ProxyStatus = 'active' | 'expired';

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
  /** `sk-wick-…` plus the last 5 characters. The full key is shown once at issue/rotate and never stored. */
  maskedKey: string;
  /** Read from the row without verifying it; authorize() verifies the row before the proxy trusts these. */
  limits: Limits;
  /** Null unless both renew_window_s and max_expires_at are set. */
  autoRenew: AutoRenew | null;
  usage: UsageTotals;
  /** Set when `env` retired this expired proxy. Unsigned, so never trusted on its own: see below. */
  cleanedAt: number | null;
  /** cleanedAt is set AND the signed expiry has passed: hidden from lists by default. */
  cleanedUp: boolean;
  /**
   * cleanedAt is set on a key whose signed expiry hasn't passed. env only marks expired keys, so
   * this means the DB was edited (e.g. to hide a working key). Shown with a warning, refused.
   */
  cleanedTampered: boolean;
}

export interface IssuedProxy {
  proxy: Proxy;
  token: string;
}

let db: DatabaseSync | null = null;
let dbPath: string | null = null;

function open(): DatabaseSync {
  const cfg = config();
  if (db && dbPath === cfg.dbPath) return db;
  fs.mkdirSync(cfg.home, { recursive: true, mode: 0o700 });
  db = new DatabaseSync(cfg.dbPath);
  dbPath = cfg.dbPath;
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS credentials (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      provider TEXT NOT NULL,
      base_url TEXT NOT NULL,
      auth_style TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS proxies (
      id TEXT PRIMARY KEY,
      label TEXT,
      credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      ttl_seconds INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS proxy_usage (
      proxy_id TEXT PRIMARY KEY REFERENCES proxies(id) ON DELETE CASCADE,
      requests INTEGER NOT NULL DEFAULT 0,
      tokens_in INTEGER NOT NULL DEFAULT 0,
      tokens_out INTEGER NOT NULL DEFAULT 0,
      uncounted INTEGER NOT NULL DEFAULT 0,
      last_used_at INTEGER,
      sig TEXT
    );
    CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY,
      proxy_id TEXT NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
      at INTEGER NOT NULL,
      model TEXT,
      status INTEGER NOT NULL,
      tokens_in INTEGER,
      tokens_out INTEGER,
      duration_ms INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS requests_by_proxy ON requests (proxy_id, id);
    -- Provider model lists for "All models" keys. Deliberately unsigned: in that mode the provider
    -- would serve any model it lists anyway, so a forged list only changes which names we pre-filter.
    CREATE TABLE IF NOT EXISTS credential_models (
      credential_id TEXT PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
      models TEXT,
      fetched_at INTEGER,
      error TEXT,
      unavailable INTEGER NOT NULL DEFAULT 0
    );
    -- Which notification types are switched off (one row, id 1). Signed like the other rows; a
    -- missing row means everything is on, and so does one that fails its signature.
    CREATE TABLE IF NOT EXISTS notification_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      disabled TEXT NOT NULL,
      sig TEXT
    );
    -- The dashboard's "since your last visit" marker (one row, id 1): the newest event seq the
    -- person has marked as seen. Signed; a row that fails its signature counts as no marker.
    CREATE TABLE IF NOT EXISTS event_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      seen_seq INTEGER NOT NULL,
      seen_hash TEXT NOT NULL DEFAULT '',
      sig TEXT
    );
  `);
  const columns = db.prepare('PRAGMA table_info(proxies)').all().map((c) => c.name);
  // Only the hash of a proxy key is kept; the key itself is shown once, at issue or rotate. The
  // last 5 characters are stored so lists can tell keys apart (display only, not signed).
  if (!columns.includes('token_tail')) db.exec('ALTER TABLE proxies ADD COLUMN token_tail TEXT');
  if (columns.includes('token')) scrubPlaintextTokens(db);
  // Rows are signed with a key from the vault, so a row inserted or edited directly in this file
  // (a forged proxy, an extended expiry, a credential pointed at another server) is rejected.
  if (!columns.includes('sig')) db.exec('ALTER TABLE proxies ADD COLUMN sig TEXT');
  const credColumns = db.prepare('PRAGMA table_info(credentials)').all().map((c) => c.name);
  if (!credColumns.includes('sig')) db.exec('ALTER TABLE credentials ADD COLUMN sig TEXT');
  // Limit columns. Existing rows get NULL / refuse_uncounted=1, which proxySigData treats as "no
  // limits" and signs exactly as before, so rows signed by older versions keep verifying.
  const limitColumns: [string, string][] = [
    ['allowed_models', 'TEXT'], ['rpm', 'INTEGER'], ['token_cap', 'INTEGER'],
    ['refuse_uncounted', 'INTEGER NOT NULL DEFAULT 1'], ['renew_window_s', 'INTEGER'], ['max_expires_at', 'INTEGER'],
    // Bumped on every signed write; see proxySigData. 0 = never written since this column existed.
    ['version', 'INTEGER NOT NULL DEFAULT 0'],
  ];
  for (const [name, type] of limitColumns) {
    if (!columns.includes(name)) db.exec(`ALTER TABLE proxies ADD COLUMN ${name} ${type}`);
  }
  // Not signed: these are hints for the UI. Enforcement must not depend on them.
  // cleaned_at is deliberately NOT in the row signature. The signature covers what a key can do
  // (credential, token, expiry, limits); this only hides an already-expired row from lists. Nothing
  // enforces on it except the refusals below, which only make renew/rotate stricter. Clearing it
  // by hand merely unhides the row; to bring the key back an attacker still needs requireAuth.
  if (!columns.includes('cleaned_at')) db.exec('ALTER TABLE proxies ADD COLUMN cleaned_at INTEGER');
  if (!credColumns.includes('usage_reporting')) db.exec('ALTER TABLE credentials ADD COLUMN usage_reporting TEXT');
  if (!credColumns.includes('stream_usage')) db.exec('ALTER TABLE credentials ADD COLUMN stream_usage TEXT');
  // Tells refused requests from forwarded ones in the log (auto-renew counts only forwarded use).
  const reqColumns = db.prepare('PRAGMA table_info(requests)').all().map((c) => c.name);
  if (!reqColumns.includes('refused_reason')) db.exec('ALTER TABLE requests ADD COLUMN refused_reason TEXT');
  // Key events (auto-renewals) live in the same log but are marked, so refused_reason IS NULL still means "a forwarded request" for rows with event NULL.
  if (!reqColumns.includes('event')) db.exec('ALTER TABLE requests ADD COLUMN event TEXT');
  if (!reqColumns.includes('renewed_to')) db.exec('ALTER TABLE requests ADD COLUMN renewed_to INTEGER');
  fs.chmodSync(cfg.dbPath, 0o600);
  // The -wal/-shm sidecars hold the same data and are created 0644 by SQLite; the data dir is 0700,
  // so this is defense in depth.
  for (const side of [`${cfg.dbPath}-wal`, `${cfg.dbPath}-shm`]) chmodQuiet(side, 0o600);
  return db;
}

/**
 * Earlier versions kept proxy keys in plain text so the dashboard could show them again. Any local
 * program could read them, so keep only the hash (which already authenticates, and is what the row
 * signature covers, so no row needs re-signing) and the display suffix. VACUUM and a WAL
 * truncate then remove the old text from free pages and the log.
 */
function scrubPlaintextTokens(d: DatabaseSync): void {
  const rows = d.prepare('SELECT id, token FROM proxies WHERE token IS NOT NULL').all() as { id: string; token: string }[];
  const setTail = d.prepare('UPDATE proxies SET token_tail = ? WHERE id = ?');
  for (const r of rows) setTail.run(r.token.slice(-TAIL_LENGTH), r.id);
  d.exec('ALTER TABLE proxies DROP COLUMN token');
  d.exec('VACUUM');
  d.exec('PRAGMA wal_checkpoint(TRUNCATE)');
}

/** Closes the cached handle; used by tests that switch WICKEY_HOME. */
export function closeStore(): void {
  db?.close();
  db = null;
  dbPath = null;
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

const TAIL_LENGTH = 5;

function maskedKey(tail: string | null): string {
  return `${BRAND.keyPrefix}…${tail ?? ''}`;
}

function newToken(): string {
  return `${BRAND.keyPrefix}${randomBytes(32).toString('base64url')}`;
}

function toCredential(row: Record<string, any>): Credential {
  return {
    id: row.id,
    name: row.name,
    provider: row.provider,
    baseUrl: row.base_url,
    authStyle: row.auth_style,
    createdAt: row.created_at,
    usageReporting: row.usage_reporting ?? null,
    streamUsage: row.stream_usage ?? null,
  };
}

// revoked_at is only set by v0.1's separate "revoke"; such rows simply count as expired.
function statusOf(row: { expires_at: number; revoked_at: number | null }, now = Date.now()): ProxyStatus {
  return row.revoked_at === null && now < row.expires_at ? 'active' : 'expired';
}

function toProxy(row: Record<string, any>): Proxy {
  return {
    id: row.id,
    label: row.label,
    credentialId: row.credential_id,
    credentialName: row.credential_name,
    provider: row.provider,
    ttlSeconds: row.ttl_seconds,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    status: statusOf(row as any),
    maskedKey: maskedKey(row.token_tail ?? null),
    limits: limitsOf(row),
    autoRenew: row.renew_window_s != null && row.max_expires_at != null
      ? { windowSeconds: row.renew_window_s, maxExpiresAt: row.max_expires_at } : null,
    usage: usageOf(row),
    cleanedAt: row.cleaned_at ?? null,
    cleanedUp: row.cleaned_at != null && statusOf(row as any) === 'expired',
    cleanedTampered: row.cleaned_at != null && statusOf(row as any) === 'active',
  };
}

function limitsOf(row: Record<string, any>): Limits {
  let models: string[] | null = null;
  if (row.allowed_models != null) {
    try {
      const parsed = JSON.parse(row.allowed_models);
      // A malformed value (edited by hand) becomes an empty allowlist: fail closed. The row
      // signature rejects such an edit anyway.
      models = Array.isArray(parsed) && parsed.every((m) => typeof m === 'string') ? parsed : [];
    } catch {
      models = [];
    }
  }
  return { models, rpm: row.rpm ?? null, tokenCap: row.token_cap ?? null, refuseUncounted: row.refuse_uncounted !== 0 };
}

function usageOf(row: Record<string, any>): UsageTotals {
  const u = usageFromJoin(row);
  // Listing also runs in the CLI, which has no unlocked vault and so can't check signatures.
  // Unverifiable there is shown as ok; the proxy (unlocked) uses getUsage(), which is strict.
  return { ...u.totals, ok: isUnlocked() ? u.verified() : true };
}

function usageFromJoin(row: Record<string, any>) {
  const present = row.u_proxy_id != null;
  const raw = {
    proxy_id: row.id, requests: row.u_requests ?? 0, tokens_in: row.u_tokens_in ?? 0, tokens_out: row.u_tokens_out ?? 0,
    uncounted: row.u_uncounted ?? 0, last_used_at: row.u_last_used_at ?? null,
  };
  return {
    totals: {
      requests: raw.requests, tokensIn: raw.tokens_in, tokensOut: raw.tokens_out, uncounted: raw.uncounted, lastUsedAt: raw.last_used_at,
    },
    // A missing row is zeros for a legacy proxy, but a proxy with a token cap always has one
    // (issueProxy/setLimits create it), so a missing row there means it was deleted to reset the count.
    verified: () => (present ? verifySignature(usageSigData(raw), row.u_sig) : row.token_cap == null),
  };
}

// ---- Row signatures ----

function credentialSigData(row: Record<string, any>): string {
  return ['credential', 'v1', row.id, row.provider, row.base_url, row.auth_style].join('|');
}
/**
 * Rows signed before limits existed must keep verifying, so the limit fields are appended only
 * when any is set or non-default. A row with no limits signs byte-for-byte as it did in v1.
 * Removing a limit from a limited row, or adding one to an unlimited row, changes the string
 * either way, so neither edit verifies. refuse_uncounted counts as default unless it is 0.
 */
function proxySigData(row: Record<string, any>): string {
  const base = ['proxy', 'v1', row.id, row.credential_id, row.token_hash, row.expires_at, row.revoked_at ?? ''];
  // version and ttl_seconds are signed once any write has happened (version > 0). Rows still at
  // version 0 verify exactly as before; the first write moves them to this format. Dropping the
  // segment (version back to 0) changes the string, so it can't be used to strip it.
  const ver = Number(row.version) > 0 ? ['version-v1', row.version, row.ttl_seconds] : [];
  const refuse = row.refuse_uncounted === 0 ? 0 : 1;
  const limited = row.allowed_models != null || row.rpm != null || row.token_cap != null || refuse === 0
    || row.renew_window_s != null || row.max_expires_at != null;
  if (!limited) return [...base, ...ver].join('|');
  const f = (v: unknown) => (v == null ? '' : String(v));
  return [...base, 'limits-v2', f(row.allowed_models), f(row.rpm), f(row.token_cap), refuse, f(row.renew_window_s), f(row.max_expires_at), ...ver].join('|');
}
function usageSigData(u: Record<string, any>): string {
  return ['usage', 'v1', u.proxy_id, u.requests, u.tokens_in, u.tokens_out, u.uncounted, u.last_used_at ?? ''].join('|');
}
function resignUsage(proxyId: string): void {
  const row = open().prepare('SELECT * FROM proxy_usage WHERE proxy_id = ?').get(proxyId) as Record<string, any>;
  open().prepare('UPDATE proxy_usage SET sig = ? WHERE proxy_id = ?').run(sign(usageSigData(row)), proxyId);
}
/** Creates the zeroed, signed usage row if the proxy has none. Never touches an existing one. */
function ensureUsageRow(proxyId: string): void {
  const res = open().prepare('INSERT OR IGNORE INTO proxy_usage (proxy_id) VALUES (?)').run(proxyId);
  if (res.changes) resignUsage(proxyId);
}
function notifySigData(disabled: string): string {
  return ['notify-settings', 'v1', disabled].join('|');
}
function resignNotifySettings(): void {
  const row = open().prepare('SELECT * FROM notification_settings WHERE id = 1').get() as Record<string, any>;
  open().prepare('UPDATE notification_settings SET sig = ? WHERE id = 1').run(sign(notifySigData(row.disabled)));
}
function seenSigData(seq: number, hash: string): string {
  return ['events-seen', 'v1', seq, hash].join('|');
}
function resignEventSettings(): void {
  const row = open().prepare('SELECT * FROM event_settings WHERE id = 1').get() as Record<string, any>;
  open().prepare('UPDATE event_settings SET sig = ? WHERE id = 1').run(sign(seenSigData(row.seen_seq, row.seen_hash)));
}
function resignCredential(id: string): void {
  const row = open().prepare('SELECT * FROM credentials WHERE id = ?').get(id) as Record<string, any>;
  open().prepare('UPDATE credentials SET sig = ? WHERE id = ?').run(sign(credentialSigData(row)), id);
}
// Highest row version seen per proxy by this process. A signed row from an older copy of the file
// still verifies, so only this memory can tell it has been put back (same idea as the usage high-water).
const versionHigh = new Map<string, number>();

function noteVersion(id: string, version: number): void {
  versionHigh.set(id, Math.max(versionHigh.get(id) ?? 0, version));
}

/** Every legitimate write to a proxies row ends here: bump the version, then sign it. */
function resignProxy(id: string): void {
  open().prepare('UPDATE proxies SET version = version + 1 WHERE id = ?').run(id);
  const row = open().prepare('SELECT * FROM proxies WHERE id = ?').get(id) as Record<string, any>;
  open().prepare('UPDATE proxies SET sig = ? WHERE id = ?').run(sign(proxySigData(row)), id);
  noteVersion(id, row.version);
}

function isVersionRolledBack(row: Record<string, any>): boolean {
  return Number(row.version) < (versionHigh.get(row.id) ?? 0);
}

/** One-time move into a new vault: signs the rows that existed before signing did. */
export function signExistingRows(): void {
  for (const c of listCredentials()) resignCredential(c.id);
  for (const { id } of open().prepare('SELECT id FROM proxies').all() as { id: string }[]) {
    resignProxy(id);
    ensureUsageRow(id);
  }
}

/**
 * Recomputes every signature (credentials, proxies, proxy_usage) with the current vault MAC key,
 * in one transaction. Row versions and usage values are left as they are. Needed when the MAC key
 * changes, e.g. moving data into a freshly created vault, and later for a data-key rotation.
 * It trusts the rows as they are (it would launder an edit), so only call it from a deliberate
 * migration, never on a normal path.
 */
export function resignAllRows(): void {
  const d = open();
  d.exec('BEGIN IMMEDIATE');
  try {
    for (const r of d.prepare('SELECT * FROM credentials').all() as Record<string, any>[]) {
      d.prepare('UPDATE credentials SET sig = ? WHERE id = ?').run(sign(credentialSigData(r)), r.id);
    }
    for (const r of d.prepare('SELECT * FROM proxies').all() as Record<string, any>[]) {
      d.prepare('UPDATE proxies SET sig = ? WHERE id = ?').run(sign(proxySigData(r)), r.id);
    }
    for (const r of d.prepare('SELECT * FROM proxy_usage').all() as Record<string, any>[]) {
      d.prepare('UPDATE proxy_usage SET sig = ? WHERE proxy_id = ?').run(sign(usageSigData(r)), r.proxy_id);
    }
    for (const r of d.prepare('SELECT * FROM notification_settings').all() as Record<string, any>[]) {
      d.prepare('UPDATE notification_settings SET sig = ? WHERE id = 1').run(sign(notifySigData(r.disabled)));
    }
    for (const r of d.prepare('SELECT * FROM event_settings').all() as Record<string, any>[]) {
      d.prepare('UPDATE event_settings SET sig = ? WHERE id = 1').run(sign(seenSigData(r.seen_seq, r.seen_hash)));
    }
    d.exec('COMMIT');
  } catch (err) {
    d.exec('ROLLBACK');
    throw err;
  }
}

const PROXY_SELECT = `
  SELECT p.*, c.name AS credential_name, c.provider AS provider,
    u.proxy_id AS u_proxy_id, u.requests AS u_requests, u.tokens_in AS u_tokens_in, u.tokens_out AS u_tokens_out,
    u.uncounted AS u_uncounted, u.last_used_at AS u_last_used_at, u.sig AS u_sig
  FROM proxies p JOIN credentials c ON c.id = p.credential_id
  LEFT JOIN proxy_usage u ON u.proxy_id = p.id`;

// ---- Credentials ----

// Must start with a letter or digit: a leading dash would become an option in a pasted command,
// and `..` is a path.
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** Storing one of our own proxy keys as a "real" key would make the proxy forward to itself. */
function refuseProxyKey(apiKey: string): void {
  if (apiKey.trim().startsWith(BRAND.keyPrefix)) {
    throw new Error('That is a Wickey proxy key, not a provider key. Paste the real key from your provider.');
  }
}

function validateName(name: string): void {
  if (!NAME_RE.test(name)) {
    throw new Error('Name must be 1-64 letters, numbers, dots, dashes or underscores, and start with a letter or number.');
  }
}

/**
 * Proxy names follow the same rules as credential names. They are pasted into shell commands
 * (`eval "$(wickey env <name> ...)"`), so anything a shell would interpret must be refused.
 */
function validateLabel(label: string): void {
  if (!NAME_RE.test(label)) {
    throw new Error('Proxy name must be 1-64 letters, numbers, dots, dashes or underscores, and start with a letter or number.');
  }
}

function normalizeBaseUrl(input: string): string {
  const baseUrl = input.trim().replace(/\/+$/, '');
  if (!baseUrl) throw new Error('A custom provider needs a base URL.');
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error(`"${baseUrl}" is not a valid URL.`);
  }
  const verdict = classifyBaseUrl(parsed);
  if (!verdict.ok) throw new Error(verdict.reason);
  // Clients append the endpoint themselves, so a base URL that already includes one doubles it.
  const endpoint = /\/(chat\/completions|completions|messages|responses|embeddings|models)$/.exec(parsed.pathname);
  if (endpoint) {
    throw new Error(`Base URL should stop before the endpoint. Use ${baseUrl.slice(0, -endpoint[0].length)} instead.`);
  }
  return baseUrl;
}

/**
 * Everything addCredential checks before writing, minus the duplicate-name check. Shared with the
 * .env import's dry run so a preview can never accept what the real add would reject.
 */
export function checkNewCredential(input: { name: string; provider: string; apiKey: string; baseUrl?: string }): { baseUrl: string; preset: ProviderPreset } {
  const preset = PROVIDERS[input.provider];
  if (!preset) throw new Error(`Unknown provider "${input.provider}".`);
  const baseUrl = normalizeBaseUrl(input.baseUrl ?? preset.baseUrl ?? '');
  validateName(input.name);
  if (!input.apiKey) throw new Error('API key is empty.');
  refuseProxyKey(input.apiKey);
  return { baseUrl, preset };
}

export function addCredential(input: {
  name: string;
  provider: string;
  apiKey: string;
  baseUrl?: string;
  authStyle?: AuthStyle;
}): Credential {
  const { baseUrl, preset } = checkNewCredential(input);
  if (getCredential(input.name)) throw new Error(`A credential named "${input.name}" already exists.`);

  const credential: Credential = {
    id: randomUUID(),
    name: input.name,
    provider: input.provider,
    baseUrl,
    authStyle: input.authStyle ?? preset.auth,
    createdAt: Date.now(),
    usageReporting: null,
    streamUsage: null,
  };
  setSecret(credential.id, input.apiKey);
  open()
    .prepare('INSERT INTO credentials (id, name, provider, base_url, auth_style, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(credential.id, credential.name, credential.provider, credential.baseUrl, credential.authStyle, credential.createdAt);
  resignCredential(credential.id);
  return credential;
}

/**
 * Changes a credential in place. Proxies reference it by id, so they keep working (and keep
 * their tokens) through a rename, a new base URL or a replaced key. An omitted field is unchanged.
 */
export function updateCredential(
  nameOrId: string,
  changes: { name?: string; baseUrl?: string; authStyle?: AuthStyle; apiKey?: string },
): Credential {
  const existing = getCredential(nameOrId);
  if (!existing) throw new Error(`No credential named "${nameOrId}".`);
  const name = changes.name ?? existing.name;
  // Only a rename validates: names stored before the leading-character rule must stay editable.
  if (name !== existing.name) validateName(name);
  if (name !== existing.name && getCredential(name)) throw new Error(`A credential named "${name}" already exists.`);
  const baseUrl = changes.baseUrl === undefined ? existing.baseUrl : normalizeBaseUrl(changes.baseUrl);
  const authStyle = changes.authStyle ?? existing.authStyle;
  if (authStyle !== 'bearer' && authStyle !== 'x-api-key') throw new Error('Invalid auth style.');
  if (changes.apiKey !== undefined) {
    if (!changes.apiKey) throw new Error('API key is empty.');
    refuseProxyKey(changes.apiKey);
  }
  // A cached list belongs to the old server and key; drop it so the next use refetches.
  if (baseUrl !== existing.baseUrl || authStyle !== existing.authStyle || changes.apiKey !== undefined) invalidateModels(existing.id);
  if (changes.apiKey !== undefined) {
    setSecret(existing.id, changes.apiKey);
  }
  open()
    .prepare('UPDATE credentials SET name = ?, base_url = ?, auth_style = ? WHERE id = ?')
    .run(name, baseUrl, authStyle, existing.id);
  resignCredential(existing.id);
  return getCredential(existing.id)!;
}

export function getCredential(nameOrId: string): Credential | null {
  const row = open().prepare('SELECT * FROM credentials WHERE name = ? OR id = ?').get(nameOrId, nameOrId);
  return row ? toCredential(row) : null;
}

export function listCredentials(): Credential[] {
  return open().prepare('SELECT * FROM credentials ORDER BY created_at').all().map(toCredential);
}

/** Removes the credential, its vault secret, and every proxy issued from it. */
export function removeCredential(nameOrId: string): Credential {
  const credential = getCredential(nameOrId);
  if (!credential) throw new Error(`No credential named "${nameOrId}".`);
  open().prepare('DELETE FROM credentials WHERE id = ?').run(credential.id);
  invalidateModels(credential.id);
  deleteSecret(credential.id);
  return credential;
}

// ---- Provider model lists (unsigned cache, see the credential_models comment) ----

export interface ModelCache {
  /** Null when no list was ever fetched successfully. */
  models: string[] | null;
  /** Time of the last attempt, successful or not; the refresh throttle counts from it. */
  fetchedAt: number;
  error: string | null;
  /** The provider definitively has no model list (e.g. 404): All mode then passes models through. */
  unavailable: boolean;
}

// Bumped when a credential's server or key changes, so a fetch that started before the edit
// can't write its stale answer afterwards.
const modelEpochs = new Map<string, number>();
export function modelsEpoch(credentialId: string): number {
  return modelEpochs.get(credentialId) ?? 0;
}

export function getModelCache(credentialId: string): ModelCache | null {
  const row = open().prepare('SELECT * FROM credential_models WHERE credential_id = ?').get(credentialId);
  if (!row) return null;
  let models: string[] | null = null;
  try {
    const parsed = JSON.parse(row.models as string);
    if (Array.isArray(parsed) && parsed.every((m) => typeof m === 'string')) models = parsed;
  } catch { /* unreadable list counts as none */ }
  return { models, fetchedAt: Number(row.fetched_at ?? 0), error: (row.error as string | null) ?? null, unavailable: row.unavailable === 1 };
}

/** Stores an attempt's outcome unless the credential changed since `epoch`. Returns whether it was stored. */
export function putModelCache(credentialId: string, epoch: number, entry: ModelCache): boolean {
  if (epoch !== modelsEpoch(credentialId) || !getCredential(credentialId)) return false;
  open()
    .prepare(`INSERT OR REPLACE INTO credential_models (credential_id, models, fetched_at, error, unavailable) VALUES (?, ?, ?, ?, ?)`)
    .run(credentialId, entry.models ? JSON.stringify(entry.models) : null, entry.fetchedAt, entry.error, entry.unavailable ? 1 : 0);
  return true;
}

export function invalidateModels(credentialId: string): void {
  modelEpochs.set(credentialId, modelsEpoch(credentialId) + 1);
  open().prepare('DELETE FROM credential_models WHERE credential_id = ?').run(credentialId);
}

export function getCredentialSecret(credential: Credential): string | null {
  return getSecret(credential.id);
}

// ---- Proxies ----

export function issueProxy(input: { credential: string; ttlSeconds: number; label?: string; limits?: Partial<Limits> | null; autoRenew?: unknown }): IssuedProxy {
  const limits = normalizeLimits(input.limits);
  const credential = getCredential(input.credential);
  if (!credential) throw new Error(`No credential named "${input.credential}".`);
  if (input.label !== undefined) validateLabel(input.label);
  const token = newToken();
  const now = Date.now();
  const id = randomBytes(4).toString('hex');
  const autoRenew = normalizeAutoRenew(input.autoRenew, { ttlSeconds: input.ttlSeconds, expiresAt: now + input.ttlSeconds * 1000, now });
  open()
    .prepare(
      `INSERT INTO proxies (id, label, credential_id, token_hash, token_tail, ttl_seconds, created_at, expires_at,
        allowed_models, rpm, token_cap, refuse_uncounted, renew_window_s, max_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(id, input.label ?? null, credential.id, hashToken(token), token.slice(-TAIL_LENGTH), input.ttlSeconds, now, now + input.ttlSeconds * 1000,
      limits.models ? JSON.stringify(limits.models) : null, limits.rpm, limits.tokenCap, limits.refuseUncounted ? 1 : 0,
      autoRenew?.windowSeconds ?? null, autoRenew?.maxExpiresAt ?? null);
  resignProxy(id);
  ensureUsageRow(id);
  return { proxy: getProxy(id)!, token };
}

/**
 * New expiry for a manual renew or rotate. An auto-renew key never goes past its hard maximum, even
 * with the passphrase: raising the maximum is a separate, explicit edit.
 */
function restartedExpiry(existing: Proxy, ttlSeconds: number): number {
  const now = Date.now();
  const want = now + ttlSeconds * 1000;
  const ar = existing.autoRenew;
  if (!ar) return want;
  if (ttlSeconds <= ar.windowSeconds) {
    throw new Error(`This key auto-renews within ${ar.windowSeconds}s of expiry, so its lifetime must be longer than that. Pick a longer TTL.`);
  }
  if (ar.maxExpiresAt <= now) {
    throw new Error(`This key reached its maximum lifetime (${new Date(ar.maxExpiresAt).toLocaleString()}). Raise the maximum with \`wickey limits ${existing.id} --max-lifetime <ttl>\` or issue a new key.`);
  }
  return Math.min(want, ar.maxExpiresAt);
}

// A tampered mark doesn't block rotate: rotating clears it and gives the user a working key back.
function refuseIfCleaned(p: Proxy): void {
  if (p.cleanedUp) throw new Error(`Proxy "${p.id}" was retired by \`wickey env\` and cannot be renewed or rotated. Run \`wickey env\` again for a fresh key.`);
}

/**
 * Reactivates a proxy after review: same base URL and same token, with the timer restarted,
 * so nothing that already uses it needs updating.
 */
export function renewProxy(id: string, ttlSeconds?: number): Proxy {
  const existing = getProxy(id);
  if (!existing) throw new Error(`No proxy with id "${id}".`);
  refuseIfCleaned(existing);
  const ttl = ttlSeconds ?? existing.ttlSeconds;
  const expiresAt = restartedExpiry(existing, ttl);
  open()
    .prepare('UPDATE proxies SET ttl_seconds = ?, expires_at = ?, revoked_at = NULL WHERE id = ?')
    .run(ttl, expiresAt, id);
  resignProxy(id);
  return getProxy(id)!;
}

/**
 * Replaces the token (same id and base URL) and restarts the timer. The old token stops
 * working immediately, so anything still using it breaks: that is the point after a leak.
 * Limits and usage are kept: the budget belongs to the proxy, not the token, so rotating
 * must not be a way to reset a token cap.
 */
export function rotateProxy(id: string, ttlSeconds?: number): IssuedProxy {
  const existing = getProxy(id);
  if (!existing) throw new Error(`No proxy with id "${id}".`);
  refuseIfCleaned(existing);
  const ttl = ttlSeconds ?? existing.ttlSeconds;
  const expiresAt = restartedExpiry(existing, ttl);
  const token = newToken();
  open()
    .prepare('UPDATE proxies SET token_hash = ?, token_tail = ?, ttl_seconds = ?, expires_at = ?, revoked_at = NULL, cleaned_at = NULL WHERE id = ?')
    .run(hashToken(token), token.slice(-TAIL_LENGTH), ttl, expiresAt, id);
  resignProxy(id);
  return { proxy: getProxy(id)!, token };
}

/**
 * `env` mints a fresh key on every run (one per terminal), under the template's label. Several
 * active proxies may share a label: each terminal has its own key and the dashboard shows the
 * label with each key's suffix. Expired proxies with the label are marked cleaned up (hidden from
 * lists, not deleted) so repeated runs do not pile up rows in the UI; active ones stay because other terminals are using them. Nothing is ever
 * revived: reviving a key that may have leaked would defeat the expiry.
 */
export function mintEnvProxy(input: { label: string; credential: string; ttlSeconds: number; limits?: Partial<Limits> | null; autoRenew?: unknown }): IssuedProxy {
  validateLabel(input.label);
  const credential = getCredential(input.credential);
  if (!credential) throw new Error(`No credential named "${input.credential}".`);
  const stale = open()
    .prepare('SELECT id FROM proxies WHERE label = ? AND cleaned_at IS NULL AND (revoked_at IS NOT NULL OR expires_at <= ?)')
    .all(input.label, Date.now()) as { id: string }[];
  // Mint first: a bad limit or TTL throws before anything is deleted.
  const issued = issueProxy({ credential: credential.id, ttlSeconds: input.ttlSeconds, label: input.label, limits: input.limits, autoRenew: input.autoRenew });
  // Marked, not deleted: deleting would take the activity log with it and let an agent erase its
  // own trail by rerunning env. Log retention (row caps + 30 days) bounds the size instead.
  // No re-sign needed: cleaned_at is outside the signature.
  const mark = open().prepare('UPDATE proxies SET cleaned_at = ? WHERE id = ? AND cleaned_at IS NULL');
  const now = Date.now();
  for (const { id } of stale) mark.run(now, id);
  return issued;
}

/** Ends a proxy now, exactly as if its TTL had run out. It stays listed so it can be renewed. */
export function expireProxy(id: string): Proxy {
  const existing = getProxy(id);
  if (!existing) throw new Error(`No proxy with id "${id}".`);
  const now = Date.now();
  open().prepare('UPDATE proxies SET expires_at = ? WHERE id = ? AND expires_at > ?').run(now, id, now);
  resignProxy(id);
  return getProxy(id)!;
}

/** Deletes a proxy record outright (as opposed to revoking it, which keeps it for review). */
export function deleteProxy(id: string): void {
  if (!getProxy(id)) throw new Error(`No proxy with id "${id}".`);
  open().prepare('DELETE FROM proxies WHERE id = ?').run(id);
  versionHigh.delete(id);
}

export function getProxy(id: string): Proxy | null {
  const row = open().prepare(`${PROXY_SELECT} WHERE p.id = ?`).get(id);
  return row ? toProxy(row) : null;
}

export function listProxies(opts: { includeCleaned?: boolean } = {}): Proxy[] {
  const all = open().prepare(`${PROXY_SELECT} ORDER BY p.created_at`).all().map(toProxy);
  // Only a mark backed by the signed expiry hides a key; a tampered mark on an active key stays visible.
  return opts.includeCleaned ? all : all.filter((p) => !p.cleanedUp);
}

export type AuthorizeResult =
  | { ok: true; proxy: Proxy; credential: Credential }
  | { ok: false; status: number; message: string; code?: 'usage_rollback' };

/**
 * Checks a presented proxy token. Reads the DB on every call so `expire` and `renew` from
 * the CLI take effect on the running proxy immediately, with no IPC.
 */
export function authorize(proxyId: string, token: string | null): AuthorizeResult {
  if (!isUnlocked()) {
    return { ok: false, status: 503, message: 'Locked. Unlock it in the dashboard or with `wickey unlock`.' };
  }
  if (!token) return { ok: false, status: 401, message: 'Missing proxy token.' };
  // The dashboard and `list` show keys as sk-wick-…abcde. Pasting that is an easy mistake; say so.
  // Node reads header bytes as Latin-1, so a pasted "…" arrives as its UTF-8 bytes: decode first.
  const asSent = Buffer.from(token, 'latin1').toString('utf8');
  if (asSent.includes('…') || token.includes('…') || token.startsWith(`${BRAND.keyPrefix}...`)) {
    return { ok: false, status: 401, message: 'That is the masked form of the key (sk-wick-…), shown for reference only. Use the full key you copied when it was issued, or rotate the proxy for a new one.' };
  }
  const row = open().prepare(`${PROXY_SELECT} WHERE p.id = ?`).get(proxyId) as Record<string, any> | undefined;
  const presented = Buffer.from(hashToken(token), 'hex');
  const stored = Buffer.from(row?.token_hash ?? '00'.repeat(32), 'hex');
  // Length check first: timingSafeEqual throws on a mismatch, which would crash the proxy on a malformed row.
  if (!row || stored.length !== presented.length || !timingSafeEqual(presented, stored)) {
    return { ok: false, status: 401, message: 'Invalid proxy token.' };
  }
  if (!verifySignature(proxySigData(row), row.sig)) {
    return { ok: false, status: 401, message: 'Proxy record failed its integrity check (it was changed outside Wickey). Rotate or delete it.' };
  }
  if (isVersionRolledBack(row)) {
    // Refused for every key, limited or not: an older row can revive an expired key or loosened limits.
    flagRollback(row.id);
    return {
      ok: false, status: 403, code: 'usage_rollback',
      message: 'This key\'s record went back to an older version (the database was restored or edited), so its limits and expiry cannot be trusted. Delete this key and issue a new one.',
    };
  }
  noteVersion(row.id, Number(row.version));
  const proxy = toProxy(row);
  if (proxy.cleanedTampered) {
    // Fail closed, like the integrity check: the row was edited outside Wickey.
    return { ok: false, status: 401, message: `Proxy record was marked cleaned up while active (it was changed outside Wickey). Rotate or delete it: \`wickey rotate ${proxy.id}\`.` };
  }
  if (proxy.status === 'expired') {
    if (proxy.cleanedUp) return { ok: false, status: 401, message: 'Proxy key was retired by `wickey env`. Run it again for a fresh key.' };
    return {
      ok: false,
      status: 401,
      message: `Proxy token expired at ${new Date(proxy.expiresAt).toISOString()}. Run \`wickey renew ${proxy.id}\`.`,
    };
  }
  const credRow = open().prepare('SELECT * FROM credentials WHERE id = ?').get(proxy.credentialId) as Record<string, any>;
  if (!verifySignature(credentialSigData(credRow), credRow.sig)) {
    // Refuse rather than risk sending the real key to a base URL someone else wrote into the file.
    return { ok: false, status: 502, message: `Credential "${credRow.name}" failed its integrity check (it was changed outside Wickey). Re-save it from the dashboard.` };
  }
  return { ok: true, proxy, credential: toCredential(credRow) };
}


// ---- Limits ----

const MODEL_ID = /^[A-Za-z0-9._:/@-]{1,200}$/;
export const MAX_MODELS = 100;
export const MAX_RPM = 100_000;
export const MAX_TOKEN_CAP = 1e12;

function intInRange(value: unknown, min: number, max: number, what: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${what} must be a whole number from ${min} to ${max}.`);
  }
  return value;
}

/** Validates user input into a full Limits value. Missing or null fields mean "no limit". */
export function normalizeLimits(input: Partial<Limits> | null | undefined): Limits {
  const raw = (input ?? {}) as Record<string, unknown>;
  let models: string[] | null = null;
  if (raw.models != null) {
    if (!Array.isArray(raw.models)) throw new Error('models must be a list of model IDs.');
    if (raw.models.length > MAX_MODELS) throw new Error(`At most ${MAX_MODELS} models per key.`);
    for (const m of raw.models) {
      if (typeof m !== 'string' || !MODEL_ID.test(m)) {
        throw new Error(`"${String(m).slice(0, 40)}" is not a valid model ID. Use 1-200 letters, numbers and . _ : / @ - (no spaces).`);
      }
    }
    models = [...new Set(raw.models as string[])];
  }
  if (raw.refuseUncounted != null && typeof raw.refuseUncounted !== 'boolean') throw new Error('refuseUncounted must be true or false.');
  return {
    models,
    rpm: raw.rpm == null ? null : intInRange(raw.rpm, 1, MAX_RPM, 'Requests per minute'),
    tokenCap: raw.tokenCap == null ? null : intInRange(raw.tokenCap, 1, MAX_TOKEN_CAP, 'Token cap'),
    refuseUncounted: raw.refuseUncounted !== false,
  };
}

/**
 * True if `next` lets the key do more than `old`. Models rank None ([]) < Selected < All (null): any
 * step up, or adding an ID to a Selected list, loosens; All -> Selected, Selected -> None and removing
 * IDs tighten. Also raising or removing rpm / tokenCap, or turning refuseUncounted off. Adding a limit, or
 * anything else, is tightening (D6): only loosening needs the passphrase. Auto-renew counts too:
 * enabling it, a later maximum or a wider window loosen; turning it off or shrinking it tightens.
 */
export function isLoosening(old: Limits, next: Limits, oldAutoRenew: AutoRenew | null = null, nextAutoRenew: AutoRenew | null = oldAutoRenew): boolean {
  if (autoRenewLoosening(oldAutoRenew, nextAutoRenew)) return true;
  if (old.models !== null && (next.models === null || next.models.some((m) => !old.models!.includes(m)))) return true;
  for (const k of ['rpm', 'tokenCap'] as const) {
    if (old[k] !== null && (next[k] === null || next[k]! > old[k]!)) return true;
  }
  return old.refuseUncounted && !next.refuseUncounted;
}

export const MAX_RENEW_WINDOW_S = 24 * 3600;
export const MIN_RENEW_WINDOW_S = 60;
export const MAX_LIFETIME_MS = 365 * 24 * 3600 * 1000;

/**
 * Validates auto-renew input. Shape: { windowSeconds: number | "10m", maxLifetime: "8h" } (relative to
 * now) or { windowSeconds, maxExpiresAt: ms }, exactly one of the two. null/undefined = off.
 * Both parts are required together. `current` lets an unchanged value pass untouched.
 */
export function normalizeAutoRenew(
  input: unknown,
  ctx: { ttlSeconds: number; expiresAt: number; now: number; current?: AutoRenew | null },
): AutoRenew | null {
  if (input == null) return null;
  if (typeof input !== 'object' || Array.isArray(input)) throw new Error('autoRenew must be an object with windowSeconds and maxLifetime.');
  const raw = input as Record<string, unknown>;
  if (raw.windowSeconds == null || (raw.maxLifetime == null && raw.maxExpiresAt == null)) {
    throw new Error('Auto-renew needs both a renew window and a maximum lifetime. A window without a maximum is not allowed.');
  }
  if (raw.maxLifetime != null && raw.maxExpiresAt != null) throw new Error('Give either maxLifetime or maxExpiresAt, not both.');
  const windowSeconds = typeof raw.windowSeconds === 'string' ? parseTtl(raw.windowSeconds) : raw.windowSeconds;
  const maxExpiresAt = raw.maxLifetime != null
    ? ctx.now + parseTtl(String(raw.maxLifetime)) * 1000
    : raw.maxExpiresAt;
  if (typeof windowSeconds !== 'number' || !Number.isInteger(windowSeconds)) throw new Error('The renew window must be a whole number of seconds.');
  if (typeof maxExpiresAt !== 'number' || !Number.isInteger(maxExpiresAt)) throw new Error('maxExpiresAt must be a time in milliseconds.');
  const cur = ctx.current;
  if (cur && cur.windowSeconds === windowSeconds && cur.maxExpiresAt === maxExpiresAt) return cur;
  if (windowSeconds < MIN_RENEW_WINDOW_S || windowSeconds > MAX_RENEW_WINDOW_S) {
    throw new Error('The renew window must be from 1 minute to 24 hours.');
  }
  if (windowSeconds >= ctx.ttlSeconds) throw new Error('The renew window must be shorter than the key\'s TTL.');
  if (maxExpiresAt <= ctx.expiresAt) throw new Error('The maximum lifetime must end after the key\'s current expiry.');
  if (maxExpiresAt > ctx.now + MAX_LIFETIME_MS) throw new Error('The maximum lifetime can be at most 365 days.');
  return { windowSeconds, maxExpiresAt };
}

/** True if auto-renew changes from `old` to `next` give the key more reach: turning it on, a later maximum, or a wider window. */
function autoRenewLoosening(old: AutoRenew | null, next: AutoRenew | null): boolean {
  if (!next) return false;
  if (!old) return true;
  return next.maxExpiresAt > old.maxExpiresAt || next.windowSeconds > old.windowSeconds;
}

/** Replaces auto-renew on a proxy (null turns it off) and re-signs. The caller decides whether it needs the passphrase. */
export function setAutoRenew(id: string, input: unknown): Proxy {
  const existing = getProxy(id);
  if (!existing) throw new Error(`No proxy with id "${id}".`);
  const ar = normalizeAutoRenew(input, { ttlSeconds: existing.ttlSeconds, expiresAt: existing.expiresAt, now: Date.now(), current: existing.autoRenew });
  open().prepare('UPDATE proxies SET renew_window_s = ?, max_expires_at = ? WHERE id = ?').run(ar?.windowSeconds ?? null, ar?.maxExpiresAt ?? null, id);
  resignProxy(id);
  return getProxy(id)!;
}

/**
 * Proxy-side auto-renew (D10). Called only once a request has really been forwarded upstream.
 * Reads and verifies the row itself, so a stale in-memory Proxy or an edited row can't renew.
 * Never renews an expired key, one past its window, one at its token cap, or past the maximum.
 * Returns the new expiry, or null if nothing changed. Logs each renewal.
 */
/**
 * `asOf` is when the request that used the key started: the window and expiry are judged then, so a
 * long response that ends after the old expiry still counts as use inside the window. `usedTokens`
 * must already include that request, so the request that reaches the cap never renews (D10 (a)).
 */
export function renewIfDue(id: string, usedTokens: number, now = Date.now(), asOf = now): number | null {
  const row = open().prepare('SELECT * FROM proxies WHERE id = ?').get(id) as Record<string, any> | undefined;
  if (!row || !isUnlocked() || !verifySignature(proxySigData(row), row.sig) || isVersionRolledBack(row)) return null;
  if (row.renew_window_s == null || row.max_expires_at == null) return null;
  if (row.revoked_at !== null || row.expires_at <= asOf) return null;
  if (row.token_cap != null && usedTokens >= row.token_cap) return null;
  if (row.expires_at - asOf > row.renew_window_s * 1000) return null;
  const to = Math.min(now + row.ttl_seconds * 1000, row.max_expires_at);
  if (to <= row.expires_at) return null;
  open().prepare('UPDATE proxies SET expires_at = ? WHERE id = ?').run(to, id);
  resignProxy(id);
  logRequest({ proxyId: id, at: now, status: 200, durationMs: 0, event: 'renewed', renewedTo: to });
  return to;
}

/** Replaces a proxy's limits (full value, not a patch) and re-signs. The caller decides whether it needs the passphrase. */
export function setLimits(id: string, input: Partial<Limits>): Proxy {
  if (!getProxy(id)) throw new Error(`No proxy with id "${id}".`);
  const limits = normalizeLimits(input);
  open()
    .prepare('UPDATE proxies SET allowed_models = ?, rpm = ?, token_cap = ?, refuse_uncounted = ? WHERE id = ?')
    .run(limits.models ? JSON.stringify(limits.models) : null, limits.rpm, limits.tokenCap, limits.refuseUncounted ? 1 : 0, id);
  resignProxy(id);
  ensureUsageRow(id);
  return getProxy(id)!;
}

// ---- Usage totals (signed) ----

/**
 * Strict read for enforcement: ok is false if the vault is locked or the stored totals don't match
 * their signature. Rotating a proxy does not reset usage: the budget belongs to the proxy, not the token.
 */
export function getUsage(proxyId: string): UsageTotals {
  const row = open().prepare('SELECT * FROM proxy_usage WHERE proxy_id = ?').get(proxyId) as Record<string, any> | undefined;
  const proxy = open().prepare('SELECT token_cap FROM proxies WHERE id = ?').get(proxyId) as Record<string, any> | undefined;
  const zero = { requests: 0, tokensIn: 0, tokensOut: 0, uncounted: 0, lastUsedAt: null };
  if (!row) return { ...zero, ok: isUnlocked() && !!proxy && proxy.token_cap == null };
  return {
    requests: row.requests, tokensIn: row.tokens_in, tokensOut: row.tokens_out, uncounted: row.uncounted, lastUsedAt: row.last_used_at,
    ok: isUnlocked() && verifySignature(usageSigData(row), row.sig),
  };
}

/**
 * Adds one request to the totals and re-signs, in one transaction. A row whose signature is
 * already bad is left alone (re-signing would launder the edit) and ok:false is returned.
 */
export function recordUsage(
  proxyId: string,
  input: { tokensIn?: number; tokensOut?: number; counted: boolean; at: number },
): UsageTotals {
  const d = open();
  d.exec('BEGIN IMMEDIATE');
  try {
    if (!d.prepare('SELECT 1 FROM proxies WHERE id = ?').get(proxyId)) throw new Error(`No proxy with id "${proxyId}".`);
    const existing = d.prepare('SELECT * FROM proxy_usage WHERE proxy_id = ?').get(proxyId) as Record<string, any> | undefined;
    if (existing && !verifySignature(usageSigData(existing), existing.sig)) {
      d.exec('ROLLBACK');
      return getUsage(proxyId);
    }
    const nat = (n: unknown) => (typeof n === 'number' && Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);
    const tin = input.counted ? nat(input.tokensIn) : 0;
    const tout = input.counted ? nat(input.tokensOut) : 0;
    d.prepare('INSERT OR IGNORE INTO proxy_usage (proxy_id) VALUES (?)').run(proxyId);
    d.prepare(
      `UPDATE proxy_usage SET requests = requests + 1, tokens_in = tokens_in + ?, tokens_out = tokens_out + ?,
       uncounted = uncounted + ?, last_used_at = ? WHERE proxy_id = ?`,
    ).run(tin, tout, input.counted ? 0 : 1, input.at, proxyId);
    resignUsage(proxyId);
    d.exec('COMMIT');
  } catch (err) {
    try { d.exec('ROLLBACK'); } catch { /* already rolled back */ }
    throw err;
  }
  return getUsage(proxyId);
}

// ---- Request log (informational, unsigned, metadata only) ----

// Forwarded rows (and renewal events) and refused rows are kept apart, so a flood of refused
// requests can't push out the record of what was actually sent upstream.
const LOG_MAX_ROWS = 500;
const LOG_MAX_REFUSED_ROWS = 200;
const LOG_MAX_AGE_MS = 30 * 24 * 3600 * 1000;

/** Never pass prompt or response content here: only these fields are stored. */
export function logRequest(entry: {
  proxyId: string;
  at: number;
  model?: string | null;
  status: number;
  tokensIn?: number | null;
  tokensOut?: number | null;
  durationMs: number;
  refusedReason?: string | null;
  event?: string | null;
  renewedTo?: number | null;
}): void {
  const d = open();
  d.prepare('INSERT INTO requests (proxy_id, at, model, status, tokens_in, tokens_out, duration_ms, refused_reason, event, renewed_to) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(entry.proxyId, entry.at, entry.model ? entry.model.slice(0, 200) : null, entry.status,
      entry.tokensIn ?? null, entry.tokensOut ?? null, Math.max(0, Math.round(entry.durationMs)), entry.refusedReason ?? null,
      entry.event ?? null, entry.renewedTo ?? null);
  d.prepare('DELETE FROM requests WHERE proxy_id = ? AND at < ?').run(entry.proxyId, Date.now() - LOG_MAX_AGE_MS);
  d.prepare('DELETE FROM requests WHERE proxy_id = ? AND refused_reason IS NULL AND id NOT IN (SELECT id FROM requests WHERE proxy_id = ? AND refused_reason IS NULL ORDER BY id DESC LIMIT ?)')
    .run(entry.proxyId, entry.proxyId, LOG_MAX_ROWS);
  d.prepare('DELETE FROM requests WHERE proxy_id = ? AND refused_reason IS NOT NULL AND id NOT IN (SELECT id FROM requests WHERE proxy_id = ? AND refused_reason IS NOT NULL ORDER BY id DESC LIMIT ?)')
    .run(entry.proxyId, entry.proxyId, LOG_MAX_REFUSED_ROWS);
}

/** Newest first. */
export function recentRequests(proxyId: string, limit = 20): RequestLogEntry[] {
  const n = Math.min(Math.max(Math.floor(limit) || 20, 1), 100);
  return open().prepare('SELECT * FROM requests WHERE proxy_id = ? ORDER BY id DESC LIMIT ?').all(proxyId, n).map((r: any) => ({
    id: r.id, proxyId: r.proxy_id, at: r.at, model: r.model, status: r.status,
    tokensIn: r.tokens_in, tokensOut: r.tokens_out, durationMs: r.duration_ms, refusedReason: r.refused_reason ?? null,
    event: r.event ?? null, renewedTo: r.renewed_to ?? null,
  }));
}

/** Cross-proxy log page, newest first. Keyset by id (`before`), so rows arriving meanwhile never shift a page. */
export function requestsPage(opts: { proxyId?: string; status?: 'ok' | 'refused'; before?: number; limit?: number }): { requests: (RequestLogEntry & { proxyLabel: string | null })[]; nextBefore: number | null } {
  const n = Math.min(Math.max(Math.floor(opts.limit ?? 50) || 50, 1), 200);
  const where: string[] = [];
  const args: (string | number)[] = [];
  if (opts.proxyId !== undefined) { where.push('r.proxy_id = ?'); args.push(opts.proxyId); }
  if (opts.status === 'refused') where.push('r.refused_reason IS NOT NULL');
  if (opts.status === 'ok') where.push('r.refused_reason IS NULL');
  if (opts.before !== undefined) { where.push('r.id < ?'); args.push(opts.before); }
  const sql = `SELECT r.*, p.label AS proxy_label FROM requests r JOIN proxies p ON p.id = r.proxy_id ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY r.id DESC LIMIT ?`;
  // One extra row tells whether another page exists without a second query.
  const rows = open().prepare(sql).all(...args, n + 1) as any[];
  const page = rows.slice(0, n);
  return {
    requests: page.map((r) => ({
      id: r.id, proxyId: r.proxy_id, proxyLabel: r.proxy_label ?? null, at: r.at, model: r.model, status: r.status,
      tokensIn: r.tokens_in, tokensOut: r.tokens_out, durationMs: r.duration_ms, refusedReason: r.refused_reason ?? null,
      event: r.event ?? null, renewedTo: r.renewed_to ?? null,
    })),
    nextBefore: rows.length > n ? page[page.length - 1].id : null,
  };
}

// ---- Provider usage hints ----

/** UX hints (warn when a token cap is set on a provider known not to report usage). Unsigned on purpose: enforcement must not trust them. */
export function setUsageReporting(credentialId: string, flags: { usage?: UsageFlag; streamUsage?: StreamUsageFlag }): void {
  if (flags.usage !== undefined && !['reports', 'missing'].includes(flags.usage)) throw new Error('Invalid usage flag.');
  if (flags.streamUsage !== undefined && !['reports', 'missing', 'rejects_option'].includes(flags.streamUsage)) throw new Error('Invalid stream usage flag.');
  if (flags.usage !== undefined) open().prepare('UPDATE credentials SET usage_reporting = ? WHERE id = ?').run(flags.usage, credentialId);
  if (flags.streamUsage !== undefined) open().prepare('UPDATE credentials SET stream_usage = ? WHERE id = ?').run(flags.streamUsage, credentialId);
}

// ---- Notification settings (signed) ----

export type NotifySettingsRead =
  | { state: 'ok'; disabled: string[] }
  | { state: 'missing' } // never changed: everything is on
  | { state: 'tampered' } // fails its signature: callers treat everything as on
  | { state: 'unverified' }; // locked, so the signature cannot be checked

/**
 * Reads the list of switched-off notification types. Never creates the database: after a reset
 * (or on a fresh install) there may be none, and that simply means "all on".
 */
export function readNotificationSettings(): NotifySettingsRead {
  if (!fs.existsSync(config().dbPath)) return { state: 'missing' };
  const row = open().prepare('SELECT * FROM notification_settings WHERE id = 1').get() as Record<string, any> | undefined;
  if (!row) return { state: 'missing' };
  if (!isUnlocked()) return { state: 'unverified' };
  if (!verifySignature(notifySigData(String(row.disabled)), row.sig ?? null)) return { state: 'tampered' };
  return { state: 'ok', disabled: String(row.disabled) === '' ? [] : String(row.disabled).split(',') };
}

/** Replaces the switched-off list and re-signs. Writing over a tampered row is fine: it only ever held "off" switches, and a bad one already counts as all on. */
export function writeNotificationSettings(disabled: string[]): void {
  const list = [...new Set(disabled)].sort().join(',');
  open().prepare('INSERT INTO notification_settings (id, disabled) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET disabled = excluded.disabled').run(list);
  resignNotifySettings();
}

// ---- Events "last seen" marker (signed) ----

export type SeenRead =
  | { state: 'ok'; seq: number; hash: string }
  | { state: 'missing' } // never marked: everything counts as new
  | { state: 'tampered' } // fails its signature: treated as no marker
  | { state: 'unverified' }; // locked, so the signature cannot be checked

/** Never creates the database (a fresh install or a reset has none, which means no marker). */
export function readEventsSeen(): SeenRead {
  if (!fs.existsSync(config().dbPath)) return { state: 'missing' };
  const row = open().prepare('SELECT * FROM event_settings WHERE id = 1').get() as Record<string, any> | undefined;
  if (!row) return { state: 'missing' };
  if (!isUnlocked()) return { state: 'unverified' };
  if (!Number.isInteger(row.seen_seq) || !verifySignature(seenSigData(row.seen_seq, row.seen_hash), row.sig ?? null)) return { state: 'tampered' };
  return { state: 'ok', seq: row.seen_seq, hash: row.seen_hash };
}

/** Sets the marker (the entry's seq and hash, so a rewritten or cut-back log invalidates it) and re-signs. Writing over a tampered row is fine: it only ever hid "new" counts, and a bad one already counts as none. */
export function writeEventsSeen(seq: number, hash: string): void {
  open().prepare('INSERT INTO event_settings (id, seen_seq, seen_hash) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET seen_seq = excluded.seen_seq, seen_hash = excluded.seen_hash').run(seq, hash);
  resignEventSettings();
}
