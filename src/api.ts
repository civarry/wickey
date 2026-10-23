import { BRAND, envVar } from './brand.ts';
import { classifyBaseUrl } from './netguard.ts';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import type http from 'node:http';
import { MAX_IMPORT_ENTRIES, importCredentials } from './credimport.ts';
import { PROVIDERS, isProvider, type AuthStyle } from './providers.ts';
import {
  addCredential,
  deleteProxy,
  expireProxy,
  getCredential,
  getProxy,
  isLoosening,
  issueProxy,
  listCredentials,
  listProxies,
  mintEnvProxy,
  normalizeAutoRenew,
  normalizeLimits,
  recentRequests,
  requestsPage,
  removeCredential,
  renewProxy,
  rotateProxy,
  setAutoRenew,
  setLimits,
  updateCredential,
  type AutoRenew,
  type IssuedProxy,
  type Limits,
  type Proxy,
} from './store.ts';
import { VIA_HEADER, logEvent, viaFromHeader, type Via } from './audit.ts';
import { entryHash, listEvents, type EventData } from './events.ts';
import { readEventsSeen, writeEventsSeen, type SeenRead } from './store.ts';
import { humanRequired } from './human.ts';
import { isLockedOn, isNotifyType, notificationSettings, setNotificationEnabled } from './notify.ts';
import { isRollbackFlagged } from './metering.ts';
import { ensureModels, forceRefreshModels } from './models.ts';
import {
  AuthRequiredError, SESSION_COOKIE, SIGN_IN_STEP, TooManyAttemptsError, changePassphrase, createSession, endSession, lock, publicStatus,
  confirmPassphrase, requireAuth, sessionIdFromCookie, sessionState, setUp, setupTokenMatches, signIn, touchSession, unlock,
} from './session.ts';
import { DEFAULT_TTL_SECONDS, parseTtl } from './ttl.ts';
import { MIN_PASSPHRASE, WrongPassphraseError, isUnlocked, vaultExists } from './vault.ts';

// The dashboard is a Vite build (web/dist). Read at request time, so rebuilding needs no restart.
// WICKEY_WEB_DIR lets tests point at a stand-in build.
/** `baseUrlScope` lets the dashboard flag private/loopback destinations; null for a saved URL that is no longer allowed. */
function withScope<T extends { baseUrl: string }>(credential: T): T & { baseUrlScope: string | null } {
  const verdict = classifyBaseUrl(credential.baseUrl);
  return { ...credential, baseUrlScope: verdict.ok ? verdict.scope : null };
}

function webDir(): string {
  return envVar('WEB_DIR') ?? fileURLToPath(new URL('../web/dist/', import.meta.url));
}

// Scripts and styles only from this server: no inline code, no eval, nothing external.
const CSP = [
  "default-src 'self'", "script-src 'self'", "style-src 'self'", "font-src 'self'", "img-src 'self' data:",
  "connect-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'",
].join('; ');

const ASSET_TYPES: Record<string, string> = {
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

/**
 * Serves index.html at / and flat files from /assets/. The name must be a plain file name with a
 * known extension, so `..`, encoded slashes and subpaths can never reach outside the build.
 */
function serveDashboard(req: http.IncomingMessage, res: http.ServerResponse, path: string): boolean {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false;
  const asset = /^\/assets\/([A-Za-z0-9_-][A-Za-z0-9._-]*)$/.exec(path);
  if (path !== '/' && !asset && !path.startsWith('/assets/')) return false;
  if (!isTrusted(req, false)) {
    json(res, 403, { error: { message: 'Open the dashboard at http://127.0.0.1 or http://localhost.' } });
    return true;
  }
  const security = { 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY' };

  if (path === '/') {
    let html: Buffer;
    try {
      html = fs.readFileSync(`${webDir()}/index.html`);
    } catch {
      res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8', ...security });
      res.end('The dashboard has not been built yet. Run `npm run build` in the Wickey folder, then reload.\n');
      return true;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': CSP, ...security });
    res.end(req.method === 'HEAD' ? undefined : html);
    return true;
  }

  const type = asset && ASSET_TYPES[asset[1].slice(asset[1].lastIndexOf('.'))];
  let body: Buffer | null = null;
  if (asset && type && !asset[1].includes('..')) {
    try {
      body = fs.readFileSync(`${webDir()}/assets/${asset[1]}`);
    } catch {
      body = null;
    }
  }
  if (!body) {
    json(res, 404, { error: { message: 'Not found.' } });
    return true;
  }
  // Vite puts a content hash in every asset name, so a name never changes meaning.
  res.writeHead(200, { 'content-type': type!, 'cache-control': 'public, max-age=31536000, immutable', ...security });
  res.end(req.method === 'HEAD' ? undefined : body);
  return true;
}
const MAX_BODY = 64 * 1024;

/** Minting or redirecting a real key needs the passphrase in the body, or the grace period. */
function auth(body: Record<string, any>, how: Via): void {
  requireAuth(typeof body.passphrase === 'string' && body.passphrase ? body.passphrase : undefined, how);
}

class HttpError extends Error {
  status: number;
  humanRequired: boolean;
  constructor(status: number, message: string, humanRequired = false) {
    super(message);
    this.status = status;
    this.humanRequired = humanRequired;
  }
}

function json(res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}

/**
 * The origin clients should use for /p/ URLs: always 127.0.0.1, never the Host the dashboard was
 * opened with. The server listens on IPv4 only, and localhost can resolve to ::1 first.
 */
function proxyOrigin(req: http.IncomingMessage): string {
  return `http://127.0.0.1:${req.socket.localPort}`;
}

/**
 * Any web page the user has open can send requests to 127.0.0.1, so the management API
 * only answers requests that are provably from the dashboard itself:
 * - Host must be the loopback address, which defeats DNS rebinding.
 * - Origin, if sent, must be that same address, which blocks cross-site form posts.
 * - A custom header is required, which forces a CORS preflight that this server never approves.
 */
function isTrusted(req: http.IncomingMessage, requireHeader: boolean): boolean {
  const port = req.socket.localPort;
  const allowed = [`127.0.0.1:${port}`, `localhost:${port}`];
  if (!allowed.includes(req.headers.host ?? '')) return false;
  const origin = req.headers.origin;
  if (origin && !allowed.some((h) => origin === `http://${h}`)) return false;
  if (requireHeader && req.headers[BRAND.requestHeader] !== '1') return false;
  return true;
}

/**
 * Parses the body and refuses fields the route doesn't read. A misspelled field would otherwise be
 * dropped silently and the request would run with a default (a 60 s key instead of the asked TTL).
 */
async function readJson(req: http.IncomingMessage, fields: readonly string[]): Promise<Record<string, any>> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new HttpError(413, 'Request body too large.');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  let body: unknown;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Body must be JSON.');
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new HttpError(400, 'Body must be a JSON object.');
  const unknown = Object.keys(body).filter((k) => !fields.includes(k));
  if (unknown.length) {
    throw new HttpError(400, `Unknown field${unknown.length > 1 ? 's' : ''} ${unknown.map((k) => `"${k}"`).join(', ')}. This request takes: ${fields.join(', ')}.`);
  }
  return body as Record<string, any>;
}

function ttlFrom(value: unknown, fallback: number | undefined): number | undefined {
  if (value === undefined || value === null || value === '') return fallback;
  return parseTtl(String(value));
}

// HttpOnly keeps it from page scripts, SameSite=Strict from cross-site requests. No Secure flag:
// the dashboard is plain http on loopback, where browsers would drop a Secure cookie.
function sessionCookie(id: string): Record<string, string> {
  return { 'set-cookie': `${SESSION_COOKIE}=${id}; HttpOnly; SameSite=Strict; Path=/` };
}

/**
 * Routes that work without a session: they either prove the passphrase or reveal only the sign-in state.
 * POST /api/lock is the one exception that does neither: it works without a session because lock()
 * is harmless (ends the grace period, clears sessions; the vault stays unlocked and proxies keep
 * forwarding), so anyone may end the window early. If lock() ever also locks the vault or stops
 * proxy traffic, remove it from this set so it needs a session again.
 */
const PUBLIC_ROUTES = new Set(['GET /api/session-status', 'POST /api/setup', 'POST /api/unlock', 'POST /api/signin', 'POST /api/lock']);

const via = (req: http.IncomingMessage): Via => viaFromHeader(req.headers[VIA_HEADER]);

/** Limits as short text for the event log (ids and numbers only). */
function limitsText(l: Limits, ar: AutoRenew | null): string {
  const models = l.models === null ? 'all' : l.models.length === 0 ? 'none' : `${l.models.length} selected`;
  return `models ${models}, rpm ${l.rpm ?? 'none'}, token cap ${l.tokenCap ?? 'none'}, ${l.refuseUncounted ? 'refuse uncounted' : 'allow uncounted'}, auto-renew ${ar ? `${ar.windowSeconds}s window` : 'off'}`;
}

function baseUrlHost(baseUrl: string): string {
  try { return new URL(baseUrl).host; } catch { return ''; }
}

let seenTamperLogged = false;
/** The marker as a number. A row that fails its signature, or is missing, is no marker (0): an edit can never hide events. */
function seenMarker(): { seq: number; hash: string; state: SeenRead['state'] } {
  let r: SeenRead;
  try {
    r = readEventsSeen();
  } catch {
    return { seq: 0, hash: '', state: 'missing' };
  }
  if (r.state === 'tampered' && !seenTamperLogged) {
    seenTamperLogged = true;
    logEvent('tamper_detected', { what: 'last-seen marker' });
  }
  return { seq: r.state === 'ok' ? r.seq : 0, hash: r.state === 'ok' ? r.hash : '', state: r.state };
}

function credentialInfo(c: { name: string; provider: string; baseUrl: string }): EventData {
  return { name: c.name, provider: c.provider, baseUrlHost: baseUrlHost(c.baseUrl) };
}

function logAutoRenewOn(proxyId: string, ar: AutoRenew, how: Via): void {
  logEvent('auto_renew_enabled', { proxyId, via: how, window: ar.windowSeconds, maxLifetime: Math.max(0, Math.round((ar.maxExpiresAt - Date.now()) / 1000)) }, 'warn');
}

/** One `key_issued` per key minted (issue, env, rotate), plus `auto_renew_enabled` when it starts renewing. */
function logMint(proxy: Proxy, op: 'issue' | 'env' | 'rotate', how: Via, autoRenewWasOn = false): void {
  const l = proxy.limits;
  logEvent('key_issued', {
    proxyId: proxy.id, credential: proxy.credentialName, label: proxy.label, via: how, op,
    models: l.models === null ? 'all' : l.models.length === 0 ? 'none' : l.models.length,
    rpm: l.rpm, tokenCap: l.tokenCap, autoRenew: proxy.autoRenew !== null,
    unlimited: l.models === null && l.rpm === null && l.tokenCap === null,
  }, 'warn');
  if (proxy.autoRenew && !autoRenewWasOn) logAutoRenewOn(proxy.id, proxy.autoRenew, how);
}

function issuedBody(req: http.IncomingMessage, issued: IssuedProxy) {
  return { proxy: issued.proxy, token: issued.token, baseUrl: `${proxyOrigin(req)}/p/${issued.proxy.id}` };
}

async function route(req: http.IncomingMessage, res: http.ServerResponse, path: string): Promise<void> {
  const method = req.method ?? 'GET';
  let m: RegExpExecArray | null;

  const sessionId = sessionIdFromCookie(req.headers.cookie);
  const signedIn = touchSession(sessionId);
  if (!signedIn && !PUBLIC_ROUTES.has(`${method} ${path}`)) {
    throw new AuthRequiredError('session_required', SIGN_IN_STEP);
  }

  if (method === 'GET' && path === '/api/session-status') return json(res, 200, publicStatus(signedIn));

  if (method === 'POST' && path === '/api/signout') {
    endSession(sessionId);
    return json(res, 200, { ok: true }, { 'set-cookie': `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0` });
  }

  if (method === 'POST' && path === '/api/signin') {
    const body = await readJson(req, ['passphrase']);
    signIn(String(body.passphrase ?? ''), via(req));
    // A new session each time: a cookie that was sent along is never promoted.
    return json(res, 200, { session: sessionState() }, sessionCookie(createSession()));
  }

  if (method === 'GET' && path === '/api/state') {
    return json(res, 200, {
      credentials: listCredentials().map(withScope),
      // Cleaned-up proxies are included (cleanedAt set); the dashboard hides them unless asked.
      // In-memory D7 flag: the dashboard shows "Needs review" for it.
      proxies: listProxies({ includeCleaned: true }).map((p) => ({ ...p, rollbackFlagged: isRollbackFlagged(p.id) })),
      providers: PROVIDERS,
      defaultTtlSeconds: DEFAULT_TTL_SECONDS,
      proxyOrigin: proxyOrigin(req),
      session: sessionState(),
    });
  }

  if (method === 'POST' && path === '/api/setup') {
    const body = await readJson(req, ['passphrase', 'token']);
    if (vaultExists()) throw new HttpError(409, 'A passphrase is already set.');
    if (!setupTokenMatches(body.token)) throw new HttpError(403, humanRequired(`open the one-time setup link printed by \`${BRAND.command} start\`, or run \`${BRAND.command} setup\` in their own terminal`), true);
    const passphrase = String(body.passphrase ?? '');
    if (passphrase.length < MIN_PASSPHRASE) throw new HttpError(400, `Passphrase must be at least ${MIN_PASSPHRASE} characters.`);
    setUp(passphrase, 'setup_link');
    return json(res, 201, { ok: true }, sessionCookie(createSession()));
  }

  if (method === 'POST' && path === '/api/unlock') {
    const body = await readJson(req, ['passphrase']);
    unlock(String(body.passphrase ?? ''), via(req), true);
    return json(res, 200, { session: sessionState() }, sessionCookie(createSession()));
  }

  // Carries its own passphrases, like unlock: never the shared passphrase-retry flow, and never the grace period.
  if (method === 'POST' && path === '/api/passphrase') {
    const body = await readJson(req, ['current', 'next']);
    if (typeof body.current !== 'string' || typeof body.next !== 'string' || !body.current || !body.next) {
      throw new HttpError(400, 'Send the current and the new passphrase.');
    }
    if (vaultExists() && !isUnlocked()) throw new HttpError(409, 'Wickey is locked. Unlock it with your passphrase first.');
    changePassphrase(body.current, body.next, via(req));
    return json(res, 200, {
      session: sessionState(),
      message: 'Passphrase changed. Minting is locked: the next key you mint asks for the new passphrase. An old copy of vault.json (a backup, say) still opens with the old passphrase.',
    });
  }

  if (method === 'POST' && path === '/api/lock') {
    lock(via(req));
    return json(res, 200, { session: sessionState() });
  }

  if (method === 'POST' && path === '/api/env') {
    const body = await readJson(req, ['credential', 'label', 'ttl', 'limits', 'autoRenew', 'passphrase']);
    const label = String(body.label ?? '').trim();
    const credential = String(body.credential ?? '').trim();
    if (!label || !credential) throw new HttpError(400, 'label and credential are required.');
    const limits = body.limits == null ? undefined : normalizeLimits(body.limits);
    // Every run mints: a key is never handed out twice, so nothing reusable sits in the database.
    auth(body, via(req));
    const result = mintEnvProxy({ label, credential, ttlSeconds: ttlFrom(body.ttl, DEFAULT_TTL_SECONDS)!, limits, autoRenew: body.autoRenew });
    logMint(result.proxy, 'env', via(req));
    return json(res, 200, issuedBody(req, result));
  }

  if (method === 'POST' && path === '/api/credentials') {
    const body = await readJson(req, ['name', 'provider', 'apiKey', 'baseUrl', 'authStyle', 'passphrase']);
    const name = String(body.name ?? '').trim();
    if (!isProvider(String(body.provider))) throw new HttpError(400, 'Unknown provider.');
    if (body.authStyle && body.authStyle !== 'bearer' && body.authStyle !== 'x-api-key') throw new HttpError(400, 'Invalid auth style.');
    auth(body, via(req));
    const credential = addCredential({
      name,
      provider: body.provider,
      apiKey: String(body.apiKey ?? '').trim(),
      baseUrl: body.baseUrl ? String(body.baseUrl).trim() : undefined,
      authStyle: (body.authStyle || undefined) as AuthStyle | undefined,
    });
    logEvent('credential_added', { ...credentialInfo(credential), via: via(req) }, 'warn');
    return json(res, 201, { credential: withScope(credential) });
  }

  // Both modes need auth: even a dry run tells the caller whether a given key is already stored.
  if (method === 'POST' && path === '/api/credentials/import') {
    const body = await readJson(req, ['entries', 'dryRun', 'passphrase']);
    auth(body, via(req));
    if (!Array.isArray(body.entries) || !body.entries.length) throw new HttpError(400, 'entries must be a non-empty list.');
    if (body.entries.length > MAX_IMPORT_ENTRIES) throw new HttpError(400, `Import at most ${MAX_IMPORT_ENTRIES} credentials at a time.`);
    if (typeof body.dryRun !== 'boolean') throw new HttpError(400, 'dryRun must be true or false.');
    const results = importCredentials(body.entries, body.dryRun);
    const count = results.filter((r) => r.outcome === 'imported').length;
    if (count > 0) logEvent('credentials_imported', { count, via: via(req) }, 'warn');
    return json(res, 200, { dryRun: body.dryRun, results });
  }

  if (method === 'PATCH' && (m = /^\/api\/credentials\/([^/]+)$/.exec(path))) {
    const body = await readJson(req, ['name', 'baseUrl', 'authStyle', 'apiKey', 'passphrase']);
    const str = (v: unknown) => (v === undefined || v === null ? undefined : String(v).trim());
    const apiKey = str(body.apiKey);
    // Editing can point a real key at a different server, so it needs the same gate as minting.
    auth(body, via(req));
    const before = getCredential(decodeURIComponent(m[1]));
    const credential = updateCredential(decodeURIComponent(m[1]), {
      name: str(body.name),
      baseUrl: str(body.baseUrl),
      authStyle: str(body.authStyle) as AuthStyle | undefined,
      // A blank key field means "keep the current key".
      apiKey: apiKey ? apiKey : undefined,
    });
    if (before) {
      const fields = [
        ...(credential.name !== before.name ? ['name'] : []),
        ...(credential.baseUrl !== before.baseUrl ? ['baseUrl'] : []),
        ...(credential.authStyle !== before.authStyle ? ['authStyle'] : []),
        ...(apiKey ? ['apiKey'] : []),
      ];
      if (fields.length) {
        logEvent('credential_changed', { ...credentialInfo(credential), fields, keyReplaced: !!apiKey, baseUrlChanged: credential.baseUrl !== before.baseUrl, via: via(req) }, 'warn');
      }
    }
    return json(res, 200, { credential: withScope(credential) });
  }

  if (method === 'DELETE' && (m = /^\/api\/credentials\/([^/]+)$/.exec(path))) {
    const removed = removeCredential(decodeURIComponent(m[1]));
    logEvent('credential_removed', { ...credentialInfo(removed), via: via(req) }, 'warn');
    return json(res, 200, { credential: withScope(removed) });
  }

  // Listing models mints nothing and changes no row, so no requireAuth; it does use the real key, so the vault must be unlocked.
  if ((method === 'GET' || method === 'POST') && (m = /^\/api\/credentials\/([^/]+)\/models(\/refresh)?$/.exec(path)) && (method === 'GET') === !m[2]) {
    const credential = getCredential(decodeURIComponent(m[1]));
    if (!credential) throw new HttpError(404, `No credential named "${decodeURIComponent(m[1])}".`);
    if (!isUnlocked()) throw new HttpError(409, 'Wickey is locked. Unlock it with your passphrase first.');
    const forced = m[2] ? await forceRefreshModels(credential) : null;
    const entry = forced ? forced.entry : await ensureModels(credential);
    return json(res, 200, {
      models: entry.models ?? [], fetchedAt: entry.fetchedAt, unavailable: entry.unavailable, ...(entry.error ? { error: entry.error } : {}),
      ...(forced?.retryAfter ? { retryAfter: forced.retryAfter, message: `The list was refreshed a moment ago. Try again in ${forced.retryAfter} seconds.` } : {}),
    });
  }

  if (method === 'POST' && path === '/api/proxies') {
    const body = await readJson(req, ['credential', 'label', 'ttl', 'limits', 'autoRenew', 'passphrase']);
    auth(body, via(req));
    const issued = issueProxy({
      credential: String(body.credential ?? ''),
      ttlSeconds: ttlFrom(body.ttl, DEFAULT_TTL_SECONDS)!,
      label: body.label ? String(body.label).trim() || undefined : undefined,
      limits: body.limits,
      autoRenew: body.autoRenew,
    });
    logMint(issued.proxy, 'issue', via(req));
    return json(res, 201, issuedBody(req, issued));
  }

  if (method === 'PATCH' && (m = /^\/api\/proxies\/([a-f0-9]+)\/limits$/.exec(path))) {
    const body = await readJson(req, ['limits', 'autoRenew', 'passphrase']);
    const existing = getProxy(m[1]);
    if (!existing) throw new HttpError(404, `No proxy with id "${m[1]}".`);
    // autoRenew: absent = unchanged, null = turn off, object = set (see normalizeAutoRenew).
    const editsAutoRenew = body.autoRenew !== undefined;
    if (!editsAutoRenew && (body.limits == null || typeof body.limits !== 'object')) throw new HttpError(400, 'limits is required.');
    const next = body.limits == null ? existing.limits : normalizeLimits(body.limits);
    const nextAutoRenew = editsAutoRenew
      ? normalizeAutoRenew(body.autoRenew, { ttlSeconds: existing.ttlSeconds, expiresAt: existing.expiresAt, now: Date.now(), current: existing.autoRenew })
      : existing.autoRenew;
    // Tightening only takes access away, like expire; loosening (including enabling or raising auto-renew) is as sensitive as minting.
    const loosening = isLoosening(existing.limits, next, existing.autoRenew, nextAutoRenew);
    if (loosening) auth(body, via(req));
    if (body.limits != null) setLimits(existing.id, next);
    const updated = editsAutoRenew ? setAutoRenew(existing.id, nextAutoRenew) : getProxy(existing.id);
    const was = limitsText(existing.limits, existing.autoRenew);
    const now = limitsText(next, nextAutoRenew);
    if (was !== now || existing.autoRenew?.maxExpiresAt !== nextAutoRenew?.maxExpiresAt) {
      logEvent(loosening ? 'limits_loosened' : 'limits_tightened', { proxyId: existing.id, via: via(req), before: was, after: now }, 'warn');
    }
    if (!existing.autoRenew && nextAutoRenew) logAutoRenewOn(existing.id, nextAutoRenew, via(req));
    return json(res, 200, { proxy: updated });
  }

  if (method === 'GET' && path === '/api/notifications') return json(res, 200, notificationSettings());

  // Turning a type ON needs only the session. Turning one OFF needs the passphrase in the body even
  // during the grace period (like changing the passphrase): otherwise a program could silence the alerts before acting.
  if (method === 'PATCH' && path === '/api/notifications') {
    const body = await readJson(req, ['type', 'enabled', 'passphrase']);
    if (!isNotifyType(body.type)) throw new HttpError(400, 'type must be one of the notification types listed by GET /api/notifications.');
    if (typeof body.enabled !== 'boolean') throw new HttpError(400, 'enabled must be true or false.');
    if (!body.enabled) {
      if (isLockedOn(body.type)) throw new HttpError(400, `"${body.type}" notifications cannot be turned off.`);
      confirmPassphrase(typeof body.passphrase === 'string' ? body.passphrase : undefined, via(req));
    }
    setNotificationEnabled(body.type, body.enabled, via(req));
    return json(res, 200, notificationSettings());
  }

  // Security event log, newest first, with the integrity summary and the "last seen" marker. Session only: it never holds secrets.
  if (method === 'GET' && path === '/api/events') {
    const q = new URL(req.url ?? '', 'http://x').searchParams;
    const int = (name: string): number | undefined => {
      const v = q.get(name);
      if (v === null) return undefined;
      if (!/^\d{1,15}$/.test(v)) throw new HttpError(400, `${name} must be a whole number.`);
      return Number(v);
    };
    const limit = int('limit');
    if (limit !== undefined && (limit < 1 || limit > 200)) throw new HttpError(400, 'limit must be between 1 and 200.');
    const type = q.get('type') ?? undefined;
    if (type !== undefined && !/^[a-z][a-z0-9_]{0,63}$/.test(type)) throw new HttpError(400, 'type must be an event type such as "unlocked".');
    const mark = seenMarker();
    const page = listEvents({ before: int('before'), limit, type, seen: mark.state === 'ok' ? { seq: mark.seq, hash: mark.hash } : undefined });
    // 'mismatch': the marker is fine but the log under it is not (cut back or rewritten), so everything counts as new again.
    return json(res, 200, { ...page, seenState: page.seenMismatch ? 'mismatch' : mark.state });
  }

  // Moves the "last seen" marker. Only this route does: signing in never does, because the CLI signs
  // in on every command and would hide exactly what the person needs to see. It never moves backwards.
  if (method === 'POST' && path === '/api/events/seen') {
    const body = await readJson(req, ['seq']);
    const mark = seenMarker();
    const asSeen = (m: { seq: number; hash: string }) => ({ seq: m.seq, hash: m.hash });
    const page = listEvents({ limit: 1, seen: mark.state === 'ok' ? asSeen(mark) : undefined });
    const seq = body.seq as number;
    if (!Number.isInteger(body.seq) || seq < 0 || seq > page.head) {
      throw new HttpError(400, `seq must be a whole number from 0 to ${page.head}, the newest event. Reload the page and try again.`);
    }
    // Never backwards, unless the old marker is not usable (missing, edited, or the log changed under it).
    if (page.seen >= seq && mark.state === 'ok' && !page.seenMismatch) return json(res, 200, { seen: page.seen });
    writeEventsSeen(seq, entryHash(seq) ?? '');
    return json(res, 200, { seen: seq });
  }

  // Read-only metadata like the per-proxy log below, so no requireAuth.
  if (method === 'GET' && path === '/api/requests') {
    const q = new URL(req.url ?? '', 'http://x').searchParams;
    const status = q.get('status');
    if (status !== null && status !== 'ok' && status !== 'refused') throw new HttpError(400, 'status must be "ok" or "refused".');
    const proxyId = q.get('proxy');
    if (proxyId !== null && !getProxy(proxyId)) throw new HttpError(404, `No proxy with id "${proxyId}".`);
    const int = (name: string): number | undefined => {
      const v = q.get(name);
      if (v === null) return undefined;
      if (!/^\d{1,15}$/.test(v)) throw new HttpError(400, `${name} must be a whole number.`);
      return Number(v);
    };
    const limit = int('limit');
    if (limit === 0) throw new HttpError(400, 'limit must be at least 1.');
    return json(res, 200, requestsPage({ proxyId: proxyId ?? undefined, status: status ?? undefined, before: int('before'), limit }));
  }

  if (method === 'GET' && (m = /^\/api\/proxies\/([a-f0-9]+)\/requests$/.exec(path))) {
    if (!getProxy(m[1])) throw new HttpError(404, `No proxy with id "${m[1]}".`);
    const n = Number(new URL(req.url ?? '', 'http://x').searchParams.get('limit') ?? 20);
    return json(res, 200, { requests: recentRequests(m[1], Number.isFinite(n) ? n : 20) });
  }

  if (method === 'POST' && (m = /^\/api\/proxies\/([a-f0-9]+)\/renew$/.exec(path))) {
    const body = await readJson(req, ['ttl', 'passphrase']);
    auth(body, via(req));
    const proxy = renewProxy(m[1], ttlFrom(body.ttl, undefined));
    logEvent('key_renewed', { proxyId: proxy.id, via: via(req) }, 'warn');
    // The key itself is unchanged and not stored, so there is nothing to show.
    return json(res, 200, { proxy, baseUrl: `${proxyOrigin(req)}/p/${proxy.id}` });
  }

  if (method === 'POST' && (m = /^\/api\/proxies\/([a-f0-9]+)\/rotate$/.exec(path))) {
    const body = await readJson(req, ['ttl', 'passphrase']);
    auth(body, via(req));
    const rotated = rotateProxy(m[1], ttlFrom(body.ttl, undefined));
    logMint(rotated.proxy, 'rotate', via(req), true);
    return json(res, 200, issuedBody(req, rotated));
  }

  if (method === 'POST' && (m = /^\/api\/proxies\/([a-f0-9]+)\/expire$/.exec(path))) {
    return json(res, 200, { proxy: expireProxy(m[1]) });
  }

  if (method === 'DELETE' && (m = /^\/api\/proxies\/([a-f0-9]+)$/.exec(path))) {
    deleteProxy(m[1]);
    return json(res, 200, { ok: true });
  }

  throw new HttpError(404, 'Not found.');
}

/** Handles the dashboard page and /api/*. Returns false if the request belongs to someone else. */
export function handleManagement(req: http.IncomingMessage, res: http.ServerResponse): boolean {
  const path = (req.url ?? '/').split('?')[0];

  if (serveDashboard(req, res, path)) return true;

  if (!path.startsWith('/api/')) return false;
  if (!isTrusted(req, true)) {
    json(res, 403, { error: { message: 'Forbidden.' } });
    return true;
  }
  route(req, res, path).catch((err: Error) => {
    if (err instanceof AuthRequiredError) return json(res, 401, { error: { code: err.code, message: err.message, humanRequired: true } });
    if (err instanceof WrongPassphraseError) return json(res, 401, { error: { code: 'wrong_passphrase', message: err.message } });
    if (err instanceof TooManyAttemptsError) return json(res, 429, { error: { code: 'too_many_attempts', message: err.message } });
    const status = err instanceof HttpError ? err.status : 400;
    json(res, status, { error: { message: err.message, ...(err instanceof HttpError && err.humanRequired ? { humanRequired: true } : {}) } });
  });
  return true;
}
