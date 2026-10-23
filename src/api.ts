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
  type IssuedProxy,
} from './store.ts';
import { humanRequired } from './human.ts';
import { isRollbackFlagged } from './metering.ts';
import { ensureModels, forceRefreshModels } from './models.ts';
import {
  AuthRequiredError, SESSION_COOKIE, SIGN_IN_STEP, TooManyAttemptsError, changePassphrase, createSession, endSession, lock, publicStatus,
  requireAuth, sessionIdFromCookie, sessionState, setUp, setupTokenMatches, signIn, touchSession, unlock,
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
function auth(body: Record<string, any>): void {
  requireAuth(typeof body.passphrase === 'string' && body.passphrase ? body.passphrase : undefined);
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
    signIn(String(body.passphrase ?? ''));
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
    setUp(passphrase);
    return json(res, 201, { ok: true }, sessionCookie(createSession()));
  }

  if (method === 'POST' && path === '/api/unlock') {
    const body = await readJson(req, ['passphrase']);
    unlock(String(body.passphrase ?? ''));
    return json(res, 200, { session: sessionState() }, sessionCookie(createSession()));
  }

  // Carries its own passphrases, like unlock: never the shared passphrase-retry flow, and never the grace period.
  if (method === 'POST' && path === '/api/passphrase') {
    const body = await readJson(req, ['current', 'next']);
    if (typeof body.current !== 'string' || typeof body.next !== 'string' || !body.current || !body.next) {
      throw new HttpError(400, 'Send the current and the new passphrase.');
    }
    if (vaultExists() && !isUnlocked()) throw new HttpError(409, 'Wickey is locked. Unlock it with your passphrase first.');
    changePassphrase(body.current, body.next);
    return json(res, 200, {
      session: sessionState(),
      message: 'Passphrase changed. Minting is locked: the next key you mint asks for the new passphrase. An old copy of vault.json (a backup, say) still opens with the old passphrase.',
    });
  }

  if (method === 'POST' && path === '/api/lock') {
    lock();
    return json(res, 200, { session: sessionState() });
  }

  if (method === 'POST' && path === '/api/env') {
    const body = await readJson(req, ['credential', 'label', 'ttl', 'limits', 'autoRenew', 'passphrase']);
    const label = String(body.label ?? '').trim();
    const credential = String(body.credential ?? '').trim();
    if (!label || !credential) throw new HttpError(400, 'label and credential are required.');
    const limits = body.limits == null ? undefined : normalizeLimits(body.limits);
    // Every run mints: a key is never handed out twice, so nothing reusable sits in the database.
    auth(body);
    const result = mintEnvProxy({ label, credential, ttlSeconds: ttlFrom(body.ttl, DEFAULT_TTL_SECONDS)!, limits, autoRenew: body.autoRenew });
    return json(res, 200, issuedBody(req, result));
  }

  if (method === 'POST' && path === '/api/credentials') {
    const body = await readJson(req, ['name', 'provider', 'apiKey', 'baseUrl', 'authStyle', 'passphrase']);
    const name = String(body.name ?? '').trim();
    if (!isProvider(String(body.provider))) throw new HttpError(400, 'Unknown provider.');
    if (body.authStyle && body.authStyle !== 'bearer' && body.authStyle !== 'x-api-key') throw new HttpError(400, 'Invalid auth style.');
    auth(body);
    const credential = addCredential({
      name,
      provider: body.provider,
      apiKey: String(body.apiKey ?? '').trim(),
      baseUrl: body.baseUrl ? String(body.baseUrl).trim() : undefined,
      authStyle: (body.authStyle || undefined) as AuthStyle | undefined,
    });
    return json(res, 201, { credential: withScope(credential) });
  }

  // Both modes need auth: even a dry run tells the caller whether a given key is already stored.
  if (method === 'POST' && path === '/api/credentials/import') {
    const body = await readJson(req, ['entries', 'dryRun', 'passphrase']);
    auth(body);
    if (!Array.isArray(body.entries) || !body.entries.length) throw new HttpError(400, 'entries must be a non-empty list.');
    if (body.entries.length > MAX_IMPORT_ENTRIES) throw new HttpError(400, `Import at most ${MAX_IMPORT_ENTRIES} credentials at a time.`);
    if (typeof body.dryRun !== 'boolean') throw new HttpError(400, 'dryRun must be true or false.');
    return json(res, 200, { dryRun: body.dryRun, results: importCredentials(body.entries, body.dryRun) });
  }

  if (method === 'PATCH' && (m = /^\/api\/credentials\/([^/]+)$/.exec(path))) {
    const body = await readJson(req, ['name', 'baseUrl', 'authStyle', 'apiKey', 'passphrase']);
    const str = (v: unknown) => (v === undefined || v === null ? undefined : String(v).trim());
    const apiKey = str(body.apiKey);
    // Editing can point a real key at a different server, so it needs the same gate as minting.
    auth(body);
    const credential = updateCredential(decodeURIComponent(m[1]), {
      name: str(body.name),
      baseUrl: str(body.baseUrl),
      authStyle: str(body.authStyle) as AuthStyle | undefined,
      // A blank key field means "keep the current key".
      apiKey: apiKey ? apiKey : undefined,
    });
    return json(res, 200, { credential: withScope(credential) });
  }

  if (method === 'DELETE' && (m = /^\/api\/credentials\/([^/]+)$/.exec(path))) {
    return json(res, 200, { credential: withScope(removeCredential(decodeURIComponent(m[1]))) });
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
    auth(body);
    const issued = issueProxy({
      credential: String(body.credential ?? ''),
      ttlSeconds: ttlFrom(body.ttl, DEFAULT_TTL_SECONDS)!,
      label: body.label ? String(body.label).trim() || undefined : undefined,
      limits: body.limits,
      autoRenew: body.autoRenew,
    });
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
    if (isLoosening(existing.limits, next, existing.autoRenew, nextAutoRenew)) auth(body);
    if (body.limits != null) setLimits(existing.id, next);
    return json(res, 200, { proxy: editsAutoRenew ? setAutoRenew(existing.id, nextAutoRenew) : getProxy(existing.id) });
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
    auth(body);
    const proxy = renewProxy(m[1], ttlFrom(body.ttl, undefined));
    // The key itself is unchanged and not stored, so there is nothing to show.
    return json(res, 200, { proxy, baseUrl: `${proxyOrigin(req)}/p/${proxy.id}` });
  }

  if (method === 'POST' && (m = /^\/api\/proxies\/([a-f0-9]+)\/rotate$/.exec(path))) {
    const body = await readJson(req, ['ttl', 'passphrase']);
    auth(body);
    return json(res, 200, issuedBody(req, rotateProxy(m[1], ttlFrom(body.ttl, undefined))));
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
