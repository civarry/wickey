import { BRAND } from './brand.ts';
import { classifyBaseUrl, guardOptions, isBlockedError } from './netguard.ts';
import http from 'node:http';
import https from 'node:https';
import { handleManagement } from './api.ts';
import { checkModel, ensureModels } from './models.ts';
import { applyUpstreamAuth, upstreamUrl } from './providers.ts';
import {
  authorize, getCredential, getCredentialSecret, getUsage, logRequest, recordUsage, renewIfDue, setUsageReporting,
  type Credential, type Limits, type Proxy,
} from './store.ts';
import {
  MAX_INFLIGHT, ResponseMeter, SUPPORTED_ENCODINGS, checkHighWater, formatError, isGenerationPath, isRollbackFlagged, observeUsage,
  rateLimiter, reservationFor, reservations,
  type ErrorKind, type MeterResult, type RefusalCode,
} from './metering.ts';

// Hop-by-hop headers (RFC 9110 §7.6.1) plus the client's auth, which must never reach upstream.
const STRIP_REQUEST = ['host', 'connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'authorization', 'x-api-key'];
const STRIP_RESPONSE = ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'trailer'];

const MAX_BODY_BYTES = 10 * 1024 * 1024;
// Unlimited keys only peek at the request body to log the model; past this the model stays unknown.
const TAP_MAX_BYTES = 2 * 1024 * 1024;
// An upstream error that might be about stream_options is held back this long before deciding.
const HOLD_MAX_BYTES = 256 * 1024;
// A capped key's upstream request outlives a client that hung up, so the final usage is still seen.
// Past this the upstream is destroyed and the request is recorded uncounted.
export const DISCONNECT_GRACE_MS = 10 * 60 * 1000;

const ROUTE = /^\/p\/([a-f0-9]+)(\/[^?]*)?(\?.*)?$/;

// Node gives each resolved address only 250ms to connect before trying the next one. On a slow
// link (300-400ms to Cloudflare, with IPv6 unusable) every attempt can time out and the request
// fails outright, so allow each attempt more time.
const CONNECT_ATTEMPT_TIMEOUT_MS = 2000;

type NetError = Error & { code?: string; address?: string; errors?: NetError[] };

/** AggregateError (all addresses failed) has an empty message; report each attempt's code instead. */
function describeNetError(err: NetError): string {
  const parts = (err.errors?.length ? err.errors : [err]).map(
    (e) => `${e.code ?? (e.message || e.name)}${e.address ? ` (${e.address})` : ''}`,
  );
  return [...new Set(parts)].join(', ');
}

function sendError(res: http.ServerResponse, status: number, message: string): void {
  // Shape matches both OpenAI- and Anthropic-style error bodies closely enough for SDKs to surface the message.
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ type: 'error', error: { type: BRAND.errorType, message: `${BRAND.errorPrefix}${message}` } }));
}

/** Accepts the proxy token from either header, since OpenAI-style clients send Bearer and Anthropic SDKs send x-api-key. */
function presentedToken(req: http.IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (auth?.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim();
  const key = req.headers['x-api-key'];
  return typeof key === 'string' ? key.trim() : null;
}

export { upstreamUrl };

export function createProxyServer(): http.Server {
  return http.createServer((req, res) => {
    // Anything thrown while handling one request becomes a 500 for that request only; an escaped
    // exception would otherwise leave the client hanging or bring the whole proxy down.
    try {
      handle(req, res);
    } catch (err) {
      if (!res.headersSent) sendError(res, 500, (err as Error).message);
      else res.destroy();
    }
  });
}


interface Ctx {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  proxy: Proxy;
  credential: Credential;
  limits: Limits;
  limited: boolean;
  /** All-models key whose provider list is known: the model is checked against it (strict, like an allowlist). */
  allList: boolean;
  path: string;
  target: URL;
  headers: http.OutgoingHttpHeaders;
  started: number;
  model: string | null;
  anthropic: boolean;
  upstream: http.ClientRequest | null;
  clientClosed: boolean;
  upRes: http.IncomingMessage | null;
  killTimer: NodeJS.Timeout | null;
  accounted: boolean;
  renewChecked: boolean;
  /** Tokens held back for this request while it runs (capped keys); 0 = nothing held. */
  reserved: number;
  /** Unlimited keys: the request body as seen passing through, for logging the model only. */
  tap: Buffer[] | null;
}

interface Attempt {
  /** Null = stream the client's request through untouched (unlimited keys). */
  body: Buffer | null;
  generation: boolean;
  /** We added stream_options.include_usage ourselves (D1), so an upstream rejection of it is ours to handle. */
  injected: boolean;
  /** Body for the single retry without the option; null when there is nothing to retry. */
  retryBody: Buffer | null;
  isRetry: boolean;
  /**
   * The proxy parsed and re-serialized this body itself, so the response says something about the
   * provider and not about whatever the client sent. Only such requests may teach a credential flag.
   */
  controlled?: boolean;
  /** Capped key, non-GET request on a path we can't meter: a 2xx is recorded uncounted. */
  unmetered?: boolean;
}

function logQuietly(fn: () => void): void {
  // Metering and logging must never break a request that has already been answered.
  try { fn(); } catch (err) { console.error(`wickey: ${(err as Error).message}`); }
}

function refuse(ctx: Ctx, status: number, kind: ErrorKind, code: RefusalCode, message: string, extra: http.OutgoingHttpHeaders = {}): void {
  const { res } = ctx;
  if (!res.headersSent) {
    res.writeHead(status, { 'content-type': 'application/json', ...extra });
    res.end(formatError(ctx.anthropic, kind, code, message));
  }
  // Refused requests are logged but never recorded as usage, so they can't move totals or keep a key alive.
  logQuietly(() => logRequest({
    proxyId: ctx.proxy.id, at: ctx.started, model: ctx.model, status, durationMs: Date.now() - ctx.started, refusedReason: code,
  }));
}

/**
 * D10 auto-renew. Called only where a request has really been forwarded and the upstream answered
 * (never from refuse() or an unreachable upstream), so refused requests can't keep a key alive.
 * The store re-verifies the row and declines expired, out-of-window or token-capped keys; the
 * rollback flag and unreadable totals are checked here because they live in this process.
 */
/** Called once per forwarded request, after its usage is recorded, so a request that hits a cap can't renew. */
function maybeRenew(ctx: Ctx, usedTokens: number): void {
  if (ctx.renewChecked) return;
  ctx.renewChecked = true;
  if (!ctx.proxy.autoRenew) return;
  // A 502 we generated because the upstream was unreachable is not use of the key.
  if (!ctx.upRes) return;
  logQuietly(() => {
    if (isRollbackFlagged(ctx.proxy.id)) return;
    renewIfDue(ctx.proxy.id, usedTokens, Date.now(), ctx.started);
  });
}

function releaseReservation(ctx: Ctx): void {
  if (!ctx.reserved) return;
  reservations.release(ctx.proxy.id, ctx.reserved);
  ctx.reserved = 0;
}

function modelFromTap(ctx: Ctx): string | null {
  if (ctx.model || !ctx.tap) return ctx.model;
  try {
    const m = JSON.parse(Buffer.concat(ctx.tap).toString('utf8'))?.model;
    return typeof m === 'string' ? m : null;
  } catch {
    return null;
  }
}

/** Records the finished request once: totals, high-water mark, credential hints, activity log. */
function account(ctx: Ctx, a: Attempt, status: number, result: MeterResult | null, aborted: boolean, sse: boolean): void {
  if (ctx.accounted) return;
  ctx.accounted = true;
  releaseReservation(ctx);
  if (ctx.killTimer) clearTimeout(ctx.killTimer);
  logQuietly(() => {
    let counted = true;
    let tokensIn: number | null = null;
    let tokensOut: number | null = null;
    const ok = status >= 200 && status < 300;
    if (aborted) {
      counted = false;
    } else if (ok && a.unmetered) {
      counted = false;
    } else if (ok && a.generation) {
      if (result?.kind === 'found') {
        tokensIn = result.tokensIn;
        tokensOut = result.tokensOut;
      } else {
        counted = false;
      }
      const flag = sse ? 'streamUsage' : 'usage';
      const current = getCredential(ctx.credential.id);
      if (current && result?.kind === 'found' && current[sse ? 'streamUsage' : 'usageReporting'] !== 'reports') {
        setUsageReporting(current.id, { [flag]: 'reports' });
      } else if (current && result?.kind === 'none' && !a.isRetry && a.controlled) {
        // A stream that rejected our option stays 'rejects_option'; it is the more specific fact.
        const known = current[sse ? 'streamUsage' : 'usageReporting'];
        if (known !== 'missing' && known !== 'rejects_option') setUsageReporting(current.id, { [flag]: 'missing' });
      }
    }
    const totals = recordUsage(ctx.proxy.id, { tokensIn: tokensIn ?? 0, tokensOut: tokensOut ?? 0, counted, at: Date.now() });
    if (totals.ok) {
      observeUsage(ctx.proxy.id, totals);
      maybeRenew(ctx, totals.tokensIn + totals.tokensOut);
    }
    logRequest({
      proxyId: ctx.proxy.id, at: ctx.started, model: modelFromTap(ctx), status, tokensIn, tokensOut, durationMs: Date.now() - ctx.started,
    });
  });
}

function sendUpstreamError(ctx: Ctx, a: Attempt, err: NetError): void {
  const { res } = ctx;
  if (!res.headersSent && !ctx.clientClosed) {
    const blocked = isBlockedError(err);
    const status = blocked ? 403 : 502;
    sendError(res, status, blocked ? err.message : `Could not reach ${ctx.target.host}: ${describeNetError(err)}`);
    account(ctx, a, status, null, false, false);
  } else {
    res.destroy();
    account(ctx, a, res.statusCode || 502, null, true, false);
  }
}

function send(ctx: Ctx, a: Attempt): void {
  const { req, res } = ctx;
  const headers: http.OutgoingHttpHeaders = { ...ctx.headers };
  if (a.body) {
    if (a.body.length > 0) headers['content-length'] = String(a.body.length);
    else delete headers['content-length'];
  }
  const client = ctx.target.protocol === 'https:' ? https : http;
  const options = { method: req.method, headers, autoSelectFamilyAttemptTimeout: CONNECT_ATTEMPT_TIMEOUT_MS, ...guardOptions(ctx.target) };
  const upstream = client.request(ctx.target, options, (upRes) => onResponse(ctx, a, upRes));
  ctx.upstream = upstream;
  upstream.on('error', (err) => sendUpstreamError(ctx, a, err));
  if (a.body) {
    upstream.end(a.body);
  } else {
    req.pipe(upstream);
    if (ctx.tap) {
      let size = 0;
      req.on('data', (c: Buffer) => {
        if (!ctx.tap) return;
        size += c.length;
        if (size > TAP_MAX_BYTES) ctx.tap = null;
        else ctx.tap.push(c);
      });
    }
  }
}

function onResponse(ctx: Ctx, a: Attempt, upRes: http.IncomingMessage): void {
  const status = upRes.statusCode ?? 502;
  ctx.upRes = upRes;
  // An upstream that dies mid-body leaves the client with a truncated reply; say so by closing the connection.
  upRes.on('close', () => {
    if (!upRes.complete) {
      if (!ctx.res.writableFinished) ctx.res.destroy();
      account(ctx, a, status, null, true, false);
    }
  });
  if (a.injected && !a.isRetry && (status === 400 || status === 422)) return holdRejected(ctx, a, upRes, status);
  relay(ctx, a, upRes, status, [], null);
}

function responseHeaders(upRes: http.IncomingMessage): http.OutgoingHttpHeaders {
  const out: http.OutgoingHttpHeaders = { ...upRes.headers };
  for (const name of STRIP_RESPONSE) delete out[name];
  return out;
}

/**
 * Sends the upstream response to the client while a decoded side copy is metered.
 * Unlimited keys: plain pipe, accounting happens after the end. Limited keys: the final end() waits
 * for accounting, so the next request from the same client already sees the new totals.
 * D4: a cap stops new requests only. Requests already in flight finish, but each one holds a
 * reservation (its max_tokens, or a default) that new requests are checked against, and at most
 * MAX_INFLIGHT run at once, so the overshoot is bounded by those reservations.
 */
function relay(ctx: Ctx, a: Attempt, upRes: http.IncomingMessage, status: number, prefix: Buffer[], meter0: ResponseMeter | null): void {
  const { res } = ctx;
  if (!ctx.clientClosed) {
    res.writeHead(status, responseHeaders(upRes));
    for (const p of prefix) res.write(p);
  }
  const metered = status >= 200 && status < 300 && a.generation;
  const meter = meter0 ?? (metered ? new ResponseMeter(upRes.headers) : null);

  if (ctx.limited) {
    upRes.on('data', (c: Buffer) => {
      meter?.write(c);
      // Client gone (capped key): keep reading so the final usage chunk is seen, but discard the bytes.
      if (!ctx.clientClosed && !res.write(c)) {
        upRes.pause();
        res.once('drain', () => upRes.resume());
      }
    });
  } else {
    upRes.pipe(res);
    if (meter) upRes.on('data', (c: Buffer) => meter.write(c));
  }
  upRes.on('end', async () => {
    const result = meter && metered ? await meter.finish() : null;
    account(ctx, a, status, result, false, meter?.sse ?? false);
    if (ctx.limited) res.end();
  });
}

/** Holds a small 400/422 back: if it complains about stream_options the client never sees it. */
function holdRejected(ctx: Ctx, a: Attempt, upRes: http.IncomingMessage, status: number): void {
  const held: Buffer[] = [];
  let size = 0;
  const meter = new ResponseMeter(upRes.headers);
  const detach = () => { upRes.off('data', onData); upRes.off('end', onEnd); };
  const onData = (c: Buffer) => {
    held.push(c);
    size += c.length;
    meter.write(c);
    if (size > HOLD_MAX_BYTES) {
      // Too big to be a short option complaint: pass it through as it is.
      detach();
      relay(ctx, a, upRes, status, held, meter);
    }
  };
  const onEnd = async () => {
    detach();
    await meter.finish();
    if (!/stream_options/i.test(meter.bodyText())) {
      ctx.res.writeHead(status, responseHeaders(upRes));
      ctx.res.end(Buffer.concat(held));
      account(ctx, a, status, null, false, false);
      return;
    }
    // Safe to blame the provider: this path only runs for a request whose stream_options were entirely ours.
    setUsageReporting(ctx.credential.id, { streamUsage: 'rejects_option' });
    if (ctx.limits.refuseUncounted) {
      refuse(ctx, 403, 'permission', 'usage_uncountable',
        'This provider rejected the option that makes it report token usage for streaming requests, so the token cap cannot be enforced on streams. Use a non-streaming request, or ask for a key that allows requests whose usage cannot be counted.');
      ctx.accounted = true;
      releaseReservation(ctx);
      return;
    }
    // Nothing has reached the client yet, so one retry without the option is invisible to it.
    if (a.retryBody) send(ctx, { ...a, body: a.retryBody, injected: false, isRetry: true });
  };
  upRes.on('data', onData);
  upRes.on('end', onEnd);
}

function readBody(req: http.IncomingMessage, onDone: (body: Buffer | null) => void): void {
  const chunks: Buffer[] = [];
  let size = 0;
  let over = false;
  req.on('data', (c: Buffer) => {
    if (over) return;
    size += c.length;
    if (size > MAX_BODY_BYTES) {
      over = true;
      chunks.length = 0;
      onDone(null);
      return;
    }
    chunks.push(c);
  });
  req.on('end', () => { if (!over) onDone(Buffer.concat(chunks)); });
}

const list = (models: string[]) => models.join(', ');

function handle(req: http.IncomingMessage, res: http.ServerResponse): void {
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
    return;
  }
  if (handleManagement(req, res)) return;

  const match = ROUTE.exec(req.url ?? '');
  if (!match) return sendError(res, 404, 'Unknown route. Proxy URLs look like /p/<proxy-id>/...');
  const [, proxyId, path = '', search = ''] = match;

  const result = authorize(proxyId, presentedToken(req));
  if (!result.ok) {
    if (!result.code) return sendError(res, result.status, result.message);
    // A record that went back to an older version: same body shape as other refusals, and logged.
    const started = Date.now();
    res.writeHead(result.status, { 'content-type': 'application/json' });
    res.end(formatError(path.endsWith('/messages'), 'permission', result.code, result.message));
    logQuietly(() => logRequest({ proxyId, at: started, status: result.status, durationMs: 0, refusedReason: result.code }));
    return;
  }

  // Decryption throws if the vault entry was tampered with; answer with an error instead of
  // letting the exception escape the request handler and take the whole proxy down.
  let secret: string | null;
  try {
    secret = getCredentialSecret(result.credential);
  } catch (err) {
    return sendError(res, 500, `Could not read the key for "${result.credential.name}" from the vault: ${(err as Error).message}`);
  }
  if (!secret) return sendError(res, 500, `The key for "${result.credential.name}" is missing from the vault. Add it again from the dashboard.`);

  // Rows saved before these rules (or literal IPs, which skip DNS) are judged here, before the key is used.
  const verdict = classifyBaseUrl(result.credential.baseUrl);
  if (!verdict.ok) return sendError(res, 403, `Credential "${result.credential.name}" was not used: ${verdict.reason} Edit the credential to fix its base URL.`);

  const target = upstreamUrl(result.credential.baseUrl, path, search);
  const headers: http.OutgoingHttpHeaders = { ...req.headers };
  for (const name of STRIP_REQUEST) delete headers[name];
  headers.host = target.host;
  applyUpstreamAuth(headers, result.credential.authStyle, secret);

  const { proxy, credential } = result;
  const limits = proxy.limits;
  const limited = limits.models !== null || limits.rpm !== null || limits.tokenCap !== null;
  const ctx: Ctx = {
    req, res, proxy, credential, limits, limited, allList: false, path, target, headers, started: Date.now(), model: null,
    anthropic: credential.provider === 'anthropic' || path.endsWith('/messages'),
    upstream: null, clientClosed: false, upRes: null, killTimer: null, accounted: false, renewChecked: false, reserved: 0, tap: limited ? null : [],
  };
  // If the client disconnects mid-stream, stop paying for tokens nobody will read.
  res.on('close', () => {
    ctx.clientClosed = true;
    if (res.writableFinished) return;
    if (limits.tokenCap === null) return void ctx.upstream?.destroy();
    // Capped key: do not cancel upstream. A client could otherwise hang up before the usage chunk
    // and the request would never count. Trade-off: the provider may finish generating a reply nobody
    // reads, which costs those tokens, but that is what makes the cap enforceable.
    ctx.upRes?.resume();
    ctx.killTimer = setTimeout(() => ctx.upstream?.destroy(), DISCONNECT_GRACE_MS);
    ctx.killTimer.unref();
  });

  // All mode: the model must be on the provider's list, so the list is looked up first (a fetch
  // on first use). A credential whose provider has no list keeps the old pass-through behavior.
  if (limits.models === null) {
    ensureModels(credential).then((entry) => {
      if (ctx.clientClosed) return;
      if (!entry.unavailable) {
        ctx.allList = true;
        ctx.limited = true;
        ctx.tap = null;
      }
      admit(ctx);
    }).catch((err: Error) => {
      if (!res.headersSent) sendError(res, 500, err.message);
      else res.destroy();
    });
    return;
  }
  admit(ctx);
}

function admit(ctx: Ctx): void {
  const { req, res, proxy, limits, path, target } = ctx;
  const generation = req.method === 'POST' && isGenerationPath(path);

  // None: nothing is forwarded, not even a bodiless GET /models.
  if (limits.models && limits.models.length === 0) {
    return refuse(ctx, 403, 'permission', 'model_not_allowed',
      'This key allows no models, so every request was refused. Change the allowed models in the dashboard (needs your passphrase), or ask for a key that allows some.');
  }

  // D7: compare stored totals with the highest this process has seen. Re-checked on every request.
  const usage = getUsage(proxy.id);
  if (usage.ok && checkHighWater(proxy.id, usage)) {
    console.error(`wickey: usage counters for proxy ${proxy.id} went backwards (database restored or edited).`);
  }
  if (usage.ok) observeUsage(proxy.id, usage);

  if (!ctx.limited) {
    // Not refused: an unlimited key has no limit to dodge, and refusing would break the agent for
    // nothing. The flag still stops task 3's auto-renew and shows in the API.
    send(ctx, { body: null, generation, injected: false, retryBody: null, isRetry: false });
    return;
  }

  if (!usage.ok) {
    return refuse(ctx, 403, 'permission', 'usage_rollback',
      'The usage totals for this key failed their integrity check, so its limits cannot be trusted. Delete this key and issue a new one.');
  }
  if (isRollbackFlagged(proxy.id)) {
    return refuse(ctx, 403, 'permission', 'usage_rollback',
      'The usage counters for this key went backwards (the database was restored or edited), so its limits cannot be trusted. Delete this key and issue a new one.');
  }
  if (limits.rpm !== null) {
    const wait = rateLimiter.peek(proxy.id, limits.rpm, Date.now());
    if (wait) return refuseRate(ctx, limits.rpm, wait);
  }
  if (limits.tokenCap !== null && usage.tokensIn + usage.tokensOut >= limits.tokenCap) {
    return refuse(ctx, 429, 'rate_limit', 'token_cap_reached',
      `Token cap reached: ${usage.tokensIn + usage.tokensOut} of ${limits.tokenCap} tokens used. Raise the cap in the dashboard (needs your passphrase) or rotate to a new key.`);
  }

  // C: a model named in the URL (Azure deployments, Gemini models/x:method) is never checked against
  // the allowlist, so such paths are refused outright. A bare /models list is fine.
  if ((limits.models || ctx.allList) && pathNamesModel(path, target.pathname)) {
    return refuse(ctx, 403, 'permission', 'model_not_allowed',
      `This key only allows ${limits.models ? `these models: ${list(limits.models)}` : "models on the provider's list"}. The URL names a model or deployment, which cannot be checked, so it was refused. Put the model in the JSON body instead.`);
  }

  readBody(req, (buf) => {
    try {
      if (buf === null) {
        res.setHeader('connection', 'close');
        res.once('finish', () => req.destroy());
        return refuse(ctx, 413, 'invalid_request', 'request_too_large', 'The request body is larger than 10 MB, which is the most a limited key will accept.');
      }
      if (!ctx.allList) return forwardLimited(ctx, buf, generation);
      // The list lookup may wait on a fetch; nothing is reserved or counted until it is done.
      gateAllModels(ctx, buf).then((ok) => {
        if (ok && !ctx.clientClosed) forwardLimited(ctx, buf, generation);
      }).catch((err: Error) => {
        releaseReservation(ctx);
        if (!res.headersSent) sendError(res, 500, err.message);
        else res.destroy();
      });
    } catch (err) {
      releaseReservation(ctx);
      if (!res.headersSent) sendError(res, 500, (err as Error).message);
      else res.destroy();
    }
  });
}

/** All mode: same shape rules as an allowlist (D5), but the model must be on the provider's cached list. */
async function gateAllModels(ctx: Ctx, buf: Buffer): Promise<boolean> {
  const { req } = ctx;
  if (buf.length === 0 && (req.method === 'GET' || req.method === 'HEAD')) return true;
  const parsed = parseObjectBody(buf);
  if (!parsed) {
    refuse(ctx, 400, 'invalid_request', 'invalid_body',
      'This key only accepts a UTF-8 JSON object as the request body, so the request was refused. Send a JSON object with a "model" string.');
    return false;
  }
  const model = typeof parsed.model === 'string' ? parsed.model : null;
  ctx.model = model;
  if (model === null) {
    refuse(ctx, 403, 'permission', 'model_not_allowed',
      "This key allows the models on the provider's list. The request has no readable model name, so it was refused. Send JSON with a \"model\" string.");
    return false;
  }
  const verdict = await checkModel(ctx.credential, model);
  if (ctx.clientClosed) return false;
  if (verdict.allowed) return true;
  const { entry } = verdict;
  const why = entry.models
    ? `Model "${model}" is not on the provider's model list for "${ctx.credential.name}" (${entry.models.length} models, checked ${new Date(entry.fetchedAt).toLocaleTimeString()}). Check the spelling, or if the provider added it recently, run \`wickey models ${ctx.credential.name} --refresh\` and try again.`
    : `Could not get the model list from the provider for "${ctx.credential.name}" (${entry.error ?? 'no answer'}), so model "${model}" could not be checked. Try again in a minute, or use a key with selected models.`;
  refuse(ctx, 403, 'permission', 'model_not_allowed', why);
  return false;
}

/** True if the path carries a deployment segment, or a model name after a models/engines/model segment. Checked raw and normalized. */
function pathNamesModel(...paths: string[]): boolean {
  return paths.some((p) => {
    let text = p;
    // Decode a few rounds so %64eployments and double-encoded forms are seen the way a server might see them.
    for (let i = 0; i < 3; i++) {
      try { const d = decodeURIComponent(text); if (d === text) break; text = d; } catch { break; }
    }
    const segs = text.toLowerCase().replace(/\\/g, '/').split('/').filter(Boolean);
    // engines/<id> (legacy OpenAI) and model/<id> (Bedrock-style /model/<id>/invoke) name a model too.
    return segs.includes('deployments') || segs.some((s, i) => (s === 'models' || s === 'engines' || s === 'model') && i < segs.length - 1);
  });
}

/** Exact bytes check for capped bodies: valid UTF-8 (a leading BOM is dropped) holding one JSON object. */
function parseObjectBody(buf: Buffer): Record<string, any> | null {
  try {
    const v = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buf));
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

function refuseRate(ctx: Ctx, rpm: number, wait: number): void {
  refuse(ctx, 429, 'rate_limit', 'rate_limit_exceeded',
    `Rate limit reached: ${rpm} requests per minute. Try again in ${wait} seconds, or raise the limit in the dashboard (needs your passphrase).`,
    { 'retry-after': String(wait) });
}

function forwardLimited(ctx: Ctx, buf: Buffer, generation: boolean): void {
  const { req, limits, credential } = ctx;
  const cap = limits.tokenCap;
  // Keys with a cap or an allowlist forward only what we parsed ourselves (B), so a body a lenient
  // provider would read differently from us (UTF-16, BOM, odd types) can't dodge the checks or the meter.
  const strict = cap !== null || limits.models !== null || ctx.allList;
  let parsed: any = null;
  if (strict) {
    const bodiless = buf.length === 0 && req.method !== 'POST';
    if (!bodiless) {
      parsed = parseObjectBody(buf);
      if (!parsed) {
        return refuse(ctx, 400, 'invalid_request', 'invalid_body',
          'This key only accepts a UTF-8 JSON object as the request body, so the request was refused. Send a JSON object with a "model" string.');
      }
    }
  } else if (buf.length > 0) {
    // Rate-limit-only key: the bytes go through untouched; the body is read only to log the model.
    try { parsed = JSON.parse(buf.toString('utf8')); } catch { /* not JSON */ }
  }
  const isObject = parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed);
  ctx.model = isObject && typeof parsed.model === 'string' ? parsed.model : null;

  // D5: only a bodiless GET may omit the model. Everything else must name one on the list.
  if (limits.models) {
    const bodiless = buf.length === 0 && (req.method === 'GET' || req.method === 'HEAD');
    if (!bodiless) {
      if (ctx.model === null) {
        return refuse(ctx, 403, 'permission', 'model_not_allowed',
          `This key only allows these models: ${list(limits.models)}. The request has no readable model name, so it was refused. Send JSON with a "model" string.`);
      }
      if (!limits.models.includes(ctx.model)) {
        return refuse(ctx, 403, 'permission', 'model_not_allowed',
          `Model "${ctx.model}" is not allowed for this key. Allowed models: ${list(limits.models)}. Use one of those, or change the allowed models in the dashboard.`);
      }
    }
  }

  // Any truthy value counts as streaming and is forwarded as true, so we and the provider agree.
  const stream = strict && isObject && !!parsed.stream;
  if (stream) parsed.stream = true;

  // Fail closed: a capped, refusing key only reaches endpoints whose usage we can read. Anything
  // else could run unmetered. Bodiless GET/HEAD (e.g. /models) generates nothing, so it passes.
  const readOnly = (req.method === 'GET' || req.method === 'HEAD') && buf.length === 0;
  const unmetered = cap !== null && !generation && !readOnly;
  if (unmetered && limits.refuseUncounted) {
    return refuse(ctx, 403, 'permission', 'usage_uncountable',
      "This endpoint isn't metered, so this key's token cap can't be enforced on it. Allow uncapped usage for this key to use it.");
  }

  // D3: fail closed when the provider is known not to report usage in this mode.
  if (cap !== null && limits.refuseUncounted && generation) {
    const flag = stream ? credential.streamUsage : credential.usageReporting;
    const missing = stream ? flag === 'missing' || flag === 'rejects_option' : flag === 'missing';
    if (missing) {
      return refuse(ctx, 403, 'permission', 'usage_uncountable',
        `Usage cannot be counted for ${stream ? 'streaming ' : ''}requests to this provider, so the token cap cannot be enforced. ${stream ? 'Use a non-streaming request, or ' : 'Ask for '}a key that allows uncapped requests when usage is missing.`);
    }
  }

  // D1: ask the provider to report streaming usage, but only for capped keys. The client's own
  // stream_options are replaced, not merged: a field the provider rejects must never be blamed on
  // the credential, and an error naming stream_options is then always about our option.
  let injected = false;
  let retryBody: Buffer | null = null;
  if (cap !== null && stream && ctx.path.endsWith('/completions') && credential.streamUsage !== 'rejects_option') {
    const { stream_options: _dropped, ...without } = parsed;
    retryBody = Buffer.from(JSON.stringify(without));
    parsed.stream_options = { include_usage: true };
    injected = true;
  }

  // Forward what we checked, re-serialized, so a duplicate "model" key or any other parser
  // difference can't show the provider a model other than the one we allowed.
  let body = buf;
  if (strict && parsed) {
    body = Buffer.from(JSON.stringify(parsed));
    ctx.headers['content-type'] = 'application/json';
    delete ctx.headers['content-encoding'];
  }
  // H: only ask for encodings the meter can undo, whatever the client offered.
  if (cap !== null) ctx.headers['accept-encoding'] = SUPPORTED_ENCODINGS;

  // D: a cap is checked against recorded usage, so requests still running must be counted too.
  // Everything from here to send() is synchronous, so parallel requests can't slip through together.
  if (cap !== null) {
    const held = reservations.state(ctx.proxy.id);
    if (held.count >= MAX_INFLIGHT) {
      return refuse(ctx, 429, 'rate_limit', 'rate_limit_exceeded',
        `Too many requests in flight: this key allows ${MAX_INFLIGHT} at a time. Wait for one to finish and try again.`);
    }
    const now = getUsage(ctx.proxy.id);
    if (!now.ok) {
      return refuse(ctx, 403, 'permission', 'usage_rollback',
        'The usage totals for this key failed their integrity check, so its limits cannot be trusted. Delete this key and issue a new one.');
    }
    const usedNow = now.tokensIn + now.tokensOut;
    if (usedNow + held.tokens >= cap) {
      return refuse(ctx, 429, 'rate_limit', 'token_cap_reached',
        usedNow >= cap
          ? `Token cap reached: ${usedNow} of ${cap} tokens used. Raise the cap in the dashboard (needs your passphrase) or rotate to a new key.`
          : `Token cap nearly reached: ${usedNow} of ${cap} tokens used, and the remaining budget is reserved by requests in flight. Try again when they finish.`);
    }
  }

  // Counted only now that the request will really be forwarded.
  if (limits.rpm !== null) {
    const wait = rateLimiter.take(ctx.proxy.id, limits.rpm, Date.now());
    if (wait) return refuseRate(ctx, limits.rpm, wait);
  }
  if (cap !== null) {
    ctx.reserved = reservationFor(parsed);
    reservations.reserve(ctx.proxy.id, ctx.reserved);
  }
  send(ctx, { body, generation, injected, retryBody, isRetry: false, unmetered, controlled: strict && !!parsed });
}
