import type { AutoRenew, AutoRenewInput, Credential, Limits, Proxy } from './api.ts';
import { compact } from './util.ts';

/** The limits form as typed: strings, so validation can explain what is wrong. */
export type ModelMode = 'selected' | 'all' | 'none';

export interface LimitsDraft {
  modelMode: ModelMode;
  /** Model IDs for Selected, one per line. */
  models: string;
  rpm: string;
  tokenCap: string;
  refuseUncounted: boolean;
  autoRenew: boolean;
  windowAmount: string;
  windowUnit: 'm' | 'h';
  maxAmount: string;
  maxUnit: 'h' | 'd';
}

export const emptyDraft = (): LimitsDraft => ({
  modelMode: 'selected', models: '', rpm: '', tokenCap: '', refuseUncounted: true,
  autoRenew: false, windowAmount: '10', windowUnit: 'm', maxAmount: '', maxUnit: 'd',
});

export function draftFromProxy(p: Proxy): LimitsDraft {
  const d = emptyDraft();
  // null (no restriction) shows as All; [] as None.
  d.modelMode = p.limits.models === null ? 'all' : p.limits.models.length ? 'selected' : 'none';
  d.models = p.limits.models?.join('\n') ?? '';
  d.rpm = p.limits.rpm?.toString() ?? '';
  d.tokenCap = p.limits.tokenCap?.toString() ?? '';
  d.refuseUncounted = p.limits.refuseUncounted;
  if (p.autoRenew) {
    const w = p.autoRenew.windowSeconds;
    d.autoRenew = true;
    if (w % 3600 === 0) Object.assign(d, { windowAmount: String(w / 3600), windowUnit: 'h' });
    else Object.assign(d, { windowAmount: String(Math.round(w / 60)), windowUnit: 'm' });
    // Max lifetime is left blank when editing: blank keeps the approved maximum.
    d.maxAmount = '';
  }
  return d;
}

/** Whole number with an optional k / m suffix ("100k"). */
function count(raw: string, what: string): number | null {
  const t = raw.trim().toLowerCase().replace(/[,_\s]/g, '');
  if (!t) return null;
  const m = /^(\d+)([km]?)$/.exec(t);
  const n = m ? Number(m[1]) * (m[2] === 'k' ? 1e3 : m[2] === 'm' ? 1e6 : 1) : NaN;
  if (!Number.isSafeInteger(n) || n < 1) throw new Error(`${what} must be a whole number of at least 1 (for example 30, or 100k for tokens).`);
  return n;
}

const whole = (raw: string, what: string): number => {
  const t = raw.trim();
  if (!/^\d+$/.test(t) || Number(t) < 1) throw new Error(`${what} must be a whole number of at least 1.`);
  return Number(t);
};

export function modelList(raw: string): string[] {
  return [...new Set(raw.split(/[\s,]+/).map((m) => m.trim()).filter(Boolean))];
}

function modelsFor(d: LimitsDraft): string[] | null {
  if (d.modelMode === 'all') return null;
  if (d.modelMode === 'none') return [];
  const list = modelList(d.models);
  if (!list.length) throw new Error('Pick at least one model, or choose All or None.');
  return list;
}

/** True when Selected is chosen with nothing picked: the key can't be issued like that. */
export const needsModels = (d: LimitsDraft): boolean => d.modelMode === 'selected' && modelList(d.models).length === 0;

/**
 * Turns the draft into the API shape. Throws a message fit for the user.
 * `current` is the key's existing auto-renew (edit only): unchanged or blank maximum keeps its approved maximum.
 * Returns autoRenew undefined for "no auto-renew" so the issue call omits it; callers that PATCH map that to null.
 */
export function buildLimits(d: LimitsDraft, current: AutoRenew | null = null): { limits: Limits; autoRenew?: AutoRenewInput } {
  const tokenCap = count(d.tokenCap, 'Token cap');
  const limits: Limits = {
    models: modelsFor(d),
    rpm: count(d.rpm, 'Requests per minute'),
    tokenCap,
    refuseUncounted: tokenCap === null ? true : d.refuseUncounted,
  };
  if (!d.autoRenew) return { limits };
  const windowSeconds = whole(d.windowAmount, 'Renew window') * (d.windowUnit === 'h' ? 3600 : 60);
  if (windowSeconds < 60 || windowSeconds > 86400) throw new Error('The renew window must be from 1 minute to 24 hours.');
  if (!d.maxAmount.trim()) {
    if (!current) throw new Error('Auto-renew needs a maximum lifetime. Enter one, or turn auto-renew off.');
    return { limits, autoRenew: { windowSeconds, maxExpiresAt: current.maxExpiresAt } };
  }
  return { limits, autoRenew: { windowSeconds, maxLifetime: `${whole(d.maxAmount, 'Maximum lifetime')}${d.maxUnit}` } };
}

/** Compact trigger text, e.g. "Limits: 2 models · 30 rpm · 100k tok · auto-renew 7d". */
export function summary(d: LimitsDraft): string {
  const parts: string[] = [];
  if (d.modelMode === 'all') parts.push('All models');
  else if (d.modelMode === 'none') parts.push('No models');
  else {
    const n = modelList(d.models).length;
    parts.push(n ? `${n} ${n === 1 ? 'model' : 'models'}` : 'Pick models');
  }
  if (d.rpm.trim()) parts.push(`${d.rpm.trim()} rpm`);
  if (d.tokenCap.trim()) {
    const n = Number(d.tokenCap.trim().toLowerCase().replace(/k$/, '000').replace(/m$/, '000000'));
    parts.push(`${Number.isFinite(n) && n > 0 ? compact(n) : d.tokenCap.trim()} tok`);
  }
  if (d.autoRenew) parts.push(`auto-renew${d.maxAmount.trim() ? ` ${d.maxAmount.trim()}${d.maxUnit}` : ''}`);
  return parts.length ? `Limits: ${parts.join(' · ')}` : 'No limits';
}

/** The provider is known not to report usage, so a token cap can only work by refusing requests. */
export function usageUnreliable(c: Credential | undefined): boolean {
  return !!c && (c.usageReporting === 'missing' || c.streamUsage === 'missing' || c.streamUsage === 'rejects_option');
}

export const REFUSAL_TEXT: Record<string, string> = {
  model_not_allowed: 'model not allowed',
  rate_limit_exceeded: 'too many requests per minute',
  token_cap_reached: 'token cap reached',
  usage_uncountable: 'usage could not be counted',
  usage_rollback: 'usage counters went backwards',
  request_too_large: 'request too large to check',
};

export const refusal = (code: string): string => `Refused: ${REFUSAL_TEXT[code] ?? code.replace(/_/g, ' ')}`;

export const atCap = (p: Proxy): boolean => p.limits.tokenCap !== null && p.usage.tokensIn + p.usage.tokensOut >= p.limits.tokenCap;
