export function duration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  if (s < 60) return `${s}s`;
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`, r && !d && !h && `${r}s`].filter(Boolean).join(' ');
}

/** Compact TTL in the form the CLI accepts, for the shell-profile snippet. */
export function ttlArg(seconds: number): string {
  for (const [unit, n] of [['d', 86400], ['h', 3600], ['m', 60]] as const) {
    if (seconds % n === 0) return `${seconds / n}${unit}`;
  }
  return `${seconds}s`;
}

export const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

const PROVIDER_LABEL: Record<string, string> = { openai: 'OpenAI', anthropic: 'Anthropic', openrouter: 'OpenRouter', custom: 'Custom' };
export const providerLabel = (p: string): string => PROVIDER_LABEL[p] ?? p;

export function clock(totalSeconds: number): string {
  const s = Math.max(0, Math.ceil(totalSeconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

/** Hides everything after the prefix, e.g. sk-wick-•••••••• */
export function maskKey(token: string): string {
  const prefix = token.startsWith('sk-wick-') ? 'sk-wick-' : '';
  return prefix + '•'.repeat(16);
}

export function stripScheme(origin: string): string {
  return origin.replace(/^https?:\/\//, '');
}

/** Resolves false when the browser blocks clipboard access. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** 12345 -> "12.3k", 2400000 -> "2.4M". */
export function compact(n: number): string {
  const f = (v: number, s: string) => `${v >= 100 || Number.isInteger(v) ? Math.round(v) : v.toFixed(1).replace(/\.0$/, '')}${s}`;
  if (n >= 1e6) return f(n / 1e6, 'M');
  if (n >= 1e3) return f(n / 1e3, 'k');
  return String(n);
}

/** "2m ago", "3h ago"; under a minute is "just now". */
export function ago(ms: number, now: number): string {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/** Short local date and time, 24-hour: "Oct 23, 14:05". */
export const dateTime = (ms: number): string =>
  new Date(ms).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
