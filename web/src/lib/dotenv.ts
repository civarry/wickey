// Pure on purpose (no DOM, no imports): the .env text is parsed in the browser tab, so variables the
// user doesn't tick never reach the server, and node:test can import this file directly.

export const MAX_ENV_BYTES = 256 * 1024;

/** The slice of a provider preset that detection reads (a subset of /api/state `providers`). */
export interface ProviderHints {
  baseUrl: string | null;
  auth: 'bearer' | 'x-api-key';
  envNames: string[];
  baseUrlEnvNames: string[];
  keyPrefixes: string[];
  hosts: string[];
}

export interface EnvVar {
  name: string;
  value: string;
  /** Unquoted or double-quoted value that refers to another variable. */
  interpolated: boolean;
}

export type EntryStatus = 'ready' | 'review' | 'unresolved' | 'skipped';

export interface EnvEntry {
  name: string;
  provider: string;
  baseUrl: string;
  /** Never render this. Use maskSecret(). Empty for entries that can't be imported. */
  apiKey: string;
  authStyle?: 'bearer' | 'x-api-key';
  status: EntryStatus;
  reason?: string;
  /** The variable the key came from. */
  source: string;
}

export interface DetectResult {
  entries: EnvEntry[];
  /** Variables that were neither a key nor a base URL for one. Only counted, never listed. */
  ignored: number;
  /** Set when the text can't be used at all. */
  error?: string;
}

const REFERENCE = /\$(\{|[A-Za-z_])/;

function unescapeDouble(s: string): string {
  return s.replace(/\\([nrt"\\$])/g, (_, c: string) => ({ n: '\n', r: '\r', t: '\t' } as Record<string, string>)[c] ?? c);
}

/** Last assignment of a name wins, as in dotenv. Lines that don't parse are skipped. */
export function parseDotenv(text: string): EnvVar[] {
  const found = new Map<string, EnvVar>();
  for (const line of text.replace(/^\uFEFF/, '').split(/\r\n|\r|\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=(.*)$/.exec(line);
    if (!m) continue;
    const rest = m[2].trimStart();
    let value: string;
    let interpolated: boolean;
    const quote = rest[0];
    if (quote === '"' || quote === "'") {
      let end = 1;
      while (end < rest.length && rest[end] !== quote) end += rest[end] === '\\' && quote === '"' ? 2 : 1;
      if (end >= rest.length) continue;
      const after = rest.slice(end + 1).trim();
      if (after && !after.startsWith('#')) continue;
      const inner = rest.slice(1, end);
      // Single quotes are literal, so a $ in them is not a reference.
      interpolated = quote === '"' && REFERENCE.test(inner);
      value = quote === '"' ? unescapeDouble(inner) : inner;
    } else {
      const raw = /^#/.test(rest) ? '' : rest.replace(/\s+#.*$/, '').trim();
      interpolated = REFERENCE.test(raw);
      value = raw;
    }
    found.set(m[1], { name: m[1], value, interpolated });
  }
  return [...found.values()];
}

/** Last four characters only, and nothing at all for short values. */
export function maskSecret(secret: string): string {
  return secret.length >= 12 ? `••••${secret.slice(-4)}` : '••••';
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function sameLocation(a: string, b: string): boolean {
  try {
    const x = new URL(a);
    const y = new URL(b);
    return x.origin === y.origin && x.pathname.replace(/\/+$/, '') === y.pathname.replace(/\/+$/, '');
  } catch {
    return false;
  }
}

/** The provider a key's prefix points at (longest prefix wins, so sk-ant- beats sk-), or null if unrecognised. */
function prefixOwner(key: string, providers: Record<string, ProviderHints>): string | null {
  let best: string | null = null;
  let len = 0;
  for (const [id, p] of Object.entries(providers)) {
    for (const prefix of p.keyPrefixes) {
      if (key.startsWith(prefix) && prefix.length > len) {
        best = id;
        len = prefix.length;
      }
    }
  }
  return best;
}

function safeName(base: string): string {
  return base.toLowerCase().replace(/[^a-z0-9._-]/g, '-').slice(0, 64) || 'credential';
}

export function detectEntries(text: string, providers: Record<string, ProviderHints>): DetectResult {
  if (text.length > MAX_ENV_BYTES) return { entries: [], ignored: 0, error: 'That file is larger than 256 KB, which is too big for an .env file. Pick a different file.' };
  const vars = parseDotenv(text);
  const byName = new Map(vars.map((v) => [v.name, v]));
  const used = new Set<string>();
  const entries: EnvEntry[] = [];
  const taken = new Set<string>();

  const unique = (base: string): string => {
    let n = safeName(base);
    for (let i = 2; taken.has(n); i++) n = `${safeName(base).slice(0, 60)}-${i}`;
    taken.add(n);
    return n;
  };

  const firstOf = (names: string[]): EnvVar | undefined => {
    for (const n of names) {
      const v = byName.get(n);
      if (v && v.value) return v;
    }
    return undefined;
  };

  const push = (e: Omit<EnvEntry, 'name'> & { nameBase: string }) => {
    const { nameBase, ...rest } = e;
    entries.push({ name: unique(nameBase), ...rest });
  };

  const handle = (keyVar: EnvVar, hintProvider: string | null, baseUrlNames: string[], derived: string) => {
    used.add(keyVar.name);
    const base = { nameBase: derived, provider: 'custom', baseUrl: '', apiKey: '', source: keyVar.name };
    if (!keyVar.value) return push({ ...base, status: 'skipped', reason: 'is empty' });
    if (keyVar.value.startsWith('sk-wick-')) return push({ ...base, status: 'skipped', reason: 'is a Wickey proxy key, not a provider key' });
    if (keyVar.interpolated) return push({ ...base, status: 'unresolved', reason: 'uses a variable reference' });

    const urlVar = firstOf(baseUrlNames);
    if (urlVar) used.add(urlVar.name);
    if (urlVar?.interpolated) return push({ ...base, status: 'unresolved', reason: 'has a base URL that uses a variable reference' });
    const url = urlVar?.value ?? '';
    const host = url ? hostOf(url) : null;
    if (url && !host) return push({ ...base, status: 'unresolved', reason: 'has a base URL that is not a valid URL' });

    // The host decides the provider when there is one; the variable name only matters without a URL.
    const hostProvider = host ? Object.keys(providers).find((id) => providers[id].hosts.includes(host)) ?? null : null;
    const provider = hostProvider ?? (url ? null : hintProvider);

    if (provider) {
      const owner = prefixOwner(keyVar.value, providers);
      if (owner && owner !== provider) {
        return push({ ...base, status: 'unresolved', reason: `has a key prefix that belongs to ${owner}, which does not match ${hostProvider ? `the ${provider} base URL` : 'its variable name'}` });
      }
      const preset = providers[provider];
      const baseUrl = url || preset.baseUrl || '';
      const differs = !!url && !!preset.baseUrl && !sameLocation(url, preset.baseUrl);
      return push({
        nameBase: hostProvider ? provider : derived, provider, baseUrl, apiKey: keyVar.value, source: keyVar.name,
        status: differs ? 'review' : 'ready',
        ...(differs ? { reason: `has a base URL that differs from the usual ${preset.baseUrl}` } : {}),
      });
    }
    if (!url) return push({ ...base, status: 'unresolved', reason: 'has no base URL' });
    // A known variable pointed at a host we don't know is usually a company gateway: import it as custom, but ask first.
    const auth = hintProvider ? providers[hintProvider].auth : 'bearer';
    push({
      nameBase: derived, provider: 'custom', baseUrl: url, apiKey: keyVar.value, source: keyVar.name, authStyle: auth,
      // A generic <X>_API_KEY / <X>_BASE_URL pair names its own destination, so only the known-variable case needs a second look.
      ...(hintProvider ? { status: 'review' as const, reason: `points at ${host}, which is not a known provider address` } : { status: 'ready' as const }),
    });
  };

  for (const [id, p] of Object.entries(providers)) {
    for (const n of p.envNames) {
      const v = byName.get(n);
      if (v) handle(v, id, p.baseUrlEnvNames, id);
    }
  }
  for (const v of vars) {
    const g = /^(.+)_API_KEY$/.exec(v.name);
    if (!g || used.has(v.name)) continue;
    handle(v, null, [`${g[1]}_BASE_URL`, `${g[1]}_API_BASE`], g[1]);
  }

  return { entries, ignored: vars.filter((v) => !used.has(v.name)).length };
}
