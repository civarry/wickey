export type AuthStyle = 'bearer' | 'x-api-key';

/** How to ask a provider which models it serves. */
export interface ModelListSpec {
  /** Relative to the credential's base URL. */
  path: string;
  headers?: Record<string, string>;
  /** Anthropic-style paging: limit=1000, then has_more / last_id -> after_id. */
  paginated?: boolean;
}

export interface ProviderPreset {
  baseUrl: string | null;
  auth: AuthStyle;
  /** Prefix for the env vars printed by `issue --env`, matching what each SDK reads. */
  envPrefix: string;
  models: ModelListSpec;
  // Detection hints for "Import from .env"; the dashboard reads them from /api/state.
  /** Variable names that hold this provider's key. */
  envNames: string[];
  /** Variable names that hold its base URL. */
  baseUrlEnvNames: string[];
  /** Key prefixes; the longest match across presets decides whose key a value is. */
  keyPrefixes: string[];
  /** Hostnames of its API, to recognise a base URL. */
  hosts: string[];
}

// baseUrl is what the provider's own SDK expects as its base URL, so request paths
// line up unchanged when a client swaps in the proxy URL.
export const PROVIDERS: Record<string, ProviderPreset> = {
  openai: { baseUrl: 'https://api.openai.com/v1', auth: 'bearer', envPrefix: 'OPENAI', models: { path: '/models' },
    envNames: ['OPENAI_API_KEY'], baseUrlEnvNames: ['OPENAI_BASE_URL', 'OPENAI_API_BASE'],
    keyPrefixes: ['sk-proj-', 'sk-svcacct-', 'sk-'], hosts: ['api.openai.com'] },
  anthropic: { baseUrl: 'https://api.anthropic.com', auth: 'x-api-key', envPrefix: 'ANTHROPIC',
    models: { path: '/v1/models', headers: { 'anthropic-version': '2023-06-01' }, paginated: true },
    envNames: ['ANTHROPIC_API_KEY'], baseUrlEnvNames: ['ANTHROPIC_BASE_URL'], keyPrefixes: ['sk-ant-'], hosts: ['api.anthropic.com'] },
  openrouter: { baseUrl: 'https://openrouter.ai/api/v1', auth: 'bearer', envPrefix: 'OPENAI', models: { path: '/models' },
    envNames: ['OPENROUTER_API_KEY'], baseUrlEnvNames: ['OPENROUTER_BASE_URL'], keyPrefixes: ['sk-or-'], hosts: ['openrouter.ai'] },
  custom: { baseUrl: null, auth: 'bearer', envPrefix: 'OPENAI', models: { path: '/models' },
    envNames: [], baseUrlEnvNames: [], keyPrefixes: [], hosts: [] },
};

export function isProvider(name: string): boolean {
  return Object.hasOwn(PROVIDERS, name);
}

/** Sets the real key on outgoing headers. Shared by request forwarding and model listing so they can't drift. */
export function applyUpstreamAuth(headers: Record<string, unknown>, authStyle: AuthStyle, secret: string): void {
  if (authStyle === 'bearer') headers.authorization = `Bearer ${secret}`;
  else headers['x-api-key'] = secret;
}

export function upstreamUrl(baseUrl: string, path: string, search: string): URL {
  const base = new URL(baseUrl);
  const url = new URL(base.origin);
  url.pathname = base.pathname.replace(/\/+$/, '') + path;
  url.search = search;
  return url;
}
