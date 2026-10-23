import type { Credential, Providers, Proxy } from '../../api.ts';
import type { CodeTab } from '../../components/CodeTabs.svelte';
import { ttlArg } from '../../util.ts';

export const nameOf = (p: Proxy): string => p.label || p.id;

export const prefixOf = (p: Proxy, providers: Providers | undefined): string => providers?.[p.provider]?.envPrefix || 'OPENAI';

/**
 * Usage examples. `token` is the full key and is only known right after issue or rotate. Without it
 * (null) the examples read the key from $<PREFIX>_API_KEY instead: the masked form can never work,
 * so Copy example must not hand it out. `model` fills the Python example; null leaves a placeholder.
 */
export function codeTabs(
  p: Proxy,
  token: string | null,
  baseUrl: string,
  cred: Credential | undefined,
  providers: Providers | undefined,
  model: string | null,
): CodeTab[] {
  const prefix = prefixOf(p, providers);
  const envVar = `${prefix}_API_KEY`;
  // Double quotes in the shell examples so $VAR expands; Python reads the same variable.
  const key = token ?? `$${envVar}`;
  const pyKey = token ? `"${token}"` : `os.environ["${envVar}"]`;
  const pyImport = token ? '' : 'import os\n';
  const anthropic = p.provider === 'anthropic';

  const shell = (key: string) =>
    token
      ? `export ${prefix}_BASE_URL=${baseUrl}\nexport ${envVar}=${key}`
      : `export ${prefix}_BASE_URL=${baseUrl}\n# The full key was shown once, when issued (${p.maskedKey}).\n# export ${envVar}=<that key>, or rotate this proxy for a new one.`;
  const curl = (key: string) => {
    if (anthropic) return `curl ${baseUrl}/v1/models \\\n  -H "x-api-key: ${key}" \\\n  -H "anthropic-version: 2023-06-01"`;
    const header = cred?.authStyle === 'x-api-key' ? `x-api-key: ${key}` : `Authorization: Bearer ${key}`;
    return `curl ${baseUrl}/models \\\n  -H "${header}"`;
  };
  const m = model ?? 'MODEL_ID';
  // A complete script: paste it into a file and run it to see a reply.
  const python = () =>
    anthropic
      ? `${pyImport}from anthropic import Anthropic\n\nclient = Anthropic(\n    base_url="${baseUrl}",\n    api_key=${pyKey},\n)\n\nmessage = client.messages.create(\n    model="${m}",\n    max_tokens=100,\n    messages=[{"role": "user", "content": "Hello!"}],\n)\n\nprint(message.content[0].text)`
      : `${pyImport}from openai import OpenAI\n\nclient = OpenAI(\n    base_url="${baseUrl}",\n    api_key=${pyKey},\n)\n\nresponse = client.chat.completions.create(\n    model="${m}",\n    messages=[{"role": "user", "content": "Hello!"}],\n)\n\nprint(response.choices[0].message.content)`;
  const pyNote = model
    ? 'Sends one short request, so it uses a few tokens. Change the model to any this key allows.'
    : 'Replace MODEL_ID with a model this key allows. Sends one short request, so it uses a few tokens.';

  const have = token !== null;
  const keyNote = have ? 'These examples include the full key. Copy it now; it is not shown again.' : `The full key was shown once, when issued, so these examples read it from $${envVar}. Set that to the key you saved, or rotate this proxy for a new one.`;
  const tabs: CodeTab[] = [
    { id: 'shell', label: 'Shell', text: shell(key), note: keyNote },
    { id: 'curl', label: 'cURL test', text: curl(key), note: `Lists models, so it costs no tokens. ${keyNote}` },
    { id: 'python', label: 'Python', text: python(), note: `${pyNote} ${keyNote}` },
  ];
  if (p.label) {
    // Each run mints a key for that terminal, so it asks for the passphrase.
    tabs.push({
      id: 'profile',
      label: 'Shell profile',
      text: `# ~/.zshrc\neval "$(wickey env ${p.label} --credential ${cred?.name ?? p.credentialName} --ttl ${ttlArg(p.ttlSeconds)})"`,
      note: 'Every new terminal asks for your passphrase and gets its own short-lived key under this name. Expired ones are cleaned up.',
    });
  }
  return tabs;
}
