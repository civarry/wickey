import fs from 'node:fs';
import type http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { detectEntries, maskSecret, MAX_ENV_BYTES } from './dotenv.ts';
import { BRAND } from './brand.ts';
import { config } from './config.ts';
import { noTerminalMessage } from './human.ts';
import { hasTerminal, promptHidden, promptVisible } from './prompt.ts';
import { PROVIDERS, isProvider } from './providers.ts';
import { createProxyServer } from './proxy.ts';
import { isProxyRunning } from './reset.ts';
import { runServiceCommand } from './service.ts';
import { setUp, unlock } from './session.ts';
import { listCredentials } from './store.ts';
import { WrongPassphraseError, isUnlocked, vaultExists } from './vault.ts';

// `setup` walks through passphrase, credentials and start-on-login. Every step can be skipped and
// every step is also its own command. State-changing calls go through the proxy's API (only it holds
// the unlocked vault), so when no proxy is running this process hosts one for the length of the
// walkthrough, using the vault it just created or unlocked. That needs nothing detached and leaves
// nothing behind: when setup ends (or is interrupted) the server is simply gone, and every write
// it made was already atomic.

export interface SetupHelpers {
  call(method: string, path: string, body?: Record<string, unknown>): Promise<any>;
  askNewPassphrase(): Promise<string | null>;
  /** Hands over a passphrase the user just typed, so the next API call does not ask again. */
  rememberPassphrase(passphrase: string): void;
  /** Makes fail() throw instead of exiting, so a rejected entry doesn't end the walkthrough. */
  soft<T>(fn: () => Promise<T>): Promise<T>;
  fail(message: string): never;
}

class Cancelled extends Error {}

async function ask(question: string): Promise<string> {
  const answer = await promptVisible(question);
  if (answer === null) throw new Cancelled();
  return answer.trim();
}

async function yesNo(question: string, dflt: boolean): Promise<boolean> {
  const a = (await ask(`${question} ${dflt ? '[Y/n]' : '[y/N]'} `)).toLowerCase();
  return a === '' ? dflt : a === 'y' || a === 'yes';
}

const NAME = /^[A-Za-z0-9._-]{1,64}$/;

/** "1,3", "2-4", or "all" (every importable entry) to a sorted list of valid indexes. */
export function parsePicks(input: string, allowed: number[], all: number[] = allowed): number[] | null {
  const text = input.trim().toLowerCase();
  if (text === '') return [];
  if (text === 'all') return all;
  const out = new Set<number>();
  for (const part of text.split(/[,\s]+/).filter(Boolean)) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(part);
    if (!m) return null;
    const [from, to] = [Number(m[1]), Number(m[2] ?? m[1])];
    if (to < from || to - from > 1000) return null;
    for (let i = from; i <= to; i++) {
      if (!allowed.includes(i)) return null;
      out.add(i);
    }
  }
  return [...out].sort((a, b) => a - b);
}

export async function runSetup(h: SetupHelpers): Promise<void> {
  if (!hasTerminal()) h.fail(noTerminalMessage());
  const { host, port } = config();
  let hosted: http.Server | null = null;
  let external = await isProxyRunning();

  const stopHosted = async () => {
    const server = hosted;
    hosted = null;
    if (!server) return;
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  };

  /** Makes sure a proxy answers on the port; hosts one here when none does. */
  const ensureProxy = async (): Promise<void> => {
    if (external || hosted) return;
    if (!isUnlocked()) {
      for (let i = 0; ; i++) {
        const passphrase = await promptHidden('Wickey passphrase: ');
        if (!passphrase) throw new Cancelled();
        try { unlock(passphrase); h.rememberPassphrase(passphrase); break; } catch (err) {
          if (!(err instanceof WrongPassphraseError) || i === 2) throw err;
          console.log('Wrong passphrase.');
        }
      }
    }
    const server = createProxyServer();
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => resolve());
    }).catch((err: NodeJS.ErrnoException) => {
      throw new Error(err.code === 'EADDRINUSE' ? `Port ${port} is in use by another program. Free it or set ${BRAND.envPrefix}PORT, then run \`${BRAND.command} setup\` again.` : err.message);
    });
    hosted = server;
  };

  let installedService = false;
  try {
    console.log(`${BRAND.command} setup. Press Enter to skip any step; each one is also its own command.\n`);

    // 1. Passphrase
    console.log('Step 1 of 4: passphrase');
    if (vaultExists()) {
      console.log('  A passphrase is already set. Skipping.\n');
    } else if (external) {
      // A running proxy only accepts setup with the one-time link it printed, which this process
      // can't have (on purpose: any local program could read wherever it would be kept).
      console.log(`  A ${BRAND.command} proxy is already running on this port without a passphrase. Open the setup`);
      console.log(`  link it printed, or stop it (for the login service: \`${BRAND.command} service uninstall\`) and run`);
      console.log(`  \`${BRAND.command} setup\` again. Credentials need a passphrase, so step 2 is skipped too.\n`);
    } else if (await yesNo('  Create the passphrase now?', true)) {
      const passphrase = await h.askNewPassphrase();
      if (passphrase === null) {
        console.log('  Skipped. Run `wickey start` later to set it.\n');
      } else {
        setUp(passphrase);
        h.rememberPassphrase(passphrase);
        console.log('  Passphrase set.\n');
      }
    } else {
      console.log('  Skipped. Credentials need a passphrase, so step 2 is skipped too.\n');
    }

    // 2. Credentials
    console.log('Step 2 of 4: credentials');
    if (!vaultExists()) {
      console.log('  No passphrase yet, so there is nowhere to keep them. Skipping.\n');
    } else {
      for (;;) {
        const choice = (await ask('  (a) add one now, (b) import from a .env file, Enter to skip: ')).toLowerCase();
        if (choice === '') break;
        if (choice !== 'a' && choice !== 'b') { console.log('  Type a, b, or press Enter.'); continue; }
        await ensureProxy();
        try {
          if (choice === 'a') await addOne(h);
          else await importFile(h);
        } catch (err) {
          if (err instanceof Cancelled) throw err;
          console.log(`  ${(err as Error).message}`);
        }
      }
      console.log('');
    }

    // 3. Start on login
    console.log('Step 3 of 4: start on login');
    if (await yesNo('  Start the proxy automatically when you log in? It starts locked: you unlock it once per login.', false)) {
      await stopHosted(); // the service needs the port, and its vault starts locked anyway
      external = false;
      const code = await runServiceCommand('install');
      installedService = code === 0;
      if (!installedService) console.log(`  Not installed. Run \`${BRAND.command} service install\` to try again.`);
    } else {
      console.log(`  Skipped. Run \`${BRAND.command} service install\` any time.`);
    }
    console.log('');

    // 4. Next steps
    console.log('Step 4 of 4: done');
    const creds = listCredentials();
    const first = creds[0]?.name ?? '<credential>';
    const url = `http://${host}:${port}/`;
    console.log(`  Dashboard: ${url}`);
    if (!installedService && !external) console.log(`  Start the proxy:   ${BRAND.command} start`);
    console.log(`  Issue a key:       ${BRAND.command} issue ${first} --ttl 1h`);
    console.log(`  Shell profile:     eval "$(${BRAND.command} env work --credential ${first} --ttl 8h)"`);
    if (installedService) console.log(`  Unlock after login: ${BRAND.command} unlock`);
  } catch (err) {
    if (!(err instanceof Cancelled)) {
      await stopHosted();
      throw err;
    }
    console.log('\nCancelled. Whatever you finished is saved; run `wickey setup` again for the rest.');
  } finally {
    await stopHosted();
  }
}

async function addOne(h: SetupHelpers): Promise<void> {
  const name = await ask('  Name (letters, digits, . _ -): ');
  if (!name) return;
  if (!NAME.test(name)) throw new Error('Names use only letters, digits, dots, underscores and hyphens, up to 64 characters.');
  const provider = (await ask(`  Provider (${Object.keys(PROVIDERS).join(', ')}) [${isProvider(name) ? name : 'custom'}]: `)).toLowerCase() || (isProvider(name) ? name : 'custom');
  if (!isProvider(provider)) throw new Error(`Provider must be one of: ${Object.keys(PROVIDERS).join(', ')}.`);
  const baseUrl = PROVIDERS[provider].baseUrl ? undefined : (await ask('  Base URL: ')) || undefined;
  const apiKey = await promptHidden(`  API key for ${name}: `);
  if (apiKey === null) throw new Cancelled();
  if (!apiKey) return;
  const { credential } = await h.soft(() => h.call('POST', '/api/credentials', { name, provider, apiKey, baseUrl }));
  console.log(`  Stored "${credential.name}" (${credential.provider}, ${credential.baseUrl}) in the vault.`);
}

async function importFile(h: SetupHelpers): Promise<void> {
  const typed = await ask('  Path to the .env file: ');
  if (!typed) return;
  const file = typed.startsWith('~') ? path.join(os.homedir(), typed.slice(1)) : path.resolve(typed.replace(/^['"]|['"]$/g, ''));
  let text: string;
  try {
    if (fs.statSync(file).size > MAX_ENV_BYTES) throw new Error('That file is larger than 256 KB, which is too big for an .env file. Pick a different file.');
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    throw new Error((err as NodeJS.ErrnoException).code ? `Cannot read ${file}: ${(err as NodeJS.ErrnoException).code}. Check the path.` : (err as Error).message);
  }
  const found = detectEntries(text, PROVIDERS);
  if (found.error) throw new Error(found.error);
  if (!found.entries.length) throw new Error('No provider API keys found in that file. Look for variables like OPENAI_API_KEY or ANTHROPIC_API_KEY.');

  console.log(`\n  Found ${found.entries.length} key${found.entries.length === 1 ? '' : 's'} (${found.ignored} other variable${found.ignored === 1 ? '' : 's'} ignored, never shown):`);
  const importable: number[] = [];
  const ready: number[] = [];
  found.entries.forEach((e, i) => {
    const n = i + 1;
    if (e.status === 'ready' || e.status === 'review') {
      importable.push(n);
      if (e.status === 'ready') ready.push(n);
      console.log(`  ${n}. ${e.name}  (${e.provider}, ${e.baseUrl})  from ${e.source}  key ${maskSecret(e.apiKey)}${e.reason ? `\n       check: ${e.reason}` : ''}`);
    } else {
      console.log(`  -  ${e.source}: not importable, ${e.reason ?? e.status}`);
    }
  });
  if (!importable.length) return;

  let picks: number[] | null = null;
  while (picks === null) {
    const input = await ask(`  Numbers to import (e.g. 1,3), "all" for the ones without a check note, Enter for none: `);
    picks = parsePicks(input, importable, ready);
    if (picks === null) console.log('  Use numbers from the list, like 1,3 or 2-4.');
  }
  if (!picks.length) { console.log('  Nothing selected.'); return; }

  const entries = picks.map((n) => {
    const e = found.entries[n - 1];
    return { name: e.name, provider: e.provider, baseUrl: e.baseUrl || undefined, apiKey: e.apiKey, authStyle: e.authStyle };
  });
  // Dry run first: it reports duplicates and invalid entries before anything is stored.
  const { results: check } = await h.soft(() => h.call('POST', '/api/credentials/import', { entries, dryRun: true }));
  const good: typeof entries = [];
  check.forEach((r: any, i: number) => {
    if (r.outcome === 'would_import') {
      good.push(entries[i]);
      console.log(`  will import ${r.name}${r.baseUrlScope && r.baseUrlScope !== 'public' ? `  (note: base URL is ${r.baseUrlScope})` : ''}`);
    } else {
      console.log(`  skip ${r.name}: ${r.message ?? r.outcome}`);
    }
  });
  if (!good.length) return;
  if (!(await yesNo(`  Import ${good.length} credential${good.length === 1 ? '' : 's'}?`, false))) { console.log('  Nothing imported.'); return; }
  const { results } = await h.soft(() => h.call('POST', '/api/credentials/import', { entries: good, dryRun: false }));
  for (const r of results) console.log(r.outcome === 'imported' ? `  Imported "${r.name}".` : `  Not imported ${r.name}: ${r.message ?? r.outcome}`);
}
