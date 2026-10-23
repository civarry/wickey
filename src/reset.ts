import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { config } from './config.ts';
import { appendEvent } from './events.ts';

// Forgot-passphrase path. There is no recovery by design, so the only way out is to delete the
// vault and start over. This lives in the CLI only: an HTTP endpoint for it would let any local
// program wipe the vault.

export interface ResetPlan {
  vaultFile: string | null;
  credentials: string[];
  proxies: number;
  logEntries: number;
}

function count(db: DatabaseSync, sql: string): number {
  try {
    return Number((db.prepare(sql).get() as { n: number }).n);
  } catch {
    return 0; // table missing in a very old or half-made database
  }
}

/** Reads the current state without creating or migrating anything. */
export function planReset(): ResetPlan {
  const { home, dbPath } = config();
  const vaultFile = path.join(home, 'vault.json');
  const plan: ResetPlan = { vaultFile: fs.existsSync(vaultFile) ? vaultFile : null, credentials: [], proxies: 0, logEntries: 0 };
  if (!fs.existsSync(dbPath)) return plan;
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    try {
      plan.credentials = (db.prepare('SELECT name FROM credentials ORDER BY name').all() as { name: string }[]).map((r) => r.name);
    } catch {
      plan.credentials = [];
    }
    plan.proxies = count(db, 'SELECT COUNT(*) AS n FROM proxies');
    plan.logEntries = count(db, 'SELECT COUNT(*) AS n FROM requests');
  } finally {
    db.close();
  }
  return plan;
}

/** True if a Wickey proxy answers on the configured port. */
export async function isProxyRunning(): Promise<boolean> {
  const { host, port } = config();
  try {
    const res = await fetch(`http://${host}:${port}/health`, { signal: AbortSignal.timeout(1500) });
    return res.ok && (await res.json())?.ok === true;
  } catch {
    return false;
  }
}

/**
 * Deletes the vault and the database. The database file is removed (not emptied) so the schema
 * and its migrations are simply recreated on the next start. The directory stays.
 * events.log is kept on purpose: a reset is exactly when a trail matters. It gets a `reset` entry
 * without a MAC (the old events key is gone with the vault).
 */
export function performReset(): void {
  const { home, dbPath } = config();
  const plan = planReset();
  const targets = [path.join(home, 'vault.json'), dbPath, `${dbPath}-wal`, `${dbPath}-shm`];
  if (fs.existsSync(home)) {
    for (const f of fs.readdirSync(home)) if (/^vault\.json\..*\.tmp$/.test(f)) targets.push(path.join(home, f));
  }
  // The anchor file is MAC'd with the key that is about to disappear. The Keychain copy stays on purpose.
  targets.push(config().anchorFile);
  for (const t of targets) fs.rmSync(t, { force: true });
  appendEvent('reset', { credentials: plan.credentials.length, proxies: plan.proxies }, { signed: false });
}
