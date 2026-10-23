import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

test('a v0.1 database (hash only, no token column) upgrades in place', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-migrate-'));
  process.env.WICKEY_HOME = home;
  const old = new DatabaseSync(path.join(home, 'wickey.db'));
  old.exec(`
    CREATE TABLE credentials (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, provider TEXT NOT NULL,
      base_url TEXT NOT NULL, auth_style TEXT NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE proxies (id TEXT PRIMARY KEY, label TEXT, credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL, ttl_seconds INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER);
    INSERT INTO credentials VALUES ('c1', 'legacy', 'openai', 'https://api.openai.com/v1', 'bearer', 0);
    INSERT INTO proxies VALUES ('abcd1234', NULL, 'c1', 'x', 60, 0, 1, NULL);
    INSERT INTO proxies VALUES ('revoked1', NULL, 'c1', 'x', 60, 0, 9999999999999, 5);
  `);
  old.close();

  process.env.WICKEY_SCRYPT_N = '1024';
  const store = await import('../src/store.ts');
  const session = await import('../src/session.ts');
  // Setting the passphrase adopts (signs) the rows that existed before signing did.
  session.setUp('correct horse battery staple');
  try {
    const legacy = store.getProxy('abcd1234')!;
    assert.equal(legacy.maskedKey, 'sk-wick-…', 'old proxies have no recoverable key, so no suffix');
    assert.equal(legacy.status, 'expired');
    // v0.1 "revoked" rows have a future expiry but must count as expired, not active.
    assert.equal(store.getProxy('revoked1')!.status, 'expired');
    assert.equal(store.authorize('revoked1', 'anything').ok, false);
    // Renew on a legacy row reactivates it; rotate gives a key that is shown once.
    store.renewProxy('abcd1234', 60);
    assert.equal(store.getProxy('abcd1234')!.status, 'active');
    const rotated = store.rotateProxy('abcd1234', 60);
    assert.equal(store.getProxy('abcd1234')!.maskedKey, `sk-wick-…${rotated.token.slice(-5)}`);
    assert.equal(store.authorize('abcd1234', rotated.token).ok, true);
  } finally {
    store.closeStore();
    fs.rmSync(home, { recursive: true, force: true });
  }
});
