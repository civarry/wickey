import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-resign-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
after(() => fs.rmSync(home, { recursive: true, force: true }));

const store = await import('../src/store.ts');
const vault = await import('../src/vault.ts');

test('resignAllRows makes rows signed by an older vault verify under a new one, without changing values', () => {
  vault.createVault('first passphrase here');
  const cred = store.addCredential({ name: 'work', provider: 'openai', apiKey: 'sk-real-secret' });
  const { proxy, token } = store.issueProxy({ credential: 'work', ttlSeconds: 600 });
  store.recordUsage(proxy.id, { tokensIn: 5, tokensOut: 7, counted: true, at: Date.now() });
  const usageBefore = store.getUsage(proxy.id);
  const versionBefore = (store.getProxy(proxy.id) as any).version;
  assert.equal(store.authorize(proxy.id, token).ok, true);

  // A fresh vault (new random data key) holding the same secrets, as a migration would build it.
  vault.lockVault();
  store.closeStore();
  fs.rmSync(path.join(home, 'vault.json'));
  vault.createVault('second passphrase here');
  vault.setSecret(cred.id, 'sk-real-secret');

  assert.equal(store.authorize(proxy.id, token).ok, false, 'old signatures do not verify under the new key');
  assert.equal(store.getUsage(proxy.id).ok, false);

  store.resignAllRows();

  assert.equal(store.authorize(proxy.id, token).ok, true);
  const usageAfter = store.getUsage(proxy.id);
  assert.equal(usageAfter.ok, true);
  assert.deepEqual({ ...usageAfter, ok: true }, { ...usageBefore, ok: true }, 'usage totals are unchanged');
  assert.equal((store.getProxy(proxy.id) as any).version, versionBefore, 'row versions are unchanged');
});

test('the database sidecar files are not group or world readable', { skip: process.platform === 'win32' }, () => {
  store.closeStore();
  const db = path.join(home, 'wickey.db');
  // A brand new database: SQLite creates the file and its sidecars with the umask's modes before
  // the store tightens them.
  for (const f of [db, `${db}-wal`, `${db}-shm`]) fs.rmSync(f, { force: true });
  const oldUmask = process.umask(0o022);
  try { store.listCredentials(); } finally { process.umask(oldUmask); }
  assert.equal(fs.existsSync(`${db}-wal`), true, 'the sidecar exists while the store is open');
  for (const f of [db, `${db}-wal`, `${db}-shm`]) {
    if (fs.existsSync(f)) assert.equal(fs.statSync(f).mode & 0o077, 0, `${path.basename(f)} is owner-only`);
  }
});
