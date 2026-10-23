import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-pass-test-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
const vault = await import('../src/vault.ts');

test('new passphrases need at least 12 characters', () => {
  // A copied vault.json can be guessed offline at roughly 6 tries per second per core, so length
  // is the protection that matters.
  try {
    assert.throws(() => vault.createVault('eleven-char'), /at least 12 characters/);
    assert.equal(vault.vaultExists(), false, 'a rejected passphrase creates nothing');
    vault.createVault('twelve-chars');
    assert.equal(vault.vaultExists(), true);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
