import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';

// The proxy and the CLI (presence enable/disable/repair) both rewrite vault.json. Each change is a
// read-modify-write of the whole file, so without the lock two processes writing at once lose
// changes. Two real processes add keys concurrently; every key must survive.
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-vault-lock-'));
process.env.WICKEY_HOME = home;
process.env.WICKEY_SCRYPT_N = '1024';
const PASS = 'correct horse battery staple';
const vault = await import('../src/vault.ts');
vault.createVault(PASS);

after(() => fs.rmSync(home, { recursive: true, force: true }));

const vaultUrl = new URL('../src/vault.ts', import.meta.url).href;
const PER_WRITER = 40;

function writer(name: string): Promise<number> {
  const code = `
    const v = await import(${JSON.stringify(vaultUrl)});
    v.unlockVault(${JSON.stringify(PASS)});
    for (let i = 0; i < ${PER_WRITER}; i++) v.setSecret('${name}-' + i, 'value-' + i);
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], { env: { ...process.env }, stdio: ['ignore', 'ignore', 'inherit'] });
  return new Promise((resolve) => child.on('exit', (c) => resolve(c ?? 1)));
}

test('two processes writing the vault at once lose nothing', async () => {
  const codes = await Promise.all([writer('a'), writer('b'), writer('c')]);
  assert.deepEqual(codes, [0, 0, 0]);
  const secrets = JSON.parse(fs.readFileSync(path.join(home, 'vault.json'), 'utf8')).secrets;
  assert.equal(Object.keys(secrets).length, 3 * PER_WRITER, 'every key written by every process is still there');
  assert.equal(fs.existsSync(path.join(home, 'vault.json.lock')), false, 'the lock is released');
});

test('a lock left by a crashed process is taken over', () => {
  const lock = path.join(home, 'vault.json.lock');
  fs.writeFileSync(lock, '');
  const old = (Date.now() - 60_000) / 1000;
  fs.utimesSync(lock, old, old);
  vault.unlockVault(PASS);
  vault.setSecret('after-crash', 'x');
  assert.equal(fs.existsSync(lock), false);
});
