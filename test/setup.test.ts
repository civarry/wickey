import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-setup-test-'));
process.env.WICKEY_HOME = path.join(tmp, 'home');
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const { parsePicks } = await import('../src/setup.ts');

test('parsePicks accepts numbers, ranges and all; rejects anything not on the list', () => {
  assert.deepEqual(parsePicks('', [1, 2, 3]), []);
  assert.deepEqual(parsePicks('1,3', [1, 2, 3]), [1, 3]);
  assert.deepEqual(parsePicks('3 1 1', [1, 2, 3]), [1, 3]);
  assert.deepEqual(parsePicks('2-3', [1, 2, 3]), [2, 3]);
  assert.deepEqual(parsePicks('ALL', [1, 2, 3], [1, 3]), [1, 3]);
  assert.equal(parsePicks('4', [1, 2, 3]), null);
  assert.equal(parsePicks('2', [1, 3]), null, 'an entry that is not importable cannot be picked');
  assert.equal(parsePicks('1-9999999', [1]), null);
  assert.equal(parsePicks('x', [1]), null);
});

test('setup refuses without a terminal and says so', { skip: process.platform === 'win32' }, async () => {
  const script = fileURLToPath(new URL('../bin/wickey.js', import.meta.url));
  // detached = new session, so there is no controlling terminal for /dev/tty to open.
  const child = spawn(process.execPath, [script, 'setup'], { env: { ...process.env, WICKEY_PORT: '1' }, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let err = '';
  child.stderr.on('data', (d) => (err += d));
  child.stdin.end();
  const code = await new Promise((r) => child.once('exit', r));
  assert.equal(code, 1);
  assert.ok(err.includes('This must be done by a human.'));
});
