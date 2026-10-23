import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, describe, test } from 'node:test';

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wickey-presence-'));
process.env.WICKEY_HOME = home;

const p = await import('../src/presence.ts');
type Exec = import('../src/presence.ts').Exec;

after(() => fs.rmSync(home, { recursive: true, force: true }));

const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');
const ok = (stdout: string, code = 0) => ({ code, stdout, stderr: '' });

/** Writes a fake helper so verifyHelper has something to hash; returns its hash. */
function fakeHelper(content = 'fake-binary'): string {
  fs.mkdirSync(path.dirname(p.helperPath()), { recursive: true });
  fs.writeFileSync(p.helperPath(), content);
  return sha(content);
}

describe('unit (injected exec)', () => {
  test('prompt wording', () => {
    assert.equal(p.presenceReason('unlock vault', 'dashboard'), 'Wickey: unlock vault (dashboard)');
    assert.equal(p.presenceReason('change passphrase', 'wickey passphrase'), 'Wickey: change passphrase (wickey passphrase)');
    assert.equal(p.presenceReason('turn off presence'), 'Wickey: turn off presence');
    assert.equal(p.presenceReason('turn off a notification'), 'Wickey: turn off a notification');
    assert.equal(p.presenceReason('repair presence'), 'Wickey: repair presence');
  });

  test('useKey passes the exact reason, returns the secret, no shell', async () => {
    const hash = fakeHelper();
    const secret = Buffer.alloc(32, 7);
    let seen: string[] = [];
    const exec: Exec = async (_f, args) => {
      seen = args;
      return ok(JSON.stringify({ ok: true, secret: secret.toString('base64') }));
    };
    const r = await p.useKey('/d', 'Wickey: unlock vault (test)', { expectedSha256: hash, exec });
    assert.deepEqual(seen, ['use', '/d', '--reason', 'Wickey: unlock vault (test)']);
    assert.ok(r.ok && r.secret.equals(secret));
  });

  test('error mapping', async () => {
    const hash = fakeHelper();
    const run = (stdout: string) => p.useKey('/d', 'r', { expectedSha256: hash, exec: async () => ok(stdout, 1) });
    const c = await run('{"ok":false,"code":-2,"message":"User canceled"}');
    assert.ok(!c.ok && c.reason === 'cancelled');
    const n = await run('{"ok":false,"code":-1004,"message":"Not interactive"}');
    assert.ok(!n.ok && n.reason === 'not-interactive');
    const o = await run('{"ok":false,"code":-9,"message":"boom"}');
    assert.ok(!o.ok && o.reason === 'error' && o.message === 'boom');
    const g = await run('not json');
    assert.ok(!g.ok && g.reason === 'error');
  });

  test('a secret of the wrong length is not accepted', async () => {
    const hash = fakeHelper();
    const r = await p.useKey('/d', 'r', {
      expectedSha256: hash,
      exec: async () => ok(JSON.stringify({ ok: true, secret: Buffer.alloc(5).toString('base64') })),
    });
    assert.equal(r.ok, false);
  });

  test('hash mismatch refuses before exec is ever called', async () => {
    fakeHelper('tampered');
    let called = 0;
    const exec: Exec = async () => (called++, ok('{}'));
    await assert.rejects(
      p.useKey('/d', 'r', { expectedSha256: sha('original'), exec }),
      (e: Error) => e.name === 'PresenceHelperMismatch' && /wickey presence repair/.test(e.message),
    );
    assert.equal(called, 0);
    await assert.rejects(p.createKey('/d', { expectedSha256: sha('original'), exec }), p.PresenceHelperMismatch);
    assert.equal(called, 0);
  });

  test('a missing helper is a mismatch too', async () => {
    fs.rmSync(p.helperPath(), { force: true });
    assert.throws(() => p.verifyHelper(sha('x')), p.PresenceHelperMismatch);
  });

  test('no swiftc', async () => {
    await assert.rejects(
      p.buildHelper({ platform: 'darwin', exec: async () => ok('', 1) }),
      { message: 'Install the Xcode Command Line Tools: run `xcode-select --install`, then try again.' },
    );
  });

  test('compile failure shows the first compiler lines', async () => {
    const exec: Exec = async (_f, args) =>
      args[0] === '--find' ? ok('/x/swiftc') : { code: 1, stdout: '', stderr: 'a.swift:1: error: oops\nline2\n' };
    await assert.rejects(p.buildHelper({ platform: 'darwin', exec }), /error: oops/);
  });

  test('not macOS', async () => {
    await assert.rejects(p.buildHelper({ platform: 'linux' }), { message: 'Presence mode is only available on macOS for now.' });
    assert.deepEqual(await p.probe({ platform: 'linux' }), { available: false, reason: p.NOT_MACOS });
  });

  test('simulated Mac without a Secure Enclave', async () => {
    const r = await p.probe({ platform: 'darwin', exec: async () => ok('{"available":false,"reason":"no-secure-enclave"}', 1) });
    assert.equal(r.available, false);
    assert.equal(
      r.reason,
      "Presence mode needs a Mac with a Secure Enclave (Apple silicon or a Mac with a T2 chip). This Mac doesn't have one.",
    );
  });
});

function hasSwiftc(): boolean {
  if (process.platform !== 'darwin') return false;
  try {
    execFileSync('xcrun', ['--find', 'swiftc'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

describe('real helper (macOS with swiftc)', { skip: !hasSwiftc() && 'needs macOS with swiftc' }, () => {
  const keyDir = path.join(home, 'presence-key');
  let hash = '';

  test('build: perms and hash', { timeout: 150_000 }, async () => {
    hash = await p.buildHelper();
    assert.equal(hash, sha(fs.readFileSync(p.helperPath())));
    assert.equal(fs.statSync(path.dirname(p.helperPath())).mode & 0o777, 0o700);
    assert.equal(fs.statSync(p.helperPath()).mode & 0o777, 0o700);
    p.verifyHelper(hash);
  });

  test('probe reports a Secure Enclave', async () => {
    assert.deepEqual(await p.probe(), { available: true });
  });

  test('create writes 0600 files; use --no-ui fails with -1004 and never prompts', async (t) => {
    try {
      await p.createKey(keyDir, { expectedSha256: hash });
    } catch (err) {
      // -25308 (errSecInteractionNotAllowed): no unlocked GUI session (screen locked, ssh, CI).
      // Creating the key never prompts but still needs one; that is the environment, not a bug.
      if (/-25308/.test(String((err as Error).message))) return t.skip('needs an unlocked GUI session');
      throw err;
    }
    for (const f of ['key.handle', 'peer.key']) assert.equal(fs.statSync(path.join(keyDir, f)).mode & 0o777, 0o600);
    const r = await p.useKey(keyDir, p.presenceReason('unlock vault', 'test'), { expectedSha256: hash, noUi: true });
    assert.ok(!r.ok && r.reason === 'not-interactive' && r.code === -1004, JSON.stringify(r));
  });

  test('a tampered binary is refused', async () => {
    const orig = fs.readFileSync(p.helperPath());
    const bad = Buffer.from(orig);
    bad[bad.length - 1] ^= 1;
    fs.writeFileSync(p.helperPath(), bad);
    await assert.rejects(p.useKey(keyDir, 'r', { expectedSha256: hash, noUi: true }), p.PresenceHelperMismatch);
    fs.writeFileSync(p.helperPath(), orig);
    p.verifyHelper(hash);
  });

  test('delete removes the handle files', async () => {
    await p.deleteKey(keyDir, { expectedSha256: hash });
    assert.equal(fs.existsSync(path.join(keyDir, 'key.handle')), false);
    assert.equal(fs.existsSync(path.join(keyDir, 'peer.key')), false);
  });
});
