import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { helperPath, setPresenceDeps, type Exec } from '../src/presence.ts';

// A stand-in for the native helper: no Secure Enclave, no system prompt, ever. The "secret" of a key
// directory is random bytes made at `create` and kept in memory plus a file next to the handle, so
// it behaves like the real one (same secret on every approved use, gone when the key is deleted).

export type Mode = 'approve' | 'cancel' | 'fail' | 'gone';

export interface FakePresence {
  mode: Mode;
  /** What `probe` answers. */
  available: boolean;
  /** Wait this long inside `use`, like a person deciding. */
  delayMs: number;
  /** Every argv the helper was run with, `use` calls include the exact prompt reason. */
  calls: string[][];
  uses(): string[];
  install(): void;
  uninstall(): void;
}

export function fakePresence(): FakePresence {
  const f: FakePresence = {
    mode: 'approve',
    available: true,
    delayMs: 0,
    calls: [],
    uses: () => f.calls.filter((c) => c[0] === 'use').map((c) => c[c.indexOf('--reason') + 1]),
    install: () => setPresenceDeps({ exec, platform: 'darwin' }),
    uninstall: () => setPresenceDeps(null),
  };
  const out = (o: unknown, code = 0) => ({ code, stdout: JSON.stringify(o), stderr: '' });
  const exec: Exec = async (file, args) => {
    if (file === 'xcrun' && args[0] === '--find') return { code: 0, stdout: '/fake/swiftc', stderr: '' };
    if (file === 'xcrun') {
      // swiftc ... -o <out>: the "binary" is fixed text, so its hash is stable.
      const target = args[args.indexOf('-o') + 1];
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, 'fake presence helper v1');
      return { code: 0, stdout: '', stderr: '' };
    }
    if (file === 'codesign') return { code: 0, stdout: '', stderr: '' };
    if (file !== helperPath()) throw new Error(`unexpected exec: ${file}`);
    f.calls.push(args);
    const [cmd, dir] = args;
    const secretFile = dir ? path.join(dir, 'fake.secret') : '';
    if (cmd === 'probe') return f.available ? out({ available: true }) : out({ available: false, reason: 'no-secure-enclave' }, 1);
    if (cmd === 'create') {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'key.handle'), 'x');
      fs.writeFileSync(secretFile, randomBytes(32));
      return out({ ok: true });
    }
    if (cmd === 'delete') {
      fs.rmSync(dir, { recursive: true, force: true });
      return out({ ok: true });
    }
    if (cmd === 'use') {
      if (f.delayMs) await new Promise((r) => setTimeout(r, f.delayMs));
      if (f.mode === 'cancel') return out({ ok: false, code: -2, message: 'canceled' }, 1);
      if (f.mode === 'fail') return out({ ok: false, code: -1, message: 'boom' }, 1);
      if (f.mode === 'gone' || !fs.existsSync(secretFile)) return out({ ok: false, code: -25300, message: 'key not found' }, 1);
      return out({ ok: true, secret: fs.readFileSync(secretFile).toString('base64') });
    }
    return out({ ok: false }, 1);
  };
  return f;
}
