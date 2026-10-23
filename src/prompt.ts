import fs from 'node:fs';
import tty from 'node:tty';

interface Terminal { input: tty.ReadStream; output: NodeJS.WritableStream; close(): void }

/**
 * The user's terminal, even when stdin/stdout are redirected: `eval "$(wickey env ...)"`
 * captures stdout, but the passphrase prompt still has to reach the person at the keyboard.
 * Null when there is no terminal at all (cron, CI, an agent's subprocess), so nothing can answer.
 */
function openTerminal(): Terminal | null {
  if (process.stdin.isTTY) return { input: process.stdin as tty.ReadStream, output: process.stderr, close() {} };
  try {
    const [inPath, outPath] = process.platform === 'win32' ? ['CONIN$', 'CONOUT$'] : ['/dev/tty', '/dev/tty'];
    const input = new tty.ReadStream(fs.openSync(inPath, 'r'));
    const output = new tty.WriteStream(fs.openSync(outPath, 'w'));
    return { input, output, close() { input.destroy(); output.destroy(); } };
  } catch {
    return null;
  }
}

/** Whether anyone could answer a prompt right now. */
export function hasTerminal(): boolean {
  const term = openTerminal();
  term?.close();
  return term !== null;
}

/** Reads a line without echoing it. Resolves null when there is no terminal to ask. */
export function promptHidden(question: string): Promise<string | null> {
  const term = openTerminal();
  if (!term) return Promise.resolve(null);
  const { input, output } = term;
  output.write(question);
  input.setRawMode(true);
  input.setEncoding('utf8');
  input.resume();
  return new Promise((resolve) => {
    let value = '';
    const finish = (result: string | null) => {
      input.off('data', onData);
      input.setRawMode(false);
      input.pause();
      output.write('\n');
      term.close();
      resolve(result);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return finish(value);
        if (ch === '\u0003') return finish(null); // Ctrl-C cancels
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else value += ch;
      }
    };
    input.on('data', onData);
  });
}

/** Reads a line with normal echo (for confirmations like typing `reset`). Null when there is no terminal. */
export function promptVisible(question: string): Promise<string | null> {
  const term = openTerminal();
  if (!term) return Promise.resolve(null);
  const { input, output } = term;
  output.write(question);
  input.setEncoding('utf8');
  input.resume();
  return new Promise((resolve) => {
    let value = '';
    const onData = (chunk: string) => {
      value += chunk;
      const end = value.search(/[\r\n]/);
      if (end === -1) return;
      input.off('data', onData);
      input.pause();
      term.close();
      resolve(value.slice(0, end));
    };
    input.on('data', onData);
  });
}

/** For values piped in (`echo $KEY | wickey add ...`). */
export async function readPiped(): Promise<string> {
  let data = '';
  for await (const chunk of process.stdin) data += chunk;
  return data.trim();
}
