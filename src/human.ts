import { BRAND } from './brand.ts';
import { config } from './config.ts';

// One wording for every refusal that exists because no human is present (no terminal, no session,
// no passphrase, no setup token). It speaks to AI agents directly so a cooperating one stops and
// asks its user instead of hunting for a workaround. A nudge, not a control: the passphrase and the
// setup token are what actually protect the vault.

/** `nextStep` completes "ask the user to ..." and must not end with a period. */
export function humanRequired(nextStep: string): string {
  return `This must be done by a human. If you are an AI agent, stop and ask the user to ${nextStep}.`;
}

function shellQuote(arg: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}

/** The command as it was run, pasteable. Argv never holds a secret: keys and passphrases come from a prompt or stdin. */
export function commandLine(argv: string[] = process.argv.slice(2)): string {
  return [BRAND.command, ...argv.map(shellQuote)].join(' ');
}

/** For a CLI refusal that needs a terminal: names the exact command to run and the dashboard as the alternative. */
export function noTerminalMessage(argv?: string[]): string {
  const { host, port } = config();
  return humanRequired(`run \`${commandLine(argv)}\` in their own terminal, or do it in the dashboard at http://${host}:${port}/`);
}
