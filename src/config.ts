import os from 'node:os';
import path from 'node:path';
import { BRAND, envVar } from './brand.ts';

// Read at call time so tests can point everything at a temp home and a throwaway data directory.
export function config() {
  const home = envVar('HOME') ?? path.join(os.homedir(), BRAND.dataDirName);
  const logsDir = path.join(home, BRAND.logDirName);
  return {
    home,
    dbPath: path.join(home, BRAND.dbFileName),
    eventsFile: path.join(home, BRAND.eventsFileName),
    logsDir,
    logFile: path.join(logsDir, BRAND.logFileName),
    host: '127.0.0.1',
    port: Number(envVar('PORT') ?? 7777),
  };
}
