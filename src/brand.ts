// Every product name used for files, OS integration and wire formats lives here, so a rename is
// one edit (plus package.json's "name" and "bin"). Behavior must not depend on the literal strings.
//
// WARNING: changing the wire/crypto entries below (keyPrefix, requestHeader, errorType,
// sessionCookie, cryptoContext) breaks existing data or clients: cryptoContext makes an existing
// vault undecryptable and invalidates every row signature, keyPrefix and requestHeader break
// deployed apps and scripts. It needs a migration, not just an edit.

export const BRAND = {
  /** CLI command name, as users type it. */
  command: 'wickey',
  /** Data directory under the user's home. */
  dataDirName: '.wickey',
  dbFileName: 'wickey.db',
  eventsFileName: 'events.log',
  /** Newest-signed-entry record kept next to events.log (see events.ts). */
  eventsAnchorFileName: 'events.anchor',
  /** macOS Keychain service holding the second copy of the anchor. */
  keychainService: 'dev.wickey.events',
  /** Prefix of every configuration environment variable (HOME, PORT, GRACE, ...). */
  envPrefix: 'WICKEY_',
  launchdLabel: 'dev.wickey.proxy',
  systemdUnit: 'wickey.service',
  windowsTask: 'wickey',
  /** Under the data directory. */
  logDirName: 'logs',
  logFileName: 'wickey.log',

  /** Proxy key prefix. Stored tokens are hashes of the whole token, so the prefix is only for display and generation. */
  keyPrefix: 'sk-wick-',
  /** Header the dashboard and CLI send to the management API (CSRF guard). */
  requestHeader: 'x-wickey',
  /** `error.type` in JSON errors the proxy itself returns. */
  errorType: 'wickey_error',
  /** Start of every proxy-generated error message. */
  errorPrefix: 'Wickey: ',
  sessionCookie: 'wickey_session',
  /** Root of the AEAD context and HKDF info strings in vault.ts. */
  cryptoContext: 'wickey/v1',
} as const;

/** Value of `<prefix><name>`, e.g. envVar('HOME') reads WICKEY_HOME. Read at call time. */
export function envVar(name: string): string | undefined {
  return process.env[BRAND.envPrefix + name];
}
