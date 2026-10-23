// Dynamic import: test files set WICKEY_* env vars first, and src modules must load after that.
/** A fresh logged-in session for the in-process server under test (what the dashboard's cookie is). */
export async function sessionCookie(): Promise<string> {
  const s = await import('../src/session.ts');
  return `${s.SESSION_COOKIE}=${s.createSession()}`;
}
