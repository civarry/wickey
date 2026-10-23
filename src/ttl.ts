// Short default while the MVP is being tested, so expiry is visible within a minute.
export const DEFAULT_TTL_SECONDS = 60;

const UNIT_SECONDS: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };

/** Parses "30", "30s", "5m", "2h", "1d" into seconds. A bare number means seconds. */
export function parseTtl(input: string): number {
  const match = /^(\d+)\s*([smhd]?)$/i.exec(input.trim());
  if (!match) {
    throw new Error(`Invalid TTL "${input}". Use a number with s, m, h or d, e.g. 30s, 5m, 2h.`);
  }
  const seconds = Number(match[1]) * UNIT_SECONDS[(match[2] || 's').toLowerCase()];
  if (seconds < 1) throw new Error('TTL must be at least 1 second.');
  return seconds;
}

export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  if (s < 60) return `${s}s`;
  const parts: string[] = [];
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const rest = s % 60;
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (rest && !d) parts.push(`${rest}s`);
  return parts.join(' ');
}
