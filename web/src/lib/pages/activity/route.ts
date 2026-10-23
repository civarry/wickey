export type StatusFilter = 'all' | 'ok' | 'refused';

export interface ActivityFilters {
  proxy: string;
  status: StatusFilter;
}

/** `#/activity?proxy=<id>&status=ok|refused`, or null when the hash is some other page. */
export function parseActivity(hash: string): ActivityFilters | null {
  const m = /^#\/activity(?:\?(.*))?$/.exec(hash);
  if (!m) return null;
  const q = new URLSearchParams(m[1] ?? '');
  const status = q.get('status');
  return { proxy: q.get('proxy') ?? '', status: status === 'ok' || status === 'refused' ? status : 'all' };
}

export function activityHash(f: Partial<ActivityFilters> = {}): string {
  const q = new URLSearchParams();
  if (f.proxy) q.set('proxy', f.proxy);
  if (f.status && f.status !== 'all') q.set('status', f.status);
  const s = q.toString();
  return `#/activity${s ? `?${s}` : ''}`;
}
