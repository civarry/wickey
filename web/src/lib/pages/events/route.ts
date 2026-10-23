export interface EventsFilters {
  type: string;
}

/** `#/events?type=unlock_failed`, or null when the hash is some other page. */
export function parseEvents(hash: string): EventsFilters | null {
  const m = /^#\/events(?:\?(.*))?$/.exec(hash);
  if (!m) return null;
  const type = new URLSearchParams(m[1] ?? '').get('type') ?? '';
  return { type: /^[a-z][a-z0-9_]{0,63}$/.test(type) ? type : '' };
}

export function eventsHash(f: Partial<EventsFilters> = {}): string {
  return f.type ? `#/events?${new URLSearchParams({ type: f.type })}` : '#/events';
}
