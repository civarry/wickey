/** Viewport placement shared by Tooltip and Popover (both use position: fixed, so nothing reflows). */
export interface Placement {
  top: number;
  left: number;
  side: 'top' | 'bottom';
}

export function place(
  anchor: DOMRect,
  size: { width: number; height: number },
  opts: { prefer?: 'top' | 'bottom'; align?: 'start' | 'center'; gap?: number; margin?: number } = {},
): Placement {
  const { prefer = 'bottom', align = 'center', gap = 6, margin = 8 } = opts;
  const vw = document.documentElement.clientWidth;
  const vh = window.innerHeight;
  const fitsBelow = anchor.bottom + gap + size.height <= vh - margin;
  const fitsAbove = anchor.top - gap - size.height >= margin;
  // Flip only when the preferred side overflows and the other one fits; otherwise keep the preference.
  const side = prefer === 'bottom' ? (fitsBelow || !fitsAbove ? 'bottom' : 'top') : fitsAbove || !fitsBelow ? 'top' : 'bottom';
  const top = side === 'bottom' ? anchor.bottom + gap : anchor.top - gap - size.height;
  const ideal = align === 'center' ? anchor.left + anchor.width / 2 - size.width / 2 : anchor.left;
  const left = Math.max(margin, Math.min(ideal, vw - margin - size.width));
  return { top: Math.max(margin, top), left, side };
}
