import type { Action } from 'svelte/action';

export interface ModalOptions {
  onclose?: () => void;
  /** Selector for the element to focus first; defaults to the first focusable one. */
  initial?: string;
}

const FOCUSABLE = 'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])';

/**
 * Overlay behaviour shared by dialogs and the drawer: focus moves in on open, Tab stays inside,
 * Escape closes, and focus goes back to whatever opened it. Listening on the node (not the
 * document) means a dialog stacked above the drawer swallows its own Escape.
 */
export const modal: Action<HTMLElement, ModalOptions | undefined> = (node, options) => {
  let opts = options ?? {};
  const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;

  // Wait a frame so conditionally rendered children (e.g. inputs) exist before we look for them.
  const raf = requestAnimationFrame(() => {
    const target = (opts.initial && node.querySelector<HTMLElement>(opts.initial)) || node.querySelector<HTMLElement>(FOCUSABLE) || node;
    target.focus();
  });

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.stopPropagation();
      opts.onclose?.();
      return;
    }
    if (e.key !== 'Tab') return;
    const items = [...node.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.offsetParent !== null || el === document.activeElement);
    if (!items.length) return e.preventDefault();
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && (document.activeElement === first || document.activeElement === node)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }
  node.addEventListener('keydown', onkeydown);

  return {
    update(next) {
      opts = next ?? {};
    },
    destroy() {
      cancelAnimationFrame(raf);
      node.removeEventListener('keydown', onkeydown);
      if (previous?.isConnected) previous.focus();
    },
  };
};
