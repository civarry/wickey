<script lang="ts">
  import { tick } from 'svelte';
  import type { Snippet } from 'svelte';
  import { place } from '../position.ts';

  /** Props the `trigger` snippet must spread onto its button (`<button {...p}>`). */
  export interface TriggerProps {
    type: 'button';
    'aria-expanded': boolean;
    'aria-haspopup': 'dialog';
    'aria-controls': string;
    onclick: () => void;
  }

  /**
   * Small interactive panel tied to one control. Opens on trigger click, floats (position: fixed)
   * so nothing reflows, flips and clamps to stay in the viewport.
   *
   * Props:
   * - open (bindable): whether it is showing.
   * - label: accessible name of the dialog.
   * - onapply: called by apply(). Return false to reject (e.g. validation failed): it stays open.
   * - trigger(props): render the opener; spread `props` on a button.
   * - children({ close, apply }): panel content. close() = cancel, apply() = onapply then close.
   *
   * Closes on Escape, outside click, close() and a successful apply(). Focus moves to the first
   * field on open and back to the trigger on Escape, close() and apply(). An outside click leaves
   * focus where the click put it, so it never steals focus from the thing the user chose.
   */
  interface Props {
    open?: boolean;
    label: string;
    onapply?: () => boolean | void;
    trigger: Snippet<[TriggerProps]>;
    children: Snippet<[{ close: () => void; apply: () => void }]>;
  }
  let { open = $bindable(false), label, onapply, trigger, children }: Props = $props();

  const uid = $props.id();
  const id = `pop-${uid}`;
  let wrap = $state<HTMLElement>();
  let panel = $state<HTMLElement>();
  let pos = $state({ top: 0, left: 0 });

  function triggerEl(): HTMLElement | null {
    return wrap?.querySelector<HTMLElement>(`[aria-controls="${id}"]`) ?? null;
  }
  function close() {
    open = false;
    triggerEl()?.focus();
  }
  function apply() {
    if (onapply?.() === false) return;
    close();
  }

  function reposition() {
    const t = triggerEl();
    if (!t || !panel) return;
    const p = place(t.getBoundingClientRect(), panel.getBoundingClientRect(), { prefer: 'bottom', align: 'start', gap: 8 });
    pos = { top: p.top, left: p.left };
  }

  $effect(() => {
    if (!open) return;
    reposition();
    tick().then(() => panel?.querySelector<HTMLElement>('input, select, textarea, button')?.focus());
    const outside = (e: PointerEvent) => {
      if (!wrap?.contains(e.target as Node)) open = false;
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        close();
      }
    };
    document.addEventListener('pointerdown', outside);
    document.addEventListener('keydown', key);
    window.addEventListener('scroll', reposition, true);
    window.addEventListener('resize', reposition);
    return () => {
      document.removeEventListener('pointerdown', outside);
      document.removeEventListener('keydown', key);
      window.removeEventListener('scroll', reposition, true);
      window.removeEventListener('resize', reposition);
    };
  });

  // Enter in a field applies the popover instead of submitting a form it may sit inside.
  function panelKey(e: KeyboardEvent) {
    if (e.key === 'Enter' && (e.target as HTMLElement).tagName === 'INPUT') {
      e.preventDefault();
      apply();
    }
  }
</script>

<span bind:this={wrap} class="inline-flex">
  {@render trigger({ type: 'button', 'aria-expanded': open, 'aria-haspopup': 'dialog', 'aria-controls': id, onclick: () => (open ? close() : (open = true)) })}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    bind:this={panel}
    {id}
    role="dialog"
    aria-label={label}
    tabindex="-1"
    hidden={!open}
    onkeydown={panelKey}
    style:top="{pos.top}px"
    style:left="{pos.left}px"
    class="fixed z-40 w-max max-w-[calc(100vw-1rem)] rounded-lg border border-border-strong bg-surface p-4 shadow-pop"
  >
    {#if open}{@render children({ close, apply })}{/if}
  </div>
</span>
