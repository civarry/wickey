<script lang="ts">
  import type { Snippet } from 'svelte';
  import { place } from '../position.ts';

  /**
   * Read-only explanation of a label, icon, button or status. One short sentence, plain text only:
   * the API takes a string so inputs, buttons and links cannot end up inside it.
   *
   * Props:
   * - text: the sentence.
   * - focusable: for disabled buttons (they receive no focus or hover). Wraps the trigger in a
   *   tab-stop and lets the wrapper take the pointer, so the tooltip opens on hover and Tab.
   *   Also use it for truncated text that has no other focusable element.
   * - block: let the wrapper fill its parent (needed for truncated text), instead of shrink-wrapping.
   * - prefer: 'top' | 'bottom' (default 'top'); flips if it would overflow the viewport.
   * - children: the trigger.
   */
  interface Props {
    text: string;
    focusable?: boolean;
    block?: boolean;
    prefer?: 'top' | 'bottom';
    children: Snippet;
  }
  let { text, focusable = false, block = false, prefer = 'top', children }: Props = $props();

  const uid = $props.id();
  const id = `tip-${uid}`;
  let open = $state(false);
  let wrap = $state<HTMLElement>();
  let tip = $state<HTMLElement>();
  let pos = $state({ top: 0, left: 0 });
  let timer: ReturnType<typeof setTimeout> | undefined;

  function show(delay: number) {
    clearTimeout(timer);
    if (delay) timer = setTimeout(() => (open = true), delay);
    else open = true;
  }
  function hide() {
    clearTimeout(timer);
    open = false;
  }

  // Point the real trigger (the wrapper's first child) at the tooltip. In focusable mode the wrapper is the trigger.
  $effect(() => {
    const target = focusable ? wrap : wrap?.firstElementChild;
    target?.setAttribute('aria-describedby', id);
  });

  function reposition() {
    if (!wrap || !tip) return;
    const p = place(wrap.getBoundingClientRect(), tip.getBoundingClientRect(), { prefer, align: 'center' });
    pos = { top: p.top, left: p.left };
  }
  $effect(() => {
    if (!open) return;
    reposition();
    window.addEventListener('scroll', reposition, true);
    window.addEventListener('resize', reposition);
    return () => {
      window.removeEventListener('scroll', reposition, true);
      window.removeEventListener('resize', reposition);
    };
  });
  $effect(() => () => clearTimeout(timer));
</script>

<!-- The wrapper only listens; it is a tab-stop only in focusable mode. -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_static_element_interactions -->
<span
  bind:this={wrap}
  role={focusable ? 'group' : undefined}
  tabindex={focusable ? 0 : undefined}
  onmouseenter={() => show(300)}
  onmouseleave={hide}
  onfocusin={() => show(0)}
  onfocusout={hide}
  onkeydown={(e) => e.key === 'Escape' && open && (hide(), e.stopPropagation())}
  class="rounded-sm {block ? 'flex min-w-0 max-w-full' : 'inline-flex'} {focusable ? '*:pointer-events-none' : ''}"
>
  {@render children()}
  <span
    bind:this={tip}
    {id}
    role="tooltip"
    hidden={!open}
    style:top="{pos.top}px"
    style:left="{pos.left}px"
    class="pointer-events-none fixed z-50 w-max max-w-64 rounded-md border border-border-strong bg-surface-2 px-2.5 py-1.5 text-xs font-normal whitespace-normal text-text shadow-pop"
  >{text}</span>
</span>
