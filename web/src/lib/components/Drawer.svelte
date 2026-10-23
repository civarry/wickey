<script lang="ts">
  import type { Snippet } from 'svelte';
  import X from '@lucide/svelte/icons/x';
  import { modal } from '../modal.ts';
  import Button from './Button.svelte';

  interface Props {
    open: boolean;
    title: string;
    subtitle?: string;
    onclose: () => void;
    /** For multi-column content such as a review list. Still full width on a phone. */
    wide?: boolean;
    children: Snippet;
    footer?: Snippet;
  }

  let { open = $bindable(), title, subtitle, onclose, wide = false, children, footer }: Props = $props();
  const uid = $props.id();

  function close() {
    open = false;
    onclose();
  }
</script>

{#if open}
  <div class="fixed inset-0 z-40 flex justify-end">
    <button type="button" tabindex="-1" aria-label="Close panel" onclick={close} class="absolute inset-0 cursor-default bg-scrim"></button>
    <div
      role="dialog"
      data-drawer
      aria-modal="true"
      aria-labelledby="{uid}-title"
      use:modal={{ onclose: close }}
      class="relative flex h-full w-full {wide ? 'max-w-3xl' : 'max-w-md'} flex-col border-l border-border-strong bg-surface shadow-pop"
    >
      <div class="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div class="min-w-0">
          <h2 id="{uid}-title" class="text-base font-semibold">{title}</h2>
          {#if subtitle}<p class="mt-0.5 truncate text-[13px] text-text-muted">{subtitle}</p>{/if}
        </div>
        <Button variant="ghost" size="sm" iconOnly aria-label="Close" onclick={close}><X size={16} aria-hidden="true" /></Button>
      </div>
      <div class="flex-1 overflow-y-auto px-5 py-4">{@render children()}</div>
      {#if footer}
        <div class="flex items-center justify-end gap-2 border-t border-border px-5 py-3">{@render footer()}</div>
      {/if}
    </div>
  </div>
{/if}
