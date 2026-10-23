<script lang="ts">
  import type { Snippet } from 'svelte';
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import Eye from '@lucide/svelte/icons/eye';
  import EyeOff from '@lucide/svelte/icons/eye-off';
  import Tooltip from './Tooltip.svelte';
  import { app } from '../state.svelte.ts';
  import { copyText, maskKey } from '../util.ts';

  interface Props {
    label: string;
    /** The full value. Copy always copies this, never the masked display. */
    value: string;
    /** Show a masked form (sk-wick-••••) with a reveal toggle. */
    masked?: boolean;
    revealed?: boolean;
    mono?: boolean;
    /** When set, shows this muted message instead of the value and offers no copy. */
    unavailable?: string;
    /** With `unavailable`: what to offer instead of Copy (e.g. a button that gets a new value). */
    action?: Snippet;
  }

  let { label, value, masked = false, revealed = $bindable(false), mono = true, unavailable, action }: Props = $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const shown = $derived(masked && !revealed ? maskKey(value) : value);

  async function copy() {
    if (!(await copyText(value))) return app.toast('Copy failed', 'The browser blocked clipboard access.');
    copied = true;
    clearTimeout(timer);
    timer = setTimeout(() => (copied = false), 1600);
  }
</script>

<div class="flex min-w-0 flex-col gap-1.5">
  <span class="text-[13px] font-medium">{label}</span>
  <div class="flex min-w-0 items-center gap-1 rounded-md border border-border-strong bg-input py-1 pr-1 pl-3">
    {#if unavailable}
      <span class="flex min-w-0 flex-1">
        <Tooltip text={unavailable} block focusable><span class="min-w-0 truncate py-1.5 text-[13px] text-text-muted">{unavailable}</span></Tooltip>
      </span>
    {:else}
    <code class="min-w-0 flex-1 truncate py-1 text-[13px] {mono ? 'font-mono' : ''}" aria-label={label + ' value'}>{shown}</code>
    {/if}
    {#if unavailable}
      <!-- nothing to reveal or copy -->
      {#if action}<span class="shrink-0">{@render action()}</span>{/if}
    {:else}
    {#if masked}
      <button
        type="button"
        aria-label={revealed ? `Hide ${label}` : `Show ${label}`}
        aria-pressed={revealed}
        onclick={() => (revealed = !revealed)}
        class="grid size-8 shrink-0 place-items-center rounded-sm text-text-muted hover:bg-surface-2 hover:text-text"
      >
        {#if revealed}<EyeOff size={16} aria-hidden="true" />{:else}<Eye size={16} aria-hidden="true" />{/if}
      </button>
    {/if}
    <button
      type="button"
      aria-label={`Copy ${label}`}
      onclick={copy}
      class="inline-flex h-8 shrink-0 items-center gap-1.5 rounded-sm px-2.5 text-[13px] font-medium hover:bg-surface-2 {copied ? 'text-accent-text' : 'text-text-muted hover:text-text'}"
    >
      {#if copied}<Check size={14} aria-hidden="true" /><span role="status">Copied</span>{:else}<Copy size={14} aria-hidden="true" />Copy{/if}
    </button>
    {/if}
  </div>
</div>
