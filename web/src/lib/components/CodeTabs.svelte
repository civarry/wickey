<script module lang="ts">
  export interface CodeTab {
    id: string;
    label: string;
    /** Full example, copied as is. */
    text: string;
    /** What is displayed while masked. Falls back to `text`. */
    maskedText?: string;
    note?: string;
  }
</script>

<script lang="ts">
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import Lock from '@lucide/svelte/icons/lock';
  import { app } from '../state.svelte.ts';
  import { copyText } from '../util.ts';

  interface Props {
    tabs: CodeTab[];
    /** Id of the selected tab. */
    active?: string;
    /** Show `text` instead of `maskedText`. */
    revealed?: boolean;
    label?: string;
  }

  let { tabs, active = $bindable(), revealed = false, label = 'Usage examples' }: Props = $props();

  const uid = $props.id();
  const current = $derived(tabs.find((t) => t.id === active) ?? tabs[0]);
  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    if (!current) return;
    if (!(await copyText(current.text))) return app.toast('Copy failed', 'The browser blocked clipboard access.');
    copied = true;
    clearTimeout(timer);
    timer = setTimeout(() => (copied = false), 1600);
  }

  function onkeydown(e: KeyboardEvent) {
    const dir = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (!dir || !current) return;
    e.preventDefault();
    const next = tabs[(tabs.indexOf(current) + dir + tabs.length) % tabs.length];
    active = next.id;
    document.getElementById(`${uid}-tab-${next.id}`)?.focus();
  }
</script>

{#if current}
  <div class="overflow-hidden rounded-md border border-border-strong bg-input">
    <div class="flex items-center justify-between gap-2 border-b border-border px-2 py-1.5">
      <div role="tablist" aria-label={label} tabindex="-1" {onkeydown} class="flex gap-0.5 overflow-x-auto">
        {#each tabs as t (t.id)}
          <button
            type="button"
            role="tab"
            id="{uid}-tab-{t.id}"
            aria-selected={t.id === current.id}
            aria-controls="{uid}-panel"
            tabindex={t.id === current.id ? 0 : -1}
            onclick={() => (active = t.id)}
            class="h-7 rounded-sm px-2.5 text-xs font-medium whitespace-nowrap {t.id === current.id ? 'bg-border-strong text-text' : 'text-text-muted hover:text-text'}"
          >
            {t.label}
          </button>
        {/each}
      </div>
      <button
        type="button"
        onclick={copy}
        class="inline-flex h-7 shrink-0 items-center gap-1.5 rounded-sm border border-border-strong px-2.5 text-xs font-medium hover:bg-surface-2 {copied ? 'text-accent-text' : 'text-text'}"
      >
        {#if copied}<Check size={13} aria-hidden="true" /><span role="status">Copied</span>{:else}<Copy size={13} aria-hidden="true" />Copy example{/if}
      </button>
    </div>
    <div role="tabpanel" id="{uid}-panel" aria-labelledby="{uid}-tab-{current.id}" tabindex="0">
      <pre class="overflow-x-auto p-3 font-mono text-[12.5px] leading-relaxed whitespace-pre text-text">{revealed ? current.text : (current.maskedText ?? current.text)}</pre>
    </div>
    {#if current.note}
      <p class="flex items-center gap-1.5 border-t border-border px-3 py-2 text-xs text-text-muted">
        <Lock size={13} aria-hidden="true" class="shrink-0" />{current.note}
      </p>
    {/if}
  </div>
{/if}
