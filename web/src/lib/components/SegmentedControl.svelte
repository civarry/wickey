<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Option {
    value: string;
    label: string;
    /**
     * Renders this option as a custom element (e.g. a Popover trigger). It receives the shared
     * segment classes and the pressed state, and must render a button using both.
     */
    render?: Snippet<[{ class: string; pressed: boolean; disabled: boolean }]>;
  }
  interface Props {
    options: Option[];
    /** Null means none selected (e.g. a custom value is in use). */
    value?: string | null;
    label: string;
    disabled?: boolean;
    size?: 'sm' | 'md';
    onchange?: (value: string) => void;
  }

  let { options, value = $bindable(null), label, disabled = false, size = 'md', onchange }: Props = $props();

  function pick(v: string) {
    value = v;
    onchange?.(v);
  }
</script>

<div role="group" aria-label={label} class="inline-flex gap-0.5 rounded-md border border-border-strong bg-input p-0.5">
  {#each options as o (o.value)}
    {@const cls = `rounded-sm px-3 font-medium whitespace-nowrap transition-colors disabled:cursor-not-allowed disabled:opacity-45 ${size === 'sm' ? 'h-7 text-xs' : 'h-8 text-[13px]'} ${value === o.value ? 'bg-border-strong text-text' : 'text-text-muted hover:text-text'}`}
    {#if o.render}
      {@render o.render({ class: cls, pressed: value === o.value, disabled })}
    {:else}
    <button
      type="button"
      {disabled}
      aria-pressed={value === o.value}
      onclick={() => pick(o.value)}
      class={cls}
    >
      {o.label}
    </button>
    {/if}
  {/each}
</div>
