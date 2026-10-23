<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';

  import Eye from '@lucide/svelte/icons/eye';
  import EyeOff from '@lucide/svelte/icons/eye-off';

  interface Props extends Omit<HTMLInputAttributes, 'class' | 'value'> {
    label: string;
    value?: string;
    help?: string;
    error?: string;
    mono?: boolean;
    /** Appends "(optional)" to the label. */
    optional?: boolean;
    /** For secrets: adds a show/hide toggle and keeps the field a password field until shown. */
    reveal?: boolean;
    /** Keeps the label for screen readers only (e.g. a search box). */
    hideLabel?: boolean;
    class?: string;
  }

  let { label, value = $bindable(''), help, error, mono = false, optional = false, reveal = false, hideLabel = false, id, class: extra = '', ...rest }: Props = $props();

  const uid = $props.id();
  const inputId = $derived(id ?? `in-${uid}`);
  const noteId = $derived(`${inputId}-note`);
  let shown = $state(false);
  const attrs = $derived(reveal ? { ...rest, type: shown ? 'text' : 'password' } : rest);
</script>

<div class="flex min-w-0 flex-col gap-1.5 {extra}">
  <label for={inputId} class="text-[13px] font-medium {hideLabel ? 'sr-only' : ''}">
    {label}{#if optional}<span class="ml-1 font-normal text-text-muted">(optional)</span>{/if}
  </label>
  <div class="relative">
  <input
    {...attrs}
    id={inputId}
    bind:value
    aria-invalid={error ? true : undefined}
    aria-describedby={error || help ? noteId : undefined}
    class="h-9 w-full rounded-md border bg-input px-3 text-sm text-text disabled:cursor-not-allowed disabled:opacity-45 {mono ? 'font-mono text-[13px]' : ''} {error ? 'border-danger' : 'border-border-strong'} {reveal ? 'pr-10' : ''}"
  />
  {#if reveal}
    <button
      type="button"
      aria-label={shown ? `Hide ${label}` : `Show ${label}`}
      aria-pressed={shown}
      onclick={() => (shown = !shown)}
      class="absolute top-0.5 right-0.5 grid size-8 place-items-center rounded-sm text-text-muted hover:bg-surface-2 hover:text-text"
    >
      {#if shown}<EyeOff size={16} aria-hidden="true" />{:else}<Eye size={16} aria-hidden="true" />{/if}
    </button>
  {/if}
  </div>
  {#if error}
    <p id={noteId} class="text-xs text-danger-text">{error}</p>
  {:else if help}
    <p id={noteId} class="text-xs text-text-muted">{help}</p>
  {/if}
</div>
