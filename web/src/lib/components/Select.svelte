<script lang="ts">
  import type { HTMLSelectAttributes } from 'svelte/elements';
  import type { Snippet } from 'svelte';

  interface Props extends Omit<HTMLSelectAttributes, 'class' | 'value'> {
    label: string;
    value?: string;
    help?: string;
    error?: string;
    class?: string;
    /** `<option>` elements. */
    children: Snippet;
  }

  let { label, value = $bindable(''), help, error, id, class: extra = '', children, ...rest }: Props = $props();

  const uid = $props.id();
  const selectId = $derived(id ?? `sel-${uid}`);
  const noteId = $derived(`${selectId}-note`);
</script>

<div class="flex min-w-0 flex-col gap-1.5 {extra}">
  <label for={selectId} class="text-[13px] font-medium">{label}</label>
  <select
    {...rest}
    id={selectId}
    bind:value
    aria-invalid={error ? true : undefined}
    aria-describedby={error || help ? noteId : undefined}
    class="h-9 w-full rounded-md border bg-input px-3 text-sm text-text disabled:cursor-not-allowed disabled:opacity-45 {error ? 'border-danger' : 'border-border-strong'}"
  >
    {@render children()}
  </select>
  {#if error}
    <p id={noteId} class="text-xs text-danger-text">{error}</p>
  {:else if help}
    <p id={noteId} class="text-xs text-text-muted">{help}</p>
  {/if}
</div>
