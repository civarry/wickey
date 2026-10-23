<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';

  interface Props extends Omit<HTMLInputAttributes, 'class' | 'checked' | 'type'> {
    label: string;
    checked?: boolean;
    help?: string;
    /** Monospace label, for IDs. */
    mono?: boolean;
    class?: string;
  }
  let { label, checked = $bindable(false), help, mono = false, id, class: extra = '', ...rest }: Props = $props();

  const uid = $props.id();
  const inputId = $derived(id ?? `cb-${uid}`);
  const noteId = $derived(`${inputId}-note`);
</script>

<div class="flex flex-col gap-1 {extra}">
  <label for={inputId} class="flex items-start gap-2 text-[13px] font-medium">
    <input {...rest} id={inputId} type="checkbox" bind:checked aria-describedby={help ? noteId : undefined} class="mt-0.5 size-4 shrink-0 accent-accent" />
    <span class={mono ? 'min-w-0 font-mono text-[13px] font-normal break-all' : ''}>{label}</span>
  </label>
  {#if help}<p id={noteId} class="pl-6 text-xs text-text-muted">{help}</p>{/if}
</div>
