<script lang="ts">
  import type { HTMLTextareaAttributes } from 'svelte/elements';

  interface Props extends Omit<HTMLTextareaAttributes, 'class' | 'value'> {
    label: string;
    value?: string;
    help?: string;
    mono?: boolean;
    class?: string;
  }
  let { label, value = $bindable(''), help, mono = false, id, class: extra = '', ...rest }: Props = $props();

  const uid = $props.id();
  const inputId = $derived(id ?? `ta-${uid}`);
  const noteId = $derived(`${inputId}-note`);
</script>

<div class="flex min-w-0 flex-col gap-1.5 {extra}">
  <label for={inputId} class="text-[13px] font-medium">{label}</label>
  <textarea
    {...rest}
    id={inputId}
    bind:value
    aria-describedby={help ? noteId : undefined}
    class="w-full resize-none rounded-md border border-border-strong bg-input px-3 py-2 text-sm text-text disabled:cursor-not-allowed disabled:opacity-45 {mono ? 'font-mono text-[13px]' : ''}"
  ></textarea>
  {#if help}<p id={noteId} class="text-xs text-text-muted">{help}</p>{/if}
</div>
