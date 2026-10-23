<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    body?: string;
    action?: Snippet;
  }
  let { title, body, action }: Props = $props();
</script>

<div class="flex flex-col items-center gap-1.5 px-6 py-10 text-center">
  <h3 class="text-sm font-semibold">{title}</h3>
  {#if body}<p class="max-w-md text-[13px] text-text-muted">{body}</p>{/if}
  {#if action}<div class="mt-3">{@render action()}</div>{/if}
</div>
