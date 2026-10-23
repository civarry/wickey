<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    /** Plain-text heading. Use `header` for custom content. */
    title?: string;
    description?: string;
    /** Replaces the default heading block. */
    header?: Snippet;
    /** Right-aligned controls in the header. */
    actions?: Snippet;
    id?: string;
    class?: string;
    children: Snippet;
  }

  let { title, description, header, actions, id, class: extra = '', children }: Props = $props();
  const headingId = $derived(id && title ? `${id}-heading` : undefined);
</script>

<section {id} aria-labelledby={headingId} class="rounded-lg border border-border bg-surface {extra}">
  {#if header || title || actions}
    <div class="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3.5">
      {#if header}
        {@render header()}
      {:else}
        <div class="min-w-0">
          <h2 id={headingId} class="text-[15px] font-semibold">{title}</h2>
          {#if description}<p class="mt-0.5 text-[13px] text-text-muted">{description}</p>{/if}
        </div>
      {/if}
      {#if actions}<div class="flex flex-wrap items-center gap-2">{@render actions()}</div>{/if}
    </div>
  {/if}
  {@render children()}
</section>
