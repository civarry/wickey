<script lang="ts">
  import Check from '@lucide/svelte/icons/check';
  import X from '@lucide/svelte/icons/x';
  import { app } from '../state.svelte.ts';
</script>

<!-- The live region stays mounted so screen readers announce each new message. -->
<div role="status" aria-live="polite" data-toast class="pointer-events-none fixed right-4 bottom-4 z-[70] w-[min(24rem,calc(100vw-2rem))]">
  {#if app.toastMessage}
    {@const t = app.toastMessage}
    <div class="pointer-events-auto flex items-start gap-3 rounded-lg border border-border-strong bg-surface-2 p-3 shadow-pop">
      <span class="mt-0.5 grid size-5 shrink-0 place-items-center rounded-full bg-accent-bg text-accent-text"><Check size={12} aria-hidden="true" /></span>
      <div class="min-w-0 flex-1 text-[13px]">
        <p class="font-semibold">{t.title}</p>
        {#if t.body}<p class="mt-0.5 text-text-muted">{t.body}</p>{/if}
      </div>
      <button
        type="button"
        aria-label="Dismiss"
        onclick={() => app.dismissToast()}
        class="grid size-6 shrink-0 place-items-center rounded-sm text-text-muted hover:bg-border hover:text-text"
      >
        <X size={13} aria-hidden="true" />
      </button>
    </div>
  {/if}
</div>
