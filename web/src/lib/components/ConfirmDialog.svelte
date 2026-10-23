<script lang="ts">
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import { Cancelled } from '../api.ts';
  import { modal } from '../modal.ts';
  import { app } from '../state.svelte.ts';
  import Button from './Button.svelte';

  const req = $derived(app.confirmRequest);
  const uid = $props.id();
  let working = $state(false);
  let error = $state('');

  function close() {
    if (working) return;
    app.confirmRequest = null;
    error = '';
  }

  async function run() {
    if (!req) return;
    working = true;
    error = '';
    try {
      await req.run();
      app.confirmRequest = null;
    } catch (err) {
      if (err instanceof Cancelled) app.confirmRequest = null;
      else error = err instanceof Error ? err.message : String(err);
    } finally {
      working = false;
    }
  }
</script>

{#if req}
  <div class="fixed inset-0 z-50 grid place-items-center p-4">
    <button type="button" tabindex="-1" aria-label="Close dialog" onclick={close} class="absolute inset-0 cursor-default bg-scrim"></button>
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="{uid}-title"
      aria-describedby="{uid}-body"
      use:modal={{ onclose: close, initial: '[data-cancel]' }}
      class="relative w-full max-w-md rounded-lg border border-border-strong bg-surface shadow-pop"
    >
      <div class="flex gap-3 p-5">
        <span
          class="grid size-9 shrink-0 place-items-center rounded-md border {req.tone === 'danger' ? 'border-danger-border bg-danger-bg text-danger-text' : 'border-warn-border bg-warn-bg text-warn-text'}"
        >
          <TriangleAlert size={18} aria-hidden="true" />
        </span>
        <div class="min-w-0">
          <h2 id="{uid}-title" class="text-[15px] font-semibold">{req.title}</h2>
          <p id="{uid}-body" class="mt-1 text-[13px] text-text-muted">{req.body}</p>
          {#if error}<p role="alert" class="mt-2 text-[13px] text-danger-text">{error}</p>{/if}
        </div>
      </div>
      <div class="flex justify-end gap-2 border-t border-border px-5 py-3">
        <!-- Cancel gets focus first so a stray Enter never confirms a destructive action. -->
        <Button data-cancel onclick={close} disabled={working}>Cancel</Button>
        <Button variant={req.tone} busy={working} busyLabel="Working…" onclick={run}>{req.action}</Button>
      </div>
    </div>
  </div>
{/if}
