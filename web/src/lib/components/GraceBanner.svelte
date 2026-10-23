<script lang="ts">
  import Clock from '@lucide/svelte/icons/clock';
  import * as api from '../api.ts';
  import { Cancelled } from '../api.ts';
  import { app } from '../state.svelte.ts';
  import { clock } from '../util.ts';
  import Button from './Button.svelte';

  let locking = $state(false);

  async function lockNow() {
    locking = true;
    try {
      await api.lock();
      await app.refresh();
      app.toast('Locked', 'Signed out everywhere. Sign in again with your passphrase. Existing proxy keys keep working.');
    } catch (err) {
      if (!(err instanceof Cancelled)) app.toast('Could not lock', err instanceof Error ? err.message : String(err));
    } finally {
      locking = false;
    }
  }
</script>

{#if app.graceLeft > 0}
  <div role="status" class="flex flex-wrap items-center gap-3 rounded-lg border border-info-border bg-info-bg px-4 py-3">
    <span class="grid size-8 shrink-0 place-items-center rounded-md text-info-text"><Clock size={18} aria-hidden="true" /></span>
    <div class="min-w-0 flex-1 basis-64 text-[13px]">
      <p class="font-semibold text-info-text">Minting unlocked · <span class="font-mono">{clock(app.graceLeft)}</span> left</p>
      <p class="text-text-muted">Until this runs out, this signed-in tab can issue or rotate keys without your passphrase. Programs on this computer have no session and still need it.</p>
    </div>
    <Button busy={locking} busyLabel="Locking…" onclick={lockNow}>Lock now</Button>
  </div>
{/if}
