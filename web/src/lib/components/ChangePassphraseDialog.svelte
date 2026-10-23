<script lang="ts">
  import KeyRound from '@lucide/svelte/icons/key-round';
  import * as api from '../api.ts';
  import { modal } from '../modal.ts';
  import { app } from '../state.svelte.ts';
  import Button from './Button.svelte';
  import Input from './Input.svelte';

  const MIN_PASSPHRASE = 12;
  const uid = $props.id();

  let current = $state('');
  let next = $state('');
  let again = $state('');
  let error = $state('');
  let busy = $state(false);

  // Fresh, empty fields every time the dialog opens.
  $effect(() => {
    if (app.changePassphraseOpen) current = next = again = error = '';
  });

  function close() {
    if (busy) return;
    current = next = again = '';
    app.changePassphraseOpen = false;
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (next.length < MIN_PASSPHRASE) return void (error = `Use at least ${MIN_PASSPHRASE} characters for the new passphrase. Four or more random words work well.`);
    if (next === current) return void (error = 'The new passphrase must be different from the current one.');
    if (next !== again) return void (error = "The new passphrases don't match.");
    busy = true;
    try {
      await api.changePassphrase(current, next);
      current = next = again = '';
      app.changePassphraseOpen = false;
      await app.refresh();
      app.toast('Passphrase changed', 'Minting is locked until you enter the new one. Old backups of vault.json still open with the old passphrase.');
    } catch (err) {
      current = '';
      error = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
    }
  }
</script>

{#if app.changePassphraseOpen}
  <div class="fixed inset-0 z-[60] grid place-items-center p-4">
    <button type="button" tabindex="-1" aria-label="Cancel" onclick={close} class="absolute inset-0 cursor-default bg-scrim"></button>
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="{uid}-title"
      use:modal={{ onclose: close, initial: 'input' }}
      class="relative w-full max-w-md rounded-lg border border-border-strong bg-surface shadow-pop"
    >
      <form novalidate onsubmit={submit}>
        <div class="flex gap-3 p-5">
          <span class="grid size-9 shrink-0 place-items-center rounded-md border border-accent-border bg-accent-bg text-accent-text">
            <KeyRound size={18} aria-hidden="true" />
          </span>
          <div class="flex min-w-0 flex-1 flex-col gap-3">
            <div>
              <h2 id="{uid}-title" class="text-[15px] font-semibold">Change passphrase</h2>
              <p class="mt-1 text-[13px] text-text-muted">
                Always asks for the current passphrase, even while minting is unlocked. Your keys and proxies are unchanged. Afterwards, minting is locked until you enter the new one. An old backup of vault.json still opens with the old passphrase.
              </p>
            </div>
            <Input label="Current passphrase" type="password" bind:value={current} autocomplete="current-password" />
            <Input label="New passphrase" type="password" bind:value={next} autocomplete="new-password" help="At least {MIN_PASSPHRASE} characters. It can't be recovered." />
            <Input label="Repeat new passphrase" type="password" bind:value={again} autocomplete="new-password" />
            {#if error}<p role="alert" class="text-[13px] text-danger-text">{error}</p>{/if}
          </div>
        </div>
        <div class="flex justify-end gap-2 border-t border-border px-5 py-3">
          <Button onclick={close} disabled={busy}>Cancel</Button>
          <Button type="submit" variant="primary" {busy} busyLabel="Changing…" disabled={!current || !next || !again}>Change passphrase</Button>
        </div>
      </form>
    </div>
  </div>
{/if}
