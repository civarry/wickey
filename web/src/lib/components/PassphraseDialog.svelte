<script lang="ts">
  import Lock from '@lucide/svelte/icons/lock';
  import { modal } from '../modal.ts';
  import { app } from '../state.svelte.ts';
  import { duration } from '../util.ts';
  import Button from './Button.svelte';
  import Input from './Input.svelte';

  const req = $derived(app.passphraseRequest);
  const uid = $props.id();
  let value = $state('');

  const body = $derived(
    req?.purpose ? req.purpose : app.session?.graceSeconds
      ? `Needed to mint keys or change credentials. Afterwards, minting stays unlocked for ${duration(app.session.graceSeconds)}.`
      : 'Needed to mint keys or change credentials.',
  );

  // A wrong passphrase re-arms the same dialog; clear the field so the next try starts fresh.
  $effect(() => {
    if (req && !req.pending) value = '';
  });

  function submit(e: SubmitEvent) {
    e.preventDefault();
    app.submitPassphrase(value);
  }
</script>

{#if req}
  <div class="fixed inset-0 z-[60] grid place-items-center p-4">
    <button type="button" tabindex="-1" aria-label="Cancel" onclick={() => app.cancelPassphrase()} class="absolute inset-0 cursor-default bg-scrim"></button>
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="{uid}-title"
      use:modal={{ onclose: () => app.cancelPassphrase(), initial: 'input' }}
      class="relative w-full max-w-md rounded-lg border border-border-strong bg-surface shadow-pop"
    >
      <form novalidate onsubmit={submit}>
      <div class="flex gap-3 p-5">
        <span class="grid size-9 shrink-0 place-items-center rounded-md border border-accent-border bg-accent-bg text-accent-text">
          <Lock size={18} aria-hidden="true" />
        </span>
        <div class="flex min-w-0 flex-1 flex-col gap-3">
          <div>
            <h2 id="{uid}-title" class="text-[15px] font-semibold">Enter your passphrase</h2>
            <p class="mt-1 text-[13px] text-text-muted">{body}</p>
          </div>
          <Input label="Passphrase" type="password" autocomplete="current-password" bind:value error={req.reason} />
        </div>
      </div>
      <div class="flex justify-end gap-2 border-t border-border px-5 py-3">
        <Button onclick={() => app.cancelPassphrase()}>Cancel</Button>
        <Button type="submit" variant="primary" busy={req.pending} busyLabel="Checking…" disabled={!value}>Continue</Button>
      </div>
      </form>
    </div>
  </div>
{/if}
