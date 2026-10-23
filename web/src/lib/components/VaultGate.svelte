<script lang="ts">
  import Shield from '@lucide/svelte/icons/shield';
  import * as api from '../api.ts';
  import { modal } from '../modal.ts';
  import { app } from '../state.svelte.ts';
  import ApprovalNotice from './ApprovalNotice.svelte';
  import Button from './Button.svelte';
  import CopyField from './CopyField.svelte';
  import Input from './Input.svelte';

  const MIN_PASSPHRASE = 12;
  const mode = $derived(app.gateMode);
  const setupMode = $derived(mode === 'setup');
  // Setup in the browser needs the one-time link `start` printed; without it the form could only fail.
  // Presence mode: unlocking waits for an approval on this Mac. Signing in to an already unlocked proxy does not.
  const approval = $derived(mode === 'unlock' && app.presenceOn);
  const needsLink = $derived(setupMode && !app.setupToken);

  let pass = $state('');
  let again = $state('');
  let error = $state('');
  let busy = $state(false);

  // Fresh fields whenever the screen switches between setup and unlock.
  $effect(() => {
    void mode;
    pass = again = error = '';
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (setupMode) {
      if (pass.length < MIN_PASSPHRASE) return void (error = `Use at least ${MIN_PASSPHRASE} characters. Four or more random words work well.`);
      if (pass !== again) return void (error = "The passphrases don't match.");
    }
    busy = true;
    try {
      if (setupMode) {
        await api.setup(pass, app.setupToken);
        app.toast('Passphrase set', 'Your keys are now encrypted.');
      } else if (mode === 'signin') {
        await api.signIn(pass);
      } else {
        await api.unlock(pass);
      }
      pass = again = '';
      await app.refresh();
    } catch (err) {
      // The server's 403 wording is written for agents; whoever sees it here followed a stale link.
      if (setupMode && err instanceof api.ApiError && err.status === 403) {
        error = 'This setup link has expired or was already used. Run `wickey start` again for a new one, or run `wickey setup` in a terminal.';
        return;
      }
      error = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
    }
  }
</script>

{#if mode}
  <div class="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-background p-4">
    <div role="dialog" aria-modal="true" aria-labelledby="gate-title" use:modal={{ initial: 'input' }} class="w-full max-w-md rounded-lg border border-border-strong bg-surface p-6 shadow-pop">
    <form novalidate onsubmit={submit} class="flex flex-col gap-4">
      <span class="grid size-10 place-items-center rounded-lg border border-accent-border bg-accent-bg text-accent-text">
        <Shield size={20} aria-hidden="true" />
      </span>
      <div class="flex flex-col gap-1.5">
        <h1 id="gate-title" class="text-lg font-semibold">{setupMode ? 'Set a passphrase' : mode === 'signin' ? 'Sign in to Wickey' : 'Unlock Wickey'}</h1>
        <p class="text-[13px] text-text-muted">
          {#if mode === 'signin'}
            Enter your passphrase to open the dashboard.
          {:else if !setupMode}
            The proxy restarted, so its keys are locked. Proxy keys stop working until you unlock.
          {:else}
            It protects your provider keys and the ability to mint proxy keys.
          {/if}
        </p>
      </div>

      {#if setupMode}
        <ul class="list-disc space-y-1.5 pl-5 text-[13px] text-text-muted marker:text-text-muted">
          <li>Your provider keys are encrypted with it and stored in <span class="font-mono text-text">~/.wickey/vault.json</span>.</li>
          <li>Issuing, rotating or renewing a key, and adding or editing a credential, ask for it.</li>
          <li>After you enter it, minting stays unlocked in this tab for a few minutes (you'll see a countdown). Lock early any time.</li>
          <li>Use at least {MIN_PASSPHRASE} characters; four or more random words work well. Anyone who copies the vault file can guess offline, so length is what protects you.</li>
          <li>It can't be recovered. If you forget it, you'll need to add your provider keys again.</li>
        </ul>
      {/if}

      {#if needsLink}
        <div class="flex flex-col gap-3 text-[13px] text-text-muted">
          <p>To set it here, open the one-time setup link that <span class="font-mono text-text">wickey start</span> printed where you ran it. It works once, and only while that process runs. This keeps other programs on this computer from setting a passphrase before you do.</p>
          <p>Or stop Wickey and run this in a terminal:</p>
          <CopyField label="Setup command" value="wickey setup" />
        </div>
      {:else}
        <Input label="Passphrase" type="password" bind:value={pass} autocomplete={setupMode ? 'new-password' : 'current-password'} />
        {#if setupMode}
          <Input label="Repeat passphrase" type="password" bind:value={again} autocomplete="new-password" />
        {/if}
        {#if approval}
          <ApprovalNotice reason="Wickey: unlock vault (dashboard)" just="clicked Unlock" waiting={busy} {error} />
        {:else if error}<p role="alert" class="text-[13px] text-danger-text">{error}</p>{/if}
        <Button type="submit" variant="primary" {busy} busyLabel={setupMode ? 'Encrypting…' : mode === 'signin' ? 'Signing in…' : 'Unlocking…'} class="w-full">
          {setupMode ? 'Set passphrase' : mode === 'signin' ? 'Sign in' : 'Unlock'}
        </Button>
      {/if}
      {#if !setupMode}
        <details class="group text-[13px]">
          <summary class="cursor-pointer text-text-muted hover:text-text">Forgot your passphrase?</summary>
          <div class="mt-3 flex flex-col gap-3 text-text-muted">
            <p>It can't be recovered, by design: nothing stored on this computer can unlock the vault without it. You can start over, which deletes the vault, all credentials, proxies and their activity log.</p>
            <p>Stop Wickey, run this in a terminal, then start it and set a new passphrase:</p>
            <CopyField label="Reset command" value="wickey reset" />
            <p>Your real provider keys are not revoked at the provider and stay valid there. Importing from a .env file makes re-adding them quick.</p>
          </div>
        </details>
      {/if}
    </form>
    </div>
  </div>
{/if}
