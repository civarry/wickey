<script lang="ts">
  import KeyRound from '@lucide/svelte/icons/key-round';
  import Button from './Button.svelte';
  import CopyField from './CopyField.svelte';

  interface Props {
    /** The full key. Lives in the parent's component state only and is dropped when this closes. */
    token: string;
    onclose: () => void;
  }
  let { token, onclose }: Props = $props();

  let panel: HTMLDivElement | undefined = $state();
  // The panel opens in a table row that can be below the fold: bring it into view and put focus on
  // Copy, so the one chance to copy the key can't be missed.
  $effect(() => {
    if (!panel) return;
    panel.scrollIntoView({ block: 'center', behavior: 'smooth' });
    panel.querySelector<HTMLButtonElement>('button[aria-label^="Copy"]')?.focus({ preventScroll: true });
  });
</script>

<div bind:this={panel} role="group" aria-label="New key" class="flex flex-col gap-3 rounded-md border border-warn-border bg-warn-bg p-3">
  <div class="flex items-start gap-2.5">
    <KeyRound size={16} aria-hidden="true" class="mt-0.5 shrink-0 text-warn-text" />
    <div class="min-w-0 flex-1">
      <p class="text-[13px] font-semibold text-warn-text">Copy it now. It won't be shown again.</p>
      <p class="text-[13px] text-text-muted">Only a hash of this key is kept, so nothing can show it later. If it is lost, rotate the proxy for a new one. A rotated proxy's old key stops working now.</p>
    </div>
    <Button size="sm" onclick={onclose}>Done</Button>
  </div>
  <CopyField label="API key" value={token} />
</div>
