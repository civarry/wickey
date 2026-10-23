<script lang="ts">
  import Fingerprint from '@lucide/svelte/icons/fingerprint';

  interface Props {
    /** Exact wording of the system prompt, e.g. "Wickey: unlock vault (dashboard)". */
    reason: string;
    /** Completes "Only approve it if you just ...". */
    just: string;
    /** True while the server waits for the approval. */
    waiting: boolean;
    /** Shown instead, in the same place, after a cancel or failure. */
    error?: string;
  }
  let { reason, just, waiting, error = '' }: Props = $props();
</script>

<!-- One fixed-height slot for all three states, so waiting for an approval never moves the form. -->
<div class="min-h-[5.5rem] text-[13px]" aria-live="polite">
  {#if waiting}
    <p role="status" class="flex gap-2 rounded-md border border-accent-border bg-accent-bg p-2.5 text-accent-text">
      <Fingerprint size={16} class="mt-0.5 shrink-0" aria-hidden="true" />
      <span>Approve the system prompt that says "{reason}". Only approve it if you just {just}.</span>
    </p>
  {:else if error}
    <p role="alert" class="text-danger-text">{error}</p>
  {:else}
    <p class="text-text-muted">Presence mode is on: this also needs your approval of a system prompt on this Mac (Touch ID, login password or Apple Watch).</p>
  {/if}
</div>
