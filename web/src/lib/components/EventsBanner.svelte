<script lang="ts">
  import ShieldAlert from '@lucide/svelte/icons/shield-alert';
  import History from '@lucide/svelte/icons/history';
  import { summarizeUnseen } from '../../../../src/eventtext.ts';
  import { app } from '../state.svelte.ts';
  import { eventsHash } from '../pages/events/route.ts';
  import Button from './Button.svelte';

  const ev = $derived(app.events);
  const total = $derived(ev ? Object.values(ev.unseen).reduce((n, c) => n + c, 0) : 0);
  // A broken log stays flagged until the person acknowledges it (the marker moves past the first bad entry);
  // a tamper_detected event newer than the marker does too. Acknowledging is "Mark as seen".
  const danger = $derived(
    ev !== null && ((ev.unseen.tamper_detected ?? 0) > 0 || (!ev.summary.ok && (ev.summary.firstBadSeq === undefined || ev.summary.firstBadSeq > ev.seen))),
  );
  const summary = $derived(ev ? summarizeUnseen(ev.unseen) : '');
</script>

{#if ev && (danger || total > 0)}
  <div
    role={danger ? 'alert' : 'status'}
    class="flex flex-wrap items-center gap-3 rounded-lg border px-4 py-3 {danger ? 'border-danger-border bg-danger-bg' : 'border-warn-border bg-warn-bg'}"
  >
    <span class="grid size-8 shrink-0 place-items-center rounded-md {danger ? 'text-danger-text' : 'text-warn-text'}">
      {#if danger}<ShieldAlert size={18} aria-hidden="true" />{:else}<History size={18} aria-hidden="true" />{/if}
    </span>
    <div class="min-w-0 flex-1 basis-64 text-[13px]">
      {#if danger}
        <p class="font-semibold text-danger-text">Something may have tampered with the security log</p>
        <p class="text-text-muted">
          {ev.summary.ok
            ? `Wickey recorded a tamper detection: the log or a setting did not match what it last wrote. ${summary ? `Since your last visit: ${summary}.` : ''}`
            : `${ev.summary.reason ? `${ev.summary.reason.charAt(0).toUpperCase()}${ev.summary.reason.slice(1)}. ` : ''}${summary ? `Since your last visit: ${summary}.` : ''}`}
          If this was not you, rotate your proxy keys and your real provider keys at the provider, and change your passphrase.
        </p>
      {:else}
        <p class="font-semibold text-warn-text">Since your last visit: {summary}</p>
        <p class="text-text-muted">This happened while you were not looking. If any of it was not you, open the events and act on it.</p>
      {/if}
    </div>
    <div class="flex flex-wrap items-center gap-2">
      <Button onclick={() => (location.hash = eventsHash())}>View events</Button>
      <Button busy={app.markingSeen} busyLabel="Saving…" onclick={() => void app.markSeen()}>{danger ? 'Acknowledge' : 'Mark as seen'}</Button>
    </div>
  </div>
{/if}
