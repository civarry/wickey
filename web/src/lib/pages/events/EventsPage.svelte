<script lang="ts">
  import Bell from '@lucide/svelte/icons/bell';
  import { describeEvent, integrityText, TRUST_HELP, TRUST_LABEL, TYPE_LABEL, viaLabel } from '../../../../../src/eventtext.ts';
  import { getEvents } from '../../api.ts';
  import type { EventEntry, EventsPage as Page } from '../../api.ts';
  import { app } from '../../state.svelte.ts';
  import Badge from '../../components/Badge.svelte';
  import Button from '../../components/Button.svelte';
  import Card from '../../components/Card.svelte';
  import EmptyState from '../../components/EmptyState.svelte';
  import Select from '../../components/Select.svelte';
  import Tooltip from '../../components/Tooltip.svelte';
  import NotificationsDrawer from './NotificationsDrawer.svelte';
  import { eventsHash } from './route.ts';

  interface Props {
    type: string;
  }
  let { type }: Props = $props();

  const PAGE = 50;
  const POLL_MS = 5000;

  let rows = $state<EventEntry[] | null>(null);
  let info = $state<Page | null>(null);
  let failed = $state<string | null>(null);
  let more = $state(false);
  let loadingMore = $state(false);
  let extended = false;
  let alertsOpen = $state(false);

  // The filter lives in the URL. `gen` drops answers to old queries.
  let gen = 0;
  $effect(() => {
    const mine = ++gen;
    rows = null;
    info = null;
    failed = null;
    more = false;
    loadingMore = false;
    extended = false;

    const load = async () => {
      try {
        const r = await getEvents({ type: type || undefined, limit: PAGE });
        if (mine !== gen) return;
        failed = null;
        info = r;
        const have = rows;
        if (!extended || have === null || have.length === 0) {
          rows = r.events;
          more = r.events.length === PAGE;
          return;
        }
        // Older pages are never refetched; only add what arrived since.
        const top = have[0].seq;
        const fresh = r.events.filter((x) => x.seq > top);
        if (fresh.length) rows = [...fresh, ...have];
      } catch (err) {
        if (mine !== gen) return;
        failed = (err as Error).message;
        if (rows === null) rows = [];
      }
    };
    void load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  });

  async function loadMore() {
    if (!rows?.length || loadingMore) return;
    const mine = gen;
    loadingMore = true;
    try {
      const r = await getEvents({ type: type || undefined, before: rows[rows.length - 1].seq, limit: PAGE });
      if (mine !== gen) return;
      const seen = new Set(rows.map((x) => x.seq));
      rows = [...rows, ...r.events.filter((x) => !seen.has(x.seq))];
      more = r.events.length === PAGE;
      extended = true;
    } catch (err) {
      if (mine === gen) app.toast('Could not load more', (err as Error).message);
    } finally {
      if (mine === gen) loadingMore = false;
    }
  }

  const go = (t: string) => {
    location.hash = eventsHash({ type: t });
  };
  const typeOptions = Object.entries(TYPE_LABEL).sort((a, b) => a[1].localeCompare(b[1]));
  const integrity = $derived(info ? integrityText(info.summary) : null);
  // The shared copy (refreshed right after Mark as seen), not this page's poll.
  const seen = $derived(app.events?.seen ?? 0);
  const unseenCount = $derived(app.events ? Object.values(app.events.unseen).reduce((n, c) => n + c, 0) : 0);
  const tone = { verified: 'ready', recorded_while_locked: 'attention', before_reset: 'neutral', unchecked: 'neutral' } as const;

  const time = (ts: string) => {
    const d = new Date(ts);
    return Number.isNaN(d.getTime())
      ? ts.slice(0, 24)
      : `${d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false })}:${String(d.getSeconds()).padStart(2, '0')}`;
  };
</script>

<Card id="events" class="scroll-mt-4">
  <div class="flex flex-wrap items-start justify-between gap-3 border-b border-border px-4 py-3.5">
    <div class="min-w-0 flex-1 basis-72">
      {#if integrity}
        <div class="flex items-center gap-2">
          <Badge status={integrity.ok ? 'ready' : 'danger'} label={integrity.ok ? 'Log intact' : 'Log problem'} />
          <p class="text-[13px] {integrity.ok ? 'text-text-muted' : 'font-medium text-danger-text'}">{integrity.text}</p>
        </div>
        {#if integrity.next}<p class="mt-1.5 text-[13px] text-text-muted">{integrity.next}</p>{/if}
        {#if info && info.summary.whileLocked > 0}
          <p class="mt-1.5 text-xs text-text-muted">{info.summary.whileLocked} {info.summary.whileLocked === 1 ? 'entry was' : 'entries were'} recorded while Wickey was locked and carry no signature.</p>
        {/if}
      {:else}
        <p class="text-[13px] text-text-muted">Checking the log…</p>
      {/if}
    </div>
    <div class="flex flex-wrap items-center gap-2">
      {#if unseenCount > 0}
        <Button size="sm" busy={app.markingSeen} busyLabel="Saving…" onclick={() => void app.markSeen()}>Mark all as seen</Button>
      {/if}
      <Button size="sm" onclick={() => (alertsOpen = true)}><Bell size={14} aria-hidden="true" /> Alerts</Button>
    </div>
  </div>
  <div class="flex flex-wrap items-end gap-x-4 gap-y-3 border-b border-border px-4 py-3.5">
    <Select label="Event type" value={type} onchange={(e) => go(e.currentTarget.value)} class="w-full sm:w-64">
      <option value="">All events</option>
      {#each typeOptions as [value, label] (value)}
        <option {value}>{label}</option>
      {/each}
    </Select>
  </div>

  {#if rows === null}
    <p class="px-4 py-10 text-center text-[13px] text-text-muted">Loading…</p>
  {:else if failed && rows.length === 0}
    <EmptyState title="Could not load events" body="{failed} Retrying." />
  {:else if rows.length === 0 && type}
    <EmptyState title="No matching events" body="Nothing in the log is of this type.">
      {#snippet action()}<Button variant="secondary" size="sm" onclick={() => go('')}>Clear filter</Button>{/snippet}
    </EmptyState>
  {:else if rows.length === 0}
    <EmptyState title="No events yet" body="Unlocks, failed passphrases, new keys and other security-relevant actions show up here, newest first." />
  {:else}
    <div class="overflow-x-auto">
      <table class="w-full min-w-[760px] border-collapse text-left text-xs">
        <thead>
          <tr class="border-b border-border text-text-muted">
            <th scope="col" class="py-2 pr-2.5 pl-4 font-medium">Time</th>
            <th scope="col" class="px-2.5 py-2 font-medium">What happened</th>
            <th scope="col" class="px-2.5 py-2 font-medium">Source</th>
            <th scope="col" class="py-2 pr-4 pl-2.5 font-medium">Integrity</th>
          </tr>
        </thead>
        <tbody>
          {#each rows as e (e.seq)}
            {@const via = viaLabel(e.data)}
            <tr class="border-b border-border last:border-b-0 {e.seq > seen ? 'bg-info-bg text-info-text' : ''}">
              <td class="py-2 pr-2.5 pl-4 whitespace-nowrap">{time(e.ts)}</td>
              <td class="px-2.5 py-2 {e.type === 'tamper_detected' ? 'font-medium text-danger-text' : ''}">{describeEvent(e)}</td>
              <td class="px-2.5 py-2 whitespace-nowrap">{via ?? '-'}</td>
              <td class="py-2 pr-4 pl-2.5">
                <Tooltip focusable text={TRUST_HELP[e.trust] ?? TRUST_HELP.unchecked}>
                  <Badge status={tone[e.trust] ?? 'neutral'} label={TRUST_LABEL[e.trust] ?? 'Unchecked'} />
                </Tooltip>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <div class="flex items-center justify-between gap-3 border-t border-border px-4 py-3">
      <p class="text-xs text-text-muted" aria-live="polite">
        {rows.length.toLocaleString('en-US')} shown{more ? '' : '. That is everything in the log.'}
      </p>
      {#if more}
        <Button variant="secondary" size="sm" busy={loadingMore} busyLabel="Loading…" onclick={loadMore}>Load more</Button>
      {/if}
    </div>
  {/if}
</Card>

<NotificationsDrawer bind:open={alertsOpen} />
