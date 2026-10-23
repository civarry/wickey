<script lang="ts">
  import { ApiError, getActivity } from '../../api.ts';
  import type { ActivityEntry } from '../../api.ts';
  import { app } from '../../state.svelte.ts';
  import { dateTime } from '../../util.ts';
  import { refusal } from '../../limits.ts';
  import Button from '../../components/Button.svelte';
  import Card from '../../components/Card.svelte';
  import EmptyState from '../../components/EmptyState.svelte';
  import SegmentedControl from '../../components/SegmentedControl.svelte';
  import Select from '../../components/Select.svelte';
  import { activityHash } from './route.ts';
  import type { StatusFilter } from './route.ts';

  interface Props {
    proxy: string;
    status: StatusFilter;
  }
  let { proxy, status }: Props = $props();

  const PAGE = 50;
  // Same cadence as the app's state poll.
  const POLL_MS = 5000;

  let rows = $state<ActivityEntry[] | null>(null);
  let nextBefore = $state<number | null>(null);
  let failed = $state<string | null>(null);
  let missing = $state(false);
  let loadingMore = $state(false);
  let extended = false;

  const go = (f: { proxy?: string; status?: StatusFilter }) => {
    location.hash = activityHash({ proxy, status, ...f });
  };

  const statusOptions = [
    { value: 'all', label: 'All' },
    { value: 'ok', label: 'OK' },
    { value: 'refused', label: 'Refused' },
  ];

  // Filters live in the URL, so a change of props is a change of query. `gen` drops answers to old queries.
  let gen = 0;
  $effect(() => {
    const q = { proxy: proxy || undefined, status: status === 'all' ? undefined : status };
    const mine = ++gen;
    rows = null;
    nextBefore = null;
    failed = null;
    missing = false;
    loadingMore = false;
    extended = false;

    const load = async () => {
      try {
        const r = await getActivity({ ...q, limit: PAGE });
        if (mine !== gen) return;
        failed = null;
        missing = false;
        const have = rows;
        // Until "Load more" is used the list is just the first page, so replace it.
        if (!extended || have === null || have.length === 0) {
          rows = r.requests;
          nextBefore = r.nextBefore;
          return;
        }
        // Older pages are never refetched. If the first page is entirely newer than what we show,
        // rows may have been missed in between, so start over from it rather than leave a gap.
        const top = have[0].id;
        if (r.nextBefore !== null && r.requests.every((x) => x.id > top)) {
          rows = r.requests;
          nextBefore = r.nextBefore;
          extended = false;
          return;
        }
        const seen = new Set(have.map((x) => x.id));
        const fresh = r.requests.filter((x) => !seen.has(x.id));
        if (fresh.length) rows = [...fresh, ...have];
      } catch (err) {
        if (mine !== gen) return;
        if (err instanceof ApiError && err.status === 404) missing = true;
        else failed = (err as Error).message;
        if (rows === null) rows = [];
      }
    };
    void load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  });

  async function more() {
    if (nextBefore === null || loadingMore) return;
    const mine = gen;
    loadingMore = true;
    try {
      const r = await getActivity({ proxy: proxy || undefined, status: status === 'all' ? undefined : status, before: nextBefore, limit: PAGE });
      if (mine !== gen) return;
      const seen = new Set((rows ?? []).map((x) => x.id));
      rows = [...(rows ?? []), ...r.requests.filter((x) => !seen.has(x.id))];
      extended = true;
      nextBefore = r.nextBefore;
    } catch (err) {
      if (mine === gen) app.toast('Could not load more', (err as Error).message);
    } finally {
      if (mine === gen) loadingMore = false;
    }
  }

  // Every proxy is listed, expired ones too: their history is still in the log.
  const proxyName = (id: string, label: string | null) => label || app.proxies.find((p) => p.id === id)?.label || id;
  const proxyOptions = $derived.by(() => {
    const list = app.proxies.map((p) => ({ id: p.id, name: p.label || p.id }));
    if (proxy && !list.some((p) => p.id === proxy)) list.push({ id: proxy, name: proxy });
    return list.sort((a, b) => a.name.localeCompare(b.name));
  });

  const time = (ms: number) => `${dateTime(ms)}:${String(new Date(ms).getSeconds()).padStart(2, '0')}`;
  const tok = (n: number | null) => (n === null ? '-' : n.toLocaleString('en-US'));
  const filtered = $derived(proxy !== '' || status !== 'all');
</script>

<Card id="activity" class="scroll-mt-4">
  <div class="flex flex-wrap items-end gap-x-4 gap-y-3 border-b border-border px-4 py-3.5">
    <Select label="Proxy" value={proxy} onchange={(e) => go({ proxy: e.currentTarget.value })} class="w-full sm:w-64">
      <option value="">All proxies</option>
      {#each proxyOptions as p (p.id)}
        <option value={p.id}>{p.name}{p.name === p.id ? '' : ` (${p.id})`}</option>
      {/each}
    </Select>
    <div class="flex flex-col gap-1.5">
      <span class="text-[13px] font-medium">Status</span>
      <SegmentedControl label="Filter by status" options={statusOptions} value={status} onchange={(v) => go({ status: v as StatusFilter })} />
    </div>
  </div>

  {#if rows === null}
    <p class="px-4 py-10 text-center text-[13px] text-text-muted">Loading…</p>
  {:else if missing}
    <EmptyState title="That proxy no longer exists" body="Its history went with it. Clear the filter to see the other proxies.">
      {#snippet action()}<Button variant="secondary" size="sm" onclick={() => go({ proxy: '' })}>Clear filter</Button>{/snippet}
    </EmptyState>
  {:else if failed && rows.length === 0}
    <EmptyState title="Could not load requests" body="{failed} Retrying." />
  {:else if rows.length === 0 && filtered}
    <EmptyState title="No matching requests" body="Nothing in the log fits these filters.">
      {#snippet action()}<Button variant="secondary" size="sm" onclick={() => (location.hash = activityHash())}>Clear filters</Button>{/snippet}
    </EmptyState>
  {:else if rows.length === 0}
    <EmptyState title="No requests yet" body="Requests made with a proxy key show up here, newest first. Only metadata is kept: never prompts or responses." />
  {:else}
    <div class="overflow-x-auto">
      <table class="w-full min-w-[820px] border-collapse text-left text-xs">
        <thead>
          <tr class="border-b border-border text-text-muted">
            <th scope="col" class="py-2 pr-2.5 pl-4 font-medium">Time</th>
            <th scope="col" class="px-2.5 py-2 font-medium">Proxy</th>
            <th scope="col" class="px-2.5 py-2 font-medium">Model</th>
            <th scope="col" class="px-2.5 py-2 font-medium">Status</th>
            <th scope="col" class="px-2.5 py-2 text-right font-medium">Tokens in</th>
            <th scope="col" class="px-2.5 py-2 text-right font-medium">Tokens out</th>
            <th scope="col" class="py-2 pr-4 pl-2.5 text-right font-medium">Duration</th>
          </tr>
        </thead>
        <tbody>
          {#each rows as r (r.id)}
            <tr class="border-b border-border last:border-b-0 {r.event ? 'bg-info-bg text-info-text' : ''}">
              <td class="py-2 pr-2.5 pl-4 whitespace-nowrap">{time(r.at)}</td>
              <td class="max-w-56 px-2.5 py-2">
                <button
                  type="button"
                  onclick={() => go({ proxy: r.proxyId })}
                  aria-label="Show only {proxyName(r.proxyId, r.proxyLabel)}"
                  class="block max-w-full rounded-sm text-left hover:underline"
                >
                  <span class="block truncate font-medium">{proxyName(r.proxyId, r.proxyLabel)}</span>
                  {#if r.proxyLabel}<span class="block truncate font-mono opacity-70">{r.proxyId}</span>{/if}
                </button>
              </td>
              {#if r.event === 'renewed'}
                <td colspan="5" class="px-2.5 py-2 pr-4">Auto-renewed until {r.renewedTo ? dateTime(r.renewedTo) : 'later'}</td>
              {:else}
                <td class="px-2.5 py-2 font-mono">{r.model ?? '-'}</td>
                <td class="px-2.5 py-2 {r.refusedReason ? 'text-danger-text' : ''}">{r.refusedReason ? `${r.status}. ${refusal(r.refusedReason)}` : r.status}</td>
                <td class="px-2.5 py-2 text-right tabular-nums">{tok(r.tokensIn)}</td>
                <td class="px-2.5 py-2 text-right tabular-nums">{tok(r.tokensOut)}</td>
                <td class="py-2 pr-4 pl-2.5 text-right whitespace-nowrap tabular-nums">{r.durationMs.toLocaleString('en-US')} ms</td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <div class="flex items-center justify-between gap-3 border-t border-border px-4 py-3">
      <p class="text-xs text-text-muted" aria-live="polite">
        {rows.length.toLocaleString('en-US')} shown{nextBefore === null ? '. That is everything in the log.' : ''}
      </p>
      {#if nextBefore !== null}
        <Button variant="secondary" size="sm" busy={loadingMore} busyLabel="Loading…" onclick={more}>Load more</Button>
      {/if}
    </div>
  {/if}
</Card>
