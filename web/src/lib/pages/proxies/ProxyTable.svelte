<script lang="ts">
  import type { SvelteSet } from 'svelte/reactivity';
  import { app } from '../../state.svelte.ts';
  import Card from '../../components/Card.svelte';
  import EmptyState from '../../components/EmptyState.svelte';
  import Input from '../../components/Input.svelte';
  import Checkbox from '../../components/Checkbox.svelte';
  import SegmentedControl from '../../components/SegmentedControl.svelte';
  import ProxyRow from './ProxyRow.svelte';
  import SectionMarker from './SectionMarker.svelte';

  interface Props {
    filter: string | null;
    query: string;
    open: SvelteSet<string>;
    /** Full keys from just-finished issues and rotates, by proxy id. Held by the page, never the app store. */
    keys: Record<string, string>;
    onkey: (id: string, token: string) => void;
    onclosekey: (id: string) => void;
  }
  let { filter = $bindable(), query = $bindable(), open, keys, onkey, onclosekey }: Props = $props();

  // Newest first, so a freshly issued proxy lands at the top.
  // Proxies `env` retired stay in the data (their activity is kept) but are hidden unless asked for.
  let showCleaned = $state(false);
  const all = $derived([...app.proxies].filter((p) => showCleaned || !p.cleanedUp).reverse());
  const counts = $derived({
    all: all.length,
    active: all.filter((p) => app.statusOf(p) === 'active').length,
    expired: all.filter((p) => app.statusOf(p) === 'expired').length,
  });
  const q = $derived(query.trim().toLowerCase());
  const list = $derived(
    all.filter(
      (p) =>
        (filter === 'all' || app.statusOf(p) === filter) &&
        (!q || [p.label, p.id, p.credentialName].some((v) => v && v.toLowerCase().includes(q))),
    ),
  );
  const options = $derived([
    { value: 'all', label: `All ${counts.all}` },
    { value: 'active', label: `Active ${counts.active}` },
    { value: 'expired', label: `Expired ${counts.expired}` },
  ]);

  // Drop open state for proxies that no longer exist.
  $effect(() => {
    // Signed out (Lock, restart): a key still waiting to be copied is dropped with the session.
    if (!app.data) return void Object.keys(keys).forEach(onclosekey);
    for (const id of open) if (!app.proxies.some((p) => p.id === id)) open.delete(id);
    for (const id of Object.keys(keys)) if (!app.proxies.some((p) => p.id === id)) onclosekey(id);
  });

  const empty = $derived.by(() => {
    if (!app.credentials.length) return { title: 'No credentials yet', body: 'Add a credential above, then issue a proxy key for it.' };
    if (!all.length) return { title: 'No proxies yet', body: 'Issue a proxy key above to get a local base URL and key.' };
    if (q) return { title: 'No matches', body: `Nothing matches "${query.trim()}".` };
    if (filter === 'active') return { title: 'No active proxies', body: 'Issue a proxy key above, or renew an expired one.' };
    return { title: 'No expired proxies', body: 'Every proxy is active.' };
  });

  const heads = ['', 'Name', 'Key ID', 'Credential', 'Status', 'Usage', 'Expiry', 'Actions'];

  function toggle(id: string) {
    if (open.has(id)) {
      open.delete(id);
      // Collapsing the row discards a key that was still waiting to be copied.
      onclosekey(id);
    } else open.add(id);
  }
</script>

<Card id="proxies-list" class="scroll-mt-4">
  {#snippet header()}
    <div class="flex min-w-0 items-center gap-2.5">
      <SectionMarker n={3} />
      <h2 id="proxies-list-heading" class="text-[15px] font-semibold">All proxies</h2>
    </div>
  {/snippet}
  {#snippet actions()}
    <Input label="Search proxies" hideLabel type="search" bind:value={query} placeholder="Search name, ID or credential" class="w-64" autocomplete="off" />
    <SegmentedControl label="Filter by status" {options} bind:value={filter} />
    <Checkbox label="Show cleaned up" bind:checked={showCleaned} />
  {/snippet}

  {#if list.length}
    <div class="@container overflow-x-auto">
      <table class="w-full min-w-[960px] border-collapse text-left">
        <thead>
          <tr class="border-b border-border text-xs text-text-muted">
            {#each heads as h, i (i)}
              <th scope="col" class="px-2 py-2 font-medium {i === 0 ? 'w-10 pl-3' : ''} {i === 7 ? 'pr-3 text-right' : ''}">
                {#if h}{h}{:else}<span class="sr-only">Details</span>{/if}
              </th>
            {/each}
          </tr>
        </thead>
        {#each list as p (p.id)}
          <ProxyRow proxy={p} open={open.has(p.id)} ontoggle={() => toggle(p.id)} onopen={() => open.add(p.id)} freshKey={keys[p.id] ?? null} onkey={(t) => onkey(p.id, t)} onclosekey={() => onclosekey(p.id)} />
        {/each}
      </table>
    </div>
  {:else}
    <EmptyState title={empty.title} body={empty.body} />
  {/if}
</Card>
