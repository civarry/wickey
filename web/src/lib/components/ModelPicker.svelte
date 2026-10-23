<script lang="ts">
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import X from '@lucide/svelte/icons/x';
  import { app } from '../state.svelte.ts';
  import { modelList } from '../limits.ts';
  import { ago } from '../util.ts';
  import Button from './Button.svelte';
  import Checkbox from './Checkbox.svelte';
  import Input from './Input.svelte';
  import Textarea from './Textarea.svelte';

  /**
   * Searchable multi-select over one credential's provider model list.
   *
   * Props:
   * - credential: credential name; its list is fetched (and kept for the session) on mount.
   * - value (bindable): chosen model IDs, one per line.
   * Shows at most MAX_SHOWN matches so a 500-model list stays light, in a fixed-height scroll area so
   * the surrounding panel never grows. Falls back to typing exact IDs when the provider has no list.
   */
  interface Props {
    credential: string;
    value?: string;
  }
  let { credential, value = $bindable('') }: Props = $props();

  const MAX_SHOWN = 100;
  let query = $state('');
  let refreshing = $state(false);

  const entry = $derived(app.modelLists[credential]);
  const data = $derived(entry?.data);
  const listed = $derived(data?.models ?? []);
  const chosen = $derived(modelList(value));
  const chosenSet = $derived(new Set(chosen));
  const listedSet = $derived(new Set(listed));
  const matches = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return q ? listed.filter((m) => m.toLowerCase().includes(q)) : listed;
  });
  const shown = $derived(matches.slice(0, MAX_SHOWN));
  const manual = $derived(!!data?.unavailable);
  const failed = $derived(entry?.status === 'error' || (entry?.status === 'ready' && !!data?.error && listed.length === 0 && !manual));

  $effect(() => {
    if (credential) void app.loadModels(credential);
  });

  function toggle(id: string, on: boolean) {
    const next = on ? [...chosen.filter((m) => m !== id), id] : chosen.filter((m) => m !== id);
    value = next.join('\n');
  }

  async function refresh() {
    refreshing = true;
    await app.loadModels(credential, true);
    refreshing = false;
  }
</script>

{#if manual}
  <Textarea label="Model IDs" bind:value rows={3} mono placeholder="gpt-4o-mini" spellcheck={false}
    help="This provider didn't return a model list. Enter exact model IDs." />
{:else if failed}
  <div class="flex flex-col gap-2">
    <p role="alert" class="text-[13px] text-danger-text">Couldn't load the model list: {entry?.status === 'error' ? entry.error : data?.error}. Retry, or check the credential's base URL and key.</p>
    <div><Button size="sm" variant="secondary" busy={refreshing || entry?.status === 'loading'} onclick={() => void refresh()}>Retry</Button></div>
  </div>
{:else if !entry || (entry.status === 'loading' && !data)}
  <p role="status" class="text-[13px] text-text-muted">Loading models…</p>
{:else}
  <div class="flex flex-col gap-2">
    {#if chosen.length}
      <ul aria-label="Selected models" class="flex max-h-20 flex-wrap gap-1 overflow-y-auto">
        {#each chosen as id (id)}
          <li class="flex max-w-full items-center gap-1 rounded-sm border border-border-strong bg-surface-2 py-0.5 pr-0.5 pl-2 text-xs">
            <span class="min-w-0 font-mono break-all">{id}</span>
            {#if !listedSet.has(id)}<span class="shrink-0 text-warn-text">not listed</span>{/if}
            <button type="button" aria-label={`Remove ${id}`} onclick={() => toggle(id, false)}
              class="grid size-5 shrink-0 place-items-center rounded-sm text-text-muted hover:bg-border-strong hover:text-text">
              <X size={12} aria-hidden="true" />
            </button>
          </li>
        {/each}
      </ul>
    {/if}
    <Input label="Search models" hideLabel bind:value={query} placeholder="Search models" autocomplete="off" spellcheck={false}
      onkeydown={(e) => { if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); } }} />
    <div class="h-40 overflow-y-auto rounded-md border border-border bg-input p-2" role="group" aria-label="Models">
      {#if shown.length === 0}
        <p class="text-[13px] text-text-muted">{listed.length ? 'No models match.' : 'The provider listed no models.'}</p>
      {:else}
        <div class="flex flex-col gap-1.5">
          {#each shown as id (id)}
            <Checkbox label={id} mono checked={chosenSet.has(id)} onchange={(e) => toggle(id, e.currentTarget.checked)} />
          {/each}
        </div>
        {#if matches.length > shown.length}
          <p class="pt-2 text-xs text-text-muted">{matches.length - shown.length} more, refine the search.</p>
        {/if}
      {/if}
    </div>
    <div class="flex items-center justify-between gap-2">
      <p class="text-xs text-text-muted">{data?.fetchedAt ? `Updated ${ago(data.fetchedAt, app.now)}` : ''}</p>
      <Button size="sm" variant="ghost" busy={refreshing || entry.status === 'loading'} onclick={() => void refresh()}>
        <RefreshCw size={12} aria-hidden="true" />Refresh list
      </Button>
    </div>
    {#if data?.error}<p class="text-xs text-warn-text">Showing the last list. Refresh failed: {data.error}</p>{/if}
  </div>
{/if}
