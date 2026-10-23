<script lang="ts">
  import Tooltip from '../../components/Tooltip.svelte';
  import FileUp from '@lucide/svelte/icons/file-up';
  import Plus from '@lucide/svelte/icons/plus';
  import Trash2 from '@lucide/svelte/icons/trash-2';
  import { removeCredential } from '../../api.ts';
  import type { Credential } from '../../api.ts';
  import { app } from '../../state.svelte.ts';
  import { plural } from '../../util.ts';
  import Avatar from '../../components/Avatar.svelte';
  import Button from '../../components/Button.svelte';
  import Card from '../../components/Card.svelte';
  import EmptyState from '../../components/EmptyState.svelte';
  import SectionMarker from './SectionMarker.svelte';

  interface Props {
    onadd: () => void;
    onimport: () => void;
    onedit: (c: Credential) => void;
    onissue: (c: Credential) => void;
  }
  let { onadd, onimport, onedit, onissue }: Props = $props();

  const counts = $derived.by(() => {
    const m = new Map<string, { active: number; total: number }>();
    // Proxies retired by `env` cleanup are hidden by default, so they don't count here either.
    for (const p of app.proxies) {
      if (p.cleanedUp) continue;
      const c = m.get(p.credentialId) ?? { active: 0, total: 0 };
      c.total++;
      if (app.statusOf(p) === 'active') c.active++;
      m.set(p.credentialId, c);
    }
    return m;
  });

  // Streaming option rejection is the more specific problem, so it wins.
  const usageNote = (c: Credential): string =>
    c.streamUsage === 'rejects_option' ? 'Rejects streaming usage option' : c.usageReporting === 'missing' || c.streamUsage === 'missing' ? "Doesn't report token usage" : '';

  function askRemove(c: Credential) {
    const total = counts.get(c.id)?.total ?? 0;
    app.confirm({
      tone: 'danger',
      action: 'Remove credential',
      title: `Remove the ${c.name} credential?`,
      body: `Its key is deleted from your vault${total === 1 ? ', and its 1 proxy stops working and is removed' : total ? `, and its ${total} proxies stop working and are removed` : ''}. This can't be undone.`,
      run: async () => {
        await removeCredential(c.id);
        await app.refresh();
        app.toast(`${c.name} removed`, 'The key was deleted from your vault.');
      },
    });
  }
</script>

<Card id="credentials" class="scroll-mt-4">
  {#snippet header()}
    <div class="flex min-w-0 items-center gap-2.5">
      <SectionMarker n={1} />
      <h2 id="credentials-heading" class="text-[15px] font-semibold">Credentials</h2>
    </div>
  {/snippet}
  {#snippet actions()}
    <div class="flex flex-wrap items-center gap-2">
      <Button variant="ghost" size="sm" onclick={onimport}><FileUp size={14} aria-hidden="true" />Import from .env</Button>
      <Button variant="secondary" size="sm" onclick={onadd}><Plus size={14} aria-hidden="true" />Add credential</Button>
    </div>
  {/snippet}

  {#if app.credentials.length}
    <ul class="divide-y divide-border">
      {#each app.credentials as c (c.id)}
        {@const n = counts.get(c.id) ?? { active: 0, total: 0 }}
        {@const url = `${c.baseUrl} · ${c.authStyle === 'bearer' ? 'Bearer' : 'x-api-key'}`}
        <li class="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5">
          <div class="flex min-w-48 flex-1 items-center gap-3">
            <Avatar name={c.name} size="md" />
            <div class="min-w-0">
              <p class="truncate text-sm font-medium">{c.name}</p>
              <Tooltip text={url} block><p class="max-w-md truncate font-mono text-xs text-text-muted">{url}</p></Tooltip>
            </div>
          </div>
          {#if usageNote(c)}
            <Tooltip focusable text="Token caps on keys for this credential can only be enforced by refusing requests whose usage can't be counted.">
              <span class="text-xs text-text-muted">{usageNote(c)}</span>
            </Tooltip>
          {/if}
          <p class="w-28 text-[13px] {n.active === 0 ? 'text-warn-text' : 'text-text-muted'}">{n.active} of {n.total} active</p>
          <div class="flex w-full items-center gap-2 sm:w-auto">
            <Button variant="primary" size="sm" onclick={() => onissue(c)}>Issue proxy</Button>
            <Button variant="secondary" size="sm" onclick={() => onedit(c)}>Edit</Button>
            <Button variant="danger" size="sm" iconOnly aria-label={`Remove credential ${c.name}`} onclick={() => askRemove(c)}>
              <Trash2 size={14} aria-hidden="true" />
            </Button>
          </div>
        </li>
      {/each}
    </ul>
  {:else}
    <EmptyState title="No credentials yet" body="Add your provider's base URL and API key. Agents only get proxy keys.">
      {#snippet action()}<Button variant="primary" onclick={onadd}>Add credential</Button>{/snippet}
    </EmptyState>
  {/if}
</Card>
