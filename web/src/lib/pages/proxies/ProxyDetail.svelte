<script lang="ts">
  import type { Proxy } from '../../api.ts';
  import { app } from '../../state.svelte.ts';
  import CodeTabs from '../../components/CodeTabs.svelte';
  import Button from '../../components/Button.svelte';
  import CopyField from '../../components/CopyField.svelte';
  import OneTimeKey from '../../components/OneTimeKey.svelte';
  import { plural, dateTime } from '../../util.ts';
  import { activityHash } from '../activity/route.ts';
  import { codeTabs, nameOf } from './snippets.ts';

  interface Props {
    proxy: Proxy;
    /** The full key, only right after issue or rotate; null otherwise. Component state in the page, never the app store. */
    freshKey?: string | null;
    onclosekey?: () => void;
    /** Opens the row's rotate confirmation: the only way to get a usable key once it was shown. */
    onrotate?: () => void;
  }
  let { proxy, freshKey = null, onclosekey, onrotate }: Props = $props();

  let tab = $state('shell');
  const expired = $derived(app.statusOf(proxy) === 'expired');
  const base = $derived(app.baseUrlOf(proxy));
  const cred = $derived(app.credentials.find((c) => c.id === proxy.credentialId));
  // The Python example names a real model: the key's first allowed one, else the first the provider lists.
  $effect(() => {
    if (cred && proxy.limits.models === null) void app.loadModels(cred.name);
  });
  const model = $derived(proxy.limits.models?.[0] ?? (cred ? app.modelLists[cred.name]?.data?.models?.[0] : undefined) ?? null);
  const tabs = $derived(codeTabs(proxy, freshKey, base, cred, app.data?.providers, model));
</script>

<div class="flex flex-col gap-4 px-4 py-4">
  {#if proxy.cleanedTampered}
    <p role="alert" class="text-[13px] text-danger-text">Tampered: marked cleaned up while active. Its database row was edited outside Wickey, so this key is refused. Rotate it to get a working key, or delete it.</p>
  {:else if expired}
    <p class="text-[13px] text-warn-text">Expired. Renew keeps this key, nothing to change in your agent. Rotate makes a new one.</p>
  {/if}
  <!-- The table truncates long names; this is where the full values live. -->
  <p class="text-[13px] break-all text-text-muted">
    <span class="font-medium text-text">{nameOf(proxy)}</span> · credential {proxy.credentialName}
  </p>
  {#if freshKey}
    <OneTimeKey token={freshKey} onclose={() => onclosekey?.()} />
  {/if}
  <div class="grid gap-4 @2xl:grid-cols-2">
    <CopyField label="Base URL" value={base} />
    {#if !freshKey}
      <CopyField label="API key" value="" unavailable={`${proxy.maskedKey} · Shown only once. Rotate to get a new key.`}>
        {#snippet action()}
          {#if onrotate && !proxy.cleanedUp}<Button size="sm" variant="secondary" onclick={onrotate}>Rotate for a new key</Button>{/if}
        {/snippet}
      </CopyField>
    {/if}
  </div>
  <CodeTabs {tabs} bind:active={tab} revealed label="Usage snippets" />
  <p class="text-[13px] text-text-muted">
    {#if proxy.usage.requests > 0}
      {plural(proxy.usage.requests, 'request', 'requests')} forwarded{proxy.usage.lastUsedAt ? ` · last ${dateTime(proxy.usage.lastUsedAt)}` : ''} ·
      <a href={activityHash({ proxy: proxy.id })} class="text-accent-text underline underline-offset-2 hover:text-text">View activity</a>
    {:else}
      No requests yet.
    {/if}
  </p>
</div>
