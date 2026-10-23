<script lang="ts">
  import { addCredential, Cancelled, updateCredential } from '../../api.ts';
  import type { AuthStyle, Credential } from '../../api.ts';
  import { app } from '../../state.svelte.ts';
  import { providerLabel } from '../../util.ts';
  import Button from '../../components/Button.svelte';
  import Drawer from '../../components/Drawer.svelte';
  import Input from '../../components/Input.svelte';
  import Select from '../../components/Select.svelte';

  interface Props {
    open: boolean;
    /** Null adds a new credential. */
    credential: Credential | null;
  }
  let { open = $bindable(), credential }: Props = $props();

  const FORM_ID = 'credential-form';
  const adding = $derived(credential === null);
  const providers = $derived(app.data?.providers ?? {});

  let name = $state('');
  let provider = $state('openai');
  let baseUrl = $state('');
  let auth = $state<AuthStyle>('bearer');
  let apiKey = $state('');
  let replacing = $state(false);
  let error = $state('');
  let saving = $state(false);

  // Fresh form each time the drawer opens.
  $effect(() => {
    if (!open) return;
    error = '';
    apiKey = '';
    replacing = false;
    if (credential) {
      name = credential.name;
      baseUrl = credential.baseUrl;
      auth = credential.authStyle;
    } else {
      name = '';
      baseUrl = '';
      provider = 'openai';
      auth = app.data?.providers.openai?.auth ?? 'bearer';
    }
  });

  const preset = $derived(providers[provider]);
  const placeholder = $derived(adding ? (preset?.baseUrl ?? 'https://api.example.com/v1') : '');
  const urlHelp = $derived(
    adding && preset?.baseUrl
      ? `Leave blank to use ${preset.baseUrl}. No endpoint path.`
      : 'The base URL for the upstream provider, without an endpoint path.',
  );
  const keyHelp = $derived(
    adding
      ? 'Encrypted in your local vault on this device.'
      : replacing
        ? 'Saving replaces the stored key. Existing proxies keep their keys.'
        : 'The current key stays in place unless you replace it. Proxies keep working either way.',
  );

  function pickProvider(value: string) {
    provider = value;
    auth = providers[value]?.auth ?? 'bearer';
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    saving = true;
    try {
      const n = name.trim();
      const key = adding || replacing ? apiKey.trim() : '';
      if (credential) {
        await updateCredential(credential.id, { name: n, baseUrl: baseUrl.trim(), authStyle: auth, apiKey: key });
      } else {
        await addCredential({ name: n, provider, baseUrl: baseUrl.trim() || undefined, authStyle: auth, apiKey: key });
      }
      open = false;
      await app.refresh();
      app.toast(
        adding ? `${n} added` : `${n} saved`,
        adding ? 'You can issue proxy keys for it now.' : key ? 'New key stored. Existing proxies keep their keys.' : 'Existing proxies keep working.',
      );
    } catch (err) {
      if (!(err instanceof Cancelled)) error = (err as Error).message;
    } finally {
      saving = false;
    }
  }
</script>

<Drawer
  bind:open
  title={adding ? 'Add credential' : 'Edit credential'}
  subtitle={adding ? 'Connect a new upstream provider.' : credential?.name}
  onclose={() => {}}
>
  <form id={FORM_ID} onsubmit={save} class="flex flex-col gap-4">
    <Input label="Name" bind:value={name} help="Letters, numbers, dot, dash and underscore." autocomplete="off" spellcheck={false} required />
    {#if adding}
      <Select label="Provider" bind:value={provider} onchange={(e) => pickProvider(e.currentTarget.value)}>
        {#each Object.keys(providers) as k (k)}
          <option value={k}>{k === 'custom' ? 'Custom (OpenAI-compatible)' : providerLabel(k)}</option>
        {/each}
      </Select>
    {/if}
    <Input label="Base URL" bind:value={baseUrl} {placeholder} help={urlHelp} mono autocomplete="off" spellcheck={false} optional={adding} />
    <Select label="Authentication" bind:value={auth} help="How the upstream provider expects the key.">
      <option value="bearer">Bearer token</option>
      <option value="x-api-key">API key header (x-api-key)</option>
    </Select>

    {#if adding || replacing}
      <Input label="API key" bind:value={apiKey} reveal mono autocomplete="off" spellcheck={false} help={keyHelp} required />
      {#if !adding}
        <div><Button variant="ghost" size="sm" onclick={() => { replacing = false; apiKey = ''; }}>Keep current</Button></div>
      {/if}
    {:else}
      <div class="flex flex-col gap-1.5">
        <Input label="API key" value="••••••••••••••••" mono disabled help={keyHelp} />
        <div><Button variant="secondary" size="sm" onclick={() => (replacing = true)}>Replace key</Button></div>
      </div>
    {/if}

    {#if error}<p role="alert" class="rounded-md border border-danger-border bg-danger-bg px-3 py-2 text-[13px] text-danger-text">{error}</p>{/if}
  </form>

  {#snippet footer()}
    <Button variant="secondary" onclick={() => (open = false)}>Cancel</Button>
    <Button variant="primary" type="submit" form={FORM_ID} busy={saving} busyLabel="Saving…">{adding ? 'Add credential' : 'Save changes'}</Button>
  {/snippet}
</Drawer>
