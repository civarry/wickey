<script lang="ts">
  import { onMount, tick } from 'svelte';
  import ActivityIcon from '@lucide/svelte/icons/activity';
  import ArrowLeftRight from '@lucide/svelte/icons/arrow-left-right';
  import KeyRound from '@lucide/svelte/icons/key-round';
  import Shield from '@lucide/svelte/icons/shield';
  import { app } from './lib/state.svelte.ts';
  import { stripScheme } from './lib/util.ts';
  import ChangePassphraseDialog from './lib/components/ChangePassphraseDialog.svelte';
  import Button from './lib/components/Button.svelte';
  import ConfirmDialog from './lib/components/ConfirmDialog.svelte';
  import GraceBanner from './lib/components/GraceBanner.svelte';
  import PassphraseDialog from './lib/components/PassphraseDialog.svelte';
  import Toast from './lib/components/Toast.svelte';
  import VaultGate from './lib/components/VaultGate.svelte';
  import ProxiesPage from './lib/pages/proxies/ProxiesPage.svelte';
  import ActivityPage from './lib/pages/activity/ActivityPage.svelte';
  import { parseActivity } from './lib/pages/activity/route.ts';

  onMount(() => app.start());

  // The hash is the router: `#/activity?...` is the Activity page, `#credentials` scrolls the Proxies page, anything else is Proxies.
  let hash = $state(location.hash);
  const activity = $derived(parseActivity(hash));
  const section = $derived<'proxies' | 'credentials' | 'activity'>(activity ? 'activity' : hash === '#credentials' ? 'credentials' : 'proxies');

  // The Proxies page stays mounted while Activity is open (open rows survive), so a plain anchor jump
  // has nothing to land on until it is shown again. Scroll once it is.
  async function onhash() {
    hash = location.hash;
    await tick();
    if (parseActivity(hash)) window.scrollTo(0, 0);
    else if (hash === '#credentials' || hash === '#proxies') document.getElementById(hash.slice(1))?.scrollIntoView();
  }

  const host = $derived(app.data ? stripScheme(app.data.proxyOrigin) : '');
  const pill = $derived(
    !app.loaded ? 'Connecting…' : app.connected ? `Proxy running · ${host}` : 'Proxy unreachable. Run wickey start',
  );

  const nav = $derived([
    { id: 'proxies' as const, label: 'Proxies', icon: ArrowLeftRight, count: app.data ? app.proxies.filter((p) => !p.cleanedUp).length : null },
    { id: 'credentials' as const, label: 'Credentials', icon: KeyRound, count: app.data ? app.credentials.length : null },
    { id: 'activity' as const, label: 'Activity', icon: ActivityIcon, count: null },
  ]);
  const hrefs = { proxies: '#proxies', credentials: '#credentials', activity: '#/activity' };
</script>

<svelte:window onhashchange={onhash} />

<!-- Everything behind the vault gate is inert so focus and screen readers stay on the gate. -->
<div class="flex min-h-screen flex-col" inert={app.gateMode !== null}>
  <header class="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-border bg-surface px-4">
    <div class="flex items-center gap-2.5">
      <span class="grid size-7 place-items-center rounded-md border border-accent-border bg-accent-bg text-accent-text">
        <Shield size={16} aria-hidden="true" />
      </span>
      <span class="text-[15px] font-semibold">Wickey</span>
    </div>
    <div class="flex min-w-0 items-center gap-2">
    {#if app.session?.vault && app.session.unlocked}
      <Button size="sm" onclick={() => (app.changePassphraseOpen = true)}>Change passphrase</Button>
    {/if}
    <div
      role="status"
      class="flex min-w-0 items-center gap-2 rounded-lg border px-3 py-1 text-xs {app.connected ? 'border-accent-border bg-accent-bg text-accent-text' : app.loaded ? 'border-danger-border bg-danger-bg text-danger-text' : 'border-border-strong bg-surface-2 text-text-muted'}"
    >
      <span class="size-1.5 shrink-0 rounded-full bg-current" aria-hidden="true"></span>
      <span class="truncate">{pill}</span>
    </div>
    </div>
  </header>

  <div class="flex min-h-0 flex-1 flex-col md:flex-row">
    <nav aria-label="Primary" class="shrink-0 border-b border-border bg-surface p-2 md:w-48 md:border-r md:border-b-0 md:p-3">
      <p class="hidden px-2 pb-2 text-xs md:block font-medium tracking-wide text-text-muted uppercase">Manage</p>
      <ul class="flex gap-1 md:flex-col md:gap-0.5">
        {#each nav as item (item.id)}
          <li class="flex-1 md:flex-none">
            <a
              href={hrefs[item.id]}
              aria-current={section === item.id ? 'page' : undefined}
              class="flex h-9 items-center gap-2.5 rounded-md px-2.5 text-sm font-medium {section === item.id ? 'bg-surface-2 text-text' : 'text-text-muted hover:bg-surface-2 hover:text-text'}"
            >
              <item.icon size={16} aria-hidden="true" />
              <span class="flex-1">{item.label}</span>
              {#if item.count !== null}<span class="font-mono text-xs text-text-muted">{item.count}</span>{/if}
            </a>
          </li>
        {/each}
      </ul>
    </nav>

    <main class="min-w-0 flex-1 overflow-x-hidden">
      <div class="mx-auto flex max-w-6xl flex-col gap-4 p-4 md:p-5">
        {#if section === 'activity'}
          <div>
            <h1 class="text-xl font-semibold">Activity</h1>
            <p class="mt-1 max-w-2xl text-[13px] text-text-muted">
              Every request that went through a proxy key, newest first. Only metadata is logged: never prompts or responses.
            </p>
          </div>
        {:else}
          <div id="proxies" class="scroll-mt-4">
            <h1 class="text-xl font-semibold">Proxies</h1>
            <p class="mt-1 max-w-2xl text-[13px] text-text-muted">
              Short-lived keys that forward to your upstream credentials. Agents get a scoped key and a local base URL instead of the real provider key.
            </p>
          </div>
        {/if}

        <GraceBanner />

        {#if activity}<ActivityPage proxy={activity.proxy} status={activity.status} />{/if}
        <div class="flex flex-col gap-4" hidden={section === 'activity'}>
          <ProxiesPage />
        </div>
      </div>
    </main>
  </div>
</div>

<VaultGate />
<PassphraseDialog />
<ChangePassphraseDialog />
<ConfirmDialog />
<Toast />
