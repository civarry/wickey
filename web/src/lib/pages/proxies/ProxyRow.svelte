<script lang="ts">
  import Check from '@lucide/svelte/icons/check';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import Copy from '@lucide/svelte/icons/copy';
  import SlidersHorizontal from '@lucide/svelte/icons/sliders-horizontal';
  import Trash2 from '@lucide/svelte/icons/trash-2';
  import { Cancelled, deleteProxy, renewProxy, rotateProxy, setProxyLimits } from '../../api.ts';
  import type { Proxy } from '../../api.ts';
  import { app } from '../../state.svelte.ts';
  import { ago, compact, copyText, dateTime, duration } from '../../util.ts';
  import { atCap, buildLimits, draftFromProxy, summary } from '../../limits.ts';
  import type { LimitsDraft } from '../../limits.ts';
  import Avatar from '../../components/Avatar.svelte';
  import Badge from '../../components/Badge.svelte';
  import Button from '../../components/Button.svelte';
  import Tooltip from '../../components/Tooltip.svelte';
  import LimitsPopover from './LimitsPopover.svelte';
  import ProxyDetail from './ProxyDetail.svelte';
  import { nameOf } from './snippets.ts';

  interface Props {
    proxy: Proxy;
    open: boolean;
    ontoggle: () => void;
    /** Keeps the row open after a rotate. */
    onopen: () => void;
    /** The full key from a just-finished issue or rotate; null otherwise. */
    freshKey: string | null;
    onkey: (token: string) => void;
    onclosekey: () => void;
  }
  let { proxy, open, ontoggle, onopen, freshKey, onkey, onclosekey }: Props = $props();

  const status = $derived(app.statusOf(proxy));
  const name = $derived(nameOf(proxy));
  const expiry = $derived(
    status === 'active'
      ? `Expires in ${duration((proxy.expiresAt - app.now) / 1000)}`
      : `Expired ${duration((app.now - proxy.expiresAt) / 1000)} ago`,
  );
  const cred = $derived(app.credentials.find((c) => c.id === proxy.credentialId));
  const cleaned = $derived(proxy.cleanedUp);
  const badge = $derived(cleaned ? 'cleaned' : proxy.cleanedTampered ? 'tampered' : proxy.rollbackFlagged ? 'review' : status === 'active' && atCap(proxy) ? 'limit' : status);
  const badgeTip = $derived(
    badge === 'tampered'
      ? 'Tampered: marked cleaned up while active. Its database row was edited outside Wickey, so the key is refused. Rotate or delete it.'
      : badge === 'review'
      ? 'This key\'s stored data went backwards, so the database may have been restored from an older copy. It is refused. Rotate or delete it; restarting would accept the older data.'
      : badge === 'limit'
        ? 'The token cap is used up. New requests are refused until you raise the cap.'
        : '',
  );
  const tokens = $derived(proxy.usage.tokensIn + proxy.usage.tokensOut);
  // A cap that cannot be enforced: no refusal fallback and the provider is not known to report usage.
  const unenforceable = $derived(
    proxy.limits.tokenCap !== null && !proxy.limits.refuseUncounted && !!cred && (cred.usageReporting !== 'reports' || cred.streamUsage === 'missing' || cred.streamUsage === 'rejects_option'),
  );
  let limitsOpen = $state(false);
  const limitsApplied = $derived<LimitsDraft>(draftFromProxy(proxy));

  async function saveLimits(d: LimitsDraft) {
    const built = buildLimits(d, proxy.autoRenew);
    // Omitting autoRenew would leave it unchanged, so turning it off must say null.
    await setProxyLimits(proxy.id, { limits: built.limits, autoRenew: built.autoRenew ?? null });
    await app.refresh();
    app.toast(`${name} limits updated`, 'The new limits apply to the next request.');
  }

  let renewing = $state(false);
  let copied = $state(false);
  let copyTimer: ReturnType<typeof setTimeout> | undefined;
  const detailId = $derived(`detail-${proxy.id}`);

  async function renew() {
    renewing = true;
    try {
      await renewProxy(proxy.id);
      await app.refresh();
      app.toast(`${name} renewed`, `Same key, active again for ${duration(proxy.ttlSeconds)}.`);
    } catch (err) {
      if (!(err instanceof Cancelled)) app.toast('Renew failed', (err as Error).message);
    } finally {
      renewing = false;
    }
  }

  function askRotate() {
    app.confirm({
      tone: 'warn',
      action: 'Rotate key',
      title: `Rotate the ${name} key?`,
      body: `A new key replaces the current one for proxy ${proxy.id}. The current key stops working immediately, so any agent still using it will need the new key. The base URL stays the same.`,
      run: async () => {
        const result = await rotateProxy(proxy.id);
        onkey(result.token);
        onopen();
        // No toast: the one-time key panel opens in this row and says what to do.
        await app.refresh();
      },
    });
  }

  function askDelete() {
    app.confirm({
      tone: 'danger',
      action: 'Delete proxy',
      title: `Delete the ${name} proxy?`,
      body: `Proxy ${proxy.id} stops working and is removed from this list. This can't be undone.`,
      run: async () => {
        await deleteProxy(proxy.id);
        await app.refresh();
        app.toast(`${name} deleted`, 'Its key no longer works.');
      },
    });
  }

  async function copyId() {
    if (!(await copyText(proxy.id))) return app.toast('Copy failed', 'The browser blocked clipboard access.');
    copied = true;
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => (copied = false), 1600);
  }

  // The whole row toggles, except its own buttons or while text is being selected.
  function rowClick(e: MouseEvent) {
    if ((e.target as HTMLElement).closest('button, [tabindex]')) return;
    if (String(window.getSelection())) return;
    ontoggle();
  }
</script>

<tbody class="border-b border-border last:border-b-0 {open ? 'bg-surface-2/40' : ''}">
  <!-- Keyboard users toggle with the chevron button; the row click is a pointer convenience. -->
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
  <tr onclick={rowClick} class="cursor-pointer hover:bg-surface-2/60">
    <td class="w-10 py-2 pl-3">
      <Button variant="ghost" size="sm" iconOnly aria-label={`${open ? 'Hide' : 'Show'} details for ${name}`} aria-expanded={open} aria-controls={detailId} onclick={ontoggle}>
        <ChevronRight size={16} aria-hidden="true" class="transition-transform {open ? 'rotate-90' : ''}" />
      </Button>
    </td>
    <td class="max-w-36 px-2 py-2"><Tooltip text={name} block><p class="truncate text-sm font-medium">{name}</p></Tooltip></td>
    <td class="px-2 py-2">
      <span class="inline-flex items-center gap-1 font-mono text-[13px] text-text-muted">
        {proxy.id}
        <Button variant="ghost" size="sm" iconOnly aria-label={`Copy proxy ID ${proxy.id}`} onclick={copyId}>
          {#if copied}<Check size={14} aria-hidden="true" class="text-accent-text" />{:else}<Copy size={14} aria-hidden="true" />{/if}
        </Button>
      </span>
    </td>
    <td class="max-w-32 px-2 py-2">
      <span class="flex items-center gap-2"><Avatar name={proxy.credentialName} /><Tooltip text={proxy.credentialName} block><span class="truncate text-[13px]">{proxy.credentialName}</span></Tooltip></span>
    </td>
    <td class="px-2 py-2">
      <div class="flex flex-col items-start gap-1">
        {#if badgeTip}<Tooltip text={badgeTip} focusable><Badge status={badge} /></Tooltip>{:else}<Badge status={badge} />{/if}
        {#if unenforceable}
          <Tooltip focusable text="This provider doesn't report token usage and the key doesn't refuse uncounted requests, so the cap may not stop it.">
            <span class="text-xs text-warn-text">Token cap not enforceable</span>
          </Tooltip>
        {/if}
      </div>
    </td>
    <td class="px-2 py-2 text-[13px] whitespace-nowrap">
      <Tooltip focusable text={`In ${proxy.usage.tokensIn.toLocaleString('en-US')}, out ${proxy.usage.tokensOut.toLocaleString('en-US')}, ${proxy.usage.uncounted.toLocaleString('en-US')} requests without a usage count.`}>
        <span class="flex flex-col">
          <span>{proxy.usage.requests} req · {compact(tokens)} tok</span>
          <span class="text-xs text-text-muted">{proxy.usage.lastUsedAt ? `Last used ${ago(proxy.usage.lastUsedAt, app.now)}` : 'Not used yet'}</span>
        </span>
      </Tooltip>
    </td>
    <td class="px-2 py-2 text-[13px] whitespace-nowrap text-text-muted">
      {expiry}
      {#if proxy.autoRenew}<span class="block text-xs">auto-renews until {dateTime(proxy.autoRenew.maxExpiresAt)}</span>{/if}
    </td>
    <td class="py-2 pr-3 pl-2">
      <div class="flex items-center justify-end gap-1.5">
        <Tooltip focusable={status === 'active' || cleaned || renewing} text={cleaned ? 'Retired by wickey env. Run env again for a fresh key.' : status === 'active' ? 'Still active. Renew reactivates this same key once it expires.' : 'Reactivate this same key for another lifetime.'}>
          <Button variant="secondary" size="sm" disabled={status === 'active' || cleaned} busy={renewing} onclick={renew}>Renew</Button>
        </Tooltip>
        <LimitsPopover label={`Limits for ${name}`} bind:open={limitsOpen} applied={limitsApplied} credential={cred} current={proxy.autoRenew} onsubmit={saveLimits}>
          {#snippet trigger(p)}
            <Tooltip text={`Edit limits. ${summary(limitsApplied).replace(/^Limits: /, '')}`}><Button {...p} variant="secondary" size="sm" iconOnly aria-label={`Edit limits for ${name}`}><SlidersHorizontal size={14} aria-hidden="true" /></Button></Tooltip>
          {/snippet}
        </LimitsPopover>
        <Tooltip text="Replace with a new key. The current key stops working.">
          <Button variant="secondary" size="sm" disabled={cleaned} onclick={askRotate}>Rotate</Button>
        </Tooltip>
        <Button variant="danger" size="sm" iconOnly aria-label={`Delete proxy ${name}`} onclick={askDelete}><Trash2 size={14} aria-hidden="true" /></Button>
      </div>
    </td>
  </tr>
  {#if open}
    <tr id={detailId}><td colspan="8" class="border-t border-border">
      <!-- Pinned to the visible width so the details never scroll away with the wide table. -->
      <div class="sticky left-0 w-[100cqw]"><ProxyDetail {proxy} {freshKey} {onclosekey} onrotate={askRotate} /></div>
    </td></tr>
  {/if}
</tbody>
