<script lang="ts">
  import Plus from '@lucide/svelte/icons/plus';
  import { untrack } from 'svelte';
  import { Cancelled, issueProxy } from '../../api.ts';
  import { app } from '../../state.svelte.ts';
  import { duration, providerLabel } from '../../util.ts';
  import Button from '../../components/Button.svelte';
  import Card from '../../components/Card.svelte';
  import Input from '../../components/Input.svelte';
  import Popover from '../../components/Popover.svelte';
  import Tooltip from '../../components/Tooltip.svelte';
  import Select from '../../components/Select.svelte';
  import SegmentedControl from '../../components/SegmentedControl.svelte';
  import { buildLimits, emptyDraft, modelList, needsModels, summary } from '../../limits.ts';
  import type { LimitsDraft } from '../../limits.ts';
  import LimitsPopover from './LimitsPopover.svelte';
  import SectionMarker from './SectionMarker.svelte';

  interface Props {
    /** Name of the selected credential. */
    credential: string;
    onaddcredential: () => void;
    onissued: (id: string, token: string) => void;
  }
  let { credential = $bindable(), onaddcredential, onissued }: Props = $props();

  const PRESETS = [
    { value: '15m', label: '15 min' },
    { value: '1h', label: '1 hour' },
    { value: '1d', label: '1 day' },
  ];
  const UNITS = [
    { value: 's', label: 'seconds' },
    { value: 'm', label: 'minutes' },
    { value: 'h', label: 'hours' },
    { value: 'd', label: 'days' },
  ];

  let lifetime = $state<string | null>('1h');
  // What the popover has applied (the selection), versus what is being edited in it (the draft).
  let applied = $state({ amount: '', unit: 'm', expireAt: '' });
  let draft = $state({ amount: '', unit: 'm', expireAt: '' });
  let popOpen = $state(false);
  let popError = $state('');
  let limitsApplied = $state<LimitsDraft>(emptyDraft());
  let limitsOpen = $state(false);
  let label = $state('');
  let error = $state('');
  let busy = $state(false);

  const empty = $derived(app.credentials.length === 0);

  // Keep the selection valid as credentials come and go.
  $effect(() => {
    if (!app.credentials.some((c) => c.name === credential)) credential = app.credentials[0]?.name ?? '';
  });

  // "Expire at" wins over the number, as in the old dashboard. Throws a message fit for the user.
  function customTtl(c: { amount: string; unit: string; expireAt: string }): string {
    if (c.expireAt) {
      const seconds = Math.ceil((new Date(c.expireAt).getTime() - Date.now()) / 1000);
      if (!(seconds > 0)) throw new Error('"Expire at" must be in the future. Pick a later time.');
      return `${seconds}s`;
    }
    const n = c.amount.trim();
    if (!n) throw new Error('Enter a custom lifetime or an "Expire at" time.');
    if (!/^\d+$/.test(n) || Number(n) < 1) throw new Error('Custom lifetime must be a whole number of at least 1.');
    return `${n}${c.unit}`;
  }

  const chosenTtl = (): string => (lifetime === 'custom' ? customTtl(applied) : (lifetime ?? '1h'));

  const customLabel = $derived.by(() => {
    if (lifetime !== 'custom') return 'Custom';
    if (applied.expireAt) {
      const when = new Date(applied.expireAt).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
      return `Until ${when}`;
    }
    return `Custom: ${applied.amount.trim()}${applied.unit}`;
  });

  // Start each edit from the current selection, so Cancel/Escape leave it untouched.
  $effect(() => {
    if (!popOpen) return;
    untrack(() => {
      draft = { ...applied };
      popError = '';
    });
  });

  function applyCustom(): boolean {
    try {
      customTtl(draft);
    } catch (err) {
      popError = (err as Error).message;
      return false;
    }
    applied = { ...draft, amount: draft.amount.trim() };
    lifetime = 'custom';
    return true;
  }

  function pickPreset() {
    applied = { amount: '', unit: 'm', expireAt: '' };
  }

  const selectedCredential = $derived(app.credentials.find((c) => c.name === credential));
  const limitsText = $derived(summary(limitsApplied));
  const blocked = $derived(needsModels(limitsApplied));
  let limitsNotice = $state('');

  // A model list belongs to one credential: on a change, load the new list and drop picks it doesn't have.
  let lastCredential = untrack(() => credential);
  $effect(() => {
    const name = credential;
    if (name === lastCredential) return;
    lastCredential = name;
    limitsNotice = '';
    if (!name) return;
    void app.loadModels(name).then(() => {
      const list = app.modelLists[name]?.data;
      if (name !== credential || !list || list.unavailable || list.error) return;
      const have = new Set(list.models ?? []);
      const picked = modelList(limitsApplied.models);
      const kept = picked.filter((m) => have.has(m));
      if (kept.length === picked.length) return;
      limitsApplied = { ...limitsApplied, models: kept.join('\n') };
      const dropped = picked.length - kept.length;
      limitsNotice = `Cleared ${dropped} ${dropped === 1 ? 'model' : 'models'} that ${name} doesn't list. Pick again.`;
    });
  });

  // Validates before closing; the popover shows the message.
  function applyLimits(d: LimitsDraft) {
    // An empty Selected is allowed here (the Issue button then explains itself); only the shape is checked.
    buildLimits(needsModels(d) ? { ...d, modelMode: 'none' } : d);
    limitsApplied = d;
    limitsNotice = '';
  }

  const LIFETIMES = $derived([...PRESETS, { value: 'custom', label: customLabel, render: customOption }]);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = true;
    try {
      const built = buildLimits(limitsApplied);
      const hasLimits = built.limits.models !== null || built.limits.rpm || built.limits.tokenCap;
      const result = await issueProxy({
        credential, ttl: chosenTtl(), label: label.trim(),
        ...(hasLimits ? { limits: built.limits } : {}),
        ...(built.autoRenew ? { autoRenew: built.autoRenew } : {}),
      });
      label = '';
      // Refresh first: the table prunes open rows for ids it has not seen yet.
      await app.refresh();
      // No toast: the one-time key panel is the confirmation, and a toast would sit on its Copy button.
      onissued(result.proxy.id, result.token);
    } catch (err) {
      if (!(err instanceof Cancelled)) error = (err as Error).message;
    } finally {
      busy = false;
    }
  }
</script>

{#snippet customOption(seg: { class: string; pressed: boolean; disabled: boolean })}
  <Popover bind:open={popOpen} label="Custom lifetime" onapply={applyCustom}>
    {#snippet trigger(p)}
      <button {...p} disabled={seg.disabled} aria-pressed={seg.pressed} class={seg.class}>{customLabel}</button>
    {/snippet}
    {#snippet children({ close, apply })}
      <div class="flex w-72 flex-col gap-3">
        <div class="flex items-end gap-2">
          <Input label="Custom lifetime" bind:value={draft.amount} inputmode="numeric" placeholder="30" class="w-28" autocomplete="off" />
          <Select label="Unit" bind:value={draft.unit} class="w-32">
            {#each UNITS as u (u.value)}<option value={u.value}>{u.label}</option>{/each}
          </Select>
        </div>
        <p class="text-[13px] text-text-muted" aria-hidden="true">or</p>
        <Input label="Expire at" type="datetime-local" bind:value={draft.expireAt} help="Overrides the custom lifetime when set." />
        {#if popError}<p role="alert" class="text-[13px] text-danger-text">{popError}</p>{/if}
        <div class="flex justify-end gap-2">
          <Button variant="ghost" size="sm" onclick={close}>Cancel</Button>
          <Button variant="primary" size="sm" onclick={apply}>Apply</Button>
        </div>
      </div>
    {/snippet}
  </Popover>
{/snippet}

<Card id="issue" class="scroll-mt-4">
  {#snippet header()}
    <div class="flex min-w-0 items-center gap-2.5">
      <SectionMarker n={2} />
      <h2 id="issue-heading" class="text-[15px] font-semibold">Issue a proxy key</h2>
    </div>
  {/snippet}

  <form id="issue-form" onsubmit={submit} class="flex flex-col gap-4 p-4">
    {#if empty}
      <div class="flex flex-wrap items-center gap-3">
        <p class="text-[13px] text-text-muted">Add a credential first</p>
        <Button variant="secondary" size="sm" onclick={onaddcredential}><Plus size={14} aria-hidden="true" />Add credential</Button>
      </div>
    {/if}
    <div class="flex flex-wrap items-end gap-3">
      <Select label="Credential" bind:value={credential} disabled={empty} class="w-52">
        {#if empty}
          <option value="">No credentials</option>
        {:else}
          {#each app.credentials as c (c.id)}
            <option value={c.name}>{c.name} · {providerLabel(c.provider)}</option>
          {/each}
        {/if}
      </Select>
      <div class="flex flex-col gap-1.5">
        <span class="text-[13px] font-medium">Lifetime</span>
        <SegmentedControl label="Lifetime" options={LIFETIMES} bind:value={lifetime} onchange={pickPreset} disabled={empty} />
      </div>
      <div class="flex flex-col gap-1.5">
        <span class="text-[13px] font-medium">Limits</span>
        <LimitsPopover bind:open={limitsOpen} label="Key limits" applied={limitsApplied} credential={selectedCredential} notice={limitsNotice} onsubmit={applyLimits}>
          {#snippet trigger(p)}
            <Tooltip text={limitsText} focusable={false}>
              <Button {...p} variant="secondary" disabled={empty} class="w-48 justify-start"><span class="truncate">{limitsText}</span></Button>
            </Tooltip>
          {/snippet}
        </LimitsPopover>
      </div>
      <Input id="issue-name" label="Name" optional bind:value={label} disabled={empty} placeholder="e.g. my-agent" class="w-36" mono autocomplete="off" spellcheck={false} />
      {#if blocked && !empty}
        <Tooltip focusable text="Pick at least one model, or choose All or None.">
          <Button type="submit" variant="primary" disabled><Plus size={14} aria-hidden="true" />Issue proxy</Button>
        </Tooltip>
      {:else}
        <Button type="submit" variant="primary" {busy} busyLabel="Issuing…" disabled={empty}><Plus size={14} aria-hidden="true" />Issue proxy</Button>
      {/if}
    </div>

    {#if error}<p role="alert" class="text-[13px] text-danger-text">{error}</p>{/if}
  </form>
</Card>
