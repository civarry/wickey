<script lang="ts">
  import { tick, untrack } from 'svelte';
  import type { Snippet } from 'svelte';
  import { Cancelled } from '../../api.ts';
  import type { AutoRenew, Credential } from '../../api.ts';
  import { app } from '../../state.svelte.ts';
  import { dateTime, providerLabel } from '../../util.ts';
  import { emptyDraft, usageUnreliable } from '../../limits.ts';
  import type { LimitsDraft, ModelMode } from '../../limits.ts';
  import Button from '../../components/Button.svelte';
  import Checkbox from '../../components/Checkbox.svelte';
  import Input from '../../components/Input.svelte';
  import Popover from '../../components/Popover.svelte';
  import Select from '../../components/Select.svelte';
  import ModelPicker from '../../components/ModelPicker.svelte';
  import SegmentedControl from '../../components/SegmentedControl.svelte';

  interface TriggerProps {
    type: 'button';
    'aria-expanded': boolean;
    'aria-haspopup': 'dialog';
    'aria-controls': string;
    onclick: () => void;
  }

  /**
   * The limits form in a Popover, shared by the issue form and the row's Limits button.
   * `applied` is what the popover starts from each time it opens. `onsubmit` validates and saves; it
   * throws to show a message inside the popover (Cancelled keeps it open silently) and may be async.
   * `current` is the key's existing auto-renew when editing: a blank maximum then keeps it.
   */
  interface Props {
    label: string;
    applied: LimitsDraft;
    credential?: Credential;
    current?: AutoRenew | null;
    open?: boolean;
    /** Shown under the model mode, e.g. which selections were cleared after the credential changed. */
    notice?: string;
    onsubmit: (draft: LimitsDraft) => void | Promise<void>;
    trigger: Snippet<[TriggerProps]>;
  }
  let { label, applied, credential, current = null, open = $bindable(false), notice = '', onsubmit, trigger }: Props = $props();

  let draft = $state<LimitsDraft>(emptyDraft());
  let error = $state('');
  let saving = $state(false);
  const ref: { close?: () => void } = {};

  // Start each edit from the applied values, so Cancel and Escape leave them untouched.
  $effect(() => {
    if (!open) return;
    untrack(() => {
      draft = { ...applied };
      error = '';
    });
  });

  const capSet = $derived(draft.tokenCap.trim() !== '');
  const warn = $derived(capSet && usageUnreliable(credential));

  const entry = $derived(credential ? app.modelLists[credential.name] : undefined);
  const noList = $derived(!!entry?.data?.unavailable);
  const provider = $derived(credential && credential.provider !== 'custom' ? providerLabel(credential.provider) : 'the provider');

  // Know early whether the provider has a list, so the All help text is right.
  $effect(() => {
    if (open && credential) void app.loadModels(credential.name);
  });

  const MODES = [{ value: 'selected', label: 'Selected' }, { value: 'all', label: 'All' }, { value: 'none', label: 'None' }];
  const modeHelp = $derived(
    draft.modelMode === 'all'
      ? noList ? "This provider didn't return a model list, so the provider decides which models work." : `Any model ${provider} lists, including ones it adds later.`
      : draft.modelMode === 'none'
        ? 'Every request with this key is refused.'
        : 'Only the models you pick. Models the provider adds later stay blocked.',
  );

  // The panel is fixed-position; ask it to re-place itself when its height changes.
  $effect(() => {
    void capSet, draft.autoRenew, warn, draft.modelMode, entry?.status, noList, notice;
    if (open) tick().then(() => window.dispatchEvent(new Event('resize')));
  });

  async function submit() {
    if (saving) return;
    error = '';
    saving = true;
    try {
      await onsubmit({ ...draft });
      ref.close?.();
    } catch (err) {
      if (!(err instanceof Cancelled)) error = (err as Error).message;
    } finally {
      saving = false;
    }
  }

  const UNITS_W = [{ value: 'm', label: 'minutes' }, { value: 'h', label: 'hours' }];
  const UNITS_M = [{ value: 'h', label: 'hours' }, { value: 'd', label: 'days' }];
</script>

<Popover bind:open {label} onapply={() => { void submit(); return false; }} {trigger}>
  {#snippet children({ close })}
    <!-- Hands Popover's close() to submit(), which also runs from Enter. -->
    <div {@attach () => { ref.close = close; }} class="flex max-h-[70vh] w-[26rem] max-w-[calc(100vw-3rem)] flex-col gap-3 overflow-y-auto p-0.5">
      <div class="flex flex-col gap-1.5">
        <span class="text-[13px] font-medium">Allowed models</span>
        <SegmentedControl label="Allowed models" size="sm" options={MODES} bind:value={draft.modelMode as string | null} />
        <p class="text-xs text-text-muted">{modeHelp}</p>
        {#if notice}<p role="status" class="text-xs text-warn-text">{notice}</p>{/if}
      </div>
      {#if draft.modelMode === 'selected' && credential}
        <ModelPicker credential={credential.name} bind:value={draft.models} />
      {/if}
      <div class="flex gap-2">
        <Input label="Requests per minute" bind:value={draft.rpm} inputmode="numeric" placeholder="No limit" autocomplete="off" />
        <Input label="Token cap" bind:value={draft.tokenCap} placeholder="No cap, e.g. 100k" autocomplete="off" />
      </div>
      {#if capSet}
        <Checkbox label="Refuse requests when usage can't be counted" bind:checked={draft.refuseUncounted} />
      {/if}
      {#if warn}
        <p role="status" class="rounded-md border border-warn-border bg-warn-bg px-2.5 py-2 text-[13px] text-warn-text">
          This provider didn't report token usage last time, so the cap can only be enforced by refusing requests.
        </p>
      {/if}
      <Checkbox label="Auto-renew" bind:checked={draft.autoRenew} help="Extends the key when it is used shortly before it expires." />
      {#if draft.autoRenew}
        <div class="flex items-end gap-2">
          <Input label="Renew window" bind:value={draft.windowAmount} inputmode="numeric" class="w-24" autocomplete="off" />
          <Select label="Unit" bind:value={draft.windowUnit} class="w-28">
            {#each UNITS_W as u (u.value)}<option value={u.value}>{u.label}</option>{/each}
          </Select>
        </div>
        <div class="flex items-end gap-2">
          <Input label="Maximum lifetime" bind:value={draft.maxAmount} inputmode="numeric" class="w-24" autocomplete="off"
            placeholder={current ? 'Keep' : '7'} />
          <Select label="Unit" bind:value={draft.maxUnit} class="w-28">
            {#each UNITS_M as u (u.value)}<option value={u.value}>{u.label}</option>{/each}
          </Select>
        </div>
        {#if current}<p class="text-xs text-text-muted">Currently renews until {dateTime(current.maxExpiresAt)}. Leave blank to keep that maximum.</p>{/if}
        <p class="text-xs text-text-muted">With auto-renew, the maximum lifetime is the real lifetime you're approving.</p>
      {/if}
      {#if error}<p role="alert" class="text-[13px] text-danger-text">{error}</p>{/if}
      <div class="flex justify-end gap-2">
        <Button variant="ghost" size="sm" onclick={close}>Cancel</Button>
        <Button variant="primary" size="sm" busy={saving} onclick={() => void submit()}>Apply</Button>
      </div>
    </div>
  {/snippet}
</Popover>
