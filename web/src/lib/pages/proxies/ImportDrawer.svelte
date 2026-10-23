<script lang="ts">
  import { untrack } from 'svelte';
  import FileUp from '@lucide/svelte/icons/file-up';
  import { Cancelled, importCredentials } from '../../api.ts';
  import type { ImportEntryInput, ImportResult } from '../../api.ts';
  import { detectEntries, maskSecret, MAX_ENV_BYTES } from '../../../../../src/dotenv.ts';
  import type { EnvEntry } from '../../../../../src/dotenv.ts';
  import { app } from '../../state.svelte.ts';
  import { plural, providerLabel } from '../../util.ts';
  import Badge from '../../components/Badge.svelte';
  import Button from '../../components/Button.svelte';
  import Checkbox from '../../components/Checkbox.svelte';
  import Drawer from '../../components/Drawer.svelte';
  import EmptyState from '../../components/EmptyState.svelte';
  import Input from '../../components/Input.svelte';
  import Tooltip from '../../components/Tooltip.svelte';

  interface Props {
    open: boolean;
  }
  let { open = $bindable() }: Props = $props();

  const MAX_ROWS = 50;
  const DEBOUNCE_MS = 400;

  interface Row extends EnvEntry {
    selected: boolean;
    /** Latest dry-run answer; null while it is being (re)checked. */
    check: ImportResult | null;
  }
  interface Summary {
    imported: string[];
    skipped: string[];
    duplicate: string[];
    unresolved: string[];
    failed: { name: string; message: string }[];
  }

  let step = $state<'pick' | 'review' | 'done'>('pick');
  let rows = $state<Row[]>([]);
  let ignored = $state(0);
  let fileError = $state('');
  let reading = $state(false);
  let dragging = $state(false);
  let checking = $state(false);
  let checkError = $state('');
  let importing = $state(false);
  let importError = $state('');
  let summary = $state<Summary | null>(null);
  let picker = $state<HTMLInputElement>();
  let seq = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;

  // Parsed entries hold real keys, so nothing survives the drawer closing.
  function reset() {
    clearTimeout(timer);
    seq++;
    step = 'pick';
    rows = [];
    ignored = 0;
    fileError = '';
    reading = dragging = checking = importing = false;
    checkError = importError = '';
    summary = null;
  }
  $effect(() => {
    if (!open) untrack(reset);
  });

  const importable = (r: Row) => r.status === 'ready' || r.status === 'review';
  const blocked = (r: Row) => r.check !== null && r.check.outcome !== 'would_import';
  const selectable = (r: Row) => importable(r) && !blocked(r);
  const chosen = $derived(rows.filter((r) => r.selected && selectable(r)));
  const waiting = $derived(checking || rows.some((r) => importable(r) && r.check === null));
  const hasKeys = $derived(rows.some(importable));

  const payload = (r: Row): ImportEntryInput => ({
    name: r.name.trim(), provider: r.provider, baseUrl: r.baseUrl || undefined, apiKey: r.apiKey, authStyle: r.authStyle,
  });

  async function readFile(file: File | undefined) {
    if (!file) return;
    fileError = '';
    if (file.size > MAX_ENV_BYTES) {
      fileError = 'That file is larger than 256 KB, which is too big for an .env file. Pick a different file.';
      return;
    }
    reading = true;
    try {
      const found = detectEntries(await file.text(), app.data?.providers ?? {});
      if (found.error) fileError = found.error;
      else if (!found.entries.length) fileError = 'No provider API keys found in that file. Look for variables like OPENAI_API_KEY or ANTHROPIC_API_KEY.';
      else if (found.entries.length > MAX_ROWS) fileError = `That file has more than ${MAX_ROWS} keys. Split it and import in parts.`;
      else {
        rows = found.entries.map((e) => ({ ...e, selected: e.status === 'ready', check: null }));
        ignored = found.ignored;
        step = 'review';
        await runCheck();
      }
    } catch {
      fileError = 'Could not read that file. Try again or pick a different one.';
    } finally {
      reading = false;
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    void readFile(e.dataTransfer?.files?.[0]);
  }

  function onPick(e: Event & { currentTarget: HTMLInputElement }) {
    const file = e.currentTarget.files?.[0];
    e.currentTarget.value = '';
    void readFile(file);
  }

  /** Dry run: validates and looks for stored duplicates without saving. Asks for the passphrase if needed. */
  async function runCheck() {
    const mine = ++seq;
    const at = rows.flatMap((r, i) => (importable(r) ? [i] : []));
    if (!at.length) return;
    checking = true;
    checkError = '';
    try {
      const { results } = await importCredentials(at.map((i) => payload(rows[i])), true);
      if (mine !== seq) return;
      at.forEach((i, k) => (rows[i].check = results[k] ?? null));
    } catch (err) {
      if (mine !== seq) return;
      checkError = err instanceof Cancelled ? 'Checking for duplicates needs your passphrase.' : (err as Error).message;
    } finally {
      if (mine === seq) checking = false;
    }
  }

  function renamed(r: Row) {
    r.check = null;
    clearTimeout(timer);
    timer = setTimeout(() => void runCheck(), DEBOUNCE_MS);
  }

  async function doImport() {
    importing = true;
    importError = '';
    const send = chosen;
    try {
      const { results } = await importCredentials(send.map(payload), false);
      const s: Summary = { imported: [], skipped: [], duplicate: [], unresolved: [], failed: [] };
      const sent = new Set(send);
      send.forEach((r, k) => {
        const res = results[k];
        if (res?.outcome === 'imported') s.imported.push(res.name);
        else if (res?.outcome === 'duplicate_key' || res?.outcome === 'duplicate_name') s.duplicate.push(r.name.trim());
        else s.failed.push({ name: r.name.trim(), message: res?.message ?? 'Not imported.' });
      });
      for (const r of rows) {
        if (sent.has(r)) continue;
        if (r.status === 'unresolved') s.unresolved.push(r.source);
        else if (r.check && r.check.outcome !== 'would_import' && importable(r)) {
          if (r.check.outcome === 'invalid') s.failed.push({ name: r.name.trim(), message: r.check.message ?? 'Not valid.' });
          else s.duplicate.push(r.name.trim());
        } else s.skipped.push(importable(r) ? r.name.trim() : r.source);
      }
      summary = s;
      for (const r of rows) r.apiKey = '';
      step = 'done';
      await app.refresh();
    } catch (err) {
      if (!(err instanceof Cancelled)) importError = (err as Error).message;
    } finally {
      importing = false;
    }
  }

  const badge = (r: Row): { status: 'ready' | 'attention' | 'danger' | 'neutral'; label: string } => {
    if (r.status === 'skipped') return { status: 'neutral', label: 'Skipped' };
    if (r.status === 'unresolved') return { status: 'danger', label: 'Unresolved' };
    if (r.check?.outcome === 'duplicate_key') return { status: 'neutral', label: 'Already stored' };
    if (r.check?.outcome === 'duplicate_name') return { status: 'neutral', label: 'Name taken' };
    if (r.check?.outcome === 'invalid') return { status: 'danger', label: 'Invalid' };
    return r.status === 'review' ? { status: 'attention', label: 'Review' } : { status: 'ready', label: 'Ready' };
  };
  const note = (r: Row): string => (r.check && r.check.outcome !== 'would_import' ? (r.check.message ?? '') : (r.reason ? `${r.source} ${r.reason}` : ''));
  const scope = (r: Row) => (r.check?.baseUrlScope === 'private' || r.check?.baseUrlScope === 'loopback' ? r.check.baseUrlScope : null);

  const counts = $derived(summary ? ([
    ['Imported', summary.imported],
    ['Skipped', summary.skipped],
    ['Duplicate', summary.duplicate],
    ['Unresolved', summary.unresolved],
  ] as const) : []);
</script>

<Drawer
  bind:open
  wide
  title="Import from .env"
  subtitle={step === 'review' ? 'Choose which credentials to add.' : step === 'done' ? 'Import finished.' : 'Add provider keys from a file.'}
  onclose={() => { if (step === 'done') void app.refresh(); }}
>
  {#if step === 'pick'}
    <div
      role="group"
      aria-label="Drop a .env file here"
      ondragover={(e) => { e.preventDefault(); dragging = true; }}
      ondragleave={() => (dragging = false)}
      ondrop={onDrop}
      class="flex flex-col items-center gap-3 rounded-md border border-dashed px-6 py-12 text-center {dragging ? 'border-accent bg-accent-bg' : 'border-border-strong bg-surface-2'}"
    >
      <FileUp size={24} class="text-text-muted" aria-hidden="true" />
      <p class="text-sm font-medium">Drop a .env file here</p>
      <Button variant="secondary" size="sm" busy={reading} busyLabel="Reading…" onclick={() => picker?.click()}>Choose file</Button>
      <input bind:this={picker} type="file" accept=".env,text/plain,*/*" class="sr-only" tabindex="-1" aria-label="Choose a .env file" onchange={onPick} />
    </div>
    <p class="mt-3 text-[13px] text-text-muted">
      The file is read in this browser tab. Only the entries you select are sent to Wickey on this machine, and other variables are never shown or sent.
    </p>
    {#if fileError}<p role="alert" class="mt-3 rounded-md border border-danger-border bg-danger-bg px-3 py-2 text-[13px] text-danger-text">{fileError}</p>{/if}
  {:else if step === 'review'}
    <ul class="divide-y divide-border rounded-md border border-border">
      {#each rows as r (r.source)}
        {@const b = badge(r)}
        {@const sc = scope(r)}
        <li class="flex flex-col gap-2 px-3 py-3">
          <div class="flex flex-wrap items-center justify-between gap-x-3 gap-y-2">
            <Checkbox
              label={r.source}
              checked={r.selected && selectable(r)}
              disabled={!selectable(r)}
              onchange={(e) => (r.selected = e.currentTarget.checked)}
            />
            <div class="flex flex-wrap items-center gap-1.5">
              {#if sc}
                <Tooltip focusable prefer="bottom" text="This address is on your own network or machine, not the public internet. Import it only if you expect that.">
                  <Badge status="attention" label="Private address" />
                </Tooltip>
              {/if}
              <Badge status={b.status} label={b.label} />
            </div>
          </div>
          {#if importable(r)}
            <Input label={`Name for ${r.source}`} hideLabel bind:value={r.name} oninput={() => renamed(r)} mono autocomplete="off" spellcheck={false} />
            <div class="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-xs text-text-muted">
              <span>{providerLabel(r.provider)}</span>
              <Tooltip text={r.baseUrl} block><span class="block max-w-xs truncate font-mono">{r.baseUrl}</span></Tooltip>
              <span class="font-mono">{maskSecret(r.apiKey)}</span>
            </div>
          {/if}
          {#if note(r)}<p class="text-xs text-text-muted">{note(r)}</p>{/if}
        </li>
      {/each}
    </ul>
    {#if ignored}<p class="mt-3 text-xs text-text-muted">{plural(ignored, 'other variable', 'other variables')} ignored.</p>{/if}
    {#if hasKeys}
      <p class="mt-1 text-xs text-text-muted">
        {#if waiting}Checking for duplicates…{:else}Nothing is saved until you click Import. No proxy keys are created.{/if}
      </p>
    {/if}
    {#if checkError}
      <div role="alert" class="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-md border border-warn-border bg-warn-bg px-3 py-2 text-[13px] text-warn-text">
        <span>{checkError}</span>
        <Button variant="secondary" size="sm" busy={checking} busyLabel="Checking…" onclick={runCheck}>Check again</Button>
      </div>
    {/if}
    {#if importError}<p role="alert" class="mt-3 rounded-md border border-danger-border bg-danger-bg px-3 py-2 text-[13px] text-danger-text">{importError}</p>{/if}
  {:else if summary}
    {#if !summary.imported.length && !summary.failed.length && !summary.duplicate.length}
      <EmptyState title="Nothing was imported" body="Every entry was skipped or could not be resolved." />
    {/if}
    <dl class="flex flex-col divide-y divide-border rounded-md border border-border">
      {#each counts as [label, names] (label)}
        <div class="flex flex-col gap-0.5 px-3 py-2.5">
          <dt class="text-[13px] font-medium">{label} <span class="font-normal text-text-muted">({names.length})</span></dt>
          {#if names.length}<dd class="font-mono text-xs break-words text-text-muted">{names.join(', ')}</dd>{/if}
        </div>
      {/each}
      <div class="flex flex-col gap-0.5 px-3 py-2.5">
        <dt class="text-[13px] font-medium">Failed <span class="font-normal text-text-muted">({summary.failed.length})</span></dt>
        {#each summary.failed as f (f.name)}<dd class="text-xs break-words text-danger-text"><span class="font-mono">{f.name}</span>: {f.message}</dd>{/each}
      </div>
    </dl>
    <p class="mt-3 text-xs text-text-muted">Imported credentials have no proxy keys yet. Use Issue proxy on a credential to create one.</p>
  {/if}

  {#snippet footer()}
    {#if step === 'done'}
      <Button variant="primary" onclick={() => (open = false)}>Done</Button>
    {:else}
      <Button variant="secondary" onclick={() => (open = false)}>Cancel</Button>
      {#if step === 'review'}
        <Button variant="primary" busy={importing} busyLabel="Importing…" disabled={!chosen.length || waiting} onclick={doImport}>
          Import {plural(chosen.length, 'credential', 'credentials')}
        </Button>
      {/if}
    {/if}
  {/snippet}
</Drawer>
