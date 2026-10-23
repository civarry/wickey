<script lang="ts">
  import { getNotifications, setNotification, Cancelled } from '../../api.ts';
  import type { NotificationSettings } from '../../api.ts';
  import { app } from '../../state.svelte.ts';
  import Checkbox from '../../components/Checkbox.svelte';
  import Drawer from '../../components/Drawer.svelte';
  import Tooltip from '../../components/Tooltip.svelte';

  interface Props {
    open: boolean;
  }
  let { open = $bindable() }: Props = $props();

  let settings = $state<NotificationSettings | null>(null);
  let loadError = $state('');
  /** Type being saved. Everything is disabled meanwhile, so two changes never race. */
  let saving = $state<string | null>(null);

  $effect(() => {
    if (!open) return;
    settings = null;
    loadError = '';
    getNotifications().then(
      (s) => (settings = s),
      (err: Error) => (loadError = err instanceof Cancelled ? '' : err.message),
    );
  });

  async function change(type: string, enabled: boolean) {
    saving = type;
    try {
      // The checkbox already flipped (it is bound); the server's answer is what stays.
      settings = await setNotification(type, enabled);
    } catch (err) {
      const row = settings?.types.find((t) => t.type === type);
      if (row) row.enabled = !enabled;
      if (!(err instanceof Cancelled)) app.toast('Could not change the alert', (err as Error).message);
    } finally {
      saving = null;
    }
  }
</script>

<Drawer bind:open title="Alerts" subtitle="Desktop notifications for security events" onclose={() => {}}>
  {#if loadError}
    <p role="alert" class="text-[13px] text-danger-text">{loadError} Close this panel and open it again.</p>
  {:else if !settings}
    <p class="text-[13px] text-text-muted">Loading…</p>
  {:else}
    {#if !settings.backend.available}
      <p class="mb-4 rounded-md border border-warn-border bg-warn-bg px-3 py-2 text-[13px] text-warn-text">
        Backend unavailable: no desktop notification can be shown here. {settings.backend.reason ?? ''}
        Events are still recorded in the log.
      </p>
    {:else}
      <p class="mb-4 text-[13px] text-text-muted">Shown through {settings.backend.name}. Turning an alert off asks for your passphrase, even during the grace period. Turning one on does not.</p>
    {/if}
    <ul class="flex flex-col gap-3">
      {#each settings.types as t (t.type)}
        <li>
          {#if t.locked}
            <Tooltip focusable text="Always on: an alert that could be switched off quietly would not protect you.">
              <Checkbox label={t.label} checked disabled help="Always on" />
            </Tooltip>
          {:else}
            <Checkbox
              label={t.label}
              bind:checked={t.enabled}
              disabled={saving !== null}
              onchange={(e) => void change(t.type, e.currentTarget.checked)}
            />
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</Drawer>
