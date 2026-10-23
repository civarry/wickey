<script lang="ts">
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import { Cancelled, renewProxy } from '../../api.ts';
  import { app } from '../../state.svelte.ts';
  import { plural } from '../../util.ts';
  import Button from '../../components/Button.svelte';

  const expired = $derived(app.proxies.filter((p) => app.statusOf(p) === 'expired' && !p.cleanedUp));
  const anyActive = $derived(app.proxies.some((p) => app.statusOf(p) === 'active'));
  let busy = $state(false);

  async function renewAll() {
    const list = [...expired];
    let done = 0;
    busy = true;
    try {
      for (const p of list) {
        await renewProxy(p.id);
        done++;
      }
      app.toast(`${plural(done, 'proxy', 'proxies')} renewed`, 'Same keys, active again for their previous lifetimes.');
    } catch (err) {
      if (!(err instanceof Cancelled)) app.toast(`Renewed ${done} of ${list.length}`, (err as Error).message);
    } finally {
      busy = false;
      await app.refresh();
    }
  }
</script>

{#if expired.length}
  <div class="flex flex-wrap items-center gap-3 rounded-lg border border-warn-border bg-warn-bg px-4 py-2.5">
    <TriangleAlert size={16} aria-hidden="true" class="shrink-0 text-warn-text" />
    <p class="min-w-0 flex-1 text-[13px] text-warn-text">
      <strong class="font-semibold">{plural(expired.length, 'proxy has', 'proxies have')} expired.</strong>
      {anyActive
        ? "Agents using expired keys can't reach a provider until you renew or rotate them."
        : "No active proxies, so agents can't reach a provider right now."}
    </p>
    <Button variant="warn" size="sm" {busy} busyLabel="Renewing…" onclick={renewAll}>Renew all</Button>
  </div>
{/if}
