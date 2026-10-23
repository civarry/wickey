<script lang="ts">
  import { SvelteSet } from 'svelte/reactivity';
  import { tick } from 'svelte';
  import type { Credential } from '../../api.ts';
  import CredentialDrawer from './CredentialDrawer.svelte';
  import CredentialsSection from './CredentialsSection.svelte';
  import ExpiredLine from './ExpiredLine.svelte';
  import ImportDrawer from './ImportDrawer.svelte';
  import IssueForm from './IssueForm.svelte';
  import ProxyTable from './ProxyTable.svelte';

  // Open rows live here so they survive polling and filter changes.
  const open = new SvelteSet<string>();
  let filter = $state<string | null>('all');
  let query = $state('');
  let issueCredential = $state('');
  // Full keys exist only here, from the issue/rotate response until the user is done with them. Not in
  // the app store, so polling never sees them and a reload or navigation drops them.
  let keys = $state<Record<string, string>>({});

  let drawerOpen = $state(false);
  let importOpen = $state(false);
  let editing = $state<Credential | null>(null);

  function openDrawer(c: Credential | null) {
    editing = c;
    drawerOpen = true;
  }

  async function issueFor(c: Credential) {
    issueCredential = c.name;
    await tick();
    document.getElementById('issue')?.scrollIntoView({ block: 'start' });
    document.getElementById('issue-name')?.focus({ preventScroll: true });
  }

  function issued(id: string, token: string) {
    keys[id] = token;
    open.add(id);
    filter = 'all';
    query = '';
  }
</script>

<ExpiredLine />
<CredentialsSection onadd={() => openDrawer(null)} onimport={() => (importOpen = true)} onedit={(c) => openDrawer(c)} onissue={issueFor} />
<svelte:window onhashchange={() => { if (location.hash.startsWith('#/activity')) keys = {}; }} />
<IssueForm bind:credential={issueCredential} onaddcredential={() => openDrawer(null)} onissued={issued} />
<ProxyTable bind:filter bind:query {open} {keys} onkey={(id, t) => (keys[id] = t)} onclosekey={(id) => delete keys[id]} />
<CredentialDrawer bind:open={drawerOpen} credential={editing} />
<ImportDrawer bind:open={importOpen} />
