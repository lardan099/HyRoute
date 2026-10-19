<script lang="ts">
  // A warning in the dialogs that change a server's config: a cascade
  // through this server may need its link deployed again afterwards.
  import type { Server } from '../api';
  import { t } from '../i18n';
  import { go } from '../router.svelte';

  let { server }: { server: Server | null | undefined } = $props();
  let chains = $derived(server?.chains?.filter((c) => c.state !== 'new' && c.state !== 'failed') ?? []);
</script>

{#if chains.length}
  <div class="note warn chain-note">
    {t('cascades.serverNote')}
    {#each chains as c, i (c.id)}{i ? ', ' : ' '}<button class="link" onclick={() => go('cascades', c.id)}>«{c.name}»</button>{/each}.
  </div>
{/if}

<style>
  .chain-note { margin: 0 0 12px; }
  .link { background: none; border: 0; padding: 0; color: inherit; text-decoration: underline; cursor: pointer; font: inherit; }
</style>
