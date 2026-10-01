<script lang="ts">
  // Takes a chain's link off its servers (keeping the chain), or deletes
  // the chain: a deployed one through the job that takes the link off
  // first, one that is not deployed at once.
  import { api, asApiError, type ApiError, type Chain, type Job } from '../api';
  import { t } from '../i18n';
  import Dialog from './Dialog.svelte';
  import { deployed } from './chain';

  let { chain, kind, onclose, ondone }: { chain: Chain; kind: 'delete' | 'unlink'; onclose: () => void; ondone: (job: Job | null) => void } = $props();

  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  const onServers = $derived(deployed(chain));

  async function go() {
    busy = true;
    error = null;
    try {
      if (kind === 'unlink') ondone(await api.unlinkChain(chain.id, false));
      else if (onServers) ondone(await api.unlinkChain(chain.id, true));
      else {
        await api.deleteChain(chain.id);
        ondone(null);
      }
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={kind === 'unlink' ? t('cascades.unlinkTitle') : t('cascades.deleteTitle')} {onclose}>
  <p>
    {#if kind === 'unlink'}{t('cascades.unlinkText', { name: chain.name })}
    {:else if onServers}{t('cascades.deleteDeployed', { name: chain.name })}
    {:else}{t('cascades.deleteNew', { name: chain.name })}{/if}
  </p>
  {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
  {#snippet actions()}
    <button onclick={onclose}>{t('common.cancel')}</button>
    <button class="primary danger-bg" onclick={go} disabled={busy}>{kind === 'unlink' ? t('cascades.unlink') : t('cascades.delete')}</button>
  {/snippet}
</Dialog>

<style>
  p { margin: 0 0 12px; max-width: 520px; }
</style>
