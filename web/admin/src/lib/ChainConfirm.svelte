<script lang="ts">
  // Takes a chain's link off its servers (keeping the chain), or deletes
  // the chain: a deployed one through the job that takes the link off
  // first, one that is not deployed at once. 'force' deletes it without
  // the servers «Удалить каскад» could not reach, listing what stays on
  // them.
  import { api, asApiError, type ApiError, type Chain, type Job } from '../api';
  import { t } from '../i18n';
  import Dialog from './Dialog.svelte';
  import { deployed } from './chain';

  let { chain, kind, onclose, ondone }: { chain: Chain; kind: 'delete' | 'unlink' | 'force'; onclose: () => void; ondone: (job: Job | null) => void } = $props();

  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  const onServers = $derived(deployed(chain));
  const title = $derived(kind === 'unlink' ? t('cascades.unlinkTitle') : kind === 'force' ? t('cascades.forceDelete') : t('cascades.deleteTitle'));

  async function go() {
    busy = true;
    error = null;
    try {
      if (kind === 'unlink') ondone(await api.unlinkChain(chain.id, false));
      else if (kind === 'force') ondone(await api.forceDeleteChain(chain.id));
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

<Dialog {title} {onclose}>
  {#if kind === 'force'}
    <p>{t('cascades.forceText', { name: chain.name })}</p>
    {#each chain.unreachable ?? [] as u (u.serverId)}
      <p class="head">{t(u.role === 'entry' ? 'cascades.forceLeftEntry' : 'cascades.forceLeftExit', { name: u.name })}</p>
      {#if u.left.length}
        <ul>
          {#each u.left as l (l)}<li>{l}</li>{/each}
        </ul>
      {:else}
        <p class="muted">{t('cascades.forceNothing')}</p>
      {/if}
    {/each}
    <p class="small muted">{t('cascades.forceMark')}</p>
  {:else}
    <p>
      {#if kind === 'unlink'}{t('cascades.unlinkText', { name: chain.name })}
      {:else if onServers}{t('cascades.deleteDeployed', { name: chain.name })}
      {:else}{t('cascades.deleteNew', { name: chain.name })}{/if}
    </p>
  {/if}
  {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
  {#snippet actions()}
    <button onclick={onclose}>{t('common.cancel')}</button>
    <button class="primary danger-bg" onclick={go} disabled={busy}>{kind === 'unlink' ? t('cascades.unlink') : kind === 'force' ? t('cascades.forceConfirm') : t('cascades.delete')}</button>
  {/snippet}
</Dialog>

<style>
  p { margin: 0 0 12px; max-width: 520px; }
  p.head { margin-bottom: 4px; font-weight: 600; }
  ul { margin: 0 0 12px; padding-left: 20px; max-width: 520px; overflow-wrap: anywhere; }
  li { margin: 2px 0; }
</style>
