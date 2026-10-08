<script lang="ts">
  // Bulk operations (P4-07): the batches of the servers in the user's
  // scope, and one batch with the progress of its servers.
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Batch, type BatchState, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import { go, route } from '../router.svelte';
  import { when } from '../lib/format';
  import BatchView from '../lib/BatchView.svelte';

  let list = $state<Batch[] | null>(null);
  let servers = $state<Record<number, Server>>({});
  let error = $state<ApiError | null>(null);

  async function load() {
    try {
      const [bs, ss] = await Promise.all([api.batches(), api.servers()]);
      list = bs;
      servers = Object.fromEntries(ss.map((s) => [s.id, s]));
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
  }
  onMount(load);

  const tone = (s: BatchState) => (s === 'completed' ? 'ok' : s === 'failed' ? 'bad' : s === 'running' || s === 'stopping' ? 'wait' : '');
  const done = (b: Batch) => b.items.filter((it) => it.state === 'completed' || it.state === 'unchanged').length;
</script>

{#if route.id}
  <button class="link back" onclick={() => (go('batches'), load())}>← {t('batches.back')}</button>
  {#key route.id}
    <BatchView id={route.id} {servers} />
  {/key}
{:else}
  <button class="link back" onclick={() => go('deployments')}>← {t('nav.deployments')}</button>
  <h1>{t('batches.title')}</h1>
  <p class="muted small intro">{t('batches.intro')}</p>
  {#if error}<div class="note error">{error.message}</div>{/if}
  {#if list && list.length === 0}
    <div class="card empty"><p>{t('batches.empty')}</p></div>
  {:else if list}
    <div class="card table">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>{t('batches.action')}</th>
            <th>{t('batches.progress')}</th>
            <th>{t('batches.state')}</th>
            <th>{t('batches.by')}</th>
            <th>{t('batches.started')}</th>
          </tr>
        </thead>
        <tbody>
          {#each list as b (b.id)}
            <tr class="click" onclick={() => go('batches', b.id)}>
              <td class="mono">{b.id}</td>
              <td>{t(`batch.action.${b.action}` as Key)}</td>
              <td>{t('batch.progress', { done: done(b), total: b.items.length })}</td>
              <td><span class="dot {tone(b.state)}"></span> {t(`bstate.${b.state}` as Key)}</td>
              <td>{b.createdBy || '—'}</td>
              <td>{when(b.createdAt)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<style>
  h1 { margin-bottom: 6px; }
  .intro { margin: 0 0 16px; }
  .back { margin-bottom: 12px; }
  .empty p { margin: 0; color: var(--muted); }
  .table { padding: 6px 8px; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 8px; }
  td { padding: 10px 8px; border-top: 1px solid var(--border); }
  tr.click { cursor: pointer; }
  tr.click:hover td { background: var(--surface-2); }
</style>
