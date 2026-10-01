<script lang="ts">
  // The config history of a server: every revision with where it came
  // from; for writers also the config of a revision, what going back to it
  // changes, and going back (an apply job with the usual rollback).
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type ConfigComparison, type ConfigRevision, type ConfigSource, type ConfigView, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import { go } from '../router.svelte';
  import { when } from './format';
  import Dialog from './Dialog.svelte';
  import DiffView from './DiffView.svelte';

  let { server, writable, onclose }: { server: Server; writable: boolean; onclose: () => void } = $props();

  let revs = $state<ConfigRevision[] | null>(null);
  let error = $state<ApiError | null>(null);
  let selected = $state<ConfigRevision | null>(null);
  let tab = $state<'diff' | 'yaml'>('diff');
  let cmp = $state<ConfigComparison | null>(null);
  let view = $state<ConfigView | null>(null);
  let loading = $state(false);
  let confirming = $state(false);
  let busy = $state(false);
  let current = $derived(revs?.find((r) => r.current) ?? null);

  const sourceKey: Record<ConfigSource, Key> = {
    deploy: 'srv.sourceDeploy',
    import: 'srv.sourceImport',
    edit: 'srv.sourceEdit',
    rollback: 'srv.sourceRollback',
    rotate: 'srv.sourceRotate',
  };
  const source = (r: ConfigRevision) => t(sourceKey[r.source], { n: r.fromRevision ?? 0 });

  onMount(async () => {
    try {
      revs = await api.configRevisions(server.id);
    } catch (e) {
      error = asApiError(e);
    }
  });

  async function select(r: ConfigRevision) {
    if (!writable || !current) return;
    selected = r;
    cmp = view = null;
    error = null;
    loading = true;
    try {
      [cmp, view] = await Promise.all([
        r.current ? Promise.resolve(null) : api.compareConfigs(server.id, current.revision, r.revision),
        api.configRevision(server.id, r.revision),
      ]);
      if (r.current) tab = 'yaml';
    } catch (e) {
      error = asApiError(e);
    } finally {
      loading = false;
    }
  }

  async function rollback() {
    if (!selected || !current) return;
    confirming = false;
    busy = true;
    try {
      const j = await api.rollbackConfig(server.id, current.revision, selected.revision);
      go('deployments', j.id);
    } catch (e) {
      error = asApiError(e);
      busy = false;
    }
  }
</script>

<section class="card">
  <div class="row">
    <h2 class="grow">{t('hist.title', { name: server.name })}</h2>
    <button onclick={onclose}>{t('hist.close')}</button>
  </div>
  {#if writable}<p class="small faint top">{t('hist.note')}</p>{/if}

  {#if revs && revs.length === 0}
    <p class="muted">{t('srv.noConfig')}</p>
  {:else if revs}
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>{t('srv.source')}</th>
          <th>{t('deploy.ports')}</th>
          <th>{t('srv.version')}</th>
          <th>{t('hist.by')}</th>
          <th>{t('hist.when')}</th>
        </tr>
      </thead>
      <tbody>
        {#each revs as r (r.revision)}
          <tr class:click={writable} class:sel={selected?.revision === r.revision} onclick={() => select(r)}>
            <td class="mono">{r.revision}</td>
            <td>{source(r)}{#if r.current} <span class="pill direct small">{t('hist.current')}</span>{/if}</td>
            <td class="mono">{r.meta.ports || '—'}</td>
            <td>{r.meta.version || '—'}</td>
            <td>{r.by || '—'}</td>
            <td>{when(r.createdAt)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}

  {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
</section>

{#if selected}
  <section class="card">
    <div class="row">
      <h2 class="grow">{t('hist.revision', { n: selected.revision })}</h2>
      {#if !selected.current}
        <div class="seg" role="tablist">
          <button class:on={tab === 'diff'} onclick={() => (tab = 'diff')}>{t('hist.tabDiff')}</button>
          <button class:on={tab === 'yaml'} onclick={() => (tab = 'yaml')}>{t('hist.tabYAML')}</button>
        </div>
      {/if}
    </div>
    {#if loading}
      <p class="muted">{t('cfg.loading')}</p>
    {:else if tab === 'diff' && cmp && !selected.current}
      <p class="small faint top">{t('hist.diffNote', { from: cmp.from, to: cmp.to })}</p>
      {#if cmp.secrets.length}<div class="note info small">{t('cfg.secrets', { list: cmp.secrets.join(', ') })}</div>{/if}
      {#if cmp.diff.some((l) => l.op !== ' ')}
        <DiffView lines={cmp.diff} />
      {:else if !cmp.secrets.length}
        <p class="muted small">{t('hist.same')}</p>
      {/if}
    {:else if view}
      <pre class="yaml mono">{view.yaml}</pre>
    {/if}
    {#if !selected.current && !loading}
      <div class="row actions">
        <span class="grow"></span>
        <button class="primary" disabled={busy || !cmp || (!cmp.diff.some((l) => l.op !== ' ') && !cmp.secrets.length)} onclick={() => (confirming = true)}>{t('hist.rollback')}</button>
      </div>
    {/if}
  </section>
{/if}

{#if confirming && selected}
  <Dialog title={t('hist.rollbackTitle', { n: selected.revision })} onclose={() => (confirming = false)}>
    <p>{t('hist.rollbackText')}</p>
    {#if cmp?.secrets.length}<p class="small warn-text">{t('hist.rollbackSecrets')}</p>{/if}
    {#snippet actions()}
      <button onclick={() => (confirming = false)}>{t('common.cancel')}</button>
      <button class="primary" onclick={rollback}>{t('hist.rollback')}</button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .card { margin-bottom: 16px; }
  .top { margin: 6px 0 12px; }
  th { text-align: left; color: var(--muted); font-weight: 500; font-size: 12.5px; padding: 6px 8px; }
  td { padding: 7px 8px; border-top: 1px solid var(--border); }
  tr.click { cursor: pointer; }
  tr.click:hover td { background: var(--surface-2); }
  tr.sel td { background: var(--surface-2); }
  .yaml { background: var(--surface-2); border-radius: var(--radius-sm); padding: 10px 12px; font-size: 12px; line-height: 1.55; overflow-x: auto; white-space: pre; margin: 0; user-select: text; }
  .actions { margin-top: 16px; }
  p { margin: 0; }
  .warn-text { margin-top: 8px; color: var(--warn); }
</style>
