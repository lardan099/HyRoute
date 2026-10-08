<script lang="ts">
  // One batch (P4-07): the progress of every server with its job, why it
  // stopped, «Остановить» (no new jobs; running ones finish) and
  // «Повторить неудачные» (a new batch over the failed and skipped
  // servers, the canary first again). Refreshed while it runs.
  import { onDestroy, onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Batch, type BatchItemState, type BatchState, type Preset, type RoutingTemplate, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import { go } from '../router.svelte';
  import { when } from './format';
  import Dialog from './Dialog.svelte';

  let { id, servers }: { id: number; servers: Record<number, Server> } = $props();

  let b = $state<Batch | null>(null);
  let error = $state<ApiError | null>(null);
  let actionError = $state<ApiError | null>(null);
  let busy = $state(false);
  let stopping = $state(false);
  let presets = $state<Preset[]>([]);
  let templates = $state<RoutingTemplate[]>([]);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let gone = false;

  const live = (s: BatchState) => s === 'running' || s === 'stopping';

  async function load() {
    clearTimeout(timer);
    try {
      b = await api.batch(id);
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
    if (!gone && (!b || live(b.state))) timer = setTimeout(load, 2000);
  }

  onMount(async () => {
    await load();
    try {
      if (b?.action === 'preset') presets = await api.presets();
      if (b?.action === 'routing') templates = await api.routingTemplates();
    } catch {} // names only
  });
  onDestroy(() => {
    gone = true;
    clearTimeout(timer);
  });

  async function stop() {
    busy = true;
    actionError = null;
    try {
      b = await api.stopBatch(id);
      stopping = false;
      load();
    } catch (e) {
      actionError = asApiError(e);
    } finally {
      busy = false;
    }
  }

  async function retry() {
    busy = true;
    actionError = null;
    try {
      const next = await api.retryBatch(id);
      go('batches', next.id);
    } catch (e) {
      actionError = asApiError(e);
      busy = false;
    }
  }

  const tone = (s: BatchState) => (s === 'completed' ? 'ok' : s === 'failed' ? 'bad' : live(s) ? 'wait' : '');
  const itemTone = (s: BatchItemState) => (s === 'completed' || s === 'unchanged' ? 'ok' : s === 'failed' ? 'bad' : s === 'running' || s === 'starting' ? 'wait' : '');

  // params are the action's choices in words.
  let params = $derived.by(() => {
    if (!b) return [] as string[];
    const p = b.params as Record<string, any>;
    const out: string[] = [];
    const src = (s: string) => t(({ auto: 'deploy.sourceAuto', direct: 'deploy.sourceDirect', relay: 'deploy.sourceRelay', node: 'deploy.sourceNode' } as Record<string, Key>)[s] ?? 'deploy.sourceAuto');
    switch (b.action) {
      case 'maintain':
        out.push(t('batch.paramVersion', { version: p.version }));
        if (p.source && p.source !== 'auto') out.push(t('batch.paramSource', { source: src(p.source) + (p.via ? ' — ' + (servers[p.via]?.name ?? '#' + p.via) : '') }));
        break;
      case 'geo':
        if (p.source && p.source !== 'auto') out.push(t('batch.paramSource', { source: src(p.source) + (p.via ? ' — ' + (servers[p.via]?.name ?? '#' + p.via) : '') }));
        break;
      case 'preset':
        out.push(presets.find((x) => x.id === p.preset)?.name ?? '#' + p.preset);
        out.push((p.sections ?? []).map((s: string) => t(`psec.${s}` as Key)).join(', '));
        break;
      case 'routing':
        out.push(templates.find((x) => x.id === p.template)?.name ?? p.template);
        out.push(t('batch.paramPlace', { place: t(`tpl.${p.place}` as Key).toLowerCase() }));
        break;
      case 'tuning':
        out.push((p.keys ?? []).map((k: string) => t(`tune.key.${k}` as Key)).join(', '));
        break;
      case 'rotate':
        out.push([p.auth && t('batch.rotateAuth'), p.obfs && t('rot.obfs'), p.cert && t('rot.cert')].filter(Boolean).join(', '));
        break;
    }
    return out.filter(Boolean);
  });

  let count = $derived.by(() => {
    const c: Record<string, number> = {};
    for (const it of b?.items ?? []) c[it.state] = (c[it.state] ?? 0) + 1;
    return c;
  });
  let done = $derived((count.completed ?? 0) + (count.unchanged ?? 0));
  let total = $derived(b?.items.length ?? 0);

  let reason = $derived.by(() => {
    if (!b?.stop) return '';
    if (b.stop === 'user') return b.stoppedBy ? t('batch.stop.user', { name: b.stoppedBy }) : t('batch.stop.userNobody');
    return t(`batch.stop.${b.stop}` as Key);
  });
</script>

{#if error && !b}<div class="note error">{error.message}</div>{/if}
{#if b}
  <div class="row head">
    <h1 class="grow">{t('batch.number', { id: b.id })}: {t(`batch.action.${b.action}` as Key)}</h1>
    {#if b.mayStop}<button disabled={busy} onclick={() => (stopping = true)}>{t('batch.stopButton')}</button>{/if}
    {#if b.mayRetry}<button class="primary" disabled={busy} onclick={retry}>{t('batch.retry')}</button>{/if}
  </div>
  {#if params.length}<p class="muted">{params.join(' · ')}</p>{/if}
  <p class="small faint">
    {b.createdBy ? t('batch.meta', { at: when(b.createdAt), by: b.createdBy, k: b.parallel }) : t('batch.metaNobody', { at: when(b.createdAt), k: b.parallel })}
  </p>

  <section class="card summary">
    <div class="row">
      <span class="dot {tone(b.state)}"></span>
      <b>{t(`bstate.${b.state}` as Key)}</b>
      <span class="muted">{t('batch.progress', { done, total })}</span>
      {#if count.failed || count.skipped || count.unchanged}
        <span class="small faint">({t('batch.counts', { failed: count.failed ?? 0, skipped: count.skipped ?? 0, unchanged: count.unchanged ?? 0 })})</span>
      {/if}
    </div>
    <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax={total} aria-valuenow={done}>
      <span class="ok" style="width: {total ? (100 * done) / total : 0}%"></span>
      <span class="bad" style="width: {total ? (100 * (count.failed ?? 0)) / total : 0}%"></span>
    </div>
    {#if reason}<p class="small">{reason}</p>{/if}
    {#if b.retryOf}<button class="link small" onclick={() => go('batches', b!.retryOf!)}>{t('batch.retryOf', { id: b.retryOf })}</button>{/if}
    {#if b.retriedBy}<button class="link small" onclick={() => go('batches', b!.retriedBy!)}>{t('batch.retriedBy', { id: b.retriedBy })}</button>{/if}
    {#if actionError}<div class="note error small">{actionError.message}</div>{/if}
  </section>

  <div class="card table">
    <table>
      <thead>
        <tr>
          <th>{t('batch.server')}</th>
          <th>{t('batch.state')}</th>
          <th>{t('batch.details')}</th>
        </tr>
      </thead>
      <tbody>
        {#each b.items as it (it.idx)}
          <tr>
            <td>
              <button class="link name" onclick={() => go('servers', it.serverId)}>{servers[it.serverId]?.name ?? '#' + it.serverId}</button>
              {#if it.canary}<span class="badge canary">{t('batch.canaryBadge')}</span>{/if}
            </td>
            <td class="st">
              <span class="dot {itemTone(it.state)}"></span> {t(`bitem.${it.state}` as Key)}
              {#if it.job && (it.state === 'running' || it.state === 'starting')}<div class="small faint">{t(`jstate.${it.job.state}` as Key)}</div>{/if}
            </td>
            <td class="small">
              {#if it.jobId}<button class="link" onclick={() => go('deployments', it.jobId!)}>{t('batch.job', { id: it.jobId })}</button>{/if}
              {#if it.message}<span class:muted={it.state !== 'failed'} class:err={it.state === 'failed'}>{it.message}</span>{/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if stopping}
  <Dialog title={t('batch.stopButton')} onclose={() => (stopping = false)}>
    <p>{t('batch.stopConfirm')}</p>
    {#if actionError}<div class="note error">{actionError.message}</div>{/if}
    {#snippet actions()}
      <button onclick={() => (stopping = false)}>{t('common.cancel')}</button>
      <button class="primary" disabled={busy} onclick={stop}>{t('batch.stopButton')}</button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .head { margin-bottom: 6px; }
  p { margin: 0 0 6px; }
  .summary { display: flex; flex-direction: column; gap: 10px; margin: 12px 0 16px; align-items: flex-start; }
  .bar { display: flex; width: 100%; height: 6px; border-radius: 3px; background: var(--surface-2); overflow: hidden; }
  .bar .ok { background: var(--direct); }
  .bar .bad { background: var(--block); }
  .table { padding: 6px 8px; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 8px; }
  td { padding: 9px 8px; border-top: 1px solid var(--border); vertical-align: top; }
  td.st { white-space: nowrap; }
  td.small { display: flex; flex-direction: column; gap: 2px; align-items: flex-start; }
  .name { font-weight: 600; color: var(--text); }
  .canary { margin-left: 6px; background: var(--accent-soft); color: var(--accent); }
  .err { color: var(--block); }
</style>
