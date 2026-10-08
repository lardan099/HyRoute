<script lang="ts">
  // The reconciliation of the server (P4-06): when it was last compared
  // with what HyRoute recorded, and each difference («изменено вне
  // HyRoute») with «Принять» and «Вернуть версию HyRoute». Nothing on
  // the server changes without one of them.
  import { onDestroy, onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Drift, type DriftItem, type DriftThing } from '../api';
  import { t, type Key } from '../i18n';
  import { go } from '../router.svelte';
  import { when } from './format';
  import Dialog from './Dialog.svelte';
  import DiffView from './DiffView.svelte';

  // onchange gets the result whenever its differences change (an accept,
  // a check, a revert's check): the server's state and revision may have
  // changed with them.
  let { serverId, writable, onchange }: { serverId: number; writable: boolean; onchange?: (d: Drift) => void } = $props();

  let data = $state<Drift | null>(null);
  let error = $state<ApiError | null>(null);
  let busy = $state(false);
  let note = $state('');
  let confirm = $state<{ item: DriftItem; action: 'accept' | 'revert' } | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;
  // gone: the card is destroyed; a read in flight then sets no timer.
  let gone = false;

  // A revert job that has not failed: its end brings a new check, so the
  // card looks again soon.
  const reverting = (it: DriftItem) => !!it.job && it.job.state !== 'failed';

  async function load() {
    clearTimeout(timer);
    try {
      const before = data?.items.length ?? 0;
      data = await api.drift(serverId);
      if (data.items.length !== before) onchange?.(data);
    } catch (e) {
      error = asApiError(e);
    }
    if (!gone) timer = setTimeout(load, data?.items.some(reverting) ? 3000 : 60e3);
  }
  onMount(load);
  onDestroy(() => {
    gone = true;
    clearTimeout(timer);
  });

  async function check() {
    busy = true;
    error = null;
    note = '';
    try {
      data = await api.checkDrift(serverId);
      onchange?.(data);
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }

  async function run() {
    const c = confirm!;
    confirm = null;
    busy = true;
    error = null;
    note = '';
    try {
      if (c.action === 'accept') {
        data = await api.acceptDrift(serverId, c.item.key);
        onchange?.(data);
      } else {
        await api.revertDrift(serverId, c.item.key);
        note = t('drift.queued');
        await load();
      }
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }

  const thing = (x: DriftThing) => (x.kind === 'link' ? t('drift.thing.link', { name: x.chain?.name ?? '' }) : t(`drift.thing.${x.kind}` as Key));
  const every = (sec: number) => (sec % 3600 === 0 ? `${sec / 3600} ч` : t('unit.min', { n: Math.round(sec / 60) }));
  const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
  const acceptText = (it: DriftItem) =>
    it.kind === 'config' ? t('drift.acceptText.config') : it.kind === 'link' ? t('drift.acceptText.link') : t('drift.acceptText.other', { title: it.title });
</script>

<section class="card drift">
  <div class="row">
    <h2 class="grow">{t('drift.title')}</h2>
    {#if data?.at}<span class="small muted">{t('drift.checked', { when: when(data.at) })}</span>{/if}
    {#if writable}<button class="ghost" disabled={busy} onclick={check}>{busy ? t('drift.checking') : t('drift.check')}</button>{/if}
  </div>
  {#if error}<div class="note error small">{error.message}</div>{/if}
  {#if note}<div class="note info small">{note}</div>{/if}
  {#if data}
    {#if data.error}<div class="note error small">{data.error}</div>{/if}
    {#if !data.at}
      <p class="muted small">{t('drift.never')}</p>
    {:else if data.items.length === 0 && data.checked.length}
      <p class="small">{t('drift.clean', { list: data.checked.map(thing).join(', ') })}</p>
    {/if}

    {#if data.items.length}
      <div class="note warn small"><b>{t('drift.changed')}</b> {t('drift.changedHint')}</div>
      {#each data.items as it (it.key)}
        <div class="item">
          <div class="row">
            <b class="grow">{cap(it.title)}</b>
            <span class="small muted">{t('drift.since', { when: when(it.since) })}</span>
          </div>
          <p class="small">{it.summary}</p>
          {#if it.diff}
            <details open>
              <summary class="small">{t('drift.diff')}</summary>
              <DiffView lines={it.diff} />
            </details>
          {/if}
          {#if it.secrets?.length}<p class="small muted">{t('drift.secrets', { list: it.secrets.join(', ') })}</p>{/if}
          {#if it.diffNote}<p class="small muted">{it.diffNote}</p>{/if}
          {#if it.job}
            <p class="small {it.job.state === 'failed' ? 'bad' : 'muted'}">
              {#if it.job.state === 'failed'}{t('drift.jobFailed', { id: it.job.id, message: it.job.errorMessage ?? '' })}
              {:else if it.job.state === 'completed'}{t('drift.jobDone', { id: it.job.id })}
              {:else}{t('drift.jobRunning', { id: it.job.id })}{/if}
              <button class="link" onclick={() => go('deployments', it.job!.id)}>{t('drift.openJob')}</button>
            </p>
          {/if}
          {#if writable}
            <div class="row actions">
              <button disabled={busy || reverting(it)} onclick={() => (confirm = { item: it, action: 'accept' })}>
                {it.kind === 'config' ? t('drift.acceptConfig') : t('drift.accept')}
              </button>
              {#if it.canRevert}
                <button class="primary" disabled={busy || reverting(it)} onclick={() => (confirm = { item: it, action: 'revert' })}>{t('drift.revert')}</button>
              {:else if it.revertNote}
                <span class="small muted grow">{it.revertNote}</span>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    {/if}

    {#if data.skipped.length}<p class="small faint">{t('drift.skipped', { list: data.skipped.map(thing).join(', ') })}</p>{/if}
    <p class="small faint">{data.interval ? t('drift.every', { every: every(data.interval) }) : t('drift.off')}</p>
  {/if}
</section>

{#if confirm}
  <Dialog title={confirm.action === 'accept' ? t('drift.acceptTitle') : t('drift.revertTitle')} onclose={() => (confirm = null)}>
    <p><b>{cap(confirm.item.title)}</b></p>
    <p>
      {#if confirm.action === 'accept'}{acceptText(confirm.item)}
      {:else}{t(`drift.revertText.${confirm.item.kind}` as Key, { rev: confirm.item.revision ?? 0 })}{/if}
    </p>
    {#snippet actions()}
      <button onclick={() => (confirm = null)}>{t('common.cancel')}</button>
      <button class="primary" onclick={run}>{confirm!.action === 'accept' ? t('drift.accept') : t('drift.revert')}</button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .drift { margin-bottom: 16px; }
  .drift h2 { margin: 0; }
  .row { gap: 10px; align-items: baseline; }
  p { margin: 6px 0 0; }
  .item { border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 10px 12px; margin-top: 10px; }
  details { margin-top: 8px; }
  summary { cursor: pointer; margin-bottom: 6px; }
  .actions { margin-top: 10px; align-items: center; }
  .bad { color: var(--block); }
  .item .link { margin-left: 6px; }
</style>
