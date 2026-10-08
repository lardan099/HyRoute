<script lang="ts">
  // Notification channels of the events (owner and admin): where they
  // go, which kinds, quiet hours, and a test message.
  import { onMount } from 'svelte';
  import { api, asApiError, type AlertChannel, type ApiError } from '../api';
  import { t, type Key } from '../i18n';
  import ChannelDialog from './ChannelDialog.svelte';
  import Dialog from './Dialog.svelte';

  let channels = $state<AlertChannel[]>([]);
  let error = $state<ApiError | null>(null);
  let editing = $state<AlertChannel | null>(null);
  let adding = $state(false);
  // result of the last test of each channel: '' sent, else the error.
  let tested = $state<Record<number, { ok: boolean; text: string }>>({});
  let testing = $state<number | null>(null);
  let deleting = $state<AlertChannel | null>(null);

  async function load() {
    try {
      channels = await api.alertChannels();
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
  }
  onMount(load);

  async function test(c: AlertChannel) {
    testing = c.id;
    try {
      await api.testAlertChannel(c.id);
      tested[c.id] = { ok: true, text: t('alerts.testSent') };
    } catch (e) {
      const err = asApiError(e);
      tested[c.id] = { ok: false, text: err.message + (err.details ? ' ' + err.details : '') };
    } finally {
      testing = null;
    }
  }

  async function remove() {
    const c = deleting;
    deleting = null;
    if (!c) return;
    try {
      await api.deleteAlertChannel(c.id);
      await load();
    } catch (e) {
      error = asApiError(e);
    }
  }

  function saved() {
    adding = false;
    editing = null;
    load();
  }

  const kinds = (c: AlertChannel) =>
    c.events.length === 0 ? t('alerts.allEvents') : c.events.map((k) => t(`alerts.ev.${k}` as Key)).join(', ');
  const where = (c: AlertChannel) => {
    const s = c.settings as Record<string, unknown>;
    if (c.kind === 'telegram') return t('alerts.toChat', { chat: String(s.chatId ?? '') });
    if (c.kind === 'webhook') return String(s.url ?? '');
    return Array.isArray(s.to) ? (s.to as string[]).join(', ') : '';
  };
</script>

<h2>{t('alerts.title')}</h2>
<p class="small muted">{t('alerts.about')}</p>
{#if error}<div class="note error small">{error.message}</div>{/if}
{#if channels.length}
  <ul>
    {#each channels as c (c.id)}
      <li>
        <span class="dot {c.enabled ? 'ok' : ''}"></span>
        <div class="grow col">
          <div class="row">
            <b>{c.name}</b>
            <span class="badge">{t(`alerts.via.${c.kind}` as Key)}</span>
            {#if !c.enabled}<span class="muted small">{t('alerts.off')}</span>{/if}
          </div>
          <span class="small muted ellipsis">{where(c)}</span>
          <span class="small">{kinds(c)}{#if c.quiet.from} · {t('alerts.quietShort', { from: c.quiet.from, to: c.quiet.to })}{/if}</span>
          {#if tested[c.id]}
            <div class="note small" class:ok={tested[c.id].ok} class:error={!tested[c.id].ok}>{tested[c.id].text}</div>
          {/if}
        </div>
        <div class="acts">
          <button onclick={() => test(c)} disabled={testing === c.id}>{testing === c.id ? t('alerts.testing') : t('alerts.test')}</button>
          <button onclick={() => (editing = c)}>{t('common.edit')}</button>
          <button class="ghost danger" onclick={() => (deleting = c)}>{t('common.delete')}</button>
        </div>
      </li>
    {/each}
  </ul>
{:else}
  <p class="small muted">{t('alerts.none')}</p>
{/if}
<div class="row"><button class="primary" onclick={() => (adding = true)}>{t('alerts.add')}</button></div>

{#if deleting}
  <Dialog title={t('alerts.deleteTitle')} onclose={() => (deleting = null)}>
    <p>{t('alerts.deleteText', { name: deleting.name })}</p>
    {#snippet actions()}
      <button onclick={() => (deleting = null)}>{t('common.cancel')}</button>
      <button class="primary" onclick={remove}>{t('common.delete')}</button>
    {/snippet}
  </Dialog>
{/if}

{#if adding || editing}
  <ChannelDialog channel={editing} onclose={() => ((adding = false), (editing = null))} onsaved={saved} />
{/if}

<style>
  h2 { margin-bottom: 6px; }
  p { margin: 0 0 8px; }
  ul { list-style: none; margin: 8px 0 12px; padding: 0; display: flex; flex-direction: column; gap: 12px; }
  li { display: flex; align-items: flex-start; gap: 10px; border-top: 1px solid var(--border); padding-top: 10px; }
  li .dot { margin-top: 6px; }
  .col { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
  .acts { display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
  .note { margin: 4px 0 0; }
</style>
