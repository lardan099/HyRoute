<script lang="ts">
  // The server's health: the last check (SSH, service, UDP port from the
  // controller, egress address) and the week's status changes.
  import { onDestroy, onMount } from 'svelte';
  import { api, type ServerHealth } from '../api';
  import { t, type Key } from '../i18n';
  import { stateTone, when } from './format';

  let { serverId }: { serverId: number } = $props();
  let data = $state<ServerHealth | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;
  // gone: the card is destroyed; a read in flight then sets no timer.
  let gone = false;

  async function load() {
    try {
      data = await api.serverHealth(serverId);
    } catch {}
    if (!gone) timer = setTimeout(load, 60e3);
  }
  onMount(load);
  onDestroy(() => {
    gone = true;
    clearTimeout(timer);
  });

  let h = $derived(data?.latest ?? null);
  const udpText = (u: string, ms?: number) =>
    u === 'ok' ? t('health.udpOk', { ms: ms ?? 0 }) : t(`health.udp_${u}` as Key);
</script>

{#if data}
  <section class="card health">
    <div class="row">
      <h2 class="grow">{t('health.title')}</h2>
      {#if h}<span class="small muted">{t('health.checked', { when: when(h.at) })}</span>{/if}
    </div>
    {#if !h}
      <p class="muted small">{t('health.none')}</p>
    {:else}
      <div class="status">
        <span class="dot {stateTone(h.status)}"></span>
        <b>{t(`state.${h.status}` as Key)}</b>
        {#if h.reason}<span class="reason">{h.reason}</span>{/if}
      </div>
      <dl>
        <dt>{t('health.ssh')}</dt>
        <dd>{h.sshMs ? t('health.ms', { ms: h.sshMs }) : t('health.sshFailed')}</dd>
        <dt>{t('health.service')}</dt>
        <dd>{h.service || '—'}</dd>
        <dt>{t('health.listening')}</dt>
        <dd>{h.listening == null ? '—' : h.listening ? t('srv.yes') : t('srv.no')}</dd>
        <dt>{t('health.udp')}</dt>
        <dd>{udpText(h.udp, h.udpMs)}</dd>
        <dt>{t('health.egress')}</dt>
        <dd class="mono">{h.egress || '—'}</dd>
      </dl>
      {#if data.changes.length > 1}
        <h3>{t('health.changes')}</h3>
        <ul>
          {#each data.changes as c (c.at)}
            <li>
              <span class="dot {stateTone(c.status)}"></span>
              <span class="when small muted">{when(c.at)}</span>
              <span class="small">{t(`state.${c.status}` as Key)}{c.reason ? ' — ' + c.reason : ''}</span>
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
  </section>
{/if}

<style>
  .health { margin-bottom: 16px; }
  .health h2 { margin: 0; }
  .status { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
  .reason { color: var(--muted); }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 12px 0 0; }
  dt { color: var(--muted); }
  dd { margin: 0; }
  ul { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 6px; max-height: 220px; overflow: auto; }
  li { display: flex; gap: 8px; align-items: baseline; }
  .when { white-space: nowrap; }
  p { margin: 8px 0 0; }
</style>
