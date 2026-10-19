<script lang="ts">
  // Traffic of the server's Hysteria users from the stats API: per hour
  // and per user over a period (stored), who is online (live) and, for
  // writers, the open connections (live, never stored).
  import { onDestroy } from 'svelte';
  import { api, asApiError, type ApiError, type ServerTraffic, type TrafficOnline, type TrafficPeriod, type TrafficStreams } from '../api';
  import { t, type Key } from '../i18n';
  import LineChart from './LineChart.svelte';
  import { bytes, pct, when } from './format';

  let { serverId, writable }: { serverId: number; writable: boolean } = $props();

  const periods: TrafficPeriod[] = ['24h', '7d', '30d', '90d'];
  let period = $state<TrafficPeriod>('24h');
  let data = $state<ServerTraffic | null>(null);
  let online = $state<TrafficOnline | null>(null);
  let onlineError = $state<ApiError | null>(null);
  let streams = $state<TrafficStreams | null>(null);
  let streamsError = $state<ApiError | null>(null);
  let showStreams = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onlineTimer: ReturnType<typeof setTimeout> | undefined;
  let streamsTimer: ReturnType<typeof setTimeout> | undefined;
  // gone: the card is destroyed; a read in flight then sets no timer.
  let gone = false;
  // seq numbers the reads of the period: only the latest one shows its
  // answer and sets the timer.
  let seq = 0;

  async function load() {
    clearTimeout(timer);
    const my = ++seq;
    try {
      const d = await api.serverTraffic(serverId, period);
      if (my === seq) data = d;
    } catch {}
    if (my === seq && !gone) timer = setTimeout(load, 60e3); // the monitor counts once a minute
  }
  $effect(() => {
    period;
    load();
  });

  // Who is online: asked over SSH every 15 s while stats are on.
  async function loadOnline() {
    clearTimeout(onlineTimer);
    try {
      online = await api.trafficOnline(serverId);
      onlineError = null;
    } catch (e) {
      online = null;
      onlineError = asApiError(e);
    }
    if (!gone && enabled) onlineTimer = setTimeout(loadOnline, 15e3);
  }
  let enabled = $derived(!!data?.enabled);
  $effect(() => {
    if (enabled) loadOnline();
    else clearTimeout(onlineTimer);
  });
  onDestroy(() => {
    gone = true;
    clearTimeout(timer);
    clearTimeout(onlineTimer);
    clearTimeout(streamsTimer);
    document.removeEventListener('visibilitychange', visible);
  });

  // The open connections: every 5 s while shown and the tab is visible
  // (each read is an SSH login), slower after an error.
  async function loadStreams() {
    clearTimeout(streamsTimer);
    if (!showStreams || document.hidden) return;
    let ok = true;
    try {
      const s = await api.trafficStreams(serverId);
      if (showStreams) streams = s;
      streamsError = null;
    } catch (e) {
      ok = false;
      streams = null;
      streamsError = asApiError(e);
    }
    clearTimeout(streamsTimer); // a read started before a hide and show
    if (showStreams && !gone) streamsTimer = setTimeout(loadStreams, ok ? 5e3 : 15e3);
  }
  function visible() {
    if (!document.hidden) loadStreams();
  }
  document.addEventListener('visibilitychange', visible);
  function toggleStreams() {
    showStreams = !showStreams;
    if (showStreams) loadStreams();
    else {
      clearTimeout(streamsTimer);
      streams = null; // where clients go is not kept, not even here
    }
  }

  // Every hour of the period, zero where nothing was counted.
  let from = $derived(data ? Date.parse(data.from) : 0);
  let to = $derived(data ? Date.parse(data.to) : 0);
  let times = $derived.by(() => {
    const out: number[] = [];
    for (let h = from; h <= to; h += 3600e3) out.push(h);
    return out;
  });
  let byHour = $derived(new Map((data?.hours ?? []).map((h) => [Date.parse(h.t), h])));
  let rx = $derived(times.map((x) => byHour.get(x)?.rx ?? 0));
  let tx = $derived(times.map((x) => byHour.get(x)?.tx ?? 0));
  let totalRx = $derived((data?.users ?? []).reduce((a, u) => a + u.rx, 0));
  let totalTx = $derived((data?.users ?? []).reduce((a, u) => a + u.tx, 0));
  let onlineBy = $derived(new Map((online?.users ?? []).map((u) => [u.user, u.connections])));
  let hasData = $derived((data?.users.length ?? 0) > 0);
  // The axis tops out at a round number of binary units (1, 2, 2.5, 5
  // or 10 of KiB, MiB…), so its ticks read cleanly.
  let top = $derived.by(() => {
    const m = Math.max(...rx, ...tx, 1) * 1.1;
    let unit = 1;
    while (m / unit >= 1024) unit *= 1024;
    const v = m / unit;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    const step = [1, 2, 2.5, 5, 10].find((k) => k * p >= v) ?? 10;
    return step * p * unit;
  });
</script>

{#if data && (data.enabled || hasData)}
  <section class="card traffic">
    <div class="row">
      <h2 class="grow">{t('tr.title')}</h2>
      <div class="seg" role="tablist" aria-label={t('mon.period')}>
        {#each periods as p (p)}
          <button class:on={period === p} onclick={() => (period = p)}>{t(`tr.p${p}` as Key)}</button>
        {/each}
      </div>
    </div>
    {#if !data.enabled}<div class="note info small">{t('tr.offKept')}</div>{/if}

    {#if data.enabled}
      <div class="online small">
        <b>{t('tr.online')}:</b>
        {#if onlineError}
          <span class="warn-text">{onlineError.message}</span>
        {:else if online}
          {#if online.users.length === 0}
            <span class="muted">{t('tr.onlineNone')}</span>
          {:else}
            {#each online.users as u (u.user)}
              <span class="who"><span class="dot ok"></span>{u.user} <span class="muted">{t('tr.onlineCount', { n: u.connections })}</span></span>
            {/each}
          {/if}
        {:else}
          <span class="muted">…</span>
        {/if}
      </div>
    {/if}

    <p class="small total">{t('tr.total', { rx: bytes(totalRx), tx: bytes(totalTx) })}</p>
    <LineChart
      label={t('tr.chart')}
      {times}
      {from}
      {to}
      gap={2 * 3600e3}
      format={bytes}
      max={top}
      legendValues={false}
      series={[
        { name: t('tr.download'), color: 'var(--viz-1)', values: rx },
        { name: t('tr.upload'), color: 'var(--viz-2)', values: tx },
      ]}
    />
    <p class="small faint">{t('tr.note')}</p>

    <h3>{t('tr.users')}</h3>
    {#if hasData}
      <div class="scroll">
        <table>
          <thead>
            <tr><th>{t('tr.user')}</th><th class="num">{t('tr.download')}</th><th class="num">{t('tr.upload')}</th><th class="num">{t('tr.sum')}</th><th class="num">{t('tr.share')}</th></tr>
          </thead>
          <tbody>
            {#each data.users as u (u.user)}
              <tr>
                <td>{#if onlineBy.has(u.user)}<span class="dot ok" title={t('tr.online')}></span>{/if}<span class="mono">{u.user}</span></td>
                <td class="num">{bytes(u.rx)}</td>
                <td class="num">{bytes(u.tx)}</td>
                <td class="num">{bytes(u.rx + u.tx)}</td>
                <td class="num">{pct((100 * (u.rx + u.tx)) / Math.max(totalRx + totalTx, 1))}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <p class="muted small">{t('tr.noUsers')}</p>
    {/if}

    {#if writable && data.enabled}
      <div class="row streams-head">
        <h3 class="grow">{t('tr.streams')}</h3>
        <button class="ghost" onclick={toggleStreams}>{showStreams ? t('tr.hideStreams') : t('tr.showStreams')}</button>
      </div>
      {#if showStreams}
        {#if streamsError}
          <div class="note error small">{streamsError.message}</div>
        {:else if streams}
          <p class="small faint">{t('tr.streamsNote', { at: when(streams.at) })}{streams.total > streams.streams.length ? ' ' + t('tr.streamsMore', { shown: streams.streams.length, total: streams.total }) : ''}</p>
          {#if streams.streams.length}
            <div class="scroll">
              <table>
                <thead>
                  <tr><th>{t('tr.user')}</th><th>{t('tr.addr')}</th><th>{t('tr.state')}</th><th class="num">{t('tr.download')}</th><th class="num">{t('tr.upload')}</th><th>{t('tr.since')}</th></tr>
                </thead>
                <tbody>
                  {#each streams.streams as s (`${s.connection}/${s.stream}`)}
                    <tr>
                      <td class="mono">{s.user}</td>
                      <td class="mono addr">{s.addr}{#if s.hookedAddr}<div class="faint">→ {s.hookedAddr}</div>{/if}</td>
                      <td>{s.state}</td>
                      <td class="num">{bytes(s.rx)}</td>
                      <td class="num">{bytes(s.tx)}</td>
                      <td>{when(s.since)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {:else}
            <p class="muted small">{t('tr.noStreams')}</p>
          {/if}
        {/if}
      {/if}
    {/if}
  </section>
{:else if data && writable}
  <section class="card traffic">
    <h2>{t('tr.title')}</h2>
    <p class="muted small">{t('tr.off')}</p>
  </section>
{/if}

<style>
  .traffic { margin-bottom: 16px; }
  .traffic h2 { margin: 0; }
  .traffic > h2 { margin-bottom: 8px; }
  h3 { margin: 16px 0 6px; font-size: 13px; color: var(--muted); font-weight: 600; }
  .streams-head { margin-top: 16px; }
  .streams-head h3 { margin: 0; }
  .online { display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: center; margin: 10px 0 0; }
  .who { white-space: nowrap; }
  .dot { margin-right: 6px; }
  .total { margin: 10px 0 6px; }
  p { margin: 0; }
  .note { margin-top: 10px; }
  .scroll { max-height: 360px; overflow: auto; }
  th { text-align: left; color: var(--muted); font-weight: 500; font-size: 12.5px; padding: 6px 8px; position: sticky; top: 0; background: var(--surface); }
  td { padding: 5px 8px; border-top: 1px solid var(--border); font-variant-numeric: tabular-nums; }
  .num { text-align: right; white-space: nowrap; }
  .addr { word-break: break-all; }
  .warn-text { color: var(--warn); }
</style>
