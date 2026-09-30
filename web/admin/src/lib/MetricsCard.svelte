<script lang="ts">
  // The server's monitoring: CPU, memory, disk, load and network over a
  // chosen period, as small charts or as a table.
  import { onDestroy } from 'svelte';
  import { api, asApiError, type ApiError, type MetricPeriod, type MetricSeries } from '../api';
  import { t, type Key } from '../i18n';
  import LineChart from './LineChart.svelte';
  import { bits, mib, pct } from './format';

  let { serverId }: { serverId: number } = $props();

  const periods: MetricPeriod[] = ['1h', '6h', '24h', '48h', '7d', '30d'];
  let period = $state<MetricPeriod>('6h');
  let data = $state<MetricSeries | null>(null);
  let error = $state<ApiError | null>(null);
  let table = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function load() {
    clearTimeout(timer);
    try {
      data = await api.serverMetrics(serverId, period);
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
    // Samples come every minute; averages every 15.
    timer = setTimeout(load, data?.step ? 5 * 60e3 : 60e3);
  }
  $effect(() => {
    period;
    load();
  });
  onDestroy(() => clearTimeout(timer));

  let pts = $derived(data?.points ?? []);
  let times = $derived(pts.map((p) => Date.parse(p.t)));
  let from = $derived(data ? Date.parse(data.from) : 0);
  let to = $derived(data ? Date.parse(data.to) : 0);
  // A line breaks where samples are missing: three times their usual
  // spacing (a missed round or two is still a line).
  let gap = $derived.by(() => {
    if (data?.step) return 2 * data.step * 1000;
    const d = times.slice(1).map((x, i) => x - times[i]).sort((a, b) => a - b);
    return Math.max(3 * (d[d.length >> 1] ?? 60e3), 3 * 60e3);
  });
  let last = $derived(pts[pts.length - 1]);
  // The memory axis goes up to the installed memory, rounded up to a
  // clean number.
  let memTop = $derived.by(() => {
    const m = Math.max(...pts.map((p) => p.memTotal), 1);
    const step = m > 4096 ? 1024 : 256;
    return Math.ceil(m / step) * step;
  });
  let diskPct = (p: { diskUsed: number; diskTotal: number }) => (p.diskTotal ? (100 * p.diskUsed) / p.diskTotal : 0);
  let rows = $derived(pts.slice(-100).reverse());
</script>

<section class="card metrics">
  <div class="row">
    <h2 class="grow">{t('mon.title')}</h2>
    <div class="seg" role="tablist" aria-label={t('mon.period')}>
      {#each periods as p (p)}
        <button class:on={period === p} onclick={() => (period = p)}>{t(`mon.p${p}` as Key)}</button>
      {/each}
    </div>
    <button class="ghost" onclick={() => (table = !table)}>{table ? t('mon.charts') : t('mon.table')}</button>
  </div>
  {#if data?.step}<p class="small faint note">{t('mon.averages')}</p>{/if}
  {#if error}<div class="note error">{error.message}</div>{/if}

  {#if data && !table}
    <div class="grid">
      <div>
        <h3>{t('mon.cpu')} <span class="now">{last?.cpu != null ? pct(last.cpu) : ''}</span></h3>
        <LineChart label={t('mon.cpu')} {times} {from} {to} {gap} max={100} format={pct} series={[{ name: t('mon.cpu'), color: 'var(--viz-1)', values: pts.map((p) => p.cpu) }]} />
      </div>
      <div>
        <h3>{t('mon.mem')} <span class="now">{last ? `${mib(last.memUsed)} / ${mib(last.memTotal)}` : ''}</span></h3>
        <LineChart label={t('mon.mem')} {times} {from} {to} {gap} max={memTop} format={mib} series={[{ name: t('mon.memUsed'), color: 'var(--viz-1)', values: pts.map((p) => p.memUsed) }]} />
      </div>
      <div>
        <h3>{t('mon.net')}</h3>
        <LineChart
          label={t('mon.net')}
          {times}
          {from}
          {to}
          {gap}
          format={bits}
          series={[
            { name: t('mon.rx'), color: 'var(--viz-1)', values: pts.map((p) => (p.rx === null ? null : p.rx * 8)) },
            { name: t('mon.tx'), color: 'var(--viz-2)', values: pts.map((p) => (p.tx === null ? null : p.tx * 8)) },
          ]}
        />
      </div>
      <div>
        <h3>{t('mon.load')} <span class="now">{last ? last.load1.toFixed(2) : ''}</span></h3>
        <LineChart label={t('mon.load')} {times} {from} {to} {gap} format={(v) => v.toFixed(v < 10 ? 1 : 0)} series={[{ name: t('mon.load1'), color: 'var(--viz-1)', values: pts.map((p) => p.load1) }]} />
      </div>
      <div>
        <h3>{t('mon.disk')} <span class="now">{last ? `${mib(last.diskUsed)} / ${mib(last.diskTotal)}` : ''}</span></h3>
        <LineChart label={t('mon.disk')} {times} {from} {to} {gap} max={100} format={pct} series={[{ name: t('mon.diskUsed'), color: 'var(--viz-1)', values: pts.map(diskPct) }]} />
      </div>
    </div>
  {:else if data}
    {#if pts.length > rows.length}<p class="small faint note">{t('mon.tableLimit', { n: rows.length })}</p>{/if}
    <div class="scroll">
      <table>
        <thead>
          <tr>
            <th>{t('mon.time')}</th><th>{t('mon.cpu')}</th><th>{t('mon.mem')}</th><th>{t('mon.disk')}</th><th>{t('mon.load')}</th><th>{t('mon.rx')}</th><th>{t('mon.tx')}</th>
          </tr>
        </thead>
        <tbody>
          {#each rows as p (p.t)}
            <tr>
              <td>{new Date(p.t).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })}</td>
              <td>{p.cpu != null ? pct(p.cpu) : '—'}</td>
              <td>{mib(p.memUsed)}</td>
              <td>{pct(diskPct(p))}</td>
              <td>{p.load1.toFixed(2)}</td>
              <td>{p.rx != null ? bits(p.rx * 8) : '—'}</td>
              <td>{p.tx != null ? bits(p.tx * 8) : '—'}</td>
            </tr>
          {:else}
            <tr><td colspan="7" class="muted">{t('mon.empty')}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .metrics { margin-bottom: 16px; }
  .metrics h2 { margin: 0; }
  .note { margin: 8px 0 0; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px 24px; margin-top: 12px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  h3 { margin: 0 0 6px; font-size: 13px; color: var(--muted); font-weight: 600; }
  .now { color: var(--text); font-weight: 600; margin-left: 6px; font-variant-numeric: tabular-nums; }
  .scroll { max-height: 420px; overflow: auto; margin-top: 12px; }
  th { text-align: left; color: var(--muted); font-weight: 500; font-size: 12.5px; padding: 6px 8px; position: sticky; top: 0; background: var(--surface); }
  td { padding: 5px 8px; border-top: 1px solid var(--border); font-variant-numeric: tabular-nums; white-space: nowrap; }
</style>
