<script lang="ts">
  import { t } from '../i18n';
  // A small time-series line chart: 2px lines (a 10% wash under a single
  // series), recessive hairline grid, one y-axis from 0, a crosshair with
  // a tooltip that lists every series (pointer and arrow keys). A line
  // breaks where a value is missing or the samples are further apart than
  // gap.
  export interface Series {
    name: string;
    color: string; // a CSS color, e.g. var(--viz-1)
    values: (number | null)[];
  }

  let {
    label,
    times,
    series,
    format,
    from,
    to,
    gap,
    max,
    legendValues = true,
  }: {
    label: string;
    times: number[]; // ms, ascending
    series: Series[];
    format: (v: number) => string;
    from: number;
    to: number;
    gap: number; // ms
    max?: number; // fixed top (100 for percent)
    legendValues?: boolean; // the legend shows each series' last value
  } = $props();

  const H = 150;
  let width = $state(0);
  let idx = $state<number | null>(null);

  function nice(v: number): number {
    if (!(v > 0)) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  let top = $derived.by(() => {
    if (max !== undefined) return max;
    let m = 0;
    for (const s of series) for (const v of s.values) if (v !== null && v > m) m = v;
    return nice(m * 1.1);
  });
  // The left margin fits the longest tick label (measured roughly: the
  // labels are short, 11px digits and units).
  let pad = $derived({ l: Math.max(36, Math.max(...[0, top / 2, top].map((v) => format(v).length)) * 6.6 + 12), r: 10, t: 8, b: 22 });
  let w = $derived(Math.max(width - pad.l - pad.r, 10));
  let h = $derived(H - pad.t - pad.b);
  const x = (t: number) => pad.l + ((t - from) / Math.max(to - from, 1)) * w;
  const y = (v: number) => pad.t + h - (Math.min(v, top) / top) * h;

  // Segments of each series: runs of present values without long gaps.
  let segments = $derived(
    series.map((s) => {
      const out: [number, number][][] = [];
      let cur: [number, number][] = [];
      s.values.forEach((v, i) => {
        const broken = v === null || (i > 0 && times[i] - times[i - 1] > gap);
        if (broken && cur.length) {
          out.push(cur);
          cur = [];
        }
        if (v !== null) cur.push([x(times[i]), y(v)]);
      });
      if (cur.length) out.push(cur);
      return out;
    }),
  );
  const line = (seg: [number, number][]) => 'M' + seg.map(([a, b]) => `${a.toFixed(1)},${b.toFixed(1)}`).join('L');
  const area = (seg: [number, number][]) => `${line(seg)}L${seg[seg.length - 1][0].toFixed(1)},${pad.t + h}L${seg[0][0].toFixed(1)},${pad.t + h}Z`;

  let yTicks = $derived([0, top / 2, top]);
  let span = $derived(to - from);
  function timeLabel(t: number): string {
    const d = new Date(t);
    const hm = d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    return span > 48 * 3600e3 ? d.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' }) : hm;
  }
  let xTicks = $derived([0, 1 / 3, 2 / 3, 1].map((f) => from + f * span));

  function nearest(t: number): number | null {
    if (!times.length) return null;
    let lo = 0;
    let hi = times.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (times[mid] < t) lo = mid + 1;
      else hi = mid;
    }
    if (lo > 0 && t - times[lo - 1] < times[lo] - t) lo--;
    return lo;
  }

  function move(e: PointerEvent) {
    const r = (e.currentTarget as SVGElement).getBoundingClientRect();
    const px = e.clientX - r.left;
    idx = nearest(from + ((px - pad.l) / w) * span);
  }

  function key(e: KeyboardEvent) {
    if (!times.length) return;
    if (e.key === 'ArrowLeft') idx = Math.max(0, (idx ?? times.length) - 1);
    else if (e.key === 'ArrowRight') idx = Math.min(times.length - 1, (idx ?? -1) + 1);
    else if (e.key === 'Escape') idx = null;
    else return;
    e.preventDefault();
  }

  let tipLeft = $derived(idx === null ? 0 : x(times[idx]));
  let flip = $derived(tipLeft > width * 0.6);
</script>

<div class="chart" bind:clientWidth={width}>
  {#if series.length > 1}
    <div class="legend small">
      {#each series as s (s.name)}
        {@const last = [...s.values].reverse().find((v) => v !== null)}
        <span><i style="background:{s.color}"></i>{s.name}{#if legendValues} <b>{last != null ? format(last) : '—'}</b>{/if}</span>
      {/each}
    </div>
  {/if}
  {#if width > 0}
    <!-- The chart takes the arrow keys (a cursor over the points); the
         values are also in the table view. -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
    <svg
      width={width}
      height={H}
      role="application"
      aria-roledescription={t('mon.chart')}
      aria-label={label}
      tabindex="0"
      onpointermove={move}
      onpointerleave={() => (idx = null)}
      onkeydown={key}
      onblur={() => (idx = null)}
    >
      {#each yTicks as v (v)}
        <line class="grid" x1={pad.l} x2={pad.l + w} y1={y(v)} y2={y(v)} />
        <text class="tick" x={pad.l - 6} y={y(v) + 4} text-anchor="end">{format(v)}</text>
      {/each}
      {#each xTicks as t, i (i)}
        <text class="tick" x={x(t)} y={H - 6} text-anchor={i === 0 ? 'start' : i === xTicks.length - 1 ? 'end' : 'middle'}>{timeLabel(t)}</text>
      {/each}
      {#each segments as segs, si (si)}
        {#each segs as seg, k (k)}
          {#if series.length === 1 && seg.length > 1}<path d={area(seg)} fill={series[si].color} opacity="0.1" />{/if}
          {#if seg.length > 1}
            <path d={line(seg)} fill="none" stroke={series[si].color} stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />
          {:else}
            <circle cx={seg[0][0]} cy={seg[0][1]} r="2" fill={series[si].color} />
          {/if}
        {/each}
      {/each}
      {#if idx !== null}
        <line class="cross" x1={tipLeft} x2={tipLeft} y1={pad.t} y2={pad.t + h} />
        {#each series as s (s.name)}
          {#if s.values[idx] !== null}
            <circle cx={tipLeft} cy={y(s.values[idx]!)} r="4" fill={s.color} stroke="var(--surface)" stroke-width="2" />
          {/if}
        {/each}
      {/if}
    </svg>
    {#if !times.length}<div class="empty small muted">{t('mon.empty')}</div>{/if}
    {#if idx !== null}
      <div class="tip small" style="left:{tipLeft}px" class:flip>
        <div class="muted">{new Date(times[idx]).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })}</div>
        {#each series as s (s.name)}
          <div class="row-t"><i style="background:{s.color}"></i><b>{s.values[idx] !== null ? format(s.values[idx]!) : '—'}</b> <span class="muted">{s.name}</span></div>
        {/each}
      </div>
    {/if}
  {/if}
</div>

<style>
  .chart { position: relative; min-height: 150px; }
  svg { display: block; outline: none; }
  svg:focus-visible { box-shadow: 0 0 0 2px var(--accent); border-radius: 4px; }
  .grid { stroke: var(--viz-grid); stroke-width: 1; }
  .cross { stroke: var(--faint); stroke-width: 1; }
  .tick { fill: var(--faint); font-size: 11px; font-variant-numeric: tabular-nums; }
  .legend { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 4px; color: var(--muted); }
  .legend i, .row-t i { display: inline-block; width: 12px; height: 2px; border-radius: 1px; vertical-align: middle; margin-right: 6px; }
  .legend b { color: var(--text); font-weight: 600; }
  .empty { position: absolute; left: 40px; right: 10px; top: 60px; text-align: center; }
  .tip {
    position: absolute;
    top: 4px;
    transform: translateX(10px);
    background: var(--surface);
    border: 1px solid var(--border);
    box-shadow: var(--shadow-lg);
    border-radius: var(--radius-sm);
    padding: 6px 9px;
    pointer-events: none;
    white-space: nowrap;
    z-index: 2;
  }
  .tip.flip { transform: translateX(calc(-100% - 10px)); }
  .row-t b { color: var(--text); font-variant-numeric: tabular-nums; }
</style>
