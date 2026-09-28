<script lang="ts">
  // A subscription's traffic and term as its panel reports them: the
  // summary, a bar of the traffic used and the details line. Every text
  // comes from Go (Russian units, truncated figures); nothing is computed
  // from the raw byte counts here.
  import { fmtDateTime, type SubInfo } from '../api';

  let { info, compact = false }: { info: SubInfo; compact?: boolean } = $props();
</script>

<div class="subinfo">
  <div class="summary {info.level}">{info.summary}</div>
  {#if info.total > 0}
    <div class="bar {info.level}" title={info.upDown || undefined} role="meter" aria-label="Израсходовано трафика" aria-valuemin={0} aria-valuemax={100} aria-valuenow={info.usedPct}>
      <span style="width: {info.usedPct}%"></span>
    </div>
  {/if}
  {#if info.details || (!compact && info.at)}
    <div class="muted small">
      {info.details}{#if !compact && info.at}{info.details ? ' · ' : ''}данные сервиса на {fmtDateTime(info.at)}{/if}
    </div>
  {/if}
</div>

<style>
  .subinfo { display: grid; gap: 4px; min-width: 0; }
  .summary { font-weight: 600; }
  .summary.low { color: var(--warn); }
  .summary.out { color: var(--block); }
  .bar { height: 6px; border-radius: 3px; background: var(--surface-3); overflow: hidden; max-width: 420px; }
  .bar span { display: block; height: 100%; background: var(--accent); transition: width 0.3s; }
  .bar.low span { background: var(--warn); }
  .bar.out span { background: var(--block); }
  .small { font-size: 12px; }
</style>
