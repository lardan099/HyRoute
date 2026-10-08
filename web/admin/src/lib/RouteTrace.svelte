<script lang="ts">
  // Where a request goes along a cascade (P4-08): the rule it matches on
  // each server and the server it leaves from. skip leaves out the first
  // hops (the routing editor shows its own server's verdict above).
  import type { RouteTrace } from '../api';
  import { t, type Key } from '../i18n';

  let { trace, skip = 0 }: { trace: RouteTrace; skip?: number } = $props();

  const tone = (o: string, next: boolean) => (next ? 'tunnel' : o.toLowerCase() === 'reject' ? 'block' : 'direct');
</script>

<ol class="trace">
  {#each trace.hops.slice(skip) as h (h.serverId)}
    <li>
      <div>
        <b>«{h.name}»</b> <span class="small faint">{t(`srvrole.${h.role}` as Key)}</span>
        {#if h.verdict}
          · {h.verdict.rule >= 0 ? t('rc.rule', { n: h.verdict.rule + 1 }) : t('rc.noRule')}
          → <span class="pill {tone(h.verdict.outbound, h.next)}">{h.verdict.outbound}</span>
          {#if h.verdict.hijack}<span class="small muted"> → {h.verdict.hijack}</span>{/if}
          {#if h.next}<span class="small muted"> · {t('cascades.routeNext')}</span>{/if}
        {/if}
      </div>
      {#if h.verdict}<p class="small muted">{h.verdict.reason}</p>{/if}
      {#if h.verdict?.unknown?.length}<p class="small warn">{t('rc.unknown', { list: h.verdict.unknown.map((i) => i + 1).join(', ') })}</p>{/if}
      {#if h.error}<p class="small warn">{h.error}</p>{/if}
    </li>
  {/each}
</ol>
<p class="summary" class:block={trace.rejected}>{trace.summary}</p>

<style>
  .trace { margin: 0; padding-left: 20px; display: flex; flex-direction: column; gap: 8px; }
  .trace p { margin: 2px 0 0; }
  .warn { color: var(--warn); }
  .summary { margin: 10px 0 0; font-weight: 600; }
  .summary.block { color: var(--block); }
</style>
