<script lang="ts">
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Health, type Job, type LatestMetric, type Server, type ServerState } from '../api';
  import { t, tOr, type Key } from '../i18n';
  import { go } from '../router.svelte';
  import { can } from '../session.svelte';
  import { flag, jobTone, pct, stateTone, when } from '../lib/format';
  import AttentionCard from '../lib/AttentionCard.svelte';

  let writable = $derived(can('deploy'));

  let health = $state<Health | null>(null);
  let error = $state<ApiError | null>(null);
  let servers = $state<Server[] | null>(null);
  let jobs = $state<Job[] | null>(null);
  let metrics = $state<Record<number, LatestMetric>>({});

  const order: ServerState[] = ['healthy', 'needs_attention', 'degraded', 'offline', 'deploying', 'new'];
  let counts = $derived(order.map((s) => ({ state: s, n: servers?.filter((x) => x.state === s).length ?? 0 })).filter((c) => c.n > 0));
  let byId = $derived(Object.fromEntries((servers ?? []).map((s) => [s.id, s])));
  // Servers that want a look come first.
  const priority: Record<ServerState, number> = { needs_attention: 0, offline: 1, degraded: 2, deploying: 3, new: 4, healthy: 5 };
  let sorted = $derived([...(servers ?? [])].sort((a, b) => priority[a.state] - priority[b.state] || a.name.localeCompare(b.name, 'ru')));

  onMount(async () => {
    try {
      [health, servers, jobs] = await Promise.all([api.health(), api.servers(), api.jobs()]);
    } catch (e) {
      error = asApiError(e);
    }
    try {
      metrics = Object.fromEntries((await api.latestMetrics()).map((m) => [m.serverId, m]));
    } catch {} // the summary is optional
  });
</script>

<h1>{t('overview.title')}</h1>

{#if error}
  <div class="note error">
    {error.message}
    {#if error.details}<div class="small mono">{error.details}</div>{/if}
  </div>
{/if}

<AttentionCard />

<div class="grid">
  <section class="card">
    <h2>{t('overview.servers')}</h2>
    {#if servers && servers.length === 0}
      {#if writable}
        <p class="muted">{t('overview.serversEmpty')}</p>
        <button class="primary add" onclick={() => go('servers')}>{t('servers.add')}</button>
      {:else}
        <p class="muted">{t('servers.emptyReadonly')}</p>
      {/if}
    {:else if servers}
      <div class="counts">
        {#each counts as c (c.state)}
          <span class="count"><span class="dot {stateTone(c.state)}"></span> {t(`state.${c.state}` as Key)}: <b>{c.n}</b></span>
        {/each}
      </div>
      <ul>
        {#each sorted.slice(0, 10) as s (s.id)}
          <li>
            <span class="dot {stateTone(s.state)}"></span>
            <div class="grow col">
              <button class="link ellipsis name" onclick={() => go('servers', s.id)}>{flag(s.country)} {s.name}</button>
              {#if metrics[s.id]}
                {@const m = metrics[s.id]}
                <span class="faint small nums">{t('mon.summary', { cpu: m.cpu != null ? pct(m.cpu) : '—', mem: pct(m.memTotal ? (100 * m.memUsed) / m.memTotal : 0) })}</span>
              {/if}
            </div>
            <span class="muted small">{t(`state.${s.state}` as Key)}</span>
          </li>
        {/each}
      </ul>
      <button class="link small" onclick={() => go('servers')}>{t('overview.serversCount', { n: servers.length })}</button>
    {/if}
  </section>

  <section class="card">
    <h2>{t('overview.jobs')}</h2>
    {#if jobs && jobs.length === 0}
      <p class="muted">{t('jobs.empty')}</p>
    {:else if jobs}
      <ul>
        {#each jobs.slice(0, 8) as j (j.id)}
          <li class="job">
            <span class="dot {jobTone(j.state)}"></span>
            <div class="grow col">
              <button class="link ellipsis name" onclick={() => go('deployments', j.id)}>{tOr(`kind.${j.kind}`, j.kind)}</button>
              <span class="muted small ellipsis">{byId[j.serverId]?.name ?? '#' + j.serverId} · {when(j.startedAt ?? j.createdAt)}</span>
            </div>
          </li>
        {/each}
      </ul>
      <button class="link small" onclick={() => go('deployments')}>{t('overview.allJobs')}</button>
    {/if}
  </section>

  <section class="card">
    <h2>{t('overview.controller')}</h2>
    <dl>
      <dt>{t('overview.status')}</dt>
      <dd>
        {#if health}<span class="dot ok"></span> {t('overview.ok')}{:else if !error}<span class="muted">{t('overview.checking')}</span>{:else}—{/if}
      </dd>
      <dt>{t('overview.version')}</dt>
      <dd class="mono">{health?.version ?? '—'}</dd>
      <dt>{t('overview.schema')}</dt>
      <dd class="mono">{health?.schemaVersion ?? '—'}</dd>
    </dl>
  </section>
</div>

<style>
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-top: 20px; align-items: start; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; margin: 0; }
  dt { color: var(--muted); }
  dd { margin: 0; display: flex; align-items: center; gap: 8px; }
  p { margin: 0; }
  .add { margin-top: 12px; }
  .counts { display: flex; flex-wrap: wrap; gap: 6px 14px; margin-bottom: 12px; font-size: 13px; }
  .count { display: inline-flex; align-items: center; gap: 6px; }
  ul { list-style: none; margin: 0 0 10px; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  li { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .name { color: var(--text); text-align: left; justify-content: flex-start; }
  li.job { align-items: flex-start; }
  li.job .dot { margin-top: 6px; }
  .col { display: flex; flex-direction: column; min-width: 0; gap: 1px; }
  .name:hover { color: var(--accent); }
  .nums { font-variant-numeric: tabular-nums; white-space: nowrap; }
</style>
