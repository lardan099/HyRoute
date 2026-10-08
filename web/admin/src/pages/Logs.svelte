<script lang="ts">
  // Logs: the controller's latest records (for users of all servers: they
  // are about every server), job logs of the servers in the user's scope, a
  // server's Hysteria journal and, for owners and admins, the audit log.
  // Everything comes redacted from the controller.
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type LogEntry, type Server } from '../api';
  import { locale, t, tOr } from '../i18n';
  import { go } from '../router.svelte';
  import { clock } from '../lib/format';
  import AuditView from '../lib/AuditView.svelte';
  import { allServers, canManageUsers, session } from '../session.svelte';

  type Source = 'controller' | 'jobs' | 'hysteria' | 'audit';
  const rank = { debug: 0, info: 1, warn: 2, error: 3 } as const;

  // controllerLog: the controller's records are shown to users of all
  // servers.
  const controllerLog = allServers();
  let source = $state<Source>(controllerLog ? 'controller' : 'jobs');
  let level = $state('');
  let text = $state('');
  let server = $state(0);
  let servers = $state<Server[]>([]);
  let entries = $state<LogEntry[]>([]);
  let loading = $state(false);
  let error = $state<ApiError | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;
  // seq numbers the requests: only the latest one may show its answer (the
  // Hysteria journal comes over SSH in seconds and must not land under
  // another tab chosen meanwhile).
  let seq = 0;

  let byId = $derived(Object.fromEntries(servers.map((s) => [s.id, s])));
  let auditable = $derived(canManageUsers(session.user));

  async function load() {
    const my = ++seq;
    error = null;
    if (source === 'audit') return;
    if (source === 'hysteria' && !server) {
      entries = [];
      loading = false;
      return;
    }
    loading = true;
    try {
      let got: LogEntry[];
      if (source === 'hysteria') {
        // The journal is filtered here: it comes as a whole from the server.
        const min = rank[(level || 'debug') as keyof typeof rank];
        const q = text.toLowerCase();
        got = (await api.journal(server, 1000))
          .filter((e) => rank[e.level] >= min && (!q || e.message.toLowerCase().includes(q)))
          .reverse();
      } else {
        got = await api.logs({ source, server: source === 'jobs' ? server : 0, level, q: text, limit: 500 });
      }
      if (my !== seq) return;
      entries = got;
    } catch (e) {
      if (my !== seq) return;
      entries = [];
      error = asApiError(e);
    } finally {
      if (my === seq) loading = false;
    }
  }

  onMount(async () => {
    try {
      servers = await api.servers();
    } catch {}
    load();
  });

  function pick(s: Source) {
    source = s;
    if (s === 'hysteria' && !server && servers.length) server = servers[0].id;
    load();
  }

  function typed() {
    clearTimeout(timer);
    timer = setTimeout(load, 300);
  }
</script>

<h1>{t('nav.logs')}</h1>

<div class="row bar">
  <div class="seg" role="tablist">
    {#if controllerLog}<button class:on={source === 'controller'} onclick={() => pick('controller')}>{t('logs.controller')}</button>{/if}
    <button class:on={source === 'jobs'} onclick={() => pick('jobs')}>{t('logs.jobs')}</button>
    <button class:on={source === 'hysteria'} onclick={() => pick('hysteria')}>{t('logs.hysteria')}</button>
    {#if auditable}<button class:on={source === 'audit'} onclick={() => pick('audit')}>{t('logs.audit')}</button>{/if}
  </div>
  <!-- The audit view has filters of its own. -->
  {#if source !== 'audit'}
    {#if source !== 'controller'}
      <select bind:value={server} onchange={load} aria-label={t('jobs.server')}>
        {#if source === 'jobs'}<option value={0}>{t('logs.allServers')}</option>{:else if !server}<option value={0}>{t('logs.pickServer')}</option>{/if}
        {#each servers as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
      </select>
    {/if}
    <select bind:value={level} onchange={load} aria-label={t('jobs.state')}>
      <option value="">{t('logs.levelAll')}</option>
      <option value="warn">{t('logs.levelWarn')}</option>
      <option value="error">{t('logs.levelError')}</option>
    </select>
    <input class="grow" type="text" bind:value={text} oninput={typed} placeholder={t('logs.search')} />
    <button disabled={loading} onclick={load}>{t('logs.refresh')}</button>
  {/if}
</div>

{#if source === 'audit'}
  <AuditView {servers} />
{:else}
{#if error}<div class="note error">{error.message}</div>{/if}

<div class="card lines mono">
  {#each entries as e, i (i)}
    <div class="line {e.level}">
      <span class="faint">{new Date(e.time).toLocaleDateString(locale)} {clock(e.time)}</span>
      {#if e.jobId}
        <button class="link small" onclick={() => go('deployments', e.jobId!)}>{tOr(`kind.${e.kind}`, e.kind ?? '')} #{e.jobId}</button>
        {#if e.serverId}<span class="faint">{byId[e.serverId]?.name ?? '#' + e.serverId}</span>{/if}
      {/if}
      <span>{e.message}</span>
      {#if e.attrs}<span class="faint">{e.attrs}</span>{/if}
    </div>
  {:else}
    <div class="faint">{loading ? t('overview.checking') : t('logs.empty')}</div>
  {/each}
</div>
<p class="small faint">{t('logs.hint')}</p>
{/if}

<style>
  h1 { margin-bottom: 16px; }
  .bar { margin-bottom: 12px; gap: 10px; }
  .bar input { min-width: 180px; }
  .lines { max-height: calc(100vh - 230px); min-height: 200px; overflow: auto; font-size: 12px; line-height: 1.6; user-select: text; }
  .line { white-space: pre-wrap; word-break: break-word; display: flex; flex-wrap: wrap; gap: 0 8px; }
  .line.warn { color: var(--warn); }
  .line.error { color: var(--block); }
  .line.debug { color: var(--faint); }
  .line .link { font-size: 12px; }
  p { margin: 10px 0 0; }
</style>
