<script lang="ts">
  // One server: the Hysteria service (status, start/stop/restart), the
  // machine, the config summary and the live journal.
  import { onMount, onDestroy } from 'svelte';
  import { api, asApiError, type ApiError, type Job, type Server, type ServerConfig, type ServiceAction, type ServiceStatus } from '../api';
  import { t, type Key } from '../i18n';
  import { go } from '../router.svelte';
  import { canWrite, session } from '../session.svelte';
  import { flag, stateTone, uptime } from '../lib/format';
  import Dialog from '../lib/Dialog.svelte';
  import DeployDialog from '../lib/DeployDialog.svelte';
  import MaintainDialog from '../lib/MaintainDialog.svelte';
  import JournalView from '../lib/JournalView.svelte';
  import ConfigEditor from '../lib/ConfigEditor.svelte';
  import ClientCard from '../lib/ClientCard.svelte';
  import ConfigHistory from '../lib/ConfigHistory.svelte';
  import MetricsCard from '../lib/MetricsCard.svelte';
  import HealthCard from '../lib/HealthCard.svelte';
  import TrafficCard from '../lib/TrafficCard.svelte';

  let { id }: { id: number } = $props();

  let server = $state<Server | null>(null);
  let config = $state<ServerConfig | null>(null);
  let status = $state<ServiceStatus | null>(null);
  let statusError = $state<ApiError | null>(null);
  let error = $state<ApiError | null>(null);
  let loadingStatus = $state(false);
  let confirming = $state<ServiceAction | null>(null);
  let deploying = $state(false);
  let maintaining = $state(false);
  let editing = $state(false);
  let history = $state(false);
  let action = $state<{ name: ServiceAction; job: Job; done: boolean; ok: boolean } | null>(null);
  let writable = $derived(canWrite(session.user));
  let poll: ReturnType<typeof setTimeout> | undefined;

  const actionName = (a: ServiceAction) => t(`srv.${a}` as Key);

  async function loadStatus() {
    loadingStatus = true;
    try {
      status = await api.serviceStatus(id);
      statusError = null;
    } catch (e) {
      status = null;
      statusError = asApiError(e);
    } finally {
      loadingStatus = false;
    }
  }

  async function load() {
    try {
      server = await api.server(id);
    } catch (e) {
      error = asApiError(e);
      return;
    }
    try {
      config = await api.serverConfig(id);
    } catch {
      config = null;
    }
    loadStatus();
  }
  onMount(load);
  onDestroy(() => clearTimeout(poll));

  async function run(a: ServiceAction) {
    confirming = null;
    try {
      const job = await api.serviceAction(id, a);
      action = { name: a, job, done: false, ok: false };
      watch(job.id);
    } catch (e) {
      error = asApiError(e);
    }
  }

  // watch polls the job until it ends, then reads the status again.
  async function watch(jobId: number) {
    try {
      const j = await api.job(jobId);
      if (j.state === 'completed' || j.state === 'failed') {
        action = { name: action!.name, job: j, done: true, ok: j.state === 'completed' };
        loadStatus();
        server = await api.server(id);
        return;
      }
    } catch {}
    poll = setTimeout(() => watch(jobId), 1000);
  }

  function ask(a: ServiceAction) {
    if (a === 'start') run(a);
    else confirming = a;
  }

  async function startImport() {
    try {
      const j = await api.startImport(id);
      go('deployments', j.id);
    } catch (e) {
      error = asApiError(e);
    }
  }

  const sourceName = { deploy: 'srv.sourceDeploy', import: 'srv.sourceImport', edit: 'srv.sourceEdit', rollback: 'srv.sourceRollback' } as const;

  // After the history or the editor: the summary may have changed.
  async function closePanel() {
    editing = history = false;
    try {
      config = await api.serverConfig(id);
    } catch {}
  }
</script>

<button class="link back" onclick={() => go('servers')}>← {t('servers.back')}</button>

{#if error}<div class="note error">{error.message}</div>{/if}

{#if server}
  <div class="row head">
    <div class="grow">
      <h1>{flag(server.country)} {server.name}</h1>
      <div class="muted small sub">
        <span class="mono">{server.sshUser}@{server.host}{server.sshPort !== 22 ? ':' + server.sshPort : ''}</span>
        <span><span class="dot {stateTone(server.state)}"></span> {t(`state.${server.state}` as Key)}</span>
        {#if server.location}<span>{server.location}</span>{/if}
      </div>
    </div>
    {#if writable}
      <button onclick={() => (deploying = true)}>{t('deploy.button')}</button>
      <button onclick={startImport}>{t('import.button')}</button>
    {/if}
  </div>

  {#if action}
    <div class="note {action.done ? (action.ok ? 'ok' : 'error') : 'info'}">
      {#if !action.done}
        {t('srv.actionRunning', { action: actionName(action.name) })}
      {:else if action.ok}
        {t('srv.actionDone', { action: actionName(action.name) })}
      {:else}
        {t('srv.actionFailed', { action: actionName(action.name), message: action.job.errorMessage })}
      {/if}
      <button class="link" onclick={() => go('deployments', action!.job.id)}>{t('srv.openJob', { id: action.job.id })}</button>
    </div>
  {/if}

  {#if editing}
    <ConfigEditor {server} onclose={closePanel} />
  {:else if history}
    <ConfigHistory {server} {writable} onclose={closePanel} />
  {:else}
  <div class="grid">
    <section class="card">
      <div class="row">
        <h2 class="grow">{t('srv.service')}</h2>
        {#if status}
          <span class="pill {status.active ? 'direct' : 'block'}">{status.active ? t('srv.running') : status.state === 'failed' ? t('srv.failed') : t('srv.stopped')}</span>
        {/if}
        <button class="ghost" disabled={loadingStatus} onclick={loadStatus}>{t('srv.refresh')}</button>
      </div>
      {#if loadingStatus && !status}
        <p class="muted">{t('srv.loading')}</p>
      {:else if statusError}
        <div class="note {statusError.code === 'no_installation' ? 'info' : 'error'}">
          {statusError.message}
          {#if statusError.details}<div class="small mono">{statusError.details}</div>{/if}
        </div>
      {:else if status}
        <dl>
          <dt>{t('srv.unit')}</dt>
          <dd class="mono">{status.unit} · {status.state}/{status.subState}</dd>
          <dt>{t('srv.uptime')}</dt>
          <dd>{status.active ? uptime(status.uptimeSec) : '—'}</dd>
          <dt>{t('srv.version')}</dt>
          <dd>{status.version || '—'}</dd>
          <dt>{t('srv.ports')}</dt>
          <dd class="mono">{status.ports.length ? status.ports.join(', ') : t('srv.noPorts')}</dd>
          <dt>{t('srv.pid')}</dt>
          <dd class="mono">{status.pid ?? '—'}</dd>
          <dt>{t('srv.memory')}</dt>
          <dd>{status.memoryMiB ? t('srv.mb', { n: status.memoryMiB }) : '—'}</dd>
          <dt>{t('srv.restarts')}</dt>
          <dd>{status.restarts}</dd>
          <dt>{t('srv.autostart')}</dt>
          <dd>{status.enabled ? t('srv.yes') : t('srv.no')}</dd>
        </dl>
        {#if writable}
          <div class="row actions">
            {#if !status.active}<button class="primary" disabled={!!action && !action.done} onclick={() => ask('start')}>{t('srv.start')}</button>{/if}
            <button disabled={!!action && !action.done} onclick={() => ask('restart')}>{t('srv.restart')}</button>
            {#if status.active}<button class="danger" disabled={!!action && !action.done} onclick={() => ask('stop')}>{t('srv.stop')}</button>{/if}
            <button class="ghost" disabled={!!action && !action.done} onclick={() => (maintaining = true)}>{t('srv.maintain')}</button>
          </div>
        {/if}
      {/if}
    </section>

    <div class="col">
      {#if status}
        <section class="card">
          <h2>{t('srv.system')}</h2>
          <dl>
            <dt>{t('srv.sysUptime')}</dt>
            <dd>{uptime(status.system.uptimeSec)}</dd>
            <dt>{t('srv.load')}</dt>
            <dd class="mono">{status.system.load.map((x) => x.toFixed(2)).join(' / ')}</dd>
            <dt>{t('srv.cpus')}</dt>
            <dd>{status.system.cpus}</dd>
            <dt>{t('srv.mem')}</dt>
            <dd>{t('srv.memValue', { avail: status.system.memAvailMiB, total: status.system.memTotalMiB })}</dd>
            <dt>{t('srv.disk')}</dt>
            <dd>{t('srv.mb', { n: status.system.diskFreeMiB })}</dd>
          </dl>
        </section>
      {/if}
      <section class="card">
        <div class="row">
          <h2 class="grow">{t('srv.config')}</h2>
          {#if config}<button class="ghost" onclick={() => (history = true)}>{t('hist.open')}</button>{/if}
          {#if config && writable}<button class="ghost" onclick={() => (editing = true)}>{t('cfg.edit')}</button>{/if}
        </div>
        {#if config}
          <dl>
            <dt>{t('deploy.ports')}</dt>
            <dd class="mono">UDP {config.meta.ports || '443'}</dd>
            <dt>{t('deploy.tls')}</dt>
            <dd>{config.meta.tls || '—'}{config.meta.sni ? ` · ${config.meta.sni}` : ''}</dd>
            {#if config.meta.pinSHA256}
              <dt>{t('deploy.pin')}</dt>
              <dd class="mono small pin">{config.meta.pinSHA256}</dd>
            {/if}
            <dt>{t('deploy.obfs')}</dt>
            <dd>{config.meta.obfs || t('deploy.none')}</dd>
            <dt>{t('deploy.revision')}</dt>
            <dd>{config.revision} · {t(sourceName[config.source], { n: config.fromRevision ?? 0 })}</dd>
          </dl>
        {:else}
          <p class="muted small">{t('srv.noConfig')}</p>
        {/if}
      </section>
    </div>
  </div>

  {#key id}<HealthCard serverId={id} />{/key}
  {#key id}<MetricsCard serverId={id} />{/key}
  {#key id}<TrafficCard serverId={id} {writable} />{/key}

  {#key config?.revision}<ClientCard serverId={id} serverName={server.name} />{/key}

  {#if status || statusError?.code !== 'no_installation'}
    {#key id}<JournalView serverId={id} />{/key}
  {/if}
  {/if}

  {#if confirming}
    <Dialog title={t('srv.confirmTitle')} onclose={() => (confirming = null)}>
      <p>{confirming === 'stop' ? t('srv.confirmStop', { name: server.name }) : t('srv.confirmRestart', { name: server.name })}</p>
      {#snippet actions()}
        <button onclick={() => (confirming = null)}>{t('common.cancel')}</button>
        <button class="primary {confirming === 'stop' ? 'danger-bg' : ''}" onclick={() => run(confirming!)}>{actionName(confirming!)}</button>
      {/snippet}
    </Dialog>
  {/if}

  {#if maintaining && status}
    <MaintainDialog {server} {status} onclose={() => (maintaining = false)} onstarted={(j) => go('deployments', j.id)} />
  {/if}

  {#if deploying}
    <DeployDialog {server} onclose={() => (deploying = false)} onstarted={(j) => go('deployments', j.id)} />
  {/if}
{/if}

<style>
  .back { margin-bottom: 12px; }
  .head { margin-bottom: 14px; align-items: flex-start; }
  .sub { display: flex; gap: 14px; flex-wrap: wrap; align-items: center; margin-top: 4px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; margin-bottom: 16px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .col { display: flex; flex-direction: column; gap: 16px; }
  h2 { margin-bottom: 10px; }
  .row h2 { margin: 0; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 12px 0 0; }
  dt { color: var(--muted); }
  dd { margin: 0; word-break: break-all; }
  .pin { user-select: all; }
  .actions { margin-top: 16px; }
  p { margin: 0; }
  .note .link { margin-left: 8px; }
</style>
