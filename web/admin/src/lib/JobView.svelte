<script lang="ts">
  // One job: its steps, error and live log (server-sent events).
  import { onMount, tick } from 'svelte';
  import { api, asApiError, jobEventsURL, type ApiError, type Job, type JobDetail, type JobLog, type JobStep, type Server } from '../api';
  import { t, tOr, type Key } from '../i18n';
  import { canWrite, session } from '../session.svelte';
  import { duration, jobTone, stepTone, when } from './format';
  import PreflightReport from './PreflightReport.svelte';
  import DeployResult from './DeployResult.svelte';
  import DeployDialog from './DeployDialog.svelte';
  import ImportReport from './ImportReport.svelte';
  import Dialog from './Dialog.svelte';
  import { go } from '../router.svelte';

  let { id, servers }: { id: number; servers: Record<number, Server> } = $props();

  let job = $state<JobDetail | null>(null);
  let logs = $state<JobLog[]>([]);
  let error = $state<ApiError | null>(null);
  let live = $state(false);
  let retrying = $state(false);
  let logBox = $state<HTMLElement | null>(null);
  let follow = $state(true);
  let source: EventSource | null = null;
  // A stream the server closed for good is opened again after backoff ms.
  let backoff = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let gone = false;
  let report = $derived.by(() => {
    try {
      return job?.data?.report ? JSON.parse(job.data.report) : null;
    } catch {
      return null;
    }
  });

  const stepName = (n: string) => tOr(`step.${n}`, n);
  const kindName = (k: string) => tOr(`kind.${k}`, k);

  async function scrollDown() {
    if (!follow) return;
    await tick();
    logBox?.scrollTo({ top: logBox.scrollHeight });
  }

  function connect() {
    clearTimeout(timer);
    source?.close();
    const last = logs.length ? logs[logs.length - 1].seq : 0;
    const es = new EventSource(jobEventsURL(id) + (last ? `?after=${last}` : ''));
    source = es;
    es.onopen = () => {
      live = true;
      backoff = 0;
    };
    es.addEventListener('log', (e) => {
      const l: JobLog = JSON.parse((e as MessageEvent).data);
      if (!logs.length || l.seq > logs[logs.length - 1].seq) {
        logs.push(l);
        scrollDown();
      }
    });
    es.addEventListener('step', (e) => {
      const s: JobStep = JSON.parse((e as MessageEvent).data);
      if (job) job.steps[s.idx] = s;
    });
    es.addEventListener('job', (e) => {
      const j: Job = JSON.parse((e as MessageEvent).data);
      if (job) Object.assign(job, j);
    });
    es.addEventListener('end', async () => {
      es.close();
      if (source === es) source = null;
      live = false;
      // The final word: steps, data (reports) and errors as stored.
      try {
        job = await api.job(id);
      } catch {}
      loadNewest();
    });
    es.onerror = () => {
      if (source !== es) return;
      live = false;
      // The stream of every job, finished ones too, closes with 'end'.
      // After a dropped connection the browser reconnects by itself with
      // Last-Event-ID. An answer other than the stream (502 while the
      // controller restarts, 401 after the session expired) closes it for
      // good: recover does what the browser will not.
      if (es.readyState === EventSource.CLOSED) {
        source = null;
        recover();
      }
    };
  }

  // recover reads the job again (an expired session brings the login
  // screen) and opens the stream again after a growing pause.
  async function recover() {
    try {
      job = await api.job(id);
    } catch (e) {
      const err = asApiError(e);
      // The session is gone (the login screen takes over) or the job is.
      if (err.status >= 400 && err.status < 500) {
        if (err.code !== 'unauthorized') error = err;
        return;
      }
    }
    if (gone) return;
    backoff = Math.min(backoff ? backoff * 2 : 1000, 30000);
    timer = setTimeout(connect, backoff);
  }

  onMount(() => {
    (async () => {
      try {
        job = await api.job(id);
        if (!gone) connect();
        loadNewest();
      } catch (e) {
        error = asApiError(e);
      }
    })();
    return () => {
      gone = true;
      clearTimeout(timer);
      source?.close();
    };
  });

  // A deploy that found someone else's Hysteria offers the import.
  let deploying = $state(false);
  // A preflight that found the server ready leads straight to the deploy.
  let canDeploy = $derived(
    !!job && job.kind === 'preflight' && job.state === 'completed' && !!report && !report.blocked && !report.hysteria?.installed && !!servers[job.serverId] && canWrite(session.user),
  );

  async function startImport() {
    if (!job) return;
    try {
      const j = await api.startImport(job.serverId);
      go('deployments', j.id);
    } catch (e) {
      error = asApiError(e);
    }
  }

  // newest is the latest job of the server (0: not known). A retry runs a
  // job again with its own parameters: retrying an older one would put
  // them back over what the later jobs changed, so it asks first (the
  // controller may refuse it as well). Preflight only reads.
  let newest = $state(0);
  let confirmRetry = $state(false);
  // A rotation: the client links changed.
  let rotated = $derived(!!job && Array.isArray(job.params?.rotated));
  let stale = $derived(!!job && job.kind !== 'preflight' && newest > job.id);

  async function loadNewest() {
    if (!job?.serverId || job.state !== 'failed') return;
    try {
      newest = (await api.jobs(job.serverId, 1))[0]?.id ?? 0;
    } catch {
      newest = 0;
    }
  }

  async function retry() {
    confirmRetry = false;
    retrying = true;
    error = null;
    try {
      await api.retryJob(id);
      job = await api.job(id);
      connect();
    } catch (e) {
      // A refusal (409: the server is busy, a newer job came after this
      // one) says why in its message.
      error = asApiError(e);
      loadNewest();
    } finally {
      retrying = false;
    }
  }
</script>

{#if error}<div class="note error">{error.message}</div>{/if}

{#if job}
  <div class="row head">
    <h1 class="grow">{kindName(job.kind)} #{job.id}</h1>
    {#if canDeploy}<button class="primary" onclick={() => (deploying = true)}>{t('deploy.button')}</button>{/if}
    {#if job.kind === 'preflight' && job.state === 'completed' && report?.hysteria?.installed && canWrite(session.user)}
      <button class="primary" onclick={startImport}>{t('import.button')}</button>
    {/if}
    {#if job.state === 'failed' && canWrite(session.user)}
      {#if job.kind === 'deploy' && job.data.foreign === '1'}<button onclick={startImport}>{t('import.fromDeploy')}</button>{/if}
      <button class="primary" disabled={retrying} onclick={() => (stale ? (confirmRetry = true) : retry())}>{t('jobs.retry')}</button>
    {/if}
  </div>
  <div class="meta muted small">
    <span><span class="dot {jobTone(job.state)}"></span> {t(`jstate.${job.state}` as Key)}</span>
    {#if job.serverId}<span>{servers[job.serverId]?.name ?? '#' + job.serverId}</span>{/if}
    <span>{when(job.startedAt ?? job.createdAt)}</span>
    <span>{duration(job.startedAt, job.finishedAt)}</span>
    {#if job.attempt > 1}<span>{t('jobs.attempt', { n: job.attempt })}</span>{/if}
    {#if live}<span class="live">● {t('jobs.live')}</span>{/if}
  </div>

  {#if job.state === 'failed' && job.errorMessage}
    <div class="note error">
      {job.errorMessage}
      {#if job.errorDetails}<details><summary class="small">{t('jobs.details')}</summary><pre class="mono small">{job.errorDetails}</pre></details>{/if}
    </div>
  {/if}

  {#if job.kind === 'deploy' && job.state === 'completed'}
    <DeployResult serverId={job.serverId} jobId={job.id} />
  {/if}
  {#if job.kind === 'apply' && job.state === 'completed' && rotated}
    <div class="note ok">
      {t('rot.done')}
      <button class="link" onclick={() => go('servers', job!.serverId)}>{t('rot.links')}</button>
    </div>
  {/if}
  {#if job.kind === 'import' && report}<ImportReport {report} />{/if}
  <!-- A deploy shows its preflight report only when the server was not ready. -->
  {#if report && (job.kind === 'preflight' || (job.kind === 'deploy' && job.state === 'failed' && report.blocked))}<PreflightReport {report} />{/if}

  <div class="cols">
    <section class="card steps">
      <h2>{t('jobs.steps')}</h2>
      <ol>
        {#each job.steps as s (s.idx)}
          <li class:current={s.state === 'running'}>
            <span class="dot {stepTone(s.state)}"></span>
            <span class="grow">{stepName(s.name)}</span>
            <span class="faint small">{t(`sstate.${s.state}` as Key)}</span>
          </li>
          {#if s.error && s.state === 'failed'}<li class="err small">{s.error}</li>{/if}
        {/each}
      </ol>
    </section>
    <section class="card log">
      <h2>{t('jobs.log')}</h2>
      <div class="lines mono" bind:this={logBox} onscroll={() => logBox && (follow = logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 20)}>
        {#each logs as l (l.seq)}
          <div class="line {l.level}"><span class="faint">{new Date(l.time).toLocaleTimeString('ru-RU')}</span> {l.message}</div>
        {:else}
          <div class="faint">{t('jobs.noLog')}</div>
        {/each}
      </div>
    </section>
  </div>
{/if}

{#if confirmRetry && job}
  <Dialog title={t('jobs.retryStaleTitle', { id: job.id })} onclose={() => (confirmRetry = false)}>
    <p>{t('jobs.retryStale', { n: newest })}</p>
    {#snippet actions()}
      <button onclick={() => (confirmRetry = false)}>{t('common.cancel')}</button>
      <button onclick={() => go('deployments', newest)}>{t('jobs.openNewest', { n: newest })}</button>
      <button class="primary danger-bg" disabled={retrying} onclick={retry}>{t('jobs.retryAnyway')}</button>
    {/snippet}
  </Dialog>
{/if}

{#if deploying && job && servers[job.serverId]}
  <DeployDialog server={servers[job.serverId]} onclose={() => (deploying = false)} onstarted={(j) => go('deployments', j.id)} />
{/if}

<style>
  .head { margin-bottom: 6px; }
  .meta { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
  .live { color: var(--direct); }
  .cols { display: grid; grid-template-columns: minmax(220px, 300px) 1fr; gap: 16px; align-items: start; }
  @media (max-width: 860px) { .cols { grid-template-columns: 1fr; } }
  ol { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  li { display: flex; align-items: center; gap: 10px; }
  li.current { font-weight: 600; }
  li.err { color: var(--block); padding-left: 19px; word-break: break-word; }
  .lines { height: 420px; overflow: auto; background: var(--surface-2); border-radius: var(--radius-sm); padding: 10px 12px; font-size: 12px; line-height: 1.6; user-select: text; }
  .line { white-space: pre-wrap; word-break: break-word; }
  .line.warn { color: var(--warn); }
  .line.error { color: var(--block); }
  details { margin-top: 6px; }
  pre { white-space: pre-wrap; margin: 6px 0 0; }
</style>
