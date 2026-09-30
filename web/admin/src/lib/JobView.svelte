<script lang="ts">
  // One job: its steps, error and live log (server-sent events).
  import { onMount, tick } from 'svelte';
  import { api, asApiError, jobEventsURL, type ApiError, type Job, type JobDetail, type JobLog, type JobStep, type Server } from '../api';
  import { t, tOr, type Key } from '../i18n';
  import { canWrite, session } from '../session.svelte';
  import { duration, jobTone, stepTone, when } from './format';

  let { id, servers }: { id: number; servers: Record<number, Server> } = $props();

  let job = $state<JobDetail | null>(null);
  let logs = $state<JobLog[]>([]);
  let error = $state<ApiError | null>(null);
  let live = $state(false);
  let retrying = $state(false);
  let logBox = $state<HTMLElement | null>(null);
  let follow = $state(true);
  let source: EventSource | null = null;

  const stepName = (n: string) => tOr(`step.${n}`, n);
  const kindName = (k: string) => tOr(`kind.${k}`, k);

  async function scrollDown() {
    if (!follow) return;
    await tick();
    logBox?.scrollTo({ top: logBox.scrollHeight });
  }

  function connect() {
    source?.close();
    const last = logs.length ? logs[logs.length - 1].seq : 0;
    source = new EventSource(jobEventsURL(id) + (last ? `?after=${last}` : ''));
    live = true;
    source.addEventListener('log', (e) => {
      const l: JobLog = JSON.parse((e as MessageEvent).data);
      if (!logs.length || l.seq > logs[logs.length - 1].seq) {
        logs.push(l);
        scrollDown();
      }
    });
    source.addEventListener('step', (e) => {
      const s: JobStep = JSON.parse((e as MessageEvent).data);
      if (job) job.steps[s.idx] = s;
    });
    source.addEventListener('job', (e) => {
      const j: Job = JSON.parse((e as MessageEvent).data);
      if (job) Object.assign(job, j);
    });
    source.addEventListener('end', () => {
      source?.close();
      live = false;
    });
    source.onerror = () => {
      // The browser reconnects by itself with Last-Event-ID; a finished
      // job closes the stream for good.
      if (job && (job.state === 'completed' || job.state === 'failed')) {
        source?.close();
        live = false;
      }
    };
  }

  onMount(() => {
    (async () => {
      try {
        job = await api.job(id);
        connect();
      } catch (e) {
        error = asApiError(e);
      }
    })();
    return () => source?.close();
  });

  async function retry() {
    retrying = true;
    try {
      await api.retryJob(id);
      job = await api.job(id);
      connect();
    } catch (e) {
      error = asApiError(e);
    } finally {
      retrying = false;
    }
  }
</script>

{#if error}<div class="note error">{error.message}</div>{/if}

{#if job}
  <div class="row head">
    <h1 class="grow">{kindName(job.kind)} #{job.id}</h1>
    {#if job.state === 'failed' && canWrite(session.user)}
      <button class="primary" disabled={retrying} onclick={retry}>{t('jobs.retry')}</button>
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
