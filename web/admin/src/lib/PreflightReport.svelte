<script lang="ts">
  import type { PreflightReport } from '../api';
  import { t } from '../i18n';

  let { report }: { report: PreflightReport } = $props();
  const icon = { ok: '✓', warn: '!', fail: '✗' } as const;
</script>

<section class="card report">
  <div class="row">
    <h2 class="grow">{t('preflight.title')}</h2>
    <span class="pill {report.blocked ? 'block' : 'direct'}">{report.blocked ? t('preflight.blocked') : t('preflight.ready')}</span>
  </div>
  <p class="facts muted small">
    {report.os || '—'} · {report.arch} · {t('preflight.cpu', { n: report.cpus })} · {report.memoryMiB} МБ · {t('preflight.disk', { n: report.diskFreeMiB })}
  </p>
  <ul>
    {#each report.checks as c (c.id + c.title)}
      <li class={c.level}>
        <span class="ic" aria-hidden="true">{icon[c.level]}</span>
        <div>
          <div>{c.title}</div>
          {#if c.details}<div class="small muted">{c.details}</div>{/if}
        </div>
      </li>
    {/each}
  </ul>
</section>

<style>
  .report { margin-bottom: 16px; }
  .report h2 { margin: 0; }
  .facts { margin: 6px 0 12px; }
  ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  li { display: flex; gap: 10px; align-items: flex-start; }
  .ic { width: 20px; height: 20px; border-radius: 50%; display: grid; place-items: center; font-size: 12px; font-weight: 700; flex: none; margin-top: 1px; }
  li.ok .ic { background: var(--ok-bg); color: var(--direct); }
  li.warn .ic { background: var(--warn-bg); color: var(--warn); }
  li.fail .ic { background: var(--danger-bg); color: var(--block); }
</style>
