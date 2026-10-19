<script lang="ts">
  // What an import found: the installation and the findings about it.
  import type { ImportReport } from '../api';
  import { t } from '../i18n';

  let { report }: { report: ImportReport } = $props();
  const icon = { warn: '!', info: 'i' } as const;
  let findings = $derived(report.findings ?? []);
  let attention = $derived(findings.some((f) => f.level === 'warn'));
  let tls = $derived(
    report.meta.tls === 'acme' ? t('deploy.tlsACME') : report.meta.tls === 'self-signed' ? t('deploy.tlsSelf') : report.meta.tls === 'file' ? t('import.tlsFile') : '—',
  );
</script>

<section class="card report">
  <div class="row">
    <h2 class="grow">{t('import.title')}</h2>
    <span class="pill {attention ? 'block' : 'direct'}">{attention ? t('import.attention') : t('import.ok')}</span>
  </div>
  <dl>
    <dt>{t('import.service')}</dt>
    <dd>
      <span class="mono">{report.unit}</span> ·
      {report.active ? t('import.running') : t('import.stopped')} ·
      {report.enabled ? t('import.autostart') : t('import.noAutostart')}
    </dd>
    <dt>{t('import.binary')}</dt>
    <dd><span class="mono">{report.binary}</span>{report.version ? ` · ${report.version}` : ''}</dd>
    <dt>{t('import.config')}</dt>
    <dd class="mono">{report.config}</dd>
    <dt>{t('import.user')}</dt>
    <dd class="mono">{report.user || 'root'}</dd>
    {#if report.meta.ports}
      <dt>{t('deploy.ports')}</dt>
      <dd class="mono">UDP {report.meta.ports}</dd>
    {/if}
    <dt>{t('deploy.tls')}</dt>
    <dd>{tls}{report.meta.sni ? ` · ${report.meta.sni}` : ''}</dd>
    {#if report.meta.pinSHA256}
      <dt>{t('deploy.pin')}</dt>
      <dd class="mono small pin">{report.meta.pinSHA256}</dd>
    {/if}
    <dt>{t('deploy.obfs')}</dt>
    <dd>{report.meta.obfs || t('deploy.none')}</dd>
    <dt>{t('import.auth')}</dt>
    <dd>{report.meta.auth || '—'}</dd>
  </dl>
  {#if findings.length}
    <ul>
      {#each findings as f, i (i)}
        <li class={f.level}>
          <span class="ic" aria-hidden="true">{icon[f.level]}</span>
          <div>
            <div>{f.title}</div>
            {#if f.details}<div class="small muted">{f.details}</div>{/if}
          </div>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="muted small">{t('import.noFindings')}</p>
  {/if}
  <p class="small faint foot">{t('import.readOnly')}</p>
</section>

<style>
  .report { margin-bottom: 16px; }
  .report h2 { margin: 0; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 12px 0 14px; }
  dt { color: var(--muted); }
  dd { margin: 0; word-break: break-all; }
  .pin { user-select: all; }
  ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  li { display: flex; gap: 10px; align-items: flex-start; }
  .ic { width: 20px; height: 20px; border-radius: 50%; display: grid; place-items: center; font-size: 12px; font-weight: 700; flex: none; margin-top: 1px; }
  li.warn .ic { background: var(--warn-bg); color: var(--warn); }
  li.info .ic { background: var(--surface-2); color: var(--muted); }
  p { margin: 0; }
  .foot { margin-top: 12px; }
</style>
