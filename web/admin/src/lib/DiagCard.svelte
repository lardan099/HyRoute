<script lang="ts">
  // The diagnostic bundle (owner and admin): the panel builds it and lists
  // its files first; the download builds it again and is audited.
  import { api, asApiError, type ApiError, type DiagFiles } from '../api';
  import { t } from '../i18n';
  import { bytes } from './format';

  const counts = [10, 20, 50, 100];
  let jobs = $state(20);
  let list = $state<DiagFiles | null>(null);
  let busy = $state(false);
  let error = $state<ApiError | null>(null);

  async function prepare() {
    busy = true;
    error = null;
    try {
      list = await api.diag(jobs);
    } catch (e) {
      error = asApiError(e);
      list = null;
    } finally {
      busy = false;
    }
  }
</script>

<h2>{t('diag.title')}</h2>
<p class="small">{t('diag.about')}</p>
<p class="small muted">{t('diag.private')}</p>
<div class="row">
  <label class="row small">
    {t('diag.jobs')}
    <select bind:value={jobs} onchange={() => (list = null)}>
      {#each counts as n (n)}<option value={n}>{n}</option>{/each}
    </select>
  </label>
  <button class="primary" disabled={busy} onclick={prepare}>{busy ? t('diag.preparing') : t('diag.prepare')}</button>
</div>
{#if error}<div class="note error small">{error.message}</div>{/if}
{#if list}
  <p class="small files">{t('diag.files', { n: list.files.length, size: bytes(list.size) })}</p>
  <table>
    <tbody>
      {#each list.files as f (f.name)}
        <tr>
          <td class="mono">{f.name}</td>
          <td class="muted small">{f.about}</td>
          <td class="muted small size">{bytes(f.size)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
  {#if !list.controllerLog}<p class="small muted">{t('diag.noLog')}</p>{/if}
  <div class="row">
    <a class="dl" href={'/api/v1/diag/bundle?jobs=' + list.jobs} download={list.name}>{t('diag.download')}</a>
  </div>
  <p class="small muted hint">{t('diag.audit')}</p>
{/if}

<style>
  h2 { margin-bottom: 10px; }
  p { margin: 0 0 6px; }
  .files { margin-top: 12px; }
  table { margin: 6px 0 10px; }
  td { padding: 5px 8px; border-top: 1px solid var(--border); vertical-align: top; }
  .size { text-align: right; white-space: nowrap; }
  .row { gap: 8px; margin-top: 8px; }
  .hint { margin-top: 10px; }
  .dl {
    display: inline-flex;
    align-items: center;
    padding: 7px 14px;
    border-radius: var(--radius-sm);
    background: var(--accent);
    color: var(--accent-text);
    text-decoration: none;
  }
  .dl:hover { filter: brightness(1.08); }
</style>
