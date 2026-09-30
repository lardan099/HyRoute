<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError, type Health } from '../api';
  import { t } from '../i18n';

  let health = $state<Health | null>(null);
  let error = $state<ApiError | null>(null);

  onMount(async () => {
    try {
      health = await api.health();
    } catch (e) {
      error = e instanceof ApiError ? e : new ApiError(0, 'unknown', t('error.unknown'), String(e));
    }
  });
</script>

<h1>{t('overview.title')}</h1>

<div class="grid">
  <section class="card">
    <h2>{t('overview.controller')}</h2>
    {#if error}
      <div class="note error">
        {error.message}
        {#if error.details}<div class="small mono">{error.details}</div>{/if}
      </div>
    {:else}
      <dl>
        <dt>{t('overview.status')}</dt>
        <dd>
          {#if health}<span class="dot ok"></span> {t('overview.ok')}{:else}<span class="muted">{t('overview.checking')}</span>{/if}
        </dd>
        <dt>{t('overview.version')}</dt>
        <dd class="mono">{health?.version ?? '—'}</dd>
        <dt>{t('overview.schema')}</dt>
        <dd class="mono">{health?.schemaVersion ?? '—'}</dd>
      </dl>
    {/if}
  </section>
  <section class="card">
    <h2>{t('overview.servers')}</h2>
    <p class="muted">{t('overview.serversEmpty')}</p>
  </section>
</div>

<style>
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 20px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; margin: 0; }
  dt { color: var(--muted); }
  dd { margin: 0; display: flex; align-items: center; gap: 8px; }
  p { margin: 0; }
</style>
