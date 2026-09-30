<script lang="ts">
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Health, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import { go } from '../router.svelte';
  import { flag, stateTone } from '../lib/format';

  let health = $state<Health | null>(null);
  let error = $state<ApiError | null>(null);
  let servers = $state<Server[] | null>(null);

  onMount(async () => {
    try {
      [health, servers] = await Promise.all([api.health(), api.servers()]);
    } catch (e) {
      error = asApiError(e);
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
    {#if servers && servers.length === 0}
      <p class="muted">{t('overview.serversEmpty')}</p>
    {:else if servers}
      <ul>
        {#each servers as s (s.id)}
          <li>
            <span class="dot {stateTone(s.state)}"></span>
            <span class="grow ellipsis">{flag(s.country)} {s.name}</span>
            <span class="muted small">{t(`state.${s.state}` as Key)}</span>
          </li>
        {/each}
      </ul>
      <button class="link small" onclick={() => go('servers')}>{t('overview.serversCount', { n: servers.length })}</button>
    {/if}
  </section>
</div>

<style>
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 20px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; margin: 0; }
  dt { color: var(--muted); }
  dd { margin: 0; display: flex; align-items: center; gap: 8px; }
  p { margin: 0; }
  ul { list-style: none; margin: 0 0 10px; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  li { display: flex; align-items: center; gap: 10px; min-width: 0; }
</style>
