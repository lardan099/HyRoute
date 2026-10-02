<script lang="ts">
  // The geo databases: what the controller has (download or update it) and
  // what the server has (put the controller's there by the geo job).
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type DeploySource, type GeoInfo, type ServerGeo } from '../api';
  import { t } from '../i18n';
  import { go } from '../router.svelte';
  import { when } from './format';
  import SourcePicker from './SourcePicker.svelte';

  let { serverId, writable }: { serverId: number; writable: boolean } = $props();

  let info = $state<GeoInfo | null>(null);
  let geo = $state<ServerGeo | null>(null);
  let error = $state<ApiError | null>(null);
  let busy = $state(false);
  let source = $state<DeploySource>('auto');
  // job: the geo job just queued (shown here: the routing draft beside it
  // stays).
  let job = $state<number | null>(null);
  let via = $state(0);

  onMount(async () => {
    try {
      [info, geo] = await Promise.all([api.geoInfo(), api.serverGeo(serverId)]);
    } catch (e) {
      error = asApiError(e);
    }
  });

  async function update() {
    busy = true;
    try {
      info = (await api.geoUpdate()).info;
      geo = await api.serverGeo(serverId);
      error = null;
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }

  async function install() {
    busy = true;
    try {
      job = (await api.installGeo(serverId, source, source === 'node' ? via : undefined)).id;
      error = null;
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }
</script>

<h2>{t('geo.title')}</h2>
{#if info}
  <p class="small">
    {#if info.release}{t('geo.controller', { release: info.release, at: when(info.at) })}{:else}{t('geo.controllerNone')}{/if}
    {#if writable}<button class="link" disabled={busy} onclick={update}>{info.release ? t('geo.update') : t('geo.download')}</button>{/if}
  </p>
{/if}
{#if geo}
  <p class="small">
    {geo.release ? t('geo.server', { release: geo.release }) : t('geo.serverNone')}
    {#if geo.release && geo.latest}<span class="pill direct small">{t('geo.latest')}</span>{/if}
  </p>
  <p class="small muted">{geo.paths ? t('geo.paths') : geo.rules ? t('geo.noPaths') : t('geo.noRules')}</p>
  {#if writable && info?.release && !(geo.latest && geo.paths) && !job}
    <div class="src"><SourcePicker {serverId} bind:source bind:via /></div>
    <button class="primary" disabled={busy || (source === 'node' && !via)} onclick={install}>{t('geo.install')}</button>
  {/if}
{/if}
{#if job}<div class="note info small">{t('geo.queued')} <button class="link" onclick={() => go('deployments', job!)}>{t('geo.openJob', { id: job })}</button></div>{/if}
{#if error}<div class="note error small">{error.message}</div>{/if}

<style>
  h2 { margin-bottom: 10px; }
  p { margin: 0 0 6px; }
  .src { margin: 8px 0; }
</style>
