<script lang="ts">
  // What a finished deploy installed: the config revision it saved (no
  // passwords).
  import { onMount } from 'svelte';
  import { api, type ServerConfig } from '../api';
  import { t } from '../i18n';
  import { go } from '../router.svelte';

  let { serverId, jobId }: { serverId: number; jobId: number } = $props();

  let cfg = $state<ServerConfig | null>(null);

  onMount(async () => {
    try {
      const c = await api.serverConfig(serverId);
      // A later deploy or edit replaced it: nothing to show here.
      if (c.jobId === jobId) cfg = c;
    } catch {}
  });
</script>

{#if cfg}
  <section class="card result">
    <div class="row">
      <h2 class="grow">{t('deploy.result')}</h2>
      <span class="pill direct">{cfg.meta.version}</span>
    </div>
    <dl>
      <dt>{t('deploy.ports')}</dt>
      <dd class="mono">UDP {cfg.meta.ports}</dd>
      <dt>{t('deploy.tls')}</dt>
      <dd>{cfg.meta.tls === 'acme' ? t('deploy.tlsACME') : t('deploy.tlsSelf')}{cfg.meta.sni ? ` · ${cfg.meta.sni}` : ''}</dd>
      {#if cfg.meta.pinSHA256}
        <dt>{t('deploy.pin')}</dt>
        <dd class="mono small pin">{cfg.meta.pinSHA256}</dd>
      {/if}
      <dt>{t('deploy.obfs')}</dt>
      <dd>{cfg.meta.obfs ? t('deploy.obfsOn') : t('deploy.none')}</dd>
      <dt>{t('deploy.revision')}</dt>
      <dd>{cfg.revision}</dd>
    </dl>
    <p class="small muted">{t('deploy.resultHint')} <button class="link small" onclick={() => go('servers', serverId)}>{t('deploy.clientLink')}</button></p>
  </section>
{/if}

<style>
  .result { margin-bottom: 16px; }
  .result h2 { margin: 0; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 12px 0 10px; }
  dt { color: var(--muted); }
  dd { margin: 0; word-break: break-all; }
  .pin { user-select: all; }
  p { margin: 0; }
</style>
