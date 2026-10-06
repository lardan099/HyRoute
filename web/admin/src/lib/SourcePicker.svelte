<script lang="ts">
  // Where the Hysteria binary comes from: the server itself, the
  // controller, or another managed server (it gives its own binary when
  // that is the same build, else downloads the release; the controller
  // carries the file over and both servers check the hash).
  import { onMount } from 'svelte';
  import { api, type DeploySource, type Server } from '../api';
  import { t } from '../i18n';

  let { serverId, source = $bindable(), via = $bindable() }: { serverId: number; source: DeploySource; via: number } = $props();

  let others = $state<Server[]>([]);
  let loaded = $state(false);
  onMount(async () => {
    try {
      others = (await api.servers()).filter((s) => s.id !== serverId);
      loaded = true;
    } catch {}
  });
  // A server deleted since the last deploy (the form restores its via)
  // is not kept as the choice.
  $effect(() => {
    if (loaded && via && !others.some((s) => s.id === via)) via = 0;
  });
</script>

<div class="src">
  <label>
    <span class="lbl">{t('deploy.source')}</span>
    <select bind:value={source}>
      <option value="auto">{t('deploy.sourceAuto')}</option>
      <option value="direct">{t('deploy.sourceDirect')}</option>
      <option value="relay">{t('deploy.sourceRelay')}</option>
      <option value="node" disabled={others.length === 0 && source !== 'node'}>{t('deploy.sourceNode')}</option>
    </select>
  </label>
  {#if source === 'node'}
    <label>
      <span class="lbl">{t('deploy.via')}</span>
      <select bind:value={via}>
        <option value={0} disabled>{t('deploy.viaPick')}</option>
        {#each others as s (s.id)}<option value={s.id}>{s.name} · {s.host}</option>{/each}
      </select>
      <span class="hint">{t('deploy.viaHint')}</span>
    </label>
  {/if}
</div>

<style>
  .src { display: flex; flex-direction: column; gap: 12px; }
  label { display: flex; flex-direction: column; gap: 5px; }
  .lbl { color: var(--muted); font-size: 12.5px; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; }
</style>
