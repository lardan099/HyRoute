<script lang="ts">
  // Lay sections of a preset over a server's config: pick the preset (from
  // a server page) or the server (from the presets page), the sections,
  // look at the diff, then apply it as an ordinary config change (copy,
  // restart, check, rollback).
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Job, type Preset, type PresetCheck, type PresetSection, type Server, type ServerConfig } from '../api';
  import { t, type Key } from '../i18n';
  import Dialog from './Dialog.svelte';
  import DiffView from './DiffView.svelte';

  let { server = null, preset = null, onclose, onstarted }: {
    server?: Server | null;
    preset?: Preset | null;
    onclose: () => void;
    onstarted: (j: Job) => void;
  } = $props();

  let presets = $state<Preset[]>([]);
  let servers = $state<Server[]>([]);
  let presetId = $state(0);
  let serverId = $state(0);
  let config = $state<ServerConfig | null>(null);
  let chosen = $state<Record<string, boolean>>({});
  let check = $state<PresetCheck | null>(null);
  let busy = $state(false);
  let error = $state<ApiError | null>(null);

  let current = $derived(preset ?? presets.find((p) => p.id === presetId) ?? null);
  let picked = $derived((current?.sections ?? []).filter((s) => chosen[s]) as PresetSection[]);
  let targetName = $derived(server?.name ?? servers.find((s) => s.id === serverId)?.name ?? '');

  onMount(async () => {
    try {
      if (!preset) {
        presets = await api.presets();
        presetId = presets[0]?.id ?? 0;
      }
      if (!server) {
        servers = await api.servers();
        serverId = servers[0]?.id ?? 0;
      }
    } catch (e) {
      error = asApiError(e);
    }
  });

  // The config of the target, for the revision the diff is against.
  $effect(() => {
    const id = server?.id ?? serverId;
    config = null;
    check = null;
    if (!id) return;
    api.serverConfig(id).then(
      (c) => (config = c),
      (e) => (error = asApiError(e)),
    );
  });

  // A new preset or a new choice of sections: the diff is old.
  $effect(() => {
    void current;
    void picked.length;
    check = null;
  });

  function target(): number {
    return server?.id ?? serverId;
  }

  async function preview() {
    if (!current || !config) return;
    busy = true;
    error = null;
    try {
      check = await api.presetPreview(target(), { base: config.revision, preset: current.id, sections: picked });
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!current || !config) return;
    busy = true;
    error = null;
    try {
      onstarted(await api.presetApply(target(), { base: config.revision, preset: current.id, sections: picked }));
    } catch (e) {
      error = asApiError(e);
      busy = false;
    }
  }

  let changes = $derived(!!check && (check.diff.some((l) => l.op !== ' ') || check.secrets.length > 0));
</script>

<Dialog title={server ? t('papply.titleServer', { name: server.name }) : t('papply.titlePreset', { name: preset?.name ?? '' })} {onclose}>
  <div class="form">
    {#if !preset}
      <label>
        <span>{t('papply.preset')}</span>
        {#if presets.length}
          <select bind:value={presetId}>
            {#each presets as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
          </select>
        {:else}
          <span class="hint">{t('papply.noPresets')}</span>
        {/if}
      </label>
    {/if}
    {#if !server}
      <label>
        <span>{t('papply.server')}</span>
        <select bind:value={serverId}>
          {#each servers as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
        </select>
      </label>
    {/if}

    {#if current}
      <div class="field">
        <span class="lbl">{t('papply.sections')}</span>
        <div class="secs">
          {#each current.sections as s (s)}
            <label class="check"><input type="checkbox" bind:checked={chosen[s]} /> {t(`psec.${s}` as Key)}</label>
          {/each}
        </div>
        <span class="hint">{t('papply.sectionsHint')}</span>
      </div>
    {/if}

    {#if !config && targetName}
      <p class="hint">{t('papply.noConfig')}</p>
    {/if}

    {#if check}
      {#if check.problems.length}
        <ul class="problems">
          {#each check.problems as pr (pr.field + pr.message)}
            <li class:warn={pr.warning}><span class="mono">{pr.field}</span>: {pr.message}</li>
          {/each}
        </ul>
      {/if}
      {#if changes}
        <DiffView lines={check.diff} />
        {#if check.secrets.length}<p class="hint">{t('papply.secrets', { list: check.secrets.join(', ') })}</p>{/if}
        {#if check.newObfs}<div class="note warn small">{t('papply.newObfs')}</div>{/if}
        {#if picked.includes('ports')}<div class="note warn small">{t('papply.ports')}</div>{/if}
      {:else}
        <div class="note info small">{t('papply.same')}</div>
      {/if}
    {/if}

    {#if error}
      <div class="note error" role="alert">{error.message}</div>
    {/if}
  </div>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button type="button" onclick={preview} disabled={busy || !current || !config || !picked.length}>{t('papply.preview')}</button>
    <button class="primary" type="button" onclick={apply} disabled={busy || !check || !check.ok || !changes}>{t('papply.apply')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 14px; }
  label:not(.check), .field { display: flex; flex-direction: column; gap: 6px; }
  label span, .lbl { color: var(--muted); font-size: 12.5px; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; margin: 0; }
  .secs { display: flex; flex-wrap: wrap; gap: 6px 16px; }
  .problems { margin: 0; padding-left: 18px; color: var(--block); font-size: 13px; }
  .problems li.warn { color: var(--muted); }
  .note { margin: 0; }
</style>
