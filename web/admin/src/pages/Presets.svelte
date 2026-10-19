<script lang="ts">
  // Presets: parts of a server config without secrets and server
  // addresses, made from a server, copied, renamed, exported and imported,
  // and laid over a server's config section by section.
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Preset, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import { can, canOn } from '../session.svelte';
  import { go } from '../router.svelte';
  import Dialog from '../lib/Dialog.svelte';
  import Menu from '../lib/Menu.svelte';
  import PresetApplyDialog from '../lib/PresetApplyDialog.svelte';
  import { when } from '../lib/format';

  let list = $state<Preset[] | null>(null);
  let servers = $state<Server[]>([]);
  let error = $state<ApiError | null>(null);
  let open = $state<number | null>(null);
  // naming: a dialog asking for a name (new from a server, copy, rename).
  let naming = $state<{ kind: 'create' | 'clone' | 'rename'; preset?: Preset } | null>(null);
  let name = $state('');
  let serverId = $state(0);
  let nameError = $state<ApiError | null>(null);
  let deleting = $state<Preset | null>(null);
  let applying = $state<Preset | null>(null);
  let fileInput = $state<HTMLInputElement | null>(null);
  let writable = $derived(can('presets'));
  // applicable: a server the caller may lay a preset over.
  let applicable = $derived(servers.some((s) => canOn(s, 'config')));

  async function load() {
    try {
      list = await api.presets();
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
  }
  onMount(async () => {
    await load();
    try {
      servers = await api.servers();
    } catch {}
  });

  function ask(kind: 'create' | 'clone' | 'rename', preset?: Preset) {
    naming = { kind, preset };
    nameError = null;
    name = kind === 'rename' ? (preset?.name ?? '') : kind === 'clone' ? t('presets.copyOf', { name: preset?.name ?? '' }) : '';
    serverId = servers[0]?.id ?? 0;
  }

  async function saveName(e: Event) {
    e.preventDefault();
    if (!naming) return;
    nameError = null;
    try {
      let p: Preset;
      if (naming.kind === 'rename') p = await api.renamePreset(naming.preset!.id, name);
      else if (naming.kind === 'clone') p = await api.createPreset(name, { from: naming.preset!.id });
      else p = await api.createPreset(name, { serverId });
      naming = null;
      await load();
      open = p.id;
    } catch (err) {
      nameError = asApiError(err);
    }
  }

  async function remove() {
    if (!deleting) return;
    try {
      await api.deletePreset(deleting.id);
      deleting = null;
      await load();
    } catch (e) {
      error = asApiError(e);
      deleting = null;
    }
  }

  // exportFile saves the preset's file.
  async function exportFile(p: Preset) {
    try {
      const data = await api.exportPreset(p.id);
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `preset-${p.name.replace(/[^\p{L}\p{N}._-]+/gu, '-')}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      error = asApiError(e);
    }
  }

  async function importFile(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    (e.currentTarget as HTMLInputElement).value = '';
    if (!f) return;
    try {
      const p = await api.importPreset(await f.text());
      await load();
      open = p.id;
    } catch (err) {
      error = asApiError(err);
    }
  }
</script>

<div class="row head">
  <h1 class="grow">{t('nav.presets')}</h1>
  {#if writable}
    <button onclick={() => fileInput?.click()}>{t('presets.import')}</button>
    <input bind:this={fileInput} type="file" accept="application/json,.json" hidden onchange={importFile} />
    <button class="primary" onclick={() => ask('create')} disabled={!servers.length}>{t('presets.create')}</button>
  {/if}
</div>
<p class="muted small intro">{t('presets.intro')}</p>

{#if error}<div class="note error">{error.message}</div>{/if}

{#if list && list.length === 0}
  <div class="card empty"><p>{t('presets.empty')}</p></div>
{:else if list}
  <div class="list">
    {#each list as p (p.id)}
      <div class="card preset">
        <div class="row">
          <button class="ghost name" onclick={() => (open = open === p.id ? null : p.id)} aria-expanded={open === p.id}>
            {open === p.id ? '▾' : '▸'} {p.name}
          </button>
          <span class="grow"></span>
          <span class="small faint">{when(p.updatedAt)}</span>
          {#if applicable}<button class="ghost" onclick={() => (applying = p)}>{t('presets.apply')}</button>{/if}
          {#if writable}
            <Menu label={t('servers.more')}>
              <button onclick={() => ask('clone', p)}>{t('presets.clone')}</button>
              <button onclick={() => ask('rename', p)}>{t('presets.rename')}</button>
              <button onclick={() => exportFile(p)}>{t('presets.export')}</button>
              <button class="danger" onclick={() => (deleting = p)}>{t('common.delete')}</button>
            </Menu>
          {:else}
            <button class="ghost" onclick={() => exportFile(p)}>{t('presets.export')}</button>
          {/if}
        </div>
        <div class="secs">
          {#each p.sections as s (s)}<span class="badge">{t(`psec.${s}` as Key)}</span>{/each}
        </div>
        {#if open === p.id}
          {#if p.notes.length}
            <ul class="notes small muted">
              {#each p.notes as n (n)}<li>{n}</li>{/each}
            </ul>
          {/if}
          <pre class="mono small">{p.config}</pre>
        {/if}
      </div>
    {/each}
  </div>
{/if}

{#if naming}
  <Dialog title={naming.kind === 'create' ? t('presets.create') : naming.kind === 'clone' ? t('presets.clone') : t('presets.rename')} onclose={() => (naming = null)}>
    <form id="name-form" class="form" onsubmit={saveName}>
      {#if naming.kind === 'create'}
        <label>
          <span>{t('presets.fromServer')}</span>
          <select bind:value={serverId}>
            {#each servers as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
          </select>
          <span class="hint">{t('presets.fromServerHint')}</span>
        </label>
      {/if}
      <label>
        <span>{t('presets.name')}</span>
        <input type="text" required maxlength="64" bind:value={name} />
      </label>
      {#if nameError}<div class="note error" role="alert">{nameError.message}</div>{/if}
    </form>
    {#snippet actions()}
      <button type="button" onclick={() => (naming = null)}>{t('common.cancel')}</button>
      <button class="primary" type="submit" form="name-form">{t('presets.save')}</button>
    {/snippet}
  </Dialog>
{/if}

{#if deleting}
  <Dialog title={t('presets.deleteTitle')} onclose={() => (deleting = null)}>
    <p>{t('presets.deleteText', { name: deleting.name })}</p>
    {#snippet actions()}
      <button onclick={() => (deleting = null)}>{t('common.cancel')}</button>
      <button class="primary" onclick={remove}>{t('common.delete')}</button>
    {/snippet}
  </Dialog>
{/if}

{#if applying}
  <PresetApplyDialog preset={applying} onclose={() => (applying = null)} onstarted={(j) => go('deployments', j.id)} />
{/if}

<style>
  .head { margin-bottom: 6px; gap: 8px; align-items: center; }
  .intro { margin: 0 0 16px; max-width: 760px; }
  .list { display: flex; flex-direction: column; gap: 10px; }
  .preset .row { gap: 8px; align-items: center; }
  .name { font-weight: 600; color: var(--text); padding-left: 0; }
  .secs { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
  .notes { margin: 10px 0 0; padding-left: 18px; }
  pre { margin: 10px 0 0; padding: 10px 12px; background: var(--surface-2); border-radius: var(--radius-sm); overflow-x: auto; max-height: 360px; }
  .form { display: flex; flex-direction: column; gap: 14px; }
  label { display: flex; flex-direction: column; gap: 6px; }
  label span { color: var(--muted); font-size: 12.5px; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; }
  .empty p { margin: 0; }
</style>
