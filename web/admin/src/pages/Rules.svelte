<script lang="ts">
  // Rule templates: HyRoute's own sets of rules and the presets with an
  // acl section; each can go onto a server (at the top, at the end or
  // instead of its rules), be saved as a file, and a file can be read in.
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type RoutingTemplate, type Server } from '../api';
  import { t } from '../i18n';
  import { go } from '../router.svelte';
  import { can, canOn } from '../session.svelte';
  import { bad, protoPort } from '../lib/acl';
  import TemplateApplyDialog from '../lib/TemplateApplyDialog.svelte';

  let list = $state<RoutingTemplate[] | null>(null);
  let imported = $state<RoutingTemplate[]>([]);
  let servers = $state<Server[]>([]);
  let error = $state<ApiError | null>(null);
  let applying = $state<RoutingTemplate | null>(null);
  let fileInput = $state<HTMLInputElement | null>(null);
  // The routing editor's import, and applying to the servers whose config
  // the caller may change.
  let writable = $derived(can('config'));
  let all = $derived([...imported, ...(list ?? [])]);

  onMount(async () => {
    try {
      list = await api.routingTemplates();
      servers = (await api.servers()).filter((s) => canOn(s, 'config'));
    } catch (e) {
      error = asApiError(e);
    }
  });

  async function importFile(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const f = input.files?.[0];
    input.value = '';
    if (!f) return;
    try {
      const x = await api.routingImport(await f.text());
      imported = [{ id: 'import:' + f.name + ':' + imported.length, name: f.name, description: t('rules.importedNote'), acl: x.acl, outbounds: x.outbounds, resolver: x.resolver }, ...imported];
      error = null;
    } catch (err) {
      error = asApiError(err);
    }
  }

  // save writes a template as a routing file (no passwords in it).
  function save(tp: RoutingTemplate) {
    const data = { format: 'hyroute-routing', version: 1, acl: tp.acl, outbounds: tp.outbounds, resolver: tp.resolver };
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `rules-${tp.name.replace(/[^\p{L}\p{N}._-]+/gu, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
</script>

<div class="row head">
  <h1 class="grow">{t('nav.rules')}</h1>
  {#if writable}
    <button onclick={() => fileInput?.click()}>{t('tpl.import')}</button>
    <input type="file" accept=".json,.acl,.txt,text/plain,application/json" class="hidden" bind:this={fileInput} onchange={importFile} />
  {/if}
</div>
<p class="muted small intro">{t('rules.intro')} <button class="link" onclick={() => go('presets')}>{t('rules.toPresets')}</button></p>

{#if error}<div class="note error">{error.message}</div>{/if}

{#if list}
  <div class="grid">
    {#each all as tp (tp.id)}
      <section class="card">
        <div class="row">
          <h2 class="grow">{tp.name}</h2>
          <span class="pill small {tp.builtin ? 'direct' : ''}">{tp.builtin ? t('rules.builtin') : tp.id.startsWith('preset:') ? t('tpl.preset') : t('rules.imported')}</span>
        </div>
        {#if tp.description}<p class="small muted">{tp.description}</p>{/if}
        <ol class="rules mono small">
          {#each tp.acl.rules ?? [] as r, i (i)}
            <li class:off={r.off}>{bad(r) ? r.text : `${r.outbound}(${r.address}${protoPort(r) ? ', ' + protoPort(r) : ''}${r.hijack ? ', ' + r.hijack : ''})`}</li>
          {/each}
        </ol>
        {#if tp.outbounds?.length}<p class="small faint">{t('rules.outbounds', { list: tp.outbounds.map((o) => o.name).join(', ') })}</p>{/if}
        <div class="row actions">
          <span class="grow"></span>
          <button class="ghost" onclick={() => save(tp)}>{t('rules.save')}</button>
          {#if servers.length}<button class="primary" onclick={() => (applying = tp)}>{t('rules.applyTo')}</button>{/if}
        </div>
      </section>
    {/each}
  </div>
{:else if !error}
  <p class="muted">{t('cfg.loading')}</p>
{/if}

{#if applying}
  <TemplateApplyDialog tpl={applying} {servers} onclose={() => (applying = null)} />
{/if}

<style>
  .head { margin-bottom: 6px; }
  .intro { margin: 0 0 16px; max-width: 820px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 16px; align-items: start; }
  .card { display: flex; flex-direction: column; gap: 8px; }
  h2 { margin: 0; }
  .rules { margin: 0; padding: 8px 8px 8px 30px; background: var(--surface-2); border-radius: var(--radius-sm); max-height: 200px; overflow: auto; }
  .rules li.off { opacity: 0.55; }
  .actions { margin-top: 4px; gap: 8px; }
  .hidden { display: none; }
  p { margin: 0; }
</style>
