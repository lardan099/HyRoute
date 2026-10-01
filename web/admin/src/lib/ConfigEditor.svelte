<script lang="ts">
  // The config editor: main settings or raw YAML, kept in step through the
  // controller (typed model); the check, the diff and the apply.
  import { onMount } from 'svelte';
  import { api, asApiError, HIDDEN, type ApiError, type ConfigCheck, type ConfigFields, type Server } from '../api';
  import { t } from '../i18n';
  import { go } from '../router.svelte';
  import Dialog from './Dialog.svelte';
  import DiffView from './DiffView.svelte';

  let { server, onclose }: { server: Server; onclose: () => void } = $props();

  let tab = $state<'main' | 'yaml'>('main');
  let revision = $state(0);
  let yaml = $state('');
  let fields = $state<ConfigFields | null>(null);
  let domains = $state('');
  let check = $state<ConfigCheck | null>(null);
  let error = $state<ApiError | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let confirming = $state(false);
  let changed = $derived(!!check && (check.diff.some((l) => l.op !== ' ') || check.secrets.length > 0));
  let errors = $derived(check?.problems.filter((p) => !p.warning) ?? []);
  let warnings = $derived(check?.problems.filter((p) => p.warning) ?? []);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let seq = 0;

  onMount(async () => {
    try {
      const v = await api.configEdit(server.id);
      revision = v.revision;
      yaml = v.yaml;
      setFields(v.fields);
      await render(false);
    } catch (e) {
      error = asApiError(e);
    } finally {
      loading = false;
    }
  });

  function setFields(f: ConfigFields) {
    fields = f;
    domains = f.acmeDomains.join(', ');
  }

  // render checks the text (withFields: after the main settings changed,
  // the controller writes them into the text).
  async function render(withFields: boolean) {
    const my = ++seq;
    busy = true;
    try {
      const f = withFields && fields ? { ...fields, acmeDomains: domains.split(',').map((d) => d.trim()).filter(Boolean) } : undefined;
      const ch = await api.renderConfig(server.id, { revision, yaml, fields: f });
      if (my !== seq) return; // a newer edit is on its way
      check = ch;
      error = null;
      if (withFields) yaml = ch.yaml;
      if (!withFields || tab === 'yaml') setFields(ch.fields);
    } catch (e) {
      if (my !== seq) return;
      error = asApiError(e);
    } finally {
      if (my === seq) busy = false;
    }
  }

  function later(withFields: boolean) {
    busy = true; // Apply waits for the check of this edit
    clearTimeout(timer);
    timer = setTimeout(() => render(withFields), 500);
  }

  function field() {
    later(true);
  }

  function setAuth(v: string) {
    if (fields) fields.authPassword = v;
    field();
  }

  function setObfsPass(v: string) {
    if (fields) fields.obfsPassword = v;
    field();
  }

  async function apply() {
    confirming = false;
    busy = true;
    try {
      const j = await api.applyConfig(server.id, { revision, yaml });
      go('deployments', j.id);
    } catch (e) {
      error = asApiError(e);
      busy = false;
    }
  }
</script>

<section class="card editor">
  <div class="row">
    <h2 class="grow">{t('cfg.title', { name: server.name })} <span class="faint small">{revision ? t('cfg.revision', { n: revision }) : ''}</span></h2>
    <div class="seg" role="tablist">
      <button class:on={tab === 'main'} onclick={() => (tab = 'main')}>{t('cfg.tabMain')}</button>
      <button class:on={tab === 'yaml'} onclick={() => (tab = 'yaml')}>{t('cfg.tabYAML')}</button>
    </div>
  </div>

  {#if loading}
    <p class="muted">{t('cfg.loading')}</p>
  {:else if fields && tab === 'main'}
    <p class="small faint note-top">{t('cfg.fieldsNote')}</p>
    <div class="form">
      <label>
        <span>{t('cfg.listen')}</span>
        <input type="text" bind:value={fields.listen} oninput={field} placeholder={t('cfg.listenPh')} spellcheck="false" />
      </label>

      <div class="field">
        <span class="lbl">{t('cfg.tls')}</span>
        <div class="seg">
          <button type="button" class:on={fields.tls === 'file'} onclick={() => fields && ((fields.tls = 'file'), field())}>{t('cfg.tlsFile')}</button>
          <button type="button" class:on={fields.tls === 'acme'} onclick={() => fields && ((fields.tls = 'acme'), field())}>{t('cfg.tlsACME')}</button>
        </div>
      </div>
      {#if fields.tls === 'file'}
        <div class="two">
          <label class="grow"><span>{t('cfg.cert')}</span><input type="text" bind:value={fields.cert} oninput={field} spellcheck="false" /></label>
          <label class="grow"><span>{t('cfg.key')}</span><input type="text" bind:value={fields.key} oninput={field} spellcheck="false" /></label>
        </div>
        <label>
          <span>{t('cfg.sniGuard')}</span>
          <select bind:value={fields.sniGuard} onchange={field}>
            <option value="">{t('cfg.sniGuardDefault')}</option>
            <option value="strict">{t('cfg.sniGuardStrict')}</option>
            <option value="disable">{t('cfg.sniGuardDisable')}</option>
          </select>
        </label>
      {:else if fields.tls === 'acme'}
        <div class="two">
          <label class="grow"><span>{t('cfg.domains')}</span><input type="text" bind:value={domains} oninput={field} placeholder="vpn.example.com" spellcheck="false" /></label>
          <label class="grow"><span>{t('cfg.email')}</span><input type="text" bind:value={fields.acmeEmail} oninput={field} spellcheck="false" /></label>
        </div>
      {/if}

      <div class="field">
        <span class="lbl">{t('cfg.auth')}</span>
        {#if fields.authType && fields.authType !== 'password'}
          <span class="small muted">{t('cfg.authOther', { type: fields.authType })}</span>
        {:else if fields.authPassword === HIDDEN}
          <div class="row"><span class="muted small">{t('cfg.hidden')}</span><button type="button" class="ghost" onclick={() => setAuth('')}>{t('cfg.setNew')}</button></div>
        {:else}
          <div class="row">
            <input class="grow mono" type="text" bind:value={fields.authPassword} oninput={field} placeholder={t('cfg.newPassword')} spellcheck="false" autocomplete="off" />
            <button type="button" class="ghost" onclick={() => setAuth(HIDDEN)}>{t('cfg.keep')}</button>
          </div>
          <span class="hint">{t('cfg.newPasswordNote')}</span>
        {/if}
      </div>

      <div class="field">
        {#if fields.obfs && fields.obfs !== 'salamander'}
          <span class="lbl">{t('cfg.obfs')}</span>
          <span class="small muted">{t('cfg.obfsOther', { type: fields.obfs })}</span>
        {:else}
          <label class="check"><input type="checkbox" checked={fields.obfs === 'salamander'} onchange={(e) => fields && ((fields.obfs = e.currentTarget.checked ? 'salamander' : ''), field())} /> {t('cfg.obfs')}</label>
          {#if fields.obfs === 'salamander'}
            {#if fields.obfsPassword === HIDDEN}
              <div class="row"><span class="muted small">{t('cfg.obfsPassword')}: {t('cfg.hidden')}</span><button type="button" class="ghost" onclick={() => setObfsPass('')}>{t('cfg.setNew')}</button></div>
            {:else}
              <input class="mono" type="text" bind:value={fields.obfsPassword} oninput={field} placeholder={t('cfg.newPassword')} spellcheck="false" autocomplete="off" />
            {/if}
          {/if}
        {/if}
      </div>

      <div class="field">
        <span class="lbl">{t('cfg.masquerade')}</span>
        {#if fields.masquerade === 'file' || fields.masquerade === 'string'}
          <span class="small muted">{t('cfg.masqOther', { type: fields.masquerade })}</span>
        {:else}
          <select bind:value={fields.masquerade} onchange={field}>
            <option value="">{t('cfg.masqNone')}</option>
            <option value="proxy">{t('cfg.masqProxy')}</option>
          </select>
          {#if fields.masquerade === 'proxy'}
            <input type="text" bind:value={fields.masqueradeUrl} oninput={field} placeholder="https://www.example.com" aria-label={t('cfg.masqURL')} spellcheck="false" />
            <label class="check"><input type="checkbox" bind:checked={fields.rewriteHost} onchange={field} /> {t('cfg.rewriteHost')}</label>
          {/if}
        {/if}
      </div>

      <div class="field">
        <span class="lbl">{t('cfg.bandwidth')}</span>
        <div class="two">
          <label class="grow"><span>{t('cfg.up')}</span><input type="text" bind:value={fields.bandwidthUp} oninput={field} placeholder={t('cfg.bwPh')} /></label>
          <label class="grow"><span>{t('cfg.down')}</span><input type="text" bind:value={fields.bandwidthDown} oninput={field} placeholder={t('cfg.bwPh')} /></label>
        </div>
        <label class="check"><input type="checkbox" bind:checked={fields.ignoreClientBandwidth} onchange={field} /> {t('cfg.ignoreClientBW')}</label>
      </div>
      <label class="check"><input type="checkbox" bind:checked={fields.speedTest} onchange={field} /> {t('cfg.speedTest')}</label>
      <label class="check"><input type="checkbox" bind:checked={fields.disableUDP} onchange={field} /> {t('cfg.disableUDP')}</label>
      <label class="check"><input type="checkbox" bind:checked={fields.trafficStats} onchange={field} /> {t('cfg.trafficStats')}</label>
      <p class="small faint hint">{t('cfg.trafficStatsHint')}</p>
      <label class="short"><span>{t('cfg.udpIdle')}</span><input type="text" bind:value={fields.udpIdleTimeout} oninput={field} placeholder={t('cfg.udpIdlePh')} /></label>
    </div>
  {:else if tab === 'yaml'}
    <p class="small faint note-top">{t('cfg.yamlNote')}</p>
    <textarea class="yaml" bind:value={yaml} oninput={() => later(false)} spellcheck="false" rows="24"></textarea>
  {/if}

  {#if error}
    <div class="note error" role="alert">{error.message}</div>
  {/if}
</section>

{#if check}
  <section class="card">
    <div class="row">
      <h2 class="grow">{t('cfg.problems')}</h2>
      {#if busy}<span class="faint small">{t('cfg.checking')}</span>{/if}
    </div>
    {#each errors as p, i (i)}<div class="prob err"><span class="mono">{p.field}</span> {p.message}</div>{/each}
    {#each warnings as p, i (i)}<div class="prob warn"><span class="mono">{p.field}</span> {p.message}</div>{/each}
    {#if !errors.length && !warnings.length}<p class="muted small">{t('cfg.noProblems')}</p>{/if}
    {#if check.secrets.length}<div class="note info small">{t('cfg.secrets', { list: check.secrets.join(', ') })}</div>{/if}

    <h3>{t('cfg.diff')}</h3>
    {#if changed && check.diff.some((l) => l.op !== ' ')}
      <DiffView lines={check.diff} />
    {:else if !changed}
      <p class="muted small">{t('cfg.noChanges')}</p>
    {/if}
    <div class="row actions">
      <span class="grow"></span>
      <button onclick={onclose}>{t('cfg.cancel')}</button>
      <button class="primary" disabled={busy || !changed || !check.ok || !!error} onclick={() => (confirming = true)}>{t('cfg.apply')}</button>
    </div>
  </section>
{/if}

{#if confirming}
  <Dialog title={t('cfg.applyTitle')} onclose={() => (confirming = false)}>
    <p>{t('cfg.applyText')}</p>
    {#snippet actions()}
      <button onclick={() => (confirming = false)}>{t('common.cancel')}</button>
      <button class="primary" onclick={apply}>{t('cfg.apply')}</button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .editor { margin-bottom: 16px; }
  .editor h2 { margin: 0; }
  .note-top { margin: 10px 0 12px; }
  .form { display: flex; flex-direction: column; gap: 14px; max-width: 720px; }
  label:not(.check), .field { display: flex; flex-direction: column; gap: 5px; }
  label span, .lbl { color: var(--muted); font-size: 12.5px; }
  .hint { color: var(--faint); font-size: 12px; }
  .two { display: flex; gap: 12px; }
  .short { max-width: 260px; }
  .seg { align-self: flex-start; }
  .yaml { width: 100%; min-height: 420px; font-size: 12.5px; line-height: 1.5; }
  .prob { padding: 4px 0; font-size: 13px; }
  .prob.err { color: var(--block); }
  .prob.warn { color: var(--warn); }
  .prob .mono { margin-right: 6px; }
  h3 { margin-top: 16px; }
  .actions { margin-top: 16px; }
  p { margin: 0; }
  .card + .card { margin-bottom: 16px; }
</style>
