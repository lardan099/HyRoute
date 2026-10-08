<script lang="ts">
  // A batch: one action over the chosen servers as ordinary jobs, the
  // canary first, then a few at a time (P4-07). The dialog asks what the
  // single-server dialogs ask, once for all of them.
  import { onMount, untrack } from 'svelte';
  import { api, asApiError, defaultHysteria, type ApiError, type Batch, type BatchAction, type DeploySource, type Preset, type RoutingTemplate, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import Dialog from './Dialog.svelte';
  import SourcePicker from './SourcePicker.svelte';

  let { action, servers, version: target = defaultHysteria, onclose, oncreated }: { action: BatchAction; servers: Server[]; version?: string; onclose: () => void; oncreated: (b: Batch) => void } = $props();

  let canary = $state(untrack(() => servers[0]?.id ?? 0));
  let parallel = $state(3);
  let busy = $state(false);
  let error = $state<ApiError | null>(null);

  // maintain, geo
  let version = $state(untrack(() => target));
  let source = $state<DeploySource>('auto');
  let via = $state(0);
  // preset
  let presets = $state<Preset[]>([]);
  let presetId = $state(0);
  let sections = $state<Record<string, boolean>>({});
  // routing
  let templates = $state<RoutingTemplate[]>([]);
  let templateId = $state('');
  let place = $state<'top' | 'bottom' | 'replace'>('top');
  let withOutbounds = $state(true);
  let withResolver = $state(true);
  // tuning
  const tuningKeys = ['net.core.rmem_max', 'net.core.wmem_max', 'net.core.default_qdisc', 'net.ipv4.tcp_congestion_control'];
  let keys = $state<Record<string, boolean>>({ 'net.core.rmem_max': true, 'net.core.wmem_max': true });
  // rotate
  let auth = $state(true);
  let obfs = $state(false);
  let cert = $state(false);
  let confirmed = $state(false);

  onMount(async () => {
    try {
      if (action === 'preset') presets = await api.presets();
      if (action === 'routing') templates = await api.routingTemplates();
    } catch (e) {
      error = asApiError(e);
    }
  });

  let preset = $derived(presets.find((p) => p.id === presetId));
  let template = $derived(templates.find((x) => x.id === templateId));
  // The servers in order: the canary first.
  let ordered = $derived([...servers.filter((s) => s.id === canary), ...servers.filter((s) => s.id !== canary)]);

  function pickPreset() {
    sections = Object.fromEntries((preset?.sections ?? []).map((s) => [s, false]));
  }

  let ready = $derived.by(() => {
    switch (action) {
      case 'maintain':
        return version.trim() !== '' && (source !== 'node' || via > 0);
      case 'geo':
        return source !== 'node' || via > 0;
      case 'preset':
        return !!preset && Object.values(sections).some(Boolean);
      case 'routing':
        return !!template;
      case 'tuning':
        return Object.values(keys).some(Boolean);
      case 'rotate':
        return (auth || obfs || cert) && confirmed;
    }
    return false;
  });

  function params(): Record<string, unknown> {
    switch (action) {
      case 'maintain':
        return { version: version.trim(), source, via: source === 'node' ? via : 0 };
      case 'geo':
        return { source, via: source === 'node' ? via : 0 };
      case 'preset':
        return { preset: presetId, sections: Object.keys(sections).filter((s) => sections[s]) };
      case 'routing':
        return { template: templateId, place, outbounds: withOutbounds && !!template?.outbounds?.length, resolver: withResolver && !!template?.resolver };
      case 'tuning':
        return { keys: tuningKeys.filter((k) => keys[k]) };
      case 'rotate':
        return { auth, obfs, cert };
    }
    return {};
  }

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    error = null;
    try {
      oncreated(await api.createBatch(action, { ...params(), servers: ordered.map((s) => s.id), parallel }));
    } catch (err) {
      error = asApiError(err);
      busy = false;
    }
  }
</script>

<Dialog title={t('batch.dialogTitle', { action: t(`batch.action.${action}` as Key), n: servers.length })} {onclose}>
  <form id="batch-form" class="form" onsubmit={submit}>
    <p class="small">{t('batch.order', { k: parallel })}</p>
    <div class="two">
      <label class="grow">
        <span>{t('batch.canary')}</span>
        <select bind:value={canary} disabled={busy}>
          {#each servers as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
        </select>
        <span class="hint">{t('batch.canaryHint')}</span>
      </label>
      <label class="k">
        <span>{t('batch.parallel')}</span>
        <input type="number" min="1" max="10" required bind:value={parallel} disabled={busy} />
        <span class="hint">{t('batch.parallelHint')}</span>
      </label>
    </div>
    <div class="list small">
      <span class="lbl">{t('batch.servers')}</span>
      <div class="names">
        {#each ordered as s, i (s.id)}<span class="badge" class:first={i === 0}>{s.name}</span>{/each}
      </div>
    </div>

    {#if action === 'maintain'}
      <label class="ver">
        <span>{t('deploy.version')}</span>
        <input type="text" required bind:value={version} spellcheck="false" disabled={busy} />
      </label>
      <p class="hint">{t('batch.maintainHint', { version: version.trim() || target })}</p>
      <SourcePicker serverId={0} bind:source bind:via />
    {:else if action === 'geo'}
      <p class="hint">{t('batch.geoHint')}</p>
      <SourcePicker serverId={0} bind:source bind:via />
    {:else if action === 'preset'}
      <label>
        <span>{t('batch.preset')}</span>
        <select bind:value={presetId} onchange={pickPreset} disabled={busy}>
          <option value={0} disabled>{t('batch.presetPick')}</option>
          {#each presets as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
        </select>
      </label>
      {#if preset}
        <div class="field">
          <span class="lbl">{t('batch.sections')}</span>
          <div class="checks">
            {#each preset.sections as s (s)}<label class="check"><input type="checkbox" bind:checked={sections[s]} disabled={busy} /> {t(`psec.${s}` as Key)}</label>{/each}
          </div>
        </div>
      {/if}
      <p class="hint">{t('batch.presetHint')}</p>
    {:else if action === 'routing'}
      <label>
        <span>{t('batch.template')}</span>
        <select bind:value={templateId} disabled={busy}>
          <option value="" disabled>{t('batch.templatePick')}</option>
          {#each templates as x (x.id)}<option value={x.id}>{x.name}</option>{/each}
        </select>
      </label>
      {#if template}
        {#if template.description}<p class="hint">{template.description}</p>{/if}
        <div class="field">
          <span class="lbl">{t('tpl.where')}</span>
          <div class="seg" role="radiogroup" aria-label={t('tpl.where')}>
            <button type="button" class:on={place === 'top'} disabled={busy} onclick={() => (place = 'top')}>{t('tpl.top')}</button>
            <button type="button" class:on={place === 'bottom'} disabled={busy} onclick={() => (place = 'bottom')}>{t('tpl.bottom')}</button>
            <button type="button" class:on={place === 'replace'} disabled={busy} onclick={() => (place = 'replace')}>{t('tpl.replace')}</button>
          </div>
          <span class="hint">{t(`tpl.hint.${place}` as Key)}</span>
        </div>
        {#if template.resolver}
          <label class="check"><input type="checkbox" bind:checked={withResolver} disabled={busy} /> {t('tpl.withResolver', { addr: template.resolver.addr || template.resolver.type })}</label>
        {/if}
        {#if template.outbounds?.length}
          <label class="check"><input type="checkbox" bind:checked={withOutbounds} disabled={busy} /> {t('tpl.outbounds', { list: template.outbounds.map((o) => o.name).join(', ') })}</label>
        {/if}
      {/if}
      <p class="hint">{t('batch.routingHint')}</p>
    {:else if action === 'tuning'}
      <div class="checks">
        {#each tuningKeys as k (k)}
          <label class="check"><input type="checkbox" bind:checked={keys[k]} disabled={busy} /> {t(`tune.key.${k}` as Key)} <span class="mono faint">{k}</span></label>
        {/each}
      </div>
      <p class="hint">{t('batch.tuningHint')}</p>
    {:else if action === 'rotate'}
      <div class="checks">
        <label class="check"><input type="checkbox" bind:checked={auth} disabled={busy} /> {t('batch.rotateAuth')}</label>
        <label class="check"><input type="checkbox" bind:checked={obfs} disabled={busy} /> {t('rot.obfs')}</label>
        <label class="check"><input type="checkbox" bind:checked={cert} disabled={busy} /> {t('rot.cert')}</label>
      </div>
      <p class="hint">{t('batch.rotateHint')}</p>
      <div class="note warn small">{t('batch.rotateWarn')}</div>
      <label class="check small"><input type="checkbox" bind:checked={confirmed} disabled={busy} /> {t('batch.rotateConfirm')}</label>
    {/if}

    {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
  </form>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button class="primary" type="submit" form="batch-form" disabled={busy || !ready}>{t('batch.start')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 14px; }
  label:not(.check), .field, .list { display: flex; flex-direction: column; gap: 5px; }
  label span, .lbl { color: var(--muted); font-size: 12.5px; }
  .two { display: flex; gap: 12px; align-items: flex-start; flex-wrap: wrap; }
  .grow { flex: 1; min-width: 200px; }
  .k { width: 190px; }
  .ver { width: 180px; }
  .hint, label span.hint { color: var(--faint); font-size: 12px; line-height: 1.4; margin: 0; }
  .names { display: flex; flex-wrap: wrap; gap: 4px; }
  .badge.first { background: var(--accent-soft); color: var(--accent); font-weight: 600; }
  .checks { display: flex; flex-direction: column; gap: 6px; }
  .seg { align-self: flex-start; }
  p { margin: 0; }
  .note { margin: 0; }
</style>
