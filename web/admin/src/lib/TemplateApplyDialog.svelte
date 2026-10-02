<script lang="ts">
  // A rule template on a server: where its rules go, the controller's
  // check of the result (problems, connections that change, config diff),
  // then the apply job.
  import { untrack } from 'svelte';
  import { api, asApiError, type ApiError, type RoutingInput, type RoutingPreview, type RoutingTemplate, type Server } from '../api';
  import { t } from '../i18n';
  import { go } from '../router.svelte';
  import { merge, type TemplateMode } from './acl';
  import Dialog from './Dialog.svelte';
  import DiffView from './DiffView.svelte';

  let { tpl, servers, onclose, onapplied }: { tpl: RoutingTemplate; servers: Server[]; onclose: () => void; onapplied?: () => void } = $props();

  let serverId = $state(untrack(() => servers[0]?.id ?? 0));
  let mode = $state<TemplateMode>('top');
  let withOutbounds = $state(true);
  let input = $state<RoutingInput | null>(null);
  let preview = $state<RoutingPreview | null>(null);
  let error = $state<ApiError | null>(null);
  let busy = $state(false);
  let ruleErrors = $derived(preview?.rules.filter((p) => p.level === 'error') ?? []);
  let warnings = $derived(preview?.rules.filter((p) => p.level === 'warn' && p.rule < 0) ?? []);

  function reset() {
    input = preview = null;
    error = null;
  }

  async function check() {
    busy = true;
    reset();
    try {
      const v = await api.routing(serverId);
      if (v.file) {
        error = { message: t('rules.fileNote', { path: v.file }) } as ApiError;
        return;
      }
      const m = merge(v.acl.rules ?? [], v.outbounds, tpl, mode, withOutbounds);
      input = { base: v.revision, acl: { rules: m.rules, tail: v.acl.tail }, outbounds: m.outbounds, resolver: m.resolver ?? v.resolver };
      preview = await api.routingPreview(serverId, input);
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!input) return;
    busy = true;
    try {
      const j = await api.routingApply(serverId, input);
      onapplied?.();
      go('deployments', j.id);
    } catch (e) {
      error = asApiError(e);
      busy = false;
    }
  }
</script>

<Dialog title={t('rules.applyTitle', { name: tpl.name })} {onclose}>
  <div class="form">
    <div class="two">
      <label class="grow">
        <span>{t('rules.server')}</span>
        <select bind:value={serverId} onchange={reset}>
          {#each servers as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
        </select>
      </label>
      <div class="field">
        <span class="lbl">{t('tpl.where')}</span>
        <div class="seg" role="radiogroup" aria-label={t('tpl.where')}>
          <button type="button" class:on={mode === 'top'} onclick={() => ((mode = 'top'), reset())}>{t('tpl.top')}</button>
          <button type="button" class:on={mode === 'bottom'} onclick={() => ((mode = 'bottom'), reset())}>{t('tpl.bottom')}</button>
          <button type="button" class:on={mode === 'replace'} onclick={() => ((mode = 'replace'), reset())}>{t('tpl.replace')}</button>
        </div>
      </div>
    </div>
    {#if tpl.resolver}<p class="small muted">{t('tpl.resolver', { addr: tpl.resolver.addr ?? tpl.resolver.type })}</p>{/if}
    {#if tpl.outbounds?.length}
      <label class="check"><input type="checkbox" bind:checked={withOutbounds} onchange={reset} /> {t('tpl.outbounds', { list: tpl.outbounds.map((o) => o.name).join(', ') })}</label>
    {/if}

    {#if error}<div class="note error small">{error.message}</div>{/if}
    {#if preview}
      {#each preview.problems.filter((p) => !p.warning) as p, i (i)}<div class="prob error"><span class="mono">{p.field}</span> {p.message}</div>{/each}
      {#if ruleErrors.length}<div class="prob error">{t('rt.ruleErrors', { n: ruleErrors.length })} {ruleErrors.map((p) => p.message).join(' ')}</div>{/if}
      {#each warnings as p, i (i)}<div class="prob warn">{p.message}</div>{/each}
      {#if preview.same}
        <p class="muted small">{t('rt.same')}</p>
      {:else}
        {#if preview.changes.length}
          <p class="small">{t('rules.changes', { n: preview.changes.length })}</p>
          <ul class="changes small">
            {#each preview.changes.slice(0, 12) as c, i (i)}
              <li><span class="mono">{c.request.host}:{c.request.port}</span> — {c.before.outbound} ⟶ <b>{c.after.outbound}</b></li>
            {/each}
          </ul>
        {/if}
        <div class="diff"><DiffView lines={preview.diff} /></div>
      {/if}
    {/if}
  </div>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    {#if preview && !preview.same && preview.ok}
      <button class="primary" disabled={busy} onclick={apply}>{t('cfg.apply')}</button>
    {:else}
      <button class="primary" disabled={busy || !serverId} onclick={check}>{t('rules.check')}</button>
    {/if}
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 12px; min-width: min(640px, 84vw); }
  label:not(.check), .field { display: flex; flex-direction: column; gap: 5px; }
  label span, .lbl { color: var(--muted); font-size: 12.5px; }
  .two { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
  .grow { flex: 1; min-width: 200px; }
  .prob { font-size: 12.5px; }
  .prob.error { color: var(--block); }
  .prob.warn { color: var(--warn); }
  .changes { margin: 0; padding-left: 18px; }
  .diff { max-height: 40vh; overflow: auto; }
  p { margin: 0; }
</style>
