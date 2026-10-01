<script lang="ts">
  // Maintenance of the installed Hysteria: another version (with the
  // previous binary kept and put back if the new one does not start), or
  // a reinstall of what the deploy installs besides the config.
  import { api, asApiError, defaultHysteria, type ApiError, type DeploySource, type Job, type MaintainOp, type Server, type ServiceStatus } from '../api';
  import { t } from '../i18n';
  import Dialog from './Dialog.svelte';

  let { server, status, onclose, onstarted }: { server: Server; status: ServiceStatus; onclose: () => void; onstarted: (j: Job) => void } = $props();

  let op = $state<MaintainOp>('upgrade');
  let version = $state(defaultHysteria);
  let source = $state<DeploySource>('auto');
  let busy = $state(false);
  let error = $state<ApiError | null>(null);

  let same = $derived(op === 'upgrade' && version.trim() === status.version);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    error = null;
    try {
      onstarted(await api.startMaintain(server.id, { op, version: op === 'upgrade' ? version.trim() : undefined, source }));
    } catch (err) {
      error = asApiError(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('maint.title', { name: server.name })} {onclose}>
  <form id="maint-form" class="form" onsubmit={submit}>
    <p class="small">{t('maint.installed', { version: status.version || t('maint.unknown') })}</p>
    <div class="seg" role="radiogroup" aria-label={t('maint.title', { name: server.name })}>
      <button type="button" class:on={op === 'upgrade'} onclick={() => (op = 'upgrade')}>{t('maint.upgrade')}</button>
      <button type="button" class:on={op === 'reinstall'} disabled={!status.managed} onclick={() => (op = 'reinstall')}>{t('maint.reinstall')}</button>
    </div>

    {#if op === 'upgrade'}
      <label class="ver">
        <span>{t('deploy.version')}</span>
        <input type="text" required bind:value={version} spellcheck="false" />
      </label>
      <p class="hint">{t('maint.upgradeHint', { latest: defaultHysteria })}</p>
      {#if same}<p class="hint">{t('maint.same')}</p>{/if}
    {:else}
      <p class="hint">{t('maint.reinstallHint', { version: status.version || defaultHysteria })}</p>
    {/if}
    {#if !status.managed}<p class="hint">{t('maint.imported')}</p>{/if}

    <label>
      <span>{t('deploy.source')}</span>
      <select bind:value={source}>
        <option value="auto">{t('deploy.sourceAuto')}</option>
        <option value="direct">{t('deploy.sourceDirect')}</option>
        <option value="relay">{t('deploy.sourceRelay')}</option>
      </select>
    </label>
    <div class="note info small">{t('maint.restartNote')}</div>

    {#if error}
      <div class="note error" role="alert">{error.message}</div>
    {/if}
  </form>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button class="primary" type="submit" form="maint-form" disabled={busy}>{op === 'upgrade' ? t('maint.submitUpgrade') : t('maint.submitReinstall')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 14px; }
  label { display: flex; flex-direction: column; gap: 5px; }
  label span { color: var(--muted); font-size: 12.5px; }
  .ver { width: 160px; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; margin: 0; }
  .seg { align-self: flex-start; }
  p { margin: 0; }
  .note { margin: 0; }
</style>
