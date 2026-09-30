<script lang="ts">
  // The client side of a server: the summary for everyone, the links,
  // QR codes and config after an explicit "show" (audited).
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type ClientProfile, type ClientSummary } from '../api';
  import { t } from '../i18n';
  import { canWrite, session } from '../session.svelte';
  import QRCode from './QRCode.svelte';

  let { serverId, serverName }: { serverId: number; serverName: string } = $props();

  let summary = $state<ClientSummary | null>(null);
  let profile = $state<ClientProfile | null>(null);
  let user = $state('');
  let form = $state<'official' | 'compat'>('official');
  let error = $state<ApiError | null>(null);
  let copied = $state('');
  let busy = $state(false);
  let link = $derived(profile ? (form === 'official' ? profile.uri : profile.compat) : '');

  onMount(async () => {
    try {
      summary = await api.clientSummary(serverId);
      user = summary.users?.[0] ?? '';
    } catch (e) {
      const err = asApiError(e);
      if (err.code !== 'no_config') error = err;
    }
  });

  async function reveal() {
    busy = true;
    try {
      profile = await api.clientProfile(serverId, user);
      error = null;
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = what;
      setTimeout(() => (copied = ''), 1500);
    } catch {
      copied = '';
    }
  }

  function download() {
    if (!profile) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([profile.config], { type: 'application/yaml' }));
    // ASCII only: browsers may drop a name they cannot store as is.
    const ascii = serverName.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '');
    a.download = `hysteria-${/[A-Za-z]/.test(ascii) ? ascii : 'server-' + serverId}.yaml`;
    document.body.append(a); // a detached link loses its file name
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
</script>

<section class="card client">
  <div class="row">
    <h2 class="grow">{t('client.title')}</h2>
    {#if profile}<button class="ghost" onclick={() => (profile = null)}>{t('client.hide')}</button>{/if}
  </div>
  {#if error}<div class="note error">{error.message}</div>{/if}
  {#if !summary && !error}
    <p class="muted small">{t('client.noConfig')}</p>
  {:else if summary}
    <dl>
      <dt>{t('client.address')}</dt>
      <dd class="mono">{summary.host}:{summary.ports}</dd>
      {#if summary.sni}<dt>{t('client.sni')}</dt><dd class="mono">{summary.sni}</dd>{/if}
      {#if summary.pinSHA256}<dt>{t('client.pin')}</dt><dd class="mono small pin">{summary.pinSHA256}</dd>{/if}
      <dt>{t('client.obfs')}</dt>
      <dd>{summary.obfs || t('deploy.none')}</dd>
      {#if summary.users?.length}
        <dt>{t('client.user')}</dt>
        <dd>
          <select bind:value={user} onchange={() => profile && reveal()}>
            {#each summary.users as u (u)}<option value={u}>{u}</option>{/each}
          </select>
        </dd>
      {/if}
    </dl>
    {#each summary.warnings as w, i (i)}<div class="note warn small">{w}</div>{/each}

    {#if !profile}
      {#if canWrite(session.user)}
        <div class="row actions">
          <button class="primary" disabled={busy} onclick={reveal}>{t('client.reveal')}</button>
          <span class="small faint">{t('client.revealNote')}</span>
        </div>
      {/if}
    {:else}
      <div class="seg forms" role="tablist">
        <button class:on={form === 'official'} onclick={() => (form = 'official')}>{t('client.official')}</button>
        <button class:on={form === 'compat'} onclick={() => (form = 'compat')}>{t('client.compat')}</button>
      </div>
      <p class="small muted">{form === 'official' ? t('client.officialHint') : t('client.compatHint')}</p>
      <div class="linkbox">
        <QRCode rows={form === 'official' ? profile.qr : profile.qrCompat} label={t('client.qr')} />
        <div class="grow col">
          <div class="uri mono">{link}</div>
          <div class="row">
            <button onclick={() => copy(link, form)}>{copied === form ? t('client.copied') : t('client.copy')}</button>
            <button onclick={download}>{t('client.download')}</button>
          </div>
          <p class="small muted">{t('client.hyroute')}</p>
        </div>
      </div>
    {/if}
  {/if}
</section>

<style>
  .client { margin-bottom: 16px; }
  .client h2 { margin: 0; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 12px 0 10px; }
  dt { color: var(--muted); }
  dd { margin: 0; word-break: break-all; }
  .pin { user-select: all; }
  .actions { margin-top: 12px; gap: 12px; }
  .forms { margin: 14px 0 6px; }
  .linkbox { display: flex; gap: 18px; align-items: flex-start; margin-top: 10px; flex-wrap: wrap; }
  .col { display: flex; flex-direction: column; gap: 10px; min-width: 260px; }
  .uri { background: var(--surface-2); border-radius: var(--radius-sm); padding: 10px 12px; word-break: break-all; user-select: all; font-size: 12px; line-height: 1.5; }
  p { margin: 0; }
  .note { margin: 6px 0 0; }
</style>
