<script lang="ts">
  // New passwords (client auth, userpass users, Salamander) or a new
  // self-signed certificate for a server. Old client links stop working:
  // the dialog says whose, and asks for a confirmation.
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type ClientSummary, type Job, type Server, type ServerConfig } from '../api';
  import { t } from '../i18n';
  import Dialog from './Dialog.svelte';
  import ChainNote from './ChainNote.svelte';

  let { server, config, onclose, onstarted }: { server: Server; config: ServerConfig; onclose: () => void; onstarted: (j: Job) => void } = $props();

  let summary = $state<ClientSummary | null>(null);
  let error = $state<ApiError | null>(null);
  let busy = $state(false);
  let auth = $state(false);
  let users = $state<Record<string, boolean>>({});
  let obfs = $state(false);
  let cert = $state(false);
  let confirmed = $state(false);

  onMount(async () => {
    try {
      summary = await api.clientSummary(server.id);
      users = Object.fromEntries((summary.users ?? []).map((u) => [u, true]));
    } catch (e) {
      error = asApiError(e);
    }
  });

  let kind = $derived(summary?.auth ?? '');
  let picked = $derived(Object.keys(users).filter((u) => users[u]));
  let canObfs = $derived(summary?.obfs === 'salamander');
  let canCert = $derived(config.meta.tls === 'self-signed');
  // Whose links break: everyone's with a shared secret, else the users'.
  let all = $derived(obfs || cert || (auth && kind === 'password'));
  let any = $derived(obfs || cert || (auth && (kind === 'password' || picked.length > 0)));

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    error = null;
    try {
      const everyone = picked.length === Object.keys(users).length;
      onstarted(await api.rotateConfig(server.id, config.revision, { auth, users: kind === 'userpass' && !everyone ? picked : undefined, obfs, cert }));
    } catch (err) {
      error = asApiError(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('rot.title', { name: server.name })} {onclose}>
  <ChainNote {server} />
  {#if !summary && !error}
    <p class="muted">{t('rot.loading')}</p>
  {:else}
    <form id="rot-form" class="form" onsubmit={submit}>
      <p class="small">{t('rot.intro')}</p>

      {#if kind === 'password'}
        <div class="field">
          <label class="check"><input type="checkbox" bind:checked={auth} /> {t('rot.auth')}</label>
          <span class="hint">{t('rot.authHint')}</span>
        </div>
      {:else if kind === 'userpass'}
        <div class="field">
          <label class="check"><input type="checkbox" bind:checked={auth} /> {t('rot.users')}</label>
          {#if auth}
            <div class="users">
              {#each Object.keys(users) as u (u)}
                <label class="check mono"><input type="checkbox" bind:checked={users[u]} /> {u}</label>
              {/each}
            </div>
          {/if}
          <span class="hint">{t('rot.usersHint')}</span>
          {#if summary?.links?.length}<span class="hint">{t('rot.linkUsers', { users: summary.links.join(', ') })}</span>{/if}
        </div>
      {:else if kind}
        <p class="hint">{t('rot.external', { type: kind })}</p>
      {/if}

      {#if canObfs}
        <div class="field">
          <label class="check"><input type="checkbox" bind:checked={obfs} /> {t('rot.obfs')}</label>
          <span class="hint">{t('rot.obfsHint')}</span>
        </div>
      {/if}

      <div class="field">
        <label class="check"><input type="checkbox" bind:checked={cert} disabled={!canCert} /> {t('rot.cert')}</label>
        <span class="hint">{canCert ? t('rot.certHint') : t('rot.noCert')}</span>
      </div>

      {#if any}
        <div class="note warn small" role="alert">
          <div>{all ? t('rot.warnAll') : t('rot.warnUsers', { users: picked.join(', ') })} {t('rot.after')}</div>
          <label class="check"><input type="checkbox" bind:checked={confirmed} /> {t('rot.confirm')}</label>
        </div>
      {/if}

      {#if error}
        <div class="note error" role="alert">{error.message}</div>
      {/if}
    </form>
  {/if}
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button class="primary" type="submit" form="rot-form" disabled={busy || !any || !confirmed}>{t('rot.submit')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 14px; }
  .field { display: flex; flex-direction: column; gap: 5px; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; margin: 0; }
  .users { display: flex; flex-wrap: wrap; gap: 6px 16px; padding-left: 24px; }
  .note { margin: 0; display: flex; flex-direction: column; gap: 10px; }
  .note .check { color: var(--text); font-weight: 600; }
  p { margin: 0; }
</style>
