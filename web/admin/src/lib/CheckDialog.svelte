<script lang="ts">
  // Connect to a server and identify it. On the first connection (or after
  // the host key changed) the admin compares the fingerprint with the
  // server and confirms it; nothing is sent to an unconfirmed server.
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type CheckResult, type HostKey, type Server } from '../api';
  import { t } from '../i18n';
  import Dialog from './Dialog.svelte';

  let { server, onclose, onchanged }: { server: Server; onclose: () => void; onchanged: () => void } = $props();

  let busy = $state(true);
  let result = $state<CheckResult | null>(null);
  let error = $state<ApiError | null>(null);
  let understood = $state(false);
  let trusted = $state<HostKey | null>(null);
  let hostKey = $derived(trusted ?? server.hostKey);

  async function check() {
    busy = true;
    error = null;
    result = null;
    try {
      result = await api.checkServer(server.id);
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }
  onMount(check);

  // keyFile is where sshd keeps the public host key of this type.
  function keyFile(type: string): string {
    const kind = type.startsWith('ecdsa') ? 'ecdsa' : type === 'ssh-rsa' ? 'rsa' : 'ed25519';
    return `/etc/ssh/ssh_host_${kind}_key.pub`;
  }

  async function trust(replace: boolean) {
    if (!error) return;
    busy = true;
    try {
      trusted = await api.trustHostKey(server.id, error.data.fingerprint, replace);
      onchanged();
      await check();
    } catch (e) {
      error = asApiError(e);
      busy = false;
    }
  }
</script>

<Dialog title={t('check.title', { name: server.name })} {onclose}>
  {#if busy}
    <p class="muted">{t('check.connecting', { host: server.host })}</p>
  {:else if result}
    <div class="note {result.ok ? 'ok' : 'warn'}">{result.ok ? t('check.ok') : result.warning?.message}</div>
    <dl>
      <dt>{t('check.user')}</dt>
      <dd>{result.probe.user} · {result.probe.root ? t('check.root') : result.probe.sudo ? t('check.sudo') : t('check.noSudo')}</dd>
      <dt>{t('check.hostname')}</dt>
      <dd class="mono">{result.probe.hostname}</dd>
      <dt>{t('check.system')}</dt>
      <dd class="mono">{result.probe.kernel} · {result.probe.arch}</dd>
      {#if hostKey}
        <dt>{t('check.hostKey')}</dt>
        <dd class="mono small">{hostKey.type} {hostKey.fingerprint}</dd>
      {/if}
    </dl>
  {:else if error?.code === 'host_key_unknown'}
    <p>{t('check.unknownText')}</p>
    <div class="fp mono">{error.data.keyType}<br />{error.data.fingerprint}</div>
    <p class="muted small">{t('check.howToCompare')}</p>
    <pre class="mono small">ssh-keygen -lf {keyFile(error.data.keyType)}</pre>
  {:else if error?.code === 'host_key_changed'}
    <div class="note error">{error.message}</div>
    <dl>
      <dt>{t('check.oldKey')}</dt>
      <dd class="mono small">{error.data.oldKeyType} {error.data.oldFingerprint}</dd>
      <dt>{t('check.newKey')}</dt>
      <dd class="mono small">{error.data.keyType} {error.data.fingerprint}</dd>
    </dl>
    <label class="check"><input type="checkbox" bind:checked={understood} /> {t('check.understood')}</label>
  {:else if error}
    <div class="note error">
      {error.message}
      {#if error.details}<div class="small mono">{error.details}</div>{/if}
    </div>
  {/if}
  {#snippet actions()}
    {#if !busy && error?.code === 'host_key_unknown'}
      <button onclick={onclose}>{t('common.cancel')}</button>
      <button class="primary" onclick={() => trust(false)}>{t('check.trust')}</button>
    {:else if !busy && error?.code === 'host_key_changed'}
      <button onclick={onclose}>{t('common.cancel')}</button>
      <button class="primary danger-bg" disabled={!understood} onclick={() => trust(true)}>{t('check.retrust')}</button>
    {:else}
      {#if !busy && error}<button onclick={check}>{t('common.retry')}</button>{/if}
      <button class="primary" onclick={onclose}>{t('common.close')}</button>
    {/if}
  {/snippet}
</Dialog>

<style>
  p { margin: 0 0 10px; }
  .fp { background: var(--surface-2); border-radius: var(--radius-sm); padding: 10px 12px; margin: 0 0 10px; word-break: break-all; user-select: all; }
  pre { background: var(--surface-2); border-radius: var(--radius-sm); padding: 8px 10px; margin: 0; overflow-x: auto; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 12px 0 0; }
  dt { color: var(--muted); }
  dd { margin: 0; word-break: break-all; }
  .check { margin-top: 12px; }
</style>
