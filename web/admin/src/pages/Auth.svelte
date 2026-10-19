<script lang="ts">
  // First-run setup (owner with the setup token) or login.
  import { api, asApiError, type ApiError } from '../api';
  import { t } from '../i18n';
  import { signedIn } from '../session.svelte';

  let { mode }: { mode: 'setup' | 'login' } = $props();

  let token = $state('');
  let username = $state('');
  let password = $state('');
  let password2 = $state('');
  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  let mismatch = $derived(mode === 'setup' && password2 !== '' && password !== password2);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (mismatch) return;
    busy = true;
    error = null;
    try {
      signedIn(mode === 'setup' ? await api.setup(token.trim(), username.trim(), password) : await api.login(username.trim(), password));
    } catch (err) {
      error = asApiError(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <form class="card" onsubmit={submit}>
    <div class="brand"><span class="logo" aria-hidden="true">H</span>{t('app.name')}</div>
    <h1>{mode === 'setup' ? t('auth.setupTitle') : t('auth.loginTitle')}</h1>
    {#if mode === 'setup'}
      <p class="muted small">{t('auth.setupHint')}</p>
      <label>
        <span>{t('auth.setupToken')}</span>
        <input type="password" autocomplete="off" required bind:value={token} />
      </label>
    {/if}
    <label>
      <span>{t('auth.username')}</span>
      <input type="text" autocomplete="username" required maxlength="64" bind:value={username} />
    </label>
    <label>
      <span>{t('auth.password')}</span>
      <input type="password" autocomplete={mode === 'setup' ? 'new-password' : 'current-password'} required minlength={mode === 'setup' ? 10 : undefined} bind:value={password} />
    </label>
    {#if mode === 'setup'}
      <label>
        <span>{t('auth.password2')}</span>
        <input type="password" autocomplete="new-password" required bind:value={password2} />
      </label>
      {#if mismatch}<div class="note warn">{t('auth.mismatch')}</div>{/if}
    {/if}
    {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
    <button class="primary" type="submit" disabled={busy || mismatch}>
      {mode === 'setup' ? t('auth.setupSubmit') : t('auth.loginSubmit')}
    </button>
  </form>
</div>

<style>
  .wrap { min-height: 100%; display: grid; place-items: center; padding: 24px; }
  form { width: min(400px, 100%); display: flex; flex-direction: column; gap: 14px; padding: 28px; }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; }
  .logo {
    width: 30px;
    height: 30px;
    border-radius: 9px;
    display: grid;
    place-items: center;
    color: #fff;
    background: linear-gradient(135deg, var(--accent), color-mix(in srgb, var(--accent) 55%, #b06cff));
  }
  label { display: flex; flex-direction: column; gap: 6px; }
  label span { color: var(--muted); font-size: 12.5px; }
  p { margin: 0; }
  .note { margin: 0; }
  button { margin-top: 4px; padding: 9px 14px; }
</style>
