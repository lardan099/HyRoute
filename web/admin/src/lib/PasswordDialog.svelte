<script lang="ts">
  // One's own password, with the current one. Every session of the user
  // ends; this browser gets a new one from the answer.
  import { api, asApiError, type ApiError } from '../api';
  import { t } from '../i18n';
  import { signedIn } from '../session.svelte';
  import Dialog from './Dialog.svelte';

  let { onclose, ondone }: { onclose: () => void; ondone: () => void } = $props();

  let current = $state('');
  let password = $state('');
  let password2 = $state('');
  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  const mismatch = $derived(password2 !== '' && password !== password2);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (mismatch) return;
    busy = true;
    error = null;
    try {
      signedIn(await api.changePassword(current, password));
      ondone();
    } catch (err) {
      error = asApiError(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('password.title')} {onclose}>
  <form id="own-password" class="form" onsubmit={submit}>
    <label>
      <span>{t('password.current')}</span>
      <input type="password" required autocomplete="current-password" bind:value={current} />
    </label>
    <label>
      <span>{t('password.new')}</span>
      <input type="password" required minlength="10" autocomplete="new-password" bind:value={password} />
    </label>
    <label>
      <span>{t('password.repeat')}</span>
      <input type="password" required autocomplete="new-password" bind:value={password2} />
    </label>
    {#if mismatch}<div class="note warn">{t('auth.mismatch')}</div>{/if}
    <p class="small muted">{t('password.hint')}</p>
    {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
  </form>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button class="primary" type="submit" form="own-password" disabled={busy || mismatch}>{t('password.submit')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 14px; min-width: 320px; }
  label { display: flex; flex-direction: column; gap: 6px; }
  label span { color: var(--muted); font-size: 12.5px; }
  p { margin: 0; max-width: 420px; }
</style>
