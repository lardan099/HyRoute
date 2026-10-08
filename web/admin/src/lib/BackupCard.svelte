<script lang="ts">
  // Copies of the controller's database (the owner's) and the check of a
  // copy of the master key (owner and admin).
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Backups, type KeyCheck } from '../api';
  import { t, type Key } from '../i18n';
  import { canBackup, session } from '../session.svelte';
  import { bytes, when } from './format';
  import Dialog from './Dialog.svelte';

  let owner = $derived(canBackup(session.user));
  let backups = $state<Backups | null>(null);
  let error = $state<ApiError | null>(null);
  let busy = $state(false);

  let checking = $state(false);
  let keyText = $state('');
  let keyBusy = $state(false);
  let keyResult = $state<KeyCheck | null>(null);
  let keyError = $state<ApiError | null>(null);

  async function load() {
    if (!owner) return;
    try {
      backups = await api.backups();
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
  }
  onMount(load);

  async function make() {
    busy = true;
    try {
      await api.createBackup();
      await load();
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }

  function every(sec: number): string {
    if (sec % 86400 === 0) return t('backup.everyDays', { n: sec / 86400 });
    if (sec % 3600 === 0) return t('backup.everyHours', { n: sec / 3600 });
    return t('backup.everyMinutes', { n: Math.round(sec / 60) });
  }

  function openCheck() {
    keyText = '';
    keyResult = null;
    keyError = null;
    checking = true;
  }

  // closeCheck forgets the pasted key with the dialog.
  function closeCheck() {
    keyText = '';
    keyResult = null;
    checking = false;
  }

  async function check(e: SubmitEvent) {
    e.preventDefault();
    keyBusy = true;
    keyError = null;
    try {
      keyResult = await api.checkMasterKey(keyText);
    } catch (err) {
      keyError = asApiError(err);
      keyResult = null;
    } finally {
      keyBusy = false;
    }
  }
</script>

<h2>{t('backup.title')}</h2>
{#if owner}
  {#if backups}
    <p class="small">
      {backups.interval ? every(backups.interval) : t('backup.manual')} · {t('backup.keep', { n: backups.keep })} ·
      {backups.encrypted ? t('backup.encrypted') : t('backup.plain')}
    </p>
    <p class="small muted">{t('backup.where', { dir: backups.dir })}</p>
    {#if backups.last.error}<div class="note error small">{t('backup.lastFailed', { at: when(backups.last.at) })} {backups.last.error}</div>{/if}
    {#if backups.items.length}
      <table>
        <tbody>
          {#each backups.items as b (b.name)}
            <tr>
              <td>{when(b.at)}</td>
              <td class="muted">{bytes(b.size)}</td>
              <td class="muted">{b.encrypted ? t('backup.encryptedShort') : ''}</td>
              <td class="act"><a href={'/api/v1/backups/' + encodeURIComponent(b.name)} download={b.name}>{t('backup.download')}</a></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="small muted">{t('backup.none')}</p>
    {/if}
    <div class="row">
      <button class="primary" disabled={busy} onclick={make}>{busy ? t('backup.making') : t('backup.make')}</button>
      <button onclick={openCheck}>{t('backup.checkKey')}</button>
    </div>
    <p class="small muted hint">{t('backup.noKey')}</p>
  {/if}
  {#if error}<div class="note error small">{error.message}</div>{/if}
{:else}
  <p class="small muted">{t('backup.ownerOnly')}</p>
  <div class="row"><button onclick={openCheck}>{t('backup.checkKey')}</button></div>
{/if}

{#if checking}
  <Dialog title={t('backup.checkKey')} onclose={closeCheck}>
    <form id="keycheck" onsubmit={check}>
      <p class="small">{t('backup.checkKeyAbout')}</p>
      <textarea rows="4" class="mono" required spellcheck="false" autocomplete="off" placeholder="1:…" bind:value={keyText}></textarea>
    </form>
    {#if keyResult}
      <div class="note small" class:ok={keyResult.ok} class:error={!keyResult.ok}>
        {keyResult.ok ? t('backup.keyOK') : t('backup.keyBad')}
      </div>
      <ul class="small">
        {#each keyResult.versions as v (v.version)}
          <li>{t('backup.version', { n: v.version })}: {t(`backup.key.${v.status}` as Key)}</li>
        {/each}
        {#if keyResult.unused.length}<li class="muted">{t('backup.unused', { list: keyResult.unused.join(', ') })}</li>{/if}
      </ul>
    {/if}
    {#if keyError}<div class="note error small">{keyError.message}</div>{/if}
    {#snippet actions()}
      <button onclick={closeCheck}>{t('common.close')}</button>
      <button class="primary" type="submit" form="keycheck" disabled={keyBusy || !keyText.trim()}>{t('backup.check')}</button>
    {/snippet}
  </Dialog>
{/if}

<style>
  h2 { margin-bottom: 10px; }
  p { margin: 0 0 6px; }
  table { margin: 6px 0 10px; }
  td { padding: 5px 8px; border-top: 1px solid var(--border); }
  .act { text-align: right; }
  .row { gap: 8px; margin-top: 8px; }
  .hint { margin-top: 10px; }
  textarea { width: 100%; box-sizing: border-box; font-size: 13px; }
  ul { margin: 8px 0 0; padding-left: 20px; }
</style>
