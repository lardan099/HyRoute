<script lang="ts">
  // Add or edit a server. Stored credentials are never shown: on edit the
  // fields are empty and an empty field keeps what is stored.
  import { untrack } from 'svelte';
  import { api, asApiError, type ApiError, type AuthType, type Server } from '../api';
  import { t } from '../i18n';
  import Dialog from './Dialog.svelte';

  // onsaved gets deploy = true when a new server was added with "Добавить
  // и развернуть".
  let { server, onclose, onsaved }: { server: Server | null; onclose: () => void; onsaved: (s: Server, deploy: boolean) => void } = $props();

  // The form starts from the server as it was when the dialog opened.
  const s = untrack(() => server);
  let name = $state(s?.name ?? '');
  let host = $state(s?.host ?? '');
  let sshPort = $state(s?.sshPort ?? 22);
  let sshUser = $state(s?.sshUser ?? 'root');
  let authType = $state<AuthType>(s?.authType ?? 'password');
  let password = $state('');
  let key = $state('');
  let keyPassphrase = $state('');
  let country = $state(s?.country ?? '');
  let location = $state(s?.location ?? '');
  let tags = $state((s?.tags ?? []).join(', '));
  let notes = $state(s?.notes ?? '');

  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  let errField = $derived(error?.code === 'invalid' ? error.details : '');

  const stored = (kind: AuthType) => (kind === 'password' ? !!s?.hasPassword : !!s?.hasKey);

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const deploy = (e.submitter as HTMLButtonElement | null)?.value === 'deploy';
    busy = true;
    error = null;
    const input = {
      name,
      host,
      sshPort: Number(sshPort) || 22,
      sshUser,
      authType,
      country,
      location,
      notes,
      tags: tags.split(',').map((x) => x.trim()).filter(Boolean),
      password: authType === 'password' && password !== '' ? password : undefined,
      key: authType === 'key' && key.trim() !== '' ? key : undefined,
      keyPassphrase: authType === 'key' && (keyPassphrase !== '' || key.trim() !== '') ? keyPassphrase : undefined,
    };
    try {
      onsaved(s ? await api.updateServer(s.id, input) : await api.createServer(input), deploy);
    } catch (err) {
      error = asApiError(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={s ? t('servers.editTitle') : t('servers.addTitle')} {onclose}>
  <form id="server-form" class="form" onsubmit={save}>
    <label class:bad={errField === 'name'}>
      <span>{t('servers.name')}</span>
      <input type="text" required maxlength="64" bind:value={name} placeholder={t('servers.namePh')} />
    </label>
    <div class="two">
      <label class="grow" class:bad={errField === 'host'}>
        <span>{t('servers.host')}</span>
        <input type="text" required bind:value={host} placeholder="vps.example.com" autocomplete="off" spellcheck="false" />
      </label>
      <label class="port" class:bad={errField === 'sshPort'}>
        <span>{t('servers.sshPort')}</span>
        <input type="number" min="1" max="65535" bind:value={sshPort} />
      </label>
    </div>
    <label class:bad={errField === 'sshUser'}>
      <span>{t('servers.sshUser')}</span>
      <input type="text" bind:value={sshUser} autocomplete="off" spellcheck="false" />
    </label>
    <div class="seg" role="radiogroup" aria-label={t('servers.auth')}>
      <button type="button" class:on={authType === 'password'} onclick={() => (authType = 'password')}>{t('servers.authPassword')}</button>
      <button type="button" class:on={authType === 'key'} onclick={() => (authType = 'key')}>{t('servers.authKey')}</button>
    </div>
    {#if authType === 'password'}
      <label class:bad={errField === 'password'}>
        <span>{t('servers.password')}</span>
        <input type="password" bind:value={password} autocomplete="new-password" placeholder={stored('password') ? t('servers.keepStored') : ''} />
      </label>
    {:else}
      <label class:bad={errField === 'key'}>
        <span>{t('servers.key')}</span>
        <textarea rows="5" bind:value={key} spellcheck="false" placeholder={stored('key') ? t('servers.keepStored') : '-----BEGIN OPENSSH PRIVATE KEY-----'}></textarea>
      </label>
      <label class:bad={errField === 'keyPassphrase'}>
        <span>{t('servers.keyPassphrase')}</span>
        <input type="password" bind:value={keyPassphrase} autocomplete="off" placeholder={s?.hasKeyPassphrase ? t('servers.keepStored') : t('servers.optional')} />
      </label>
    {/if}
    <div class="two">
      <label class="country" class:bad={errField === 'country'}>
        <span>{t('servers.country')}</span>
        <input type="text" maxlength="2" bind:value={country} placeholder="DE" />
      </label>
      <label class="grow" class:bad={errField === 'location'}>
        <span>{t('servers.location')}</span>
        <input type="text" maxlength="64" bind:value={location} placeholder={t('servers.locationPh')} />
      </label>
    </div>
    <label class:bad={errField === 'tags'}>
      <span>{t('servers.tags')}</span>
      <input type="text" bind:value={tags} placeholder={t('servers.tagsPh')} />
    </label>
    <label class:bad={errField === 'notes'}>
      <span>{t('servers.notes')}</span>
      <textarea rows="2" bind:value={notes} class="plain"></textarea>
    </label>
    {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
  </form>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    {#if !s}<button type="submit" form="server-form" value="add" disabled={busy}>{t('servers.add')}</button>{/if}
    <button class="primary" type="submit" form="server-form" value={s ? 'save' : 'deploy'} disabled={busy}>{s ? t('common.save') : t('deploy.addAndDeploy')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 12px; }
  label { display: flex; flex-direction: column; gap: 5px; }
  label span { color: var(--muted); font-size: 12.5px; }
  label.bad input, label.bad textarea { border-color: var(--block); }
  .two { display: flex; gap: 10px; }
  .port { width: 110px; }
  .country { width: 90px; }
  textarea.plain { font-family: var(--font); font-size: 14px; }
  .note { margin: 0; }
  .seg { align-self: flex-start; }
</style>
