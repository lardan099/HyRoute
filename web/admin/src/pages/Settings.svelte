<script lang="ts">
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Role, type SessionInfo, type User } from '../api';
  import { t, type Key } from '../i18n';
  import { canManageUsers, session, signedOut } from '../session.svelte';

  let users = $state<User[]>([]);
  let sessions = $state<SessionInfo[]>([]);
  let error = $state<ApiError | null>(null);
  let manage = $derived(canManageUsers(session.user));

  let newName = $state('');
  let newPass = $state('');
  let newRole = $state<Role>('readonly');
  let creating = $state(false);
  let createError = $state<ApiError | null>(null);

  const fmt = (s: string) => new Date(s).toLocaleString('ru-RU');
  const who = (id: number) => users.find((u) => u.id === id)?.username ?? '#' + id;

  async function load() {
    try {
      [users, sessions] = await Promise.all([api.users(), api.sessions(manage)]);
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
  }
  onMount(load);

  async function revoke(s: SessionInfo) {
    if (s.current) return logout();
    try {
      await api.revokeSession(s.id);
      await load();
    } catch (e) {
      error = asApiError(e);
    }
  }

  async function logout() {
    try {
      await api.logout();
    } finally {
      signedOut();
    }
  }

  async function create(e: SubmitEvent) {
    e.preventDefault();
    creating = true;
    createError = null;
    try {
      await api.createUser(newName.trim(), newPass, newRole);
      newName = newPass = '';
      await load();
    } catch (err) {
      createError = asApiError(err);
    } finally {
      creating = false;
    }
  }
</script>

<h1>{t('nav.settings')}</h1>

{#if error}<div class="note error">{error.message}</div>{/if}

<section class="card">
  <div class="row head">
    <h2 class="grow">{t('settings.account')}</h2>
    <button onclick={logout}>{t('settings.logout')}</button>
  </div>
  {#if session.user}
    <p>{session.user.username} · <span class="muted">{t(`role.${session.user.role}` as Key)}</span></p>
  {/if}
</section>

<section class="card">
  <h2>{manage ? t('settings.allSessions') : t('settings.sessions')}</h2>
  <table>
    <thead>
      <tr>
        {#if manage}<th>{t('settings.user')}</th>{/if}
        <th>{t('settings.ip')}</th>
        <th>{t('settings.lastSeen')}</th>
        <th>{t('settings.browser')}</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each sessions as s (s.id)}
        <tr>
          {#if manage}<td>{who(s.userId)}</td>{/if}
          <td class="mono">{s.ip}</td>
          <td>{fmt(s.lastSeenAt)}{#if s.current} <span class="badge">{t('settings.current')}</span>{/if}</td>
          <td class="ua ellipsis" title={s.userAgent}>{s.userAgent}</td>
          <td class="act"><button class="ghost danger" onclick={() => revoke(s)}>{s.current ? t('settings.logout') : t('settings.revoke')}</button></td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>

<section class="card">
  <h2>{t('settings.users')}</h2>
  <table>
    <tbody>
      {#each users as u (u.id)}
        <tr>
          <td>{u.username}</td>
          <td class="muted">{t(`role.${u.role}` as Key)}</td>
          <td class="muted">{u.disabled ? t('settings.disabled') : ''}</td>
        </tr>
      {/each}
    </tbody>
  </table>
  {#if manage}
    <form class="row create" onsubmit={create}>
      <input type="text" placeholder={t('auth.username')} required maxlength="64" autocomplete="off" bind:value={newName} />
      <input type="password" placeholder={t('auth.password')} required minlength="10" autocomplete="new-password" bind:value={newPass} />
      <select bind:value={newRole}>
        <option value="admin">{t('role.admin')}</option>
        <option value="operator">{t('role.operator')}</option>
        <option value="readonly">{t('role.readonly')}</option>
      </select>
      <button class="primary" type="submit" disabled={creating}>{t('settings.addUser')}</button>
    </form>
    {#if createError}<div class="note error">{createError.message}</div>{/if}
  {/if}
</section>

<style>
  section { margin-top: 16px; max-width: 900px; }
  .head h2 { margin: 0; }
  p { margin: 8px 0 0; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 6px 8px; }
  td { padding: 6px 8px; border-top: 1px solid var(--border); }
  .ua { max-width: 260px; }
  .act { text-align: right; }
  td .badge { margin-left: 6px; }
  .create { margin-top: 14px; }
</style>
