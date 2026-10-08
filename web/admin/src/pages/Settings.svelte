<script lang="ts">
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type SessionInfo, type User } from '../api';
  import { locale, t, type Key } from '../i18n';
  import { canDiagnose, canManageUsers, session, signedOut } from '../session.svelte';
  import BackupCard from '../lib/BackupCard.svelte';
  import PasswordDialog from '../lib/PasswordDialog.svelte';
  import UsersCard from '../lib/UsersCard.svelte';
  import DiagCard from '../lib/DiagCard.svelte';

  let users = $state<User[]>([]);
  let sessions = $state<SessionInfo[]>([]);
  let error = $state<ApiError | null>(null);
  let manage = $derived(canManageUsers(session.user));
  let changing = $state(false);
  let changed = $state(false);

  const fmt = (s: string) => new Date(s).toLocaleString(locale);
  const who = (id: number) => users.find((u) => u.id === id)?.username ?? '#' + id;
  // An owner's sessions are ended only by an owner (or the owner).
  const mayEnd = (s: SessionInfo) =>
    s.userId === session.user?.id || session.user?.role === 'owner' || users.find((u) => u.id === s.userId)?.role !== 'owner';

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
</script>

<h1>{t('nav.settings')}</h1>

{#if error}<div class="note error">{error.message}</div>{/if}

<section class="card">
  <div class="row head">
    <h2 class="grow">{t('settings.account')}</h2>
    <button
      onclick={() => {
        changing = true;
        changed = false;
      }}>{t('settings.changePassword')}</button
    >
    <button onclick={logout}>{t('settings.logout')}</button>
  </div>
  {#if session.user}
    <p>{session.user.username} · <span class="muted">{t(`role.${session.user.role}` as Key)}</span></p>
  {/if}
  {#if changed}<div class="note ok">{t('settings.passwordChanged')}</div>{/if}
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
          <td class="act">
            {#if mayEnd(s)}<button class="ghost danger" onclick={() => revoke(s)}>{s.current ? t('settings.logout') : t('settings.revoke')}</button>{/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>

<UsersCard changed={load} />

{#if changing}
  <PasswordDialog
    onclose={() => (changing = false)}
    ondone={() => {
      changing = false;
      changed = true;
      load();
    }}
  />
{/if}

{#if manage}
  <section class="card">
    <BackupCard />
  </section>
{/if}

{#if canDiagnose(session.user)}
  <section class="card">
    <DiagCard />
  </section>
{/if}

<style>
  section { margin-top: 16px; max-width: 900px; }
  .head h2 { margin: 0; }
  p { margin: 8px 0 0; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 6px 8px; }
  td { padding: 6px 8px; border-top: 1px solid var(--border); }
  .ua { max-width: 260px; }
  .act { text-align: right; }
  td .badge { margin-left: 6px; }
</style>
