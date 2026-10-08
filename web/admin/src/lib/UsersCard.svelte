<script lang="ts">
  // Panel users: role, scope, state and last login of each. Owners and
  // admins add users, change roles and scopes, reset passwords, block,
  // unblock and delete; an owner also hands the owner role over. The
  // controller decides who may do what (an owner is managed only by an
  // owner, nobody blocks or deletes themselves, the last owner stays,
  // owners and admins reach every server); the menu only follows it. A
  // role is a fixed set of permissions: the dialog shows them.
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Role, type RoleInfo, type Scope, type User } from '../api';
  import { t, type Key } from '../i18n';
  import { canManageUsers, loadSession, session } from '../session.svelte';
  import Dialog from './Dialog.svelte';
  import Menu from './Menu.svelte';
  import ScopePicker from './ScopePicker.svelte';
  import { when } from './format';

  // changed: users were changed (sessions may have ended).
  let { changed }: { changed?: () => void } = $props();

  type Action = 'role' | 'password' | 'block' | 'delete' | 'owner';

  let users = $state<User[]>([]);
  let error = $state<ApiError | null>(null);
  const me = $derived(session.user);
  const manage = $derived(canManageUsers(me));
  const owner = $derived(me?.role === 'owner');

  let newName = $state('');
  let newPass = $state('');
  let newRole = $state<Role>('readonly');
  let newScope = $state<Scope>({ all: true });
  let roles = $state<RoleInfo[]>([]);
  // tagsInUse: the tags of the servers, offered for scopes.
  let tagsInUse = $state<string[]>([]);
  let creating = $state(false);
  let createError = $state<ApiError | null>(null);

  let acting = $state<{ kind: Action; user: User } | null>(null);
  let role = $state<Role>('readonly');
  let scope = $state<Scope>({ all: true });
  let generate = $state(true);
  let typed = $state('');
  let generated = $state('');
  let copied = $state(false);
  let busy = $state(false);
  let actError = $state<ApiError | null>(null);

  // mayManage: the menu for u (the controller checks again).
  const mayManage = (u: User) => manage && u.id !== me?.id && (u.role !== 'owner' || owner);
  // unscoped: the role reaches every server whatever the scope.
  const unscoped = (r: Role) => roles.find((x) => x.role === r)?.unscoped ?? (r === 'owner' || r === 'admin');
  const permsText = (r: Role) => (roles.find((x) => x.role === r)?.permissions ?? []).map((p) => t(`perm.${p}` as Key)).join(', ');
  const scopeText = (s?: Scope) => (!s || s.all ? t('scope.allShort') : (s.tags ?? []).join(', '));
  // scopeOK: a scope that reaches something.
  const scopeOK = (r: Role, s: Scope) => unscoped(r) || !!s.all || !!s.tags?.length;

  async function load() {
    try {
      users = await api.users();
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
    if (!manage || roles.length) return;
    try {
      const [rs, ss] = await Promise.all([api.roles(), api.servers()]);
      roles = rs;
      tagsInUse = [...new Set(ss.flatMap((s) => s.tags))];
    } catch {}
  }
  onMount(load);

  async function reload() {
    await load();
    changed?.();
  }

  async function create(e: SubmitEvent) {
    e.preventDefault();
    creating = true;
    createError = null;
    try {
      await api.createUser(newName.trim(), newPass, newRole, unscoped(newRole) ? { all: true } : newScope);
      newName = newPass = '';
      newScope = { all: true };
      await load();
    } catch (err) {
      createError = asApiError(err);
    } finally {
      creating = false;
    }
  }

  function open(kind: Action, user: User) {
    acting = { kind, user };
    role = user.role;
    scope = user.scope ?? { all: true };
    generate = true;
    typed = generated = '';
    copied = false;
    actError = null;
  }

  function close() {
    // The generated password is not kept anywhere once its dialog closes.
    acting = null;
    generated = typed = '';
  }

  async function unblock(u: User) {
    try {
      await api.updateUser(u.id, { disabled: false });
      await reload();
    } catch (e) {
      error = asApiError(e);
    }
  }

  async function run(e?: Event) {
    e?.preventDefault();
    if (!acting) return;
    const u = acting.user;
    busy = true;
    actError = null;
    try {
      switch (acting.kind) {
        case 'role':
          // Owners and admins reach every server: the controller sets it.
          await api.updateUser(u.id, unscoped(role) ? { role } : { role, scope });
          break;
        case 'block':
          await api.updateUser(u.id, { disabled: true });
          break;
        case 'delete':
          await api.deleteUser(u.id);
          break;
        case 'owner':
          await api.transferOwner(u.id);
          // Our own role changed: the pages follow it.
          await loadSession();
          break;
        case 'password': {
          const r = await api.resetPassword(u.id, generate ? undefined : typed);
          if (r?.password) {
            generated = r.password;
            await reload();
            return;
          }
          break;
        }
      }
      close();
      await reload();
    } catch (err) {
      actError = asApiError(err);
    } finally {
      busy = false;
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(generated);
      copied = true;
      setTimeout(() => (copied = false), 1500);
    } catch {
      copied = false;
    }
  }

  const titles: Record<Action, Key> = {
    role: 'users.accessTitle',
    password: 'users.resetTitle',
    block: 'users.blockTitle',
    delete: 'users.deleteTitle',
    owner: 'users.transferTitle',
  };
</script>

<section class="card">
  <h2>{t('settings.users')}</h2>
  {#if error}<div class="note error">{error.message}</div>{/if}
  <table>
    <thead>
      <tr>
        <th>{t('users.name')}</th>
        <th>{t('users.role')}</th>
        {#if manage}<th>{t('scope.title')}</th>{/if}
        <th>{t('users.state')}</th>
        <th>{t('users.lastLogin')}</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each users as u (u.id)}
        <tr class:off={u.disabled}>
          <td>{u.username}{#if u.id === me?.id} <span class="badge">{t('users.you')}</span>{/if}</td>
          <td class="muted">{t(`role.${u.role}` as Key)}</td>
          {#if manage}<td class="muted">{scopeText(u.scope)}</td>{/if}
          <td class:blocked={u.disabled}>{u.disabled ? t('users.blocked') : t('users.active')}</td>
          <td class="muted">{when(u.lastLoginAt)}</td>
          <td class="act">
            {#if mayManage(u)}
              <Menu label={t('users.actions')}>
                <button onclick={() => open('role', u)}>{t('users.changeAccess')}</button>
                <button onclick={() => open('password', u)}>{t('users.resetPassword')}</button>
                {#if u.disabled}
                  <button onclick={() => unblock(u)}>{t('users.unblock')}</button>
                {:else}
                  <button onclick={() => open('block', u)}>{t('users.block')}</button>
                {/if}
                {#if owner && u.role !== 'owner' && !u.disabled}
                  <button onclick={() => open('owner', u)}>{t('users.transfer')}</button>
                {/if}
                <button class="danger" onclick={() => open('delete', u)}>{t('common.delete')}</button>
              </Menu>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  {#if manage}
    <form class="create" onsubmit={create}>
      <div class="row">
        <input type="text" placeholder={t('auth.username')} required maxlength="64" autocomplete="off" bind:value={newName} />
        <input type="password" placeholder={t('auth.password')} required minlength="10" autocomplete="new-password" bind:value={newPass} />
        <select bind:value={newRole} aria-label={t('users.role')}>
          <option value="admin">{t('role.admin')}</option>
          <option value="operator">{t('role.operator')}</option>
          <option value="clients">{t('role.clients')}</option>
          <option value="readonly">{t('role.readonly')}</option>
        </select>
        <button class="primary" type="submit" disabled={creating || !scopeOK(newRole, newScope)}>{t('settings.addUser')}</button>
      </div>
      <p class="small muted">{t('users.perms', { list: permsText(newRole) })}</p>
      {#if !unscoped(newRole)}<ScopePicker bind:scope={newScope} tags={tagsInUse} />{/if}
    </form>
    {#if createError}<div class="note error">{createError.message}</div>{/if}
    <p class="small faint">{t('users.rolesHint')}</p>
  {/if}
</section>

{#if acting}
  <Dialog title={t(titles[acting.kind], { name: acting.user.username })} onclose={close}>
    {#if acting.kind === 'role'}
      <form id="user-act" class="form" onsubmit={run}>
        <select bind:value={role} aria-label={t('users.role')}>
          {#if owner}<option value="owner">{t('role.owner')}</option>{/if}
          <option value="admin">{t('role.admin')}</option>
          <option value="operator">{t('role.operator')}</option>
          <option value="clients">{t('role.clients')}</option>
          <option value="readonly">{t('role.readonly')}</option>
        </select>
        <p class="small muted">{t('users.perms', { list: permsText(role) })}</p>
        <h3 class="small">{t('scope.title')}</h3>
        {#if unscoped(role)}
          <p class="small muted">{t('scope.unscoped')}</p>
        {:else}
          <ScopePicker bind:scope tags={tagsInUse} />
        {/if}
        <p class="small muted">{role === 'owner' ? t('users.ownerHint') : t('users.roleHint')}</p>
      </form>
    {:else if acting.kind === 'password' && generated}
      <p>{t('users.generated', { name: acting.user.username })}</p>
      <div class="row">
        <input class="grow mono" type="text" readonly value={generated} aria-label={t('auth.password')} onfocus={(e) => e.currentTarget.select()} />
        <button onclick={copy}>{copied ? t('users.copied') : t('users.copy')}</button>
      </div>
    {:else if acting.kind === 'password'}
      <form id="user-act" class="form" onsubmit={run}>
        <div class="seg" role="radiogroup" aria-label={t('users.resetPassword')}>
          <button type="button" class:on={generate} onclick={() => (generate = true)}>{t('users.resetGenerate')}</button>
          <button type="button" class:on={!generate} onclick={() => (generate = false)}>{t('users.resetType')}</button>
        </div>
        {#if !generate}
          <input type="password" required minlength="10" autocomplete="new-password" placeholder={t('auth.password')} bind:value={typed} />
        {/if}
        <p class="small muted">{t('users.resetHint')}</p>
      </form>
    {:else if acting.kind === 'block'}
      <p>{t('users.blockText')}</p>
    {:else if acting.kind === 'delete'}
      <p>{t('users.deleteText')}</p>
    {:else}
      <p>{t('users.transferText', { name: acting.user.username })}</p>
    {/if}
    {#if actError}<div class="note error" role="alert">{actError.message}</div>{/if}
    {#snippet actions()}
      {#if acting?.kind === 'password' && generated}
        <button class="primary" onclick={close}>{t('common.close')}</button>
      {:else}
        <button onclick={close}>{t('common.cancel')}</button>
        {#if acting?.kind === 'role' || acting?.kind === 'password'}
          <button class="primary" type="submit" form="user-act" disabled={busy || (acting.kind === 'role' && !scopeOK(role, scope))}>{acting.kind === 'role' ? t('common.save') : t('users.resetSubmit')}</button>
        {:else if acting?.kind === 'owner'}
          <button class="primary" onclick={() => run()} disabled={busy}>{t('users.transferSubmit')}</button>
        {:else}
          <button class="primary danger-bg" onclick={() => run()} disabled={busy}>{acting?.kind === 'block' ? t('users.block') : t('common.delete')}</button>
        {/if}
      {/if}
    {/snippet}
  </Dialog>
{/if}

<style>
  section { margin-top: 16px; max-width: 900px; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 6px 8px; }
  td { padding: 6px 8px; border-top: 1px solid var(--border); }
  tr.off td:first-child { color: var(--muted); }
  td.blocked { color: var(--block); }
  .act { text-align: right; }
  td .badge { margin-left: 6px; }
  .create { margin-top: 14px; display: flex; flex-direction: column; gap: 8px; }
  .create p { margin: 0; }
  h3 { margin: 4px 0 0; }
  .form { display: flex; flex-direction: column; gap: 12px; min-width: 320px; }
  p { margin: 0 0 12px; max-width: 520px; }
  .form p { margin: 0; }
  section p.small { margin: 10px 0 0; }
</style>
