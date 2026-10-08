<script lang="ts">
  // The audit log (owners and admins): who did what in the panel, newest
  // first, filtered by user, action, object and period, page by page.
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type AuditEntry, type Chain, type Server, type User } from '../api';
  import { locale, t, tOr, type Key } from '../i18n';
  import { go } from '../router.svelte';
  import { clock } from './format';

  let { servers }: { servers: Server[] } = $props();

  // The known actions by group; an unknown one is shown as it is stored.
  const groups: { key: Key; actions: string[] }[] = [
    { key: 'audit.gAuth', actions: ['login', 'logout', 'login_failed', 'setup', 'setup_failed', 'session_revoked', 'password_change_failed'] },
    {
      key: 'audit.gUsers',
      actions: ['user_created', 'user_password_changed', 'user_password_reset', 'user_role_changed', 'user_blocked', 'user_unblocked', 'user_deleted', 'owner_transferred'],
    },
    { key: 'audit.gServers', actions: ['server_created', 'server_updated', 'server_deleted', 'host_key_trusted', 'host_key_replaced', 'server.hop_interval', 'client.reveal'] },
    { key: 'audit.gJobs', actions: ['job_submitted', 'job_retried'] },
    { key: 'audit.gChains', actions: ['chain_created', 'chain_updated', 'chain_deleted', 'chain_force_delete'] },
    { key: 'audit.gPresets', actions: ['preset.create', 'preset.import', 'preset.clone', 'preset.rename', 'preset.delete'] },
    { key: 'audit.gPanel', actions: ['backup_created', 'backup_downloaded', 'master_key_checked', 'diag_downloaded'] },
  ];

  let users = $state<User[]>([]);
  let chains = $state<Chain[]>([]);
  let user = $state(0);
  let action = $state('');
  let target = $state('');
  let from = $state('');
  let to = $state('');
  let entries = $state<AuditEntry[]>([]);
  let next = $state(0);
  let loading = $state(false);
  let error = $state<ApiError | null>(null);
  // seq numbers the requests: only the latest one may show its answer.
  let seq = 0;

  // day turns a date of the picker into the local midnight it starts, or
  // (end) the one it ends.
  function day(v: string, end = false): string | undefined {
    if (!v) return undefined;
    const [y, m, d] = v.split('-').map(Number);
    return new Date(y, m - 1, d + (end ? 1 : 0)).toISOString();
  }

  async function load(more = false) {
    const my = ++seq;
    loading = true;
    error = null;
    try {
      const page = await api.audit({ user, action, target, from: day(from), to: day(to, true), before: more ? next : 0, limit: 100 });
      if (my !== seq) return;
      entries = more ? [...entries, ...page.entries] : page.entries;
      next = page.next;
    } catch (e) {
      if (my !== seq) return;
      if (!more) entries = [];
      error = asApiError(e);
    } finally {
      if (my === seq) loading = false;
    }
  }

  onMount(async () => {
    load();
    try {
      [users, chains] = await Promise.all([api.users(), api.chains()]);
    } catch {}
  });

  const actionName = (a: string) => tOr(`audit.a.${a}`, a);

  // jobOf reads "job=12 kind=deploy …" of a job entry.
  function jobOf(e: AuditEntry): { id: number; kind: string; rest: string } | null {
    const m = /^job=(\d+) kind=(\S+)\s*(.*)$/.exec(e.details);
    return m && e.action.startsWith('job_') ? { id: Number(m[1]), kind: m[2], rest: m[3] } : null;
  }

  // open goes to the page of a server or cascade the entry is about.
  function opener(target: string): (() => void) | null {
    const m = /^(server|chain)\/(\d+)$/.exec(target);
    if (!m) return null;
    const id = Number(m[2]);
    return m[1] === 'server' ? () => go('servers', id) : () => go('cascades', id);
  }
</script>

<div class="row bar">
  <select bind:value={user} onchange={() => load()} aria-label={t('audit.user')}>
    <option value={0}>{t('audit.allUsers')}</option>
    {#each users as u (u.id)}<option value={u.id}>{u.username}</option>{/each}
  </select>
  <select bind:value={action} onchange={() => load()} aria-label={t('audit.action')}>
    <option value="">{t('audit.allActions')}</option>
    {#each groups as g (g.key)}
      <optgroup label={t(g.key)}>
        <option value={g.actions.join(',')}>{t('audit.groupAll', { group: t(g.key) })}</option>
        {#each g.actions as a (a)}<option value={a}>{actionName(a)}</option>{/each}
      </optgroup>
    {/each}
  </select>
  <select bind:value={target} onchange={() => load()} aria-label={t('audit.object')}>
    <option value="">{t('audit.allObjects')}</option>
    <optgroup label={t('audit.gServers')}>
      <option value="server/">{t('audit.allServers')}</option>
      {#each servers as s (s.id)}<option value={'server/' + s.id}>{s.name}</option>{/each}
    </optgroup>
    <optgroup label={t('audit.gChains')}>
      <option value="chain/">{t('audit.allChains')}</option>
      {#each chains as c (c.id)}<option value={'chain/' + c.id}>{c.name}</option>{/each}
    </optgroup>
    <optgroup label={t('audit.gUsers')}>
      <option value="user/">{t('audit.allUsers')}</option>
      {#each users as u (u.id)}<option value={'user/' + u.id}>{u.username}</option>{/each}
    </optgroup>
    <optgroup label={t('audit.gPresets')}>
      <option value="preset/">{t('audit.allPresets')}</option>
    </optgroup>
  </select>
  <label class="date">{t('audit.from')} <input type="date" bind:value={from} onchange={() => load()} /></label>
  <label class="date">{t('audit.to')} <input type="date" bind:value={to} onchange={() => load()} /></label>
  <span class="grow"></span>
  <button disabled={loading} onclick={() => load()}>{t('logs.refresh')}</button>
</div>

{#if error}<div class="note error">{error.message}</div>{/if}

<div class="card list">
  <table>
    <thead>
      <tr>
        <th>{t('audit.time')}</th>
        <th>{t('audit.user')}</th>
        <th>{t('audit.action')}</th>
        <th>{t('audit.object')}</th>
        <th>{t('audit.details')}</th>
      </tr>
    </thead>
    <tbody>
      {#each entries as e (e.id)}
        {@const job = jobOf(e)}
        {@const open = opener(e.target)}
        <tr>
          <td class="nowrap faint">{new Date(e.time).toLocaleDateString(locale)} {clock(e.time)}</td>
          <td>{e.user || (e.userId ? t('audit.deletedUser', { id: e.userId }) : '—')}</td>
          <td class:fail={e.action.endsWith('_failed')}>{actionName(e.action)}</td>
          <td class="obj">
            {#if open && e.object}<button class="link" onclick={open}>{e.object}</button>{:else}{e.object || e.target}{/if}
          </td>
          <td class="details">
            {#if job}
              <button class="link" onclick={() => go('deployments', job.id)}>{tOr(`kind.${job.kind}`, job.kind)} #{job.id}</button>
              {job.rest}
            {:else}{e.details}{/if}
          </td>
        </tr>
      {:else}
        <tr><td colspan="5" class="faint">{loading ? t('overview.checking') : t('audit.empty')}</td></tr>
      {/each}
    </tbody>
  </table>
  {#if next}
    <div class="more"><button disabled={loading} onclick={() => load(true)}>{t('audit.more')}</button></div>
  {/if}
</div>
<p class="small faint">{t('audit.hint')}</p>

<style>
  .bar { margin-bottom: 12px; gap: 10px; }
  .date { display: inline-flex; align-items: center; gap: 6px; color: var(--muted); font-size: 12.5px; }
  .date input { background: var(--surface-2); border: 1px solid transparent; border-radius: var(--radius-sm); padding: 6px 9px; }
  .list { overflow-x: auto; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 6px 8px; white-space: nowrap; }
  td { padding: 6px 8px; border-top: 1px solid var(--border); vertical-align: top; font-size: 13px; }
  .nowrap { white-space: nowrap; }
  td.fail { color: var(--warn); }
  .obj { max-width: 220px; overflow-wrap: anywhere; }
  .details { overflow-wrap: anywhere; user-select: text; }
  .more { margin-top: 10px; text-align: center; }
  p { margin: 10px 0 0; }
</style>
