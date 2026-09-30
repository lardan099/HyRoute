<script lang="ts">
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import { canWrite, session } from '../session.svelte';
  import Dialog from '../lib/Dialog.svelte';
  import ServerDialog from '../lib/ServerDialog.svelte';
  import CheckDialog from '../lib/CheckDialog.svelte';
  import { flag, stateTone } from '../lib/format';

  let list = $state<Server[] | null>(null);
  let error = $state<ApiError | null>(null);
  let editing = $state<Server | null | undefined>(undefined); // undefined: closed, null: new
  let deleting = $state<Server | null>(null);
  let checking = $state<Server | null>(null);
  let deleteError = $state<ApiError | null>(null);
  let writable = $derived(canWrite(session.user));

  async function load() {
    try {
      list = await api.servers();
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
  }
  onMount(load);

  async function remove() {
    if (!deleting) return;
    try {
      await api.deleteServer(deleting.id);
      deleting = null;
      await load();
    } catch (e) {
      deleteError = asApiError(e);
    }
  }
</script>

<div class="row head">
  <h1 class="grow">{t('nav.servers')}</h1>
  {#if writable}<button class="primary" onclick={() => (editing = null)}>{t('servers.add')}</button>{/if}
</div>

{#if error}<div class="note error">{error.message}</div>{/if}

{#if list && list.length === 0}
  <div class="card empty">
    <p>{t('servers.empty')}</p>
  </div>
{:else if list}
  <div class="card table">
    <table>
      <thead>
        <tr>
          <th>{t('servers.name')}</th>
          <th>{t('servers.host')}</th>
          <th>{t('servers.role')}</th>
          <th>{t('servers.state')}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each list as s (s.id)}
          <tr>
            <td>
              <div class="name">{flag(s.country)} {s.name}</div>
              {#if s.location || s.tags.length}
                <div class="sub small muted">
                  {s.location}
                  {#each s.tags as tag (tag)}<span class="badge">{tag}</span>{/each}
                </div>
              {/if}
            </td>
            <td class="mono">{s.sshUser}@{s.host}{s.sshPort !== 22 ? ':' + s.sshPort : ''}</td>
            <td>{t(`srvrole.${s.role}` as Key)}</td>
            <td>
              <span class="dot {stateTone(s.state)}"></span> {t(`state.${s.state}` as Key)}
              {#if !s.hostKey}<div class="small faint">{t('servers.keyNotConfirmed')}</div>{/if}
            </td>
            <td class="act">
              {#if writable}
                <button class="ghost" onclick={() => (checking = s)}>{t('check.button')}</button>
                <button class="ghost" onclick={() => (editing = s)}>{t('common.edit')}</button>
                <button class="ghost danger" onclick={() => ((deleting = s), (deleteError = null))}>{t('common.delete')}</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if editing !== undefined}
  <ServerDialog
    server={editing}
    onclose={() => (editing = undefined)}
    onsaved={() => {
      editing = undefined;
      load();
    }}
  />
{/if}

{#if checking}
  <CheckDialog server={checking} onclose={() => (checking = null)} onchanged={load} />
{/if}

{#if deleting}
  <Dialog title={t('servers.deleteTitle')} onclose={() => (deleting = null)}>
    <p>{t('servers.deleteText', { name: deleting.name })}</p>
    {#if deleteError}<div class="note error">{deleteError.message}</div>{/if}
    {#snippet actions()}
      <button onclick={() => (deleting = null)}>{t('common.cancel')}</button>
      <button class="primary danger-bg" onclick={remove}>{t('common.delete')}</button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .head { margin-bottom: 16px; }
  .empty p { margin: 0; color: var(--muted); }
  .table { padding: 6px 8px; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 8px; }
  td { padding: 10px 8px; border-top: 1px solid var(--border); vertical-align: middle; }
  .name { font-weight: 600; }
  .sub { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-top: 2px; }
  .act { text-align: right; white-space: nowrap; }
  p { margin: 0; }
  :global(button.danger-bg) { background: var(--block); }
</style>
