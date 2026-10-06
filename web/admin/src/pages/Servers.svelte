<script lang="ts">
  import { untrack } from 'svelte';
  import { api, asApiError, type ApiError, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import { canWrite, session } from '../session.svelte';
  import Dialog from '../lib/Dialog.svelte';
  import ServerDialog from '../lib/ServerDialog.svelte';
  import CheckDialog from '../lib/CheckDialog.svelte';
  import DeployDialog from '../lib/DeployDialog.svelte';
  import Menu from '../lib/Menu.svelte';
  import ServerPage from './ServerPage.svelte';
  import { flag, stateTone } from '../lib/format';
  import { go, route } from '../router.svelte';

  let list = $state<Server[] | null>(null);
  let error = $state<ApiError | null>(null);
  let editing = $state<Server | null | undefined>(undefined); // undefined: closed, null: new
  let deleting = $state<Server | null>(null);
  let checking = $state<Server | null>(null);
  // then: the check dialog is the first step of a deploy or an import.
  let then = $state<'deploy' | 'import' | null>(null);
  let deploying = $state<Server | null>(null);
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
  // The list loads when it is shown (also on the way back from a server).
  $effect(() => {
    if (route.id === null) untrack(load);
  });

  async function preflight(s: Server) {
    try {
      const j = await api.startPreflight(s.id);
      go('deployments', j.id);
    } catch (e) {
      error = asApiError(e);
    }
  }

  // deploy opens the deploy form; a server whose SSH key is not confirmed
  // yet is checked first.
  function deploy(s: Server) {
    if (s.hostKey) {
      deploying = s;
    } else {
      checking = s;
      then = 'deploy';
    }
  }

  // importServer starts the import (it only reads the server); a server
  // whose SSH key is not confirmed yet is checked first.
  function importServer(s: Server) {
    if (s.hostKey) {
      startImport(s.id);
    } else {
      checking = s;
      then = 'import';
    }
  }

  async function startImport(id: number) {
    try {
      const j = await api.startImport(id);
      go('deployments', j.id);
    } catch (e) {
      error = asApiError(e);
    }
  }

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

{#if route.id}
  {#key route.id}<ServerPage id={route.id} />{/key}
{:else}
<div class="row head">
  <h1 class="grow">{t('nav.servers')}</h1>
  {#if writable}<button class="primary" onclick={() => (editing = null)}>{t('servers.add')}</button>{/if}
</div>

{#if error}<div class="note error">{error.message}</div>{/if}

{#if list && list.length === 0}
  <div class="card empty">
    <p>{writable ? t('servers.empty') : t('servers.emptyReadonly')}</p>
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
              <a class="name" href="/servers/{s.id}" onclick={(e) => { if (e.ctrlKey || e.metaKey || e.shiftKey || e.button !== 0) return; e.preventDefault(); go('servers', s.id); }}>{flag(s.country)} {s.name}</a>
              {#if s.location || s.tags.length}
                <div class="sub small muted">
                  {s.location}
                  {#each s.tags as tag (tag)}<span class="badge">{tag}</span>{/each}
                </div>
              {/if}
            </td>
            <td class="mono">{s.sshUser}@{s.host}{s.sshPort !== 22 ? ':' + s.sshPort : ''}</td>
            <td>{t(`srvrole.${s.role}` as Key)}</td>
            <td class="state">
              <span class="dot {stateTone(s.state)}"></span> {t(`state.${s.state}` as Key)}
              {#if !s.hostKey}<div class="small faint">{t('servers.keyNotConfirmed')}</div>{/if}
            </td>
            <td class="act">
              {#if writable}<div class="acts">
                <button class="ghost" onclick={() => deploy(s)}>{t('deploy.button')}</button>
                <button class="ghost" onclick={() => importServer(s)}>{t('import.button')}</button>
                <Menu label={t('servers.more')}>
                  <button onclick={() => ((checking = s), (then = null))}>{t('check.button')}</button>
                  <button onclick={() => preflight(s)}>{t('preflight.button')}</button>
                  <button onclick={() => (editing = s)}>{t('common.edit')}</button>
                  <button class="danger" onclick={() => ((deleting = s), (deleteError = null))}>{t('common.delete')}</button>
                </Menu>
              </div>{/if}
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
    onsaved={(s, andDeploy) => {
      editing = undefined;
      load();
      if (andDeploy) deploy(s);
    }}
  />
{/if}

{#if checking}
  <CheckDialog
    server={checking}
    onclose={() => (checking = null)}
    onchanged={load}
    oncontinue={then
      ? () => {
          const s = checking;
          checking = null;
          if (s && then === 'deploy') deploying = s;
          else if (s) startImport(s.id);
        }
      : undefined}
    continueLabel={then === 'import' ? t('import.continue') : t('deploy.continue')}
  />
{/if}

{#if deploying}
  <DeployDialog server={deploying} onclose={() => (deploying = null)} onstarted={(j) => go('deployments', j.id)} />
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

{/if}

<style>
  .head { margin-bottom: 16px; }
  .empty p { margin: 0; color: var(--muted); }
  .table { padding: 6px 8px; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 8px; }
  td { padding: 10px 8px; border-top: 1px solid var(--border); vertical-align: middle; }
  .name { font-weight: 600; color: inherit; text-decoration: none; display: block; }
  .name:hover { color: var(--accent); }
  .sub { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-top: 2px; }
  .state { white-space: nowrap; }
  .acts { display: flex; justify-content: flex-end; gap: 2px; }
  .acts button { padding: 6px 8px; }
  p { margin: 0; }
  :global(button.danger-bg) { background: var(--block); }
</style>
