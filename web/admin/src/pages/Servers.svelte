<script lang="ts">
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import { canWrite, session } from '../session.svelte';
  import Dialog from '../lib/Dialog.svelte';
  import ServerDialog from '../lib/ServerDialog.svelte';
  import CheckDialog from '../lib/CheckDialog.svelte';
  import DeployDialog from '../lib/DeployDialog.svelte';
  import { flag, stateTone } from '../lib/format';
  import { go } from '../router.svelte';

  let list = $state<Server[] | null>(null);
  let error = $state<ApiError | null>(null);
  let editing = $state<Server | null | undefined>(undefined); // undefined: closed, null: new
  let deleting = $state<Server | null>(null);
  let checking = $state<Server | null>(null);
  // checkThenDeploy: the check dialog is the first step of a deploy.
  let checkThenDeploy = $state(false);
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
  onMount(load);

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
      checkThenDeploy = true;
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
            <td class="state">
              <span class="dot {stateTone(s.state)}"></span> {t(`state.${s.state}` as Key)}
              {#if !s.hostKey}<div class="small faint">{t('servers.keyNotConfirmed')}</div>{/if}
            </td>
            <td class="act">
              {#if writable}<div class="acts">
                <button class="ghost" onclick={() => deploy(s)}>{t('deploy.button')}</button>
                <button class="ghost" onclick={() => ((checking = s), (checkThenDeploy = false))}>{t('check.button')}</button>
                <button class="ghost" onclick={() => preflight(s)}>{t('preflight.button')}</button>
                <button class="ghost" onclick={() => (editing = s)}>{t('common.edit')}</button>
                <button class="ghost danger" onclick={() => ((deleting = s), (deleteError = null))}>{t('common.delete')}</button>
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
    oncontinue={checkThenDeploy
      ? () => {
          deploying = checking;
          checking = null;
        }
      : undefined}
    continueLabel={t('deploy.continue')}
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

<style>
  .head { margin-bottom: 16px; }
  .empty p { margin: 0; color: var(--muted); }
  .table { padding: 6px 8px; overflow-x: auto; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 8px; }
  td { padding: 10px 8px; border-top: 1px solid var(--border); vertical-align: middle; }
  .name { font-weight: 600; }
  .sub { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-top: 2px; }
  .state { white-space: nowrap; }
  .acts { display: flex; justify-content: flex-end; gap: 2px; }
  .acts button { padding: 6px 8px; }
  p { margin: 0; }
  :global(button.danger-bg) { background: var(--block); }
</style>
