<script lang="ts">
  import { untrack } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import { api, asApiError, batchActions, batchPerm, type ApiError, type BatchAction, type Server, type ServerRole, type ServerState } from '../api';
  import { t, type Key } from '../i18n';
  import { can, canOn } from '../session.svelte';
  import Dialog from '../lib/Dialog.svelte';
  import ServerDialog from '../lib/ServerDialog.svelte';
  import CheckDialog from '../lib/CheckDialog.svelte';
  import DeployDialog from '../lib/DeployDialog.svelte';
  import Menu from '../lib/Menu.svelte';
  import BatchDialog from '../lib/BatchDialog.svelte';
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
  // adding: the role adds servers (with one of the user's tags when the
  // scope is narrower: the controller checks it).
  let adding = $derived(can('deploy'));

  // Search, filters and the selection a batch starts for (P4-07). The
  // selection keeps the servers a filter hides; «выбрать все найденные»
  // adds what the filters show.
  let q = $state('');
  let fState = $state<ServerState | ''>('');
  let fTag = $state('');
  let fRole = $state<ServerRole | ''>('');
  const selected = new SvelteSet<number>();
  let batching = $state<BatchAction | null>(null);
  const states: ServerState[] = ['healthy', 'degraded', 'offline', 'needs_attention', 'deploying', 'new'];
  const roles: ServerRole[] = ['standalone', 'entry', 'relay', 'exit'];
  let tags = $derived([...new Set((list ?? []).flatMap((s) => s.tags.map((x) => x.toLowerCase())))].sort());
  let found = $derived(
    (list ?? []).filter((s) => {
      const text = q.trim().toLowerCase();
      const hay = [s.name, s.host, s.location, ...s.tags].join(' ').toLowerCase();
      return (!text || hay.includes(text)) && (!fState || s.state === fState) && (!fRole || s.role === fRole) && (!fTag || s.tags.some((x) => x.toLowerCase() === fTag));
    }),
  );
  let filtered = $derived(!!q.trim() || !!fState || !!fTag || !!fRole);
  let chosen = $derived((list ?? []).filter((s) => selected.has(s.id)));
  let allFound = $derived(found.length > 0 && found.every((s) => selected.has(s.id)));
  // batches: the role may start some batch; the servers' perms decide
  // each action.
  let batches = $derived(can('config') || can('deploy'));
  const allowed = (a: BatchAction) => chosen.length > 0 && chosen.every((s) => canOn(s, batchPerm(a)));

  function toggleFound() {
    if (allFound) for (const s of found) selected.delete(s.id);
    else for (const s of found) selected.add(s.id);
  }

  function toggle(id: number) {
    if (selected.has(id)) selected.delete(id);
    else selected.add(id);
  }

  function resetFilters() {
    [q, fState, fTag, fRole] = ['', '', '', ''];
  }

  async function load() {
    try {
      list = await api.servers();
      error = null;
      for (const id of [...selected]) if (!list.some((s) => s.id === id)) selected.delete(id);
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
  {#if adding}<button class="primary" onclick={() => (editing = null)}>{t('servers.add')}</button>{/if}
</div>

{#if error}<div class="note error">{error.message}</div>{/if}

{#if list && list.length === 0}
  <div class="card empty">
    <p>{adding ? t('servers.empty') : t('servers.emptyReadonly')}</p>
  </div>
{:else if list}
  <div class="filters">
    <input class="search" type="search" placeholder={t('srv.search')} aria-label={t('srv.search')} bind:value={q} />
    <select bind:value={fState} aria-label={t('servers.state')}>
      <option value="">{t('srv.allStates')}</option>
      {#each states as st (st)}<option value={st}>{t(`state.${st}` as Key)}</option>{/each}
    </select>
    {#if tags.length}
      <select bind:value={fTag} aria-label={t('servers.tags')}>
        <option value="">{t('srv.allTags')}</option>
        {#each tags as tag (tag)}<option value={tag}>{tag}</option>{/each}
      </select>
    {/if}
    <select bind:value={fRole} aria-label={t('servers.role')}>
      <option value="">{t('srv.allRoles')}</option>
      {#each roles as r (r)}<option value={r}>{t(`srvrole.${r}` as Key)}</option>{/each}
    </select>
    {#if filtered}
      <span class="small muted">{t('srv.found', { n: found.length, total: list.length })}</span>
      <button class="link small" onclick={resetFilters}>{t('srv.reset')}</button>
    {/if}
  </div>

  {#if batches && selected.size > 0}
    <div class="selbar card">
      <span class="small"><b>{t('srv.selected', { n: selected.size })}</b></span>
      {#if !allFound && found.length}<button class="link small" onclick={toggleFound}>{t('srv.selectFound', { n: found.length })}</button>{/if}
      <button class="link small" onclick={() => selected.clear()}>{t('srv.clearSelection')}</button>
      <span class="grow"></span>
      <span class="small muted">{t('srv.batchFor')}</span>
      {#each batchActions as a (a)}
        <button class="ghost" disabled={!allowed(a)} title={allowed(a) ? undefined : t('srv.noPermSome')} onclick={() => (batching = a)}>{t(`batch.action.${a}` as Key)}</button>
      {/each}
    </div>
  {/if}

  {#if found.length === 0}
    <div class="card empty"><p>{t('srv.nothingFound')}</p></div>
  {:else}
  <div class="card table">
    <table>
      <thead>
        <tr>
          {#if batches}
            <th class="pick"><input type="checkbox" checked={allFound} onchange={toggleFound} aria-label={t('srv.selectFound', { n: found.length })} title={t('srv.selectFound', { n: found.length })} /></th>
          {/if}
          <th>{t('servers.name')}</th>
          <th>{t('servers.host')}</th>
          <th>{t('servers.role')}</th>
          <th>{t('servers.state')}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each found as s (s.id)}
          <tr class:sel={selected.has(s.id)}>
            {#if batches}
              <td class="pick"><input type="checkbox" checked={selected.has(s.id)} onchange={() => toggle(s.id)} aria-label={t('srv.selectRow', { name: s.name })} /></td>
            {/if}
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
              {#if canOn(s, 'deploy') || canOn(s, 'credentials')}<div class="acts">
                {#if canOn(s, 'deploy')}
                  <button class="ghost" onclick={() => deploy(s)}>{t('deploy.button')}</button>
                  <button class="ghost" onclick={() => importServer(s)}>{t('import.button')}</button>
                {/if}
                <Menu label={t('servers.more')}>
                  {#if canOn(s, 'credentials')}<button onclick={() => ((checking = s), (then = null))}>{t('check.button')}</button>{/if}
                  {#if canOn(s, 'deploy')}<button onclick={() => preflight(s)}>{t('preflight.button')}</button>{/if}
                  {#if canOn(s, 'credentials')}<button onclick={() => (editing = s)}>{t('common.edit')}</button>{/if}
                  {#if canOn(s, 'deploy')}<button class="danger" onclick={() => ((deleting = s), (deleteError = null))}>{t('common.delete')}</button>{/if}
                </Menu>
              </div>{/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {/if}
{/if}

{#if batching}
  <BatchDialog action={batching} servers={chosen} onclose={() => (batching = null)} oncreated={(b) => ((batching = null), selected.clear(), go('batches', b.id))} />
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
  .filters { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
  .search { flex: 1; min-width: 220px; max-width: 420px; }
  .selbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 10px 14px; margin-bottom: 12px; }
  .selbar button.ghost { padding: 6px 10px; }
  th.pick, td.pick { width: 28px; padding-right: 0; }
  tr.sel td { background: var(--accent-soft); }
</style>
