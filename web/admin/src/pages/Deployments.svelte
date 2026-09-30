<script lang="ts">
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Job, type Server } from '../api';
  import { t, tOr, type Key } from '../i18n';
  import { go, route } from '../router.svelte';
  import { duration, jobTone, when } from '../lib/format';
  import JobView from '../lib/JobView.svelte';

  let list = $state<Job[] | null>(null);
  let servers = $state<Record<number, Server>>({});
  let error = $state<ApiError | null>(null);

  async function load() {
    try {
      const [js, ss] = await Promise.all([api.jobs(), api.servers()]);
      list = js;
      servers = Object.fromEntries(ss.map((s) => [s.id, s]));
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
  }
  onMount(load);

  const kindName = (k: string) => tOr(`kind.${k}`, k);
</script>

{#if route.id}
  <button class="link back" onclick={() => (go('deployments'), load())}>← {t('nav.deployments')}</button>
  {#key route.id}
    <JobView id={route.id} {servers} />
  {/key}
{:else}
  <h1>{t('nav.deployments')}</h1>
  {#if error}<div class="note error">{error.message}</div>{/if}
  {#if list && list.length === 0}
    <div class="card empty"><p>{t('jobs.empty')}</p></div>
  {:else if list}
    <div class="card table">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>{t('jobs.kind')}</th>
            <th>{t('jobs.server')}</th>
            <th>{t('jobs.state')}</th>
            <th>{t('jobs.started')}</th>
            <th>{t('jobs.duration')}</th>
          </tr>
        </thead>
        <tbody>
          {#each list as j (j.id)}
            <tr class="click" onclick={() => go('deployments', j.id)}>
              <td class="mono">{j.id}</td>
              <td>{kindName(j.kind)}</td>
              <td>{servers[j.serverId]?.name ?? (j.serverId ? '#' + j.serverId : '—')}</td>
              <td><span class="dot {jobTone(j.state)}"></span> {t(`jstate.${j.state}` as Key)}</td>
              <td>{when(j.startedAt ?? j.createdAt)}</td>
              <td>{duration(j.startedAt, j.finishedAt)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<style>
  h1 { margin-bottom: 16px; }
  .back { margin-bottom: 12px; }
  .empty p { margin: 0; color: var(--muted); }
  .table { padding: 6px 8px; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 8px; }
  td { padding: 10px 8px; border-top: 1px solid var(--border); }
  tr.click { cursor: pointer; }
  tr.click:hover td { background: var(--surface-2); }
</style>
