<script lang="ts">
  // Cascades: chains of an entry and an exit server. The list shows each
  // chain's servers, link state, latest check and egress; /cascades/<id>
  // is one chain.
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Chain, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import { canWrite, session } from '../session.svelte';
  import { go, route } from '../router.svelte';
  import { flag, stateTone } from '../lib/format';
  import { busy, deployed, linkStateText, linkTone, pendingEntry } from '../lib/chain';
  import ChainCreate from '../lib/ChainCreate.svelte';
  import ChainConfirm from '../lib/ChainConfirm.svelte';
  import ChainView from '../lib/ChainView.svelte';
  import Menu from '../lib/Menu.svelte';

  let list = $state<Chain[] | null>(null);
  let servers = $state<Server[]>([]);
  let error = $state<ApiError | null>(null);
  let creating = $state(false);
  let confirm = $state<{ chain: Chain; kind: 'delete' | 'unlink' } | null>(null);
  // notice: why the link of a chain just created did not start.
  let notice = $state<ApiError | null>(null);
  let writable = $derived(canWrite(session.user));
  let byId = $derived(Object.fromEntries(servers.map((s) => [s.id, s])));

  async function load() {
    try {
      list = await api.chains();
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
  }
  onMount(async () => {
    await load();
    try {
      servers = await api.servers();
    } catch {}
  });
  $effect(() => {
    if (!route.id) {
      notice = null;
      load();
    }
  });

  async function deploy(c: Chain) {
    try {
      const j = await api.linkChain(c.id);
      go('deployments', j.id);
    } catch (e) {
      error = asApiError(e);
    }
  }

  const ms = (n: number) => t('cascades.ms', { n });
</script>

{#if route.id}
  {#key route.id}<ChainView id={route.id} {notice} />{/key}
{:else}
  <div class="row head">
    <h1 class="grow">{t('nav.cascades')}</h1>
    {#if writable}<button class="primary" onclick={() => (creating = true)} disabled={servers.length < 2}>{t('cascades.create')}</button>{/if}
  </div>
  <p class="muted small intro">{t('cascades.intro')}</p>

  {#if error}<div class="note error">{error.message}</div>{/if}

  {#if list && list.length === 0}
    <div class="card empty"><p>{t('cascades.empty')}</p></div>
  {:else if list}
    <div class="list">
      {#each list as c (c.id)}
        {@const link = c.links[0]}
        <div class="card chain">
          <div class="row">
            <a class="name grow" href="/cascades/{c.id}" onclick={(e) => { if (e.ctrlKey || e.metaKey || e.shiftKey || e.button !== 0) return; e.preventDefault(); go('cascades', c.id); }}>{c.name}</a>
            {#if writable}
              <div class="acts">
                {#if !busy(c)}<button class="ghost" onclick={() => deploy(c)}>{deployed(c) ? t('cascades.refresh') : t('cascades.deploy')}</button>{/if}
                <Menu label={t('servers.more')}>
                  {#if deployed(c) && !busy(c)}<button onclick={() => (confirm = { chain: c, kind: 'unlink' })}>{t('cascades.unlink')}</button>{/if}
                  {#if !busy(c)}<button class="danger" onclick={() => (confirm = { chain: c, kind: 'delete' })}>{t('cascades.delete')}</button>{/if}
                </Menu>
              </div>
            {/if}
          </div>
          <div class="path">
            {#each c.nodes as n, i (n.serverId)}
              {#if i > 0}<span class="arrow" aria-hidden="true">→</span>{/if}
              <span class="node">{flag(byId[n.serverId]?.country ?? '')} {n.name}</span>
            {/each}
          </div>
          <div class="facts small">
            {#if link}<span><span class="dot {linkTone(link.state)}"></span> {linkStateText(link.state)}</span>{/if}
            {#if c.health}<span><span class="dot {stateTone(c.health)}"></span> {t('cascades.health')}: {t(`state.${c.health}` as Key)}</span>{/if}
            {#if link?.check?.handshakeMs}<span class="muted">{t('cascades.latency')}: {ms(link.check.handshakeMs)}</span>{/if}
            {#if c.egress}<span class="muted">{t('cascades.egress')}: <span class="mono">{c.egress}</span></span>{/if}
          </div>
          {#if link?.check?.reason && link.check.status !== 'healthy'}<div class="small reason">{link.check.reason}</div>{/if}
        </div>
      {/each}
    </div>
  {/if}
{/if}

{#if creating}
  <ChainCreate
    {servers}
    onclose={() => (creating = false)}
    oncreated={(c, job, linkError, tpl) => {
      creating = false;
      if (tpl?.entry) pendingEntry.set(c.id, { id: 'chain:' + c.id, name: tpl.name, description: t('ctpl.entryOffer'), acl: tpl.entry.acl, resolver: tpl.entry.resolver });
      if (job) go('deployments', job.id);
      else {
        notice = linkError;
        go('cascades', c.id);
      }
    }}
  />
{/if}

{#if confirm}
  <ChainConfirm
    chain={confirm.chain}
    kind={confirm.kind}
    onclose={() => (confirm = null)}
    ondone={(j) => {
      confirm = null;
      if (j) go('deployments', j.id);
      else load();
    }}
  />
{/if}

<style>
  .head { margin-bottom: 6px; }
  .intro { margin: 0 0 16px; max-width: 760px; }
  .empty p { margin: 0; color: var(--muted); }
  .list { display: flex; flex-direction: column; gap: 10px; }
  .chain { display: flex; flex-direction: column; gap: 6px; }
  .name { font-weight: 600; color: inherit; text-decoration: none; }
  .name:hover { color: var(--accent); }
  .acts { display: flex; gap: 2px; }
  .acts button { padding: 6px 8px; }
  .path { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .arrow { color: var(--muted); }
  .facts { display: flex; flex-wrap: wrap; gap: 14px; align-items: center; }
  .reason { color: var(--muted); }
</style>
