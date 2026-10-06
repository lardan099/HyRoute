<script lang="ts">
  // One cascade: its servers with the services on each, the link between
  // them (state, latest check, latency), the egress address, the check
  // history and what can be done with it.
  import { onDestroy, onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Chain, type LinkCheck, type RoutingTemplate, type Server } from '../api';
  import { t, type Key } from '../i18n';
  import { canForce, canWrite, session } from '../session.svelte';
  import { go } from '../router.svelte';
  import { flag, stateTone, when } from './format';
  import { busy, deployed, linkStateText, linkTone, pendingEntry } from './chain';
  import ChainConfirm from './ChainConfirm.svelte';
  import Dialog from './Dialog.svelte';
  import TemplateApplyDialog from './TemplateApplyDialog.svelte';

  let { id, notice = null }: { id: number; notice?: ApiError | null } = $props();

  let chain = $state<Chain | null>(null);
  let servers = $state<Record<number, Server>>({});
  let checks = $state<LinkCheck[]>([]);
  let error = $state<ApiError | null>(null);
  let confirm = $state<'delete' | 'unlink' | 'force' | null>(null);
  let editing = $state(false);
  let name = $state('');
  let notes = $state('');
  let editError = $state<ApiError | null>(null);
  let writable = $derived(canWrite(session.user));
  // unreachable: the servers «Удалить каскад» could not reach; owners and
  // admins may delete the cascade without them.
  let unreachable = $derived(chain && !busy(chain) ? (chain.unreachable ?? []) : []);
  let link = $derived(chain?.links[0] ?? null);
  let timer: ReturnType<typeof setInterval> | undefined;
  // gone: the view is destroyed before the reads of onMount ended.
  let gone = false;
  let checking = $state(false);
  // offer: the entry rules of the template the cascade was made from.
  let offer = $state<RoutingTemplate | null>(null);
  let offering = $state(false);

  // saveTemplate saves the cascade as a template file: the link's
  // settings and the entry's rules, no servers and no secrets. The notes
  // stay out (private); the admin may give the file a description.
  let tplOpen = $state(false);
  let tplDesc = $state('');
  async function saveTemplate() {
    try {
      const data = await api.chainTemplate(id);
      if (tplDesc.trim()) data.description = tplDesc.trim();
      tplOpen = false;
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `chain-${(chain?.name ?? String(id)).replace(/[^\p{L}\p{N}._-]+/gu, '-')}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      error = asApiError(e);
    }
  }

  async function checkNow() {
    checking = true;
    try {
      chain = await api.checkChain(id);
      checks = await api.chainChecks(id, 0, 50);
      error = null;
    } catch (e) {
      error = asApiError(e);
    } finally {
      checking = false;
    }
  }

  async function load() {
    try {
      chain = await api.chain(id);
      checks = await api.chainChecks(id, 0, 50);
      error = null;
    } catch (e) {
      error = asApiError(e);
    }
  }
  onMount(async () => {
    offer = pendingEntry.get(id) ?? null;
    await load();
    try {
      servers = Object.fromEntries((await api.servers()).map((s) => [s.id, s]));
    } catch {}
    // Checks come every monitor round; a running job changes the state.
    if (!gone) timer = setInterval(load, 15000);
  });
  onDestroy(() => {
    gone = true;
    clearInterval(timer);
  });

  async function deploy() {
    try {
      const j = await api.linkChain(id);
      go('deployments', j.id);
    } catch (e) {
      error = asApiError(e);
    }
  }

  function edit() {
    if (!chain) return;
    name = chain.name;
    notes = chain.notes;
    editError = null;
    editing = true;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    try {
      chain = await api.updateChain(id, name, notes);
      editing = false;
    } catch (err) {
      editError = asApiError(err);
    }
  }

  const ms = (n: number) => (n ? t('cascades.ms', { n }) : '—');
  const srv = (sid: number) => servers[sid];
</script>

<button class="ghost back" onclick={() => go('cascades')}>{t('cascades.back')}</button>

{#if notice}<div class="note error">{notice.message}</div>{/if}
{#if error}<div class="note error">{error.message}</div>{/if}

{#if chain}
  <div class="row head">
    <h1 class="grow">{chain.name}</h1>
    {#if writable}
      {#if !busy(chain)}
        <button class="primary" onclick={deploy}>{deployed(chain) ? t('cascades.refresh') : t('cascades.deploy')}</button>
        {#if deployed(chain)}<button onclick={checkNow} disabled={checking}>{t('cascades.check')}</button>{/if}
        {#if deployed(chain)}<button onclick={() => (confirm = 'unlink')}>{t('cascades.unlink')}</button>{/if}
      {/if}
      <button onclick={edit}>{t('cascades.rename')}</button>
      <button onclick={() => ((tplDesc = ''), (tplOpen = true))}>{t('ctpl.save')}</button>
      {#if !busy(chain)}<button class="danger" onclick={() => (confirm = 'delete')}>{t('cascades.delete')}</button>{/if}
    {/if}
  </div>
  {#if link?.state === 'stale'}<div class="note warn">{t('cascades.staleNote')}</div>{/if}
  {#if unreachable.length && writable}
    <div class="note warn row offer">
      <span class="grow">
        {t('cascades.unreachableNote', { names: unreachable.map((u) => `«${u.name}»`).join(', ') })}
        {#if !canForce(session.user)}{t('cascades.unreachableOwner')}{/if}
      </span>
      {#if canForce(session.user)}<button class="danger" onclick={() => (confirm = 'force')}>{t('cascades.forceDelete')}</button>{/if}
    </div>
  {/if}
  {#if offer && writable}
    <div class="note info row offer">
      <span class="grow">{t('ctpl.offer', { name: offer.name })}</span>
      <button class="primary" onclick={() => (offering = true)}>{t('ctpl.apply')}</button>
      <button class="ghost" onclick={() => (pendingEntry.delete(id), (offer = null))}>{t('ctpl.dismiss')}</button>
    </div>
  {/if}

  <div class="card schema">
    {#each chain.nodes as n, i (n.serverId)}
      {#if i > 0 && link}
        <div class="link">
          <span class="arrow" aria-hidden="true">→</span>
          <span><span class="dot {linkTone(link.state)}"></span> {linkStateText(link.state)}</span>
          {#if link.check}
            <span><span class="dot {stateTone(link.check.status)}"></span> {t(`state.${link.check.status}` as Key)}</span>
            <span class="small muted">{t('cascades.latency')}: {ms(link.check.handshakeMs)}</span>
            {#if link.check.reason}<span class="small reason">{link.check.reason}</span>{/if}
          {:else if deployed(chain)}
            <span class="small faint">{t('cascades.notChecked')}</span>
          {/if}
          {#if link.params.up || link.params.noUdp || link.params.checkTarget}
            <span class="small faint">
              {#if link.params.up}{link.params.up} / {link.params.down}{/if}
              {#if link.params.noUdp} · {t('cascades.noUdpShort')}{/if}
              {#if link.params.checkTarget} · {t('cascades.target')}: {link.params.checkTarget}{/if}
            </span>
          {/if}
        </div>
      {/if}
      <div class="node">
        <div class="small muted">{t(`srvrole.${n.role}` as Key)}</div>
        <button class="link-btn name" onclick={() => go('servers', n.serverId)}>{flag(srv(n.serverId)?.country ?? '')} {n.name}</button>
        {#if srv(n.serverId)}<div class="small mono faint">{srv(n.serverId).host}</div>{/if}
        <ul class="svc small">
          <li><span class="dot {srv(n.serverId) ? stateTone(srv(n.serverId).state) : ''}"></span> {t('cascades.server')}</li>
          {#if i === 0 && deployed(chain)}
            <li><span class="dot {link?.check ? (link.check.service === 'active' ? 'ok' : 'bad') : ''}"></span> {t('cascades.client')}</li>
          {/if}
        </ul>
      </div>
    {/each}
  </div>

  <div class="facts small">
    {#if chain.egress}<span>{t('cascades.egress')}: <span class="mono">{chain.egress}</span></span>{/if}
    {#if chain.notes}<span class="notes">{chain.notes}</span>{/if}
  </div>

  {#if deployed(chain)}
    <h2>{t('cascades.checks')}</h2>
    {#if checks.length === 0}
      <p class="muted small">{t('cascades.checksEmpty')}</p>
    {:else}
      <div class="card table">
        <table>
          <thead>
            <tr><th>{t('cascades.when')}</th><th>{t('cascades.health')}</th><th>{t('cascades.latency')}</th><th>TCP</th><th>{t('cascades.reason')}</th></tr>
          </thead>
          <tbody>
            {#each checks as c (c.at)}
              <tr>
                <td class="nowrap">{when(c.at)}</td>
                <td class="nowrap"><span class="dot {stateTone(c.status)}"></span> {t(`state.${c.status}` as Key)}</td>
                <td>{ms(c.handshakeMs)}</td>
                <td>{ms(c.tcpMs)}</td>
                <td class="small">{c.reason}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
{/if}

{#if offering && offer && chain && srv(chain.nodes[0].serverId)}
  <TemplateApplyDialog tpl={offer} servers={[srv(chain.nodes[0].serverId)]} onclose={() => (offering = false)} onapplied={() => pendingEntry.delete(id)} />
{/if}

{#if confirm && chain}
  <ChainConfirm
    {chain}
    kind={confirm}
    onclose={() => (confirm = null)}
    ondone={(j) => {
      confirm = null;
      if (j) go('deployments', j.id);
      else go('cascades');
    }}
  />
{/if}

{#if tplOpen}
  <Dialog title={t('ctpl.save')} onclose={() => (tplOpen = false)}>
    <form id="chain-tpl" class="form" onsubmit={(e) => (e.preventDefault(), saveTemplate())}>
      <p class="muted">{t('ctpl.saveNote')}</p>
      <label>
        <span>{t('ctpl.description')}</span>
        <textarea rows="3" maxlength="4000" bind:value={tplDesc}></textarea>
      </label>
    </form>
    {#snippet actions()}
      <button type="button" onclick={() => (tplOpen = false)}>{t('common.cancel')}</button>
      <button type="submit" form="chain-tpl" class="primary">{t('ctpl.saveFile')}</button>
    {/snippet}
  </Dialog>
{/if}

{#if editing}
  <Dialog title={t('cascades.rename')} onclose={() => (editing = false)}>
    <form id="chain-edit" class="form" onsubmit={save}>
      <label>
        <span>{t('cascades.name')}</span>
        <input type="text" maxlength="64" bind:value={name} required />
      </label>
      <label>
        <span>{t('cascades.notes')}</span>
        <textarea rows="3" bind:value={notes}></textarea>
      </label>
      {#if editError}<div class="note error">{editError.message}</div>{/if}
    </form>
    {#snippet actions()}
      <button type="button" onclick={() => (editing = false)}>{t('common.cancel')}</button>
      <button type="submit" form="chain-edit" class="primary">{t('common.save')}</button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .back { margin-bottom: 8px; padding-left: 0; }
  .head { margin-bottom: 12px; gap: 6px; }
  .schema { display: flex; align-items: stretch; gap: 12px; flex-wrap: wrap; }
  .node { flex: 1; min-width: 180px; display: flex; flex-direction: column; gap: 3px; }
  .link { flex: 1; min-width: 180px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 3px; text-align: center; }
  .arrow { font-size: 26px; color: var(--muted); line-height: 1; }
  .reason { color: var(--muted); max-width: 260px; }
  .link-btn { background: none; border: 0; padding: 0; text-align: left; font: inherit; color: inherit; cursor: pointer; }
  .name { font-weight: 600; font-size: 15px; }
  .name:hover { color: var(--accent); }
  .svc { list-style: none; padding: 0; margin: 6px 0 0; display: flex; flex-direction: column; gap: 3px; }
  .facts { display: flex; flex-wrap: wrap; gap: 16px; margin: 12px 0; }
  .notes { white-space: pre-wrap; color: var(--muted); }
  h2 { font-size: 15px; margin: 18px 0 8px; }
  .table { padding: 6px 8px; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 8px; }
  td { padding: 8px; border-top: 1px solid var(--border); vertical-align: top; }
  .nowrap { white-space: nowrap; }
  .form { display: flex; flex-direction: column; gap: 12px; min-width: min(460px, 80vw); }
  .form label { display: flex; flex-direction: column; gap: 5px; }
  .form label span { color: var(--muted); font-size: 12.5px; }
  .note { margin: 0 0 12px; }
  .offer { gap: 8px; }
</style>
