<script lang="ts">
  // «Проверить правило» along a cascade (P4-08): the entry's rules, and
  // while they send the request into the cascade, the next server's, to
  // the server it leaves from for the internet.
  import { api, asApiError, type ApiError, type RouteTrace as Trace } from '../api';
  import { t } from '../i18n';
  import RouteTrace from './RouteTrace.svelte';

  let { id }: { id: number } = $props();

  let host = $state('');
  let ips = $state('');
  let proto = $state('tcp');
  let port = $state(443);
  let trace = $state<Trace | null>(null);
  let error = $state<ApiError | null>(null);
  let busy = $state(false);

  async function run(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    try {
      trace = await api.routeChain(id, { host: host.trim(), ips: ips.split(/[\s,]+/).filter(Boolean), proto, port: Number(port) });
      error = null;
    } catch (err) {
      trace = null;
      error = asApiError(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="card">
  <p class="small muted hint">{t('cascades.routeHint')}</p>
  <form class="form" onsubmit={run}>
    <div class="two">
      <label class="grow"><span>{t('rc.host')}</span><input type="text" bind:value={host} placeholder="www.example.com" spellcheck="false" required /></label>
      <label class="proto">
        <span>{t('rt.proto')}</span>
        <select bind:value={proto}><option value="tcp">TCP</option><option value="udp">UDP</option></select>
      </label>
      <label class="port"><span>{t('rt.port')}</span><input type="number" min="1" max="65535" bind:value={port} required /></label>
    </div>
    <label><span>{t('rc.ips')}</span><input type="text" bind:value={ips} placeholder={t('rc.ipsPh')} spellcheck="false" /></label>
    <div class="row"><span class="grow"></span><button class="primary" disabled={busy || !host.trim()}>{t('cascades.routeRun')}</button></div>
  </form>
  {#if error}<div class="note error small">{error.message}</div>{/if}
  {#if trace}<div class="result"><RouteTrace {trace} /></div>{/if}
</div>

<style>
  .hint { margin: 0 0 10px; max-width: 760px; }
  .form { display: flex; flex-direction: column; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 5px; }
  label span { color: var(--muted); font-size: 12.5px; }
  .two { display: flex; gap: 10px; align-items: flex-start; flex-wrap: wrap; }
  .grow { flex: 1; min-width: 160px; }
  .proto { width: 90px; }
  .port { width: 100px; }
  .result { margin-top: 12px; padding: 10px; background: var(--surface-2); border-radius: var(--radius-sm); }
  .note { margin: 10px 0 0; }
</style>
