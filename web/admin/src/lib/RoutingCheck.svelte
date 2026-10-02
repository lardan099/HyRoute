<script lang="ts">
  // "Check a rule": which rule of the draft a connection matches, as the
  // server would decide it.
  import { api, asApiError, type AclDocument, type AclVerdict, type ApiError } from '../api';
  import { t } from '../i18n';

  let { serverId, acl, outbounds, onrule }: { serverId: number; acl: () => AclDocument; outbounds: string[]; onrule: (i: number) => void } = $props();

  let host = $state('');
  let ips = $state('');
  let proto = $state('tcp');
  let port = $state(443);
  let verdict = $state<AclVerdict | null>(null);
  let error = $state<ApiError | null>(null);
  let busy = $state(false);

  async function run(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    try {
      const request = { host: host.trim(), ips: ips.split(/[\s,]+/).filter(Boolean), proto, port: Number(port) };
      verdict = await api.routingCheck(serverId, { acl: acl(), outbounds, request });
      error = null;
      if (verdict.rule >= 0) onrule(verdict.rule);
    } catch (err) {
      verdict = null;
      error = asApiError(err);
    } finally {
      busy = false;
    }
  }
</script>

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
  <div class="row"><span class="grow small faint">{t('rc.hint')}</span><button class="primary" disabled={busy || !host.trim()}>{t('rc.run')}</button></div>
</form>

{#if error}<div class="note error small">{error.message}</div>{/if}
{#if verdict}
  <div class="verdict">
    <div>
      {#if verdict.rule >= 0}<button class="link" onclick={() => onrule(verdict!.rule)}>{t('rc.rule', { n: verdict.rule + 1 })}</button>{:else}{t('rc.noRule')}{/if}
      → <span class="pill {verdict.outbound.toLowerCase() === 'reject' ? 'block' : 'direct'}">{verdict.outbound}</span>
      {#if verdict.hijack}<span class="small muted"> → {verdict.hijack}</span>{/if}
    </div>
    <p class="small">{verdict.reason}</p>
    {#if verdict.unknown?.length}<p class="small warn">{t('rc.unknown', { list: verdict.unknown.map((i) => i + 1).join(', ') })}</p>{/if}
  </div>
{/if}

<style>
  .form { display: flex; flex-direction: column; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 5px; }
  label span { color: var(--muted); font-size: 12.5px; }
  .two { display: flex; gap: 10px; align-items: flex-start; flex-wrap: wrap; }
  .grow { flex: 1; min-width: 160px; }
  .proto { width: 90px; }
  .port { width: 100px; }
  .verdict { margin-top: 12px; padding: 10px; background: var(--surface-2); border-radius: var(--radius-sm); display: flex; flex-direction: column; gap: 6px; }
  .warn { color: var(--warn); }
  p { margin: 0; }
</style>
