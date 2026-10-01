<script lang="ts">
  // System settings of a server for Hysteria, read on demand over SSH.
  // Three kinds of congestion control are kept apart: Linux TCP (the
  // kernel's, for the server's own TCP), QUIC congestion control of
  // Hysteria (its config) and Brutal (the speed a client asks for).
  import { api, asApiError, type ApiError, type Job, type TuningState } from '../api';
  import { t } from '../i18n';

  let { serverId, writable, onstarted }: { serverId: number; writable: boolean; onstarted: (j: Job) => void } = $props();

  let st = $state<TuningState | null>(null);
  let error = $state<ApiError | null>(null);
  let loading = $state(false);
  let busy = $state(false);
  let chosen = $state<Record<string, boolean>>({});

  async function load() {
    loading = true;
    error = null;
    try {
      st = await api.tuning(serverId);
      // Offered: what is not set yet, and what HyRoute's file keeps.
      chosen = Object.fromEntries(st.settings.map((s) => [s.key, s.supported && (s.inFile || !s.done)]));
    } catch (e) {
      error = asApiError(e);
    } finally {
      loading = false;
    }
  }

  async function apply() {
    busy = true;
    error = null;
    try {
      onstarted(await api.startTuning(serverId, Object.keys(chosen).filter((k) => chosen[k])));
    } catch (e) {
      error = asApiError(e);
      busy = false;
    }
  }

  let picked = $derived(Object.values(chosen).filter(Boolean).length);
  let udp = $derived(st?.settings.filter((s) => s.group === 'udp') ?? []);
  let tcp = $derived(st?.settings.filter((s) => s.group === 'tcp') ?? []);
  const mib = (v: string) => (/^\d+$/.test(v) ? `${Math.round(Number(v) / 1048576 * 10) / 10} МиБ` : v);
  const label = (k: string) => t(('tune.key.' + k) as Parameters<typeof t>[0]);
</script>

<section class="card">
  <div class="row">
    <h2 class="grow">{t('tune.title')}</h2>
    <button class="ghost" onclick={load} disabled={loading}>{st ? t('tune.reload') : t('tune.read')}</button>
  </div>
  {#if !st && !error}
    <p class="muted small">{t('tune.intro')}</p>
  {/if}
  {#if error}<div class="note error small">{error.message}</div>{/if}

  {#if st}
    <p class="small faint">{st.kernel}</p>
    <div class="blocks">
      <div class="block">
        <h3>{t('tune.udpTitle')}</h3>
        <p class="hint">{t('tune.udpHint')}</p>
        {#each udp as s (s.key)}
          <label class="check">
            <input type="checkbox" bind:checked={chosen[s.key]} disabled={!s.supported || !writable} />
            <span>{label(s.key)}: <b>{mib(s.current)}</b>{#if !s.done}{' → ' + mib(s.want)}{:else}{' ✓'}{/if}</span>
          </label>
        {/each}
      </div>

      <div class="block">
        <h3>{t('tune.tcpTitle')}</h3>
        <p class="hint">{t('tune.tcpHint')}</p>
        {#each tcp as s (s.key)}
          <label class="check">
            <input type="checkbox" bind:checked={chosen[s.key]} disabled={!s.supported || !writable} />
            <span>{label(s.key)}: <b>{s.current || '—'}</b>{#if !s.done && s.supported}{' → ' + s.want}{:else if s.done}{' ✓'}{/if}</span>
          </label>
          {#if s.why}<p class="hint why">{s.why}</p>{/if}
        {/each}
        <p class="hint">{t('tune.available', { list: st.available.join(', ') || '—' })}</p>
      </div>

      <div class="block">
        <h3>{t('tune.quicTitle')}</h3>
        <p class="hint">{t('tune.quicHint')}</p>
        <p class="small">{t('tune.quicNow', { type: st.quic.type || t('tune.quicDefault'), profile: st.quic.profile || t('tune.quicProfileDefault') })}</p>
      </div>

      <div class="block">
        <h3>{t('tune.brutalTitle')}</h3>
        <p class="hint">{t('tune.brutalHint')}</p>
        <p class="small">
          {#if st.brutal.ignoreClient}{t('tune.brutalOff')}{:else}{t('tune.brutalNow', { up: st.brutal.up || t('tune.unlimited'), down: st.brutal.down || t('tune.unlimited') })}{/if}
        </p>
      </div>
    </div>

    {#if st.file}
      <details class="file">
        <summary class="small">{t('tune.file')}</summary>
        <pre class="mono small">{st.file}</pre>
      </details>
    {/if}
    {#if writable}
      <div class="row foot">
        <span class="hint grow">{t('tune.applyHint')}</span>
        <button class="primary" onclick={apply} disabled={busy || picked === 0}>{t('tune.apply')}</button>
      </div>
    {/if}
  {/if}
</section>

<style>
  .blocks { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 10px; }
  @media (max-width: 720px) { .blocks { grid-template-columns: 1fr; } }
  .block { border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 10px 12px; display: flex; flex-direction: column; gap: 6px; }
  h3 { margin: 0; font-size: 13.5px; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; margin: 0; }
  .why { padding-left: 26px; }
  .check { align-items: flex-start; font-size: 13px; }
  .file { margin-top: 10px; }
  pre { margin: 6px 0 0; padding: 8px 10px; background: var(--surface-2); border-radius: var(--radius-sm); overflow-x: auto; }
  .foot { margin-top: 12px; gap: 12px; align-items: center; }
  p { margin: 0; }
</style>
