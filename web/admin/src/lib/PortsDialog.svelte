<script lang="ts">
  // The ports of a server: one port, or ports and ranges for port hopping
  // (Hysteria listens on the lowest and redirects the others to it), the
  // addresses it listens on, and the hop interval of the client links.
  // New ports go through an apply job; the interval is saved at once. The
  // controller checks the ports again, and the job checks the server.
  import { untrack } from 'svelte';
  import { api, asApiError, type ApiError, type Job, type Server, type ServerConfig } from '../api';
  import { t } from '../i18n';
  import Dialog from './Dialog.svelte';

  let { server, config, onclose, onstarted, onsaved }: {
    server: Server;
    config: ServerConfig;
    onclose: () => void;
    onstarted: (j: Job) => void;
    onsaved: () => void;
  } = $props();

  const maxEntries = 16;
  const defaultRange = '20000-50000';

  // split is the host and the port list of a listen address.
  function split(listen: string): [string, string[]] {
    let host = '';
    let ports = listen;
    if (listen.startsWith('[')) {
      const end = listen.indexOf(']');
      host = listen.slice(0, end + 1);
      ports = listen.slice(end + 2);
    } else {
      const i = listen.indexOf(':');
      host = listen.slice(0, i);
      ports = listen.slice(i + 1);
    }
    if (host === '[::]') host = '';
    return [host, ports.split(',').map((p) => p.trim()).filter(Boolean)];
  }

  // The form starts from the config and the server as the dialog opened.
  const [curHost, curPorts] = untrack(() => split(config.meta.listen || ':' + (config.meta.ports || '443')));
  const curInterval = untrack(() => server.hopInterval || 0);
  let entries = $state<string[]>(curPorts.length ? [...curPorts] : ['443']);
  let host = $state(curHost);
  let interval = $state<number | null>(curInterval || null);
  let busy = $state(false);
  let error = $state<ApiError | null>(null);

  type Range = { from: number; to: number; text: string };

  // parsed mirrors the controller's check, for an answer while typing.
  let parsed = $derived.by((): { ranges: Range[]; problem: string } => {
    const ranges: Range[] = [];
    for (const raw of entries) {
      const e = raw.trim();
      if (!e) continue;
      const m = /^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/.exec(e);
      const from = m ? Number(m[1]) : NaN;
      const to = m ? Number(m[2] ?? m[1]) : NaN;
      if (!m || from < 1 || to > 65535 || from > 65535) return { ranges, problem: t('ports.bad', { e }) };
      if (to < from) return { ranges, problem: t('ports.reversed', { e }) };
      ranges.push({ from, to, text: e });
    }
    if (!ranges.length) return { ranges, problem: t('ports.none') };
    if (ranges.length > maxEntries) return { ranges, problem: t('ports.many', { n: maxEntries }) };
    ranges.sort((a, b) => a.from - b.from);
    for (let i = 1; i < ranges.length; i++) {
      if (ranges[i].from <= ranges[i - 1].to) return { ranges, problem: t('ports.overlap', { a: ranges[i - 1].text, b: ranges[i].text }) };
    }
    return { ranges, problem: '' };
  });
  let count = $derived(parsed.ranges.reduce((n, r) => n + r.to - r.from + 1, 0));
  let hopping = $derived(count > 1);
  let first = $derived(parsed.ranges[0]?.from ?? 0);
  let joined = $derived(parsed.ranges.map((r) => (r.from === r.to ? `${r.from}` : `${r.from}-${r.to}`)).join(','));
  // The current list in the same order (Hysteria sorts it too).
  const curJoined = [...curPorts].sort((a, b) => parseInt(a) - parseInt(b)).join(',');
  let portsChanged = $derived(!parsed.problem && (joined !== curJoined || host !== curHost));
  let intervalBad = $derived(interval != null && interval !== 0 && (interval < 5 || interval > 3600));
  let intervalChanged = $derived((interval || 0) !== curInterval);

  function add(v = '') {
    entries = [...entries, v];
  }

  function remove(i: number) {
    entries = entries.filter((_, j) => j !== i);
  }

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    error = null;
    try {
      const r = await api.setPorts(server.id, { base: config.revision, ports: parsed.ranges.map((x) => x.text), host, hopInterval: interval || 0 });
      if (r.job) onstarted(r.job);
      else onsaved();
    } catch (err) {
      error = asApiError(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('ports.title', { name: server.name })} {onclose}>
  <form id="ports-form" class="form" onsubmit={submit}>
    <p class="small">{t('ports.intro')}</p>

    <div class="field">
      <span class="lbl">{t('ports.list')}</span>
      {#each entries as _, i (i)}
        <div class="entry">
          <input type="text" bind:value={entries[i]} placeholder={i === 0 ? '443' : defaultRange} aria-label={t('ports.list')} spellcheck="false" />
          <button type="button" class="ghost" onclick={() => remove(i)} disabled={entries.length === 1} aria-label={t('ports.remove')}>✕</button>
        </div>
      {/each}
      <div class="row">
        <button type="button" class="ghost" onclick={() => add()} disabled={entries.length >= maxEntries}>{t('ports.add')}</button>
        {#if !entries.some((e) => e.includes('-'))}
          <button type="button" class="ghost" onclick={() => add(defaultRange)}>{t('ports.addRange', { r: defaultRange })}</button>
        {/if}
      </div>
      <span class="hint">{t('ports.listHint')}</span>
    </div>

    {#if parsed.problem}
      <div class="note error small" role="alert">{parsed.problem}</div>
    {:else}
      <div class="note info small">
        {#if hopping}
          {t('ports.summaryHop', { first, n: count })}
        {:else}
          {t('ports.summaryOne', { first })}
        {/if}
      </div>
    {/if}

    <label>
      <span>{t('ports.host')}</span>
      <select bind:value={host}>
        <option value="">{t('ports.hostAll')}</option>
        <option value="0.0.0.0">{t('ports.hostV4')}</option>
        {#if curHost && curHost !== '0.0.0.0'}<option value={curHost}>{t('ports.hostOne', { host: curHost })}</option>{/if}
      </select>
      <span class="hint">{host === '' ? t('ports.hostAllHint') : t('ports.hostV4Hint')}</span>
    </label>

    <label class="ival">
      <span>{t('ports.interval')}</span>
      <input type="number" min="5" max="3600" bind:value={interval} disabled={!hopping} placeholder="30" />
    </label>
    <span class="hint">{t('ports.intervalHint')}</span>
    {#if intervalBad}<span class="bad small">{t('ports.intervalBad')}</span>{/if}

    {#if portsChanged}
      <div class="note warn small">{t('ports.changeNote')}</div>
    {/if}

    {#if error}
      <div class="note error" role="alert">{error.message}</div>
    {/if}
  </form>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button class="primary" type="submit" form="ports-form" disabled={busy || !!parsed.problem || intervalBad || (!portsChanged && !intervalChanged)}>
      {portsChanged ? t('ports.apply') : t('ports.save')}
    </button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 14px; }
  label, .field { display: flex; flex-direction: column; gap: 6px; }
  label span, .lbl { color: var(--muted); font-size: 12.5px; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; margin: 0; }
  .entry { display: flex; gap: 8px; align-items: center; }
  .entry input { flex: 1; min-width: 0; font-family: var(--mono); }
  .row { display: flex; gap: 8px; flex-wrap: wrap; }
  .ival { width: 200px; }
  .bad { color: var(--block); }
  p { margin: 0; }
  .note { margin: 0; }
</style>
