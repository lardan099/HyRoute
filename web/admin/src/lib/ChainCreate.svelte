<script lang="ts">
  // A new cascade: entry and exit, the link's settings, and (by default)
  // the job that deploys the link right away.
  import { onMount } from 'svelte';
  import { api, asApiError, type ApiError, type Chain, type ChainTemplate, type Job, type Server } from '../api';
  import { t } from '../i18n';
  import { flag } from './format';
  import Dialog from './Dialog.svelte';

  let {
    servers,
    onclose,
    oncreated,
  }: {
    servers: Server[];
    onclose: () => void;
    oncreated: (c: Chain, job: Job | null, linkError: ApiError | null, tpl: ChainTemplate | null) => void;
  } = $props();

  let name = $state('');
  let entry = $state(0);
  let exit = $state(0);
  let notes = $state('');
  let up = $state('');
  let down = $state('');
  let noUdp = $state(false);
  let checkTarget = $state('');
  let deployNow = $state(true);
  let templates = $state<ChainTemplate[]>([]);
  let tplIndex = $state(-1);
  let tpl = $derived(templates[tplIndex] ?? null);
  let fileInput = $state<HTMLInputElement | null>(null);

  onMount(async () => {
    try {
      templates = await api.chainTemplates();
    } catch {}
  });

  // pick fills the link's settings from a template.
  function pick(i: number) {
    tplIndex = i;
    const l = templates[i]?.link ?? {};
    up = l.up ?? '';
    down = l.down ?? '';
    noUdp = !!l.noUdp;
    checkTarget = l.checkTarget ?? '';
  }

  async function importFile(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const f = input.files?.[0];
    input.value = '';
    if (!f) return;
    try {
      const x = await api.importChainTemplate(await f.text());
      templates = [...templates, x];
      pick(templates.length - 1);
      error = null;
    } catch (err) {
      error = asApiError(err);
    }
  }
  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  let errField = $derived(error?.code === 'invalid' ? error.details : '');

  const label = (s: Server) => `${flag(s.country)} ${s.name}`.trim();

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!entry || !exit || entry === exit) {
      error = { code: 'invalid', message: t('cascades.pickTwo'), details: 'nodes' } as ApiError;
      return;
    }
    busy = true;
    error = null;
    try {
      const c = await api.createChain({
        name,
        notes,
        nodes: [entry, exit],
        link: { up: up.trim() || undefined, down: down.trim() || undefined, noUdp: noUdp || undefined, checkTarget: checkTarget.trim() || undefined },
      });
      let job: Job | null = null;
      let linkError: ApiError | null = null;
      if (deployNow) {
        try {
          job = await api.linkChain(c.id);
        } catch (err) {
          // The chain is there: its page says what keeps the link back.
          linkError = asApiError(err);
        }
      }
      oncreated(c, job, linkError, tpl);
    } catch (err) {
      error = asApiError(err);
    } finally {
      busy = false;
    }
  }
</script>

<Dialog title={t('cascades.createTitle')} {onclose}>
  <form id="chain-create" class="form" onsubmit={save}>
    <div class="tpl">
      <label class="grow">
        <span>{t('ctpl.template')}</span>
        <select value={tplIndex} onchange={(e) => pick(Number(e.currentTarget.value))}>
          <option value={-1}>{t('ctpl.none')}</option>
          {#each templates as x, i (i)}<option value={i}>{x.name}{x.builtin ? '' : ' · ' + t('ctpl.file')}</option>{/each}
        </select>
      </label>
      <button type="button" class="ghost" onclick={() => fileInput?.click()}>{t('ctpl.load')}</button>
      <input type="file" accept=".json,application/json" class="hidden" bind:this={fileInput} onchange={importFile} />
    </div>
    {#if tpl?.description}<p class="small muted desc">{tpl.description}</p>{/if}
    {#if tpl?.entry}<p class="small faint desc">{t('ctpl.entryNote')}</p>{/if}
    <label class:bad={errField === 'name'}>
      <span>{t('cascades.name')}</span>
      <input type="text" maxlength="64" bind:value={name} required />
    </label>
    <div class="pair" class:bad={errField === 'nodes'}>
      <label>
        <span>{t('cascades.entry')} · <span class="faint">{t('cascades.entryHint')}</span></span>
        <select bind:value={entry} required>
          <option value={0} disabled>—</option>
          {#each servers as s (s.id)}<option value={s.id} disabled={s.id === exit}>{label(s)}</option>{/each}
        </select>
      </label>
      <span class="arrow" aria-hidden="true">→</span>
      <label>
        <span>{t('cascades.exit')} · <span class="faint">{t('cascades.exitHint')}</span></span>
        <select bind:value={exit} required>
          <option value={0} disabled>—</option>
          {#each servers as s (s.id)}<option value={s.id} disabled={s.id === entry}>{label(s)}</option>{/each}
        </select>
      </label>
    </div>
    <details>
      <summary>{t('cascades.advanced')}</summary>
      <div class="adv">
        <label class:bad={errField === 'up' || errField === 'down'}>
          <span>{t('cascades.speed')}</span>
          <span class="two">
            <input type="text" placeholder="100 mbps" bind:value={up} />
            <input type="text" placeholder="300 mbps" bind:value={down} />
          </span>
          <span class="small faint">{t('cascades.speedHint')}</span>
        </label>
        <label class="check"><input type="checkbox" bind:checked={noUdp} /> {t('cascades.noUdp')}</label>
        <label class:bad={errField === 'checkTarget'}>
          <span>{t('cascades.checkTarget')}</span>
          <input type="text" placeholder="1.1.1.1:443" bind:value={checkTarget} />
          <span class="small faint">{t('cascades.checkTargetHint')}</span>
        </label>
      </div>
    </details>
    <label class:bad={errField === 'notes'}>
      <span>{t('cascades.notes')}</span>
      <textarea rows="2" bind:value={notes} class="plain"></textarea>
    </label>
    <label class="check"><input type="checkbox" bind:checked={deployNow} /> {t('cascades.deployNow')}</label>
    {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
  </form>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button type="submit" form="chain-create" class="primary" disabled={busy}>{t('cascades.create')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 12px; min-width: min(560px, 80vw); }
  label { display: flex; flex-direction: column; gap: 5px; }
  label > span:first-child { color: var(--muted); font-size: 12.5px; }
  label.check { flex-direction: row; align-items: center; gap: 8px; }
  label.bad input, label.bad textarea, .pair.bad select { border-color: var(--block); }
  .pair { display: flex; align-items: flex-end; gap: 10px; }
  .pair label { flex: 1; min-width: 0; }
  .arrow { padding-bottom: 8px; color: var(--muted); font-size: 18px; }
  .adv { display: flex; flex-direction: column; gap: 10px; margin-top: 10px; }
  .two { display: flex; gap: 8px; }
  .two input { flex: 1; min-width: 0; }
  summary { cursor: pointer; color: var(--muted); font-size: 13px; }
  textarea.plain { font-family: var(--font); font-size: 14px; }
  .note { margin: 0; }
  .tpl { display: flex; align-items: flex-end; gap: 8px; }
  .grow { flex: 1; min-width: 0; }
  .desc { margin: -4px 0 0; }
  .hidden { display: none; }
</style>
