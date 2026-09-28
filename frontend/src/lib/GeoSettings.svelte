<script lang="ts">
  // "Базы правил": geosite.dat / geoip.dat behind geosite:… and geoip:…
  import { onMount, onDestroy } from 'svelte';
  import { api, errText, fmtDateTime, fmtBytes, type GeoInfo } from '../api';
  import { hide } from '../state.svelte';
  import { trackUnsaved } from '../state.svelte'; // backup
  import Icon from './Icon.svelte';
  import { loadGeo } from '../geo.svelte';

  let info = $state<GeoInfo | null>(null);
  let error = $state('');
  let ok = $state('');
  let source = $state('');
  let siteURL = $state('');
  let ipURL = $state('');
  let auto = $state(true);
  let hours = $state(12);
  let timer: ReturnType<typeof setInterval> | undefined;

  async function load(resetForm = false) {
    try {
      const v = await api.GeoInfo();
      if (!info || resetForm) {
        source = v.source;
        siteURL = v.custom.site;
        ipURL = v.custom.ip;
        auto = v.auto;
        hours = v.hours;
      }
      info = v;
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(() => {
    load(true);
    timer = setInterval(() => {
      if (info?.busy) load();
    }, 700);
  });
  onDestroy(() => clearInterval(timer));

  async function savePrefs() {
    error = ok = '';
    try {
      await api.SetGeoPrefs(source, siteURL.trim(), ipURL.trim(), auto, Number(hours));
      ok = 'Сохранено';
      await load(true);
      loadGeo(true); // lists everywhere name the new database
    } catch (e) {
      error = errText(e);
    }
  }

  async function update(force: boolean) {
    error = ok = '';
    const p = api.UpdateGeo(force);
    setTimeout(() => load(), 150);
    try {
      const r = await p;
      ok = r.changed ? r.notes.join('. ') : 'Базы уже свежие';
      loadGeo(true);
    } catch (e) {
      error = errText(e);
    }
    await load();
  }

  async function rollback() {
    if (!confirm('Вернуть предыдущую версию баз? Правила сразу начнут работать по ней.')) return;
    error = ok = '';
    try {
      await api.RollbackGeo();
      ok = 'Возвращена предыдущая версия';
    } catch (e) {
      error = errText(e);
    }
    await load();
  }

  const cur = $derived(info?.sources.find((s) => s.id === source));
  const dirty = $derived(
    !!info && (source !== info.source || auto !== info.auto || Number(hours) !== info.hours || siteURL !== info.custom.site || ipURL !== info.custom.ip),
  );
  trackUnsaved(() => dirty); // backup
  const intervals = [
    { v: 6, l: 'каждые 6 часов' },
    { v: 12, l: 'каждые 12 часов' },
    { v: 24, l: 'раз в сутки' },
    { v: 72, l: 'раз в 3 дня' },
    { v: 168, l: 'раз в неделю' },
  ];
</script>

<section class="card">
  <h2><Icon name="database" size={17} /> Базы правил</h2>
  {#if info}
    <div class="now">Сейчас правила берут списки из базы <b>{info.sourceName}</b>. Все записи <code>geosite:…</code> и <code>geoip:…</code> в правилах и шаблонах ищутся в ней.</div>
  {/if}
  <p class="muted small">
    Готовые списки сайтов и адресов для правил: <code>geosite:youtube</code> — все домены YouTube, <code>geoip:ru</code> — все IP России,
    <code>geosite:ru-blocked</code> — заблокированное в России. Те же базы, что в v2rayN, Nekoray и Xray. HyRoute скачивает их, только если они нужны
    правилам, проверяет контрольную сумму и держит свежими.
  </p>

  {#if info}
    <div class="files">
      {#each [{ k: 'Сайты (geosite.dat)', f: info.site, i: 0 }, { k: 'Адреса (geoip.dat)', f: info.ip, i: 1 }] as x}
        <div class="file">
          <div class="grow">
            <b>{x.k}</b>
            {#if info.busy && info.progress[x.i] > 0 && info.progress[x.i] < 1}
              <div class="bar"><span style="width: {Math.round(info.progress[x.i] * 100)}%"></span></div>
            {:else if x.f}
              <div class="muted small">
                {fmtDateTime(x.f.updated)} · {fmtBytes(x.f.size)} · категорий {x.f.categories}
                {#if x.f.verified}<span class="okc" title="Совпала с опубликованной SHA-256">· <Icon name="check" size={12} /> проверена</span>{/if}
              </div>
            {:else}
              <div class="muted small">не скачана</div>
            {/if}
          </div>
        </div>
      {/each}
    </div>

    {#if info.used.length}
      <div class="muted small">Используются в правилах: {info.used.join(', ')}</div>
    {:else}
      <div class="muted small">Правила пока не используют базы — скачивать нечего. Добавьте шаблон «Заблокированное в России» или «YouTube».</div>
    {/if}
    {#each info.warnings as w}<div class="note warn small">{w}</div>{/each}
    {#if info.error}<div class="note error small">Последнее обновление не удалось: {hide(info.error)}. Правила работают по прежней версии баз.</div>{/if}
    {#if info.viaVPN}<div class="muted small">Напрямую GitHub не ответил — базы скачивались через VPN.</div>{/if}
    {#if info.checked}<div class="faint small">Проверено: {fmtDateTime(info.checked)}</div>{/if}

    <div class="row">
      <button class="primary" onclick={() => update(false)} disabled={info.busy}>
        <Icon name="refresh" size={15} />{info.busy ? 'Обновляется…' : info.site || info.ip ? 'Проверить обновления' : 'Скачать'}
      </button>
      <button onclick={() => update(true)} disabled={info.busy} title="Скачать заново, даже если версия не изменилась">Скачать заново</button>
      {#if info.hasPrevious}<button onclick={rollback} disabled={info.busy}>Откатить</button>{/if}
    </div>

    <div class="grid">
      <label for="geo-src">Источник</label>
      <div>
        <select id="geo-src" bind:value={source}>
          {#each info.sources as s (s.id)}<option value={s.id}>{s.name} ({s.size})</option>{/each}
          <option value="custom">Свои ссылки</option>
        </select>
        {#if cur}<div class="muted small">{cur.description}</div>{/if}
        {#if source === 'custom'}
          <input bind:value={siteURL} placeholder="https://…/geosite.dat" />
          <input bind:value={ipURL} placeholder="https://…/geoip.dat" />
          <div class="muted small">Если рядом лежит файл <code>.sha256sum</code>, HyRoute проверит по нему целостность.</div>
        {/if}
      </div>
      <label for="geo-auto">Автообновление</label>
      <div class="row">
        <label class="check"><input id="geo-auto" type="checkbox" bind:checked={auto} /> обновлять</label>
        <select bind:value={hours} disabled={!auto}>
          {#each intervals as i}<option value={i.v}>{i.l}</option>{/each}
          {#if !intervals.some((i) => i.v === Number(hours))}<option value={hours}>каждые {hours} ч</option>{/if}
        </select>
      </div>
    </div>
    {#if dirty}
      <div class="row"><button class="primary" onclick={savePrefs}>Сохранить</button><button onclick={() => load(true)}>Отмена</button></div>
    {/if}
  {/if}
  {#if error}<div class="note error">{hide(error)}</div>{/if}
  {#if ok}<div class="note ok">{ok}</div>{/if}
</section>

<style>
  .now { margin: 4px 0 8px; font-size: 13.5px; }
  .files { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 10px 0 6px; }
  .file { display: flex; gap: 10px; padding: 10px 12px; border-radius: var(--radius-sm); background: var(--surface-2); }
  .okc { color: var(--direct); display: inline-flex; align-items: center; gap: 2px; }
  .bar { height: 6px; border-radius: 3px; background: var(--surface-3); overflow: hidden; margin-top: 6px; }
  .bar span { display: block; height: 100%; background: var(--accent); transition: width 0.3s; }
  .grid { display: grid; grid-template-columns: 140px 1fr; gap: 10px 14px; align-items: start; margin-top: 14px; }
  .grid > label { padding-top: 7px; color: var(--muted); }
  .grid input { width: 100%; margin-top: 6px; }
  .check { display: inline-flex; align-items: center; gap: 6px; }
  code { font-family: var(--mono); font-size: 11.5px; }
  section > .row { margin-top: 10px; }
</style>
