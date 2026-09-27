<script lang="ts">
  // Lists: which geosite/geoip lists contain a site or IP, what is inside a
  // list, and Hysteria ACL conversion.
  import { api, errText, cleanSettings, toLists, type InspectResult, type InspectHit, type ConvertResult, type Rule } from '../api';
  import { hide, profileName, mainProfile } from '../state.svelte';
  import { geo, loadGeo } from '../geo.svelte';
  import Icon from './Icon.svelte';
  import ListViewer from './ListViewer.svelte';
  import RuleEditor from './RuleEditor.svelte';

  loadGeo();

  let tab = $state<'search' | 'acl'>('search');
  let query = $state('');
  let res = $state<InspectResult | null>(null);
  let busy = $state(false);
  let error = $state('');
  let info = $state('');
  let viewing = $state<string | null>(null);
  let adding = $state<Rule | null>(null);

  async function search(q = query) {
    query = q;
    if (!q.trim()) return;
    busy = true;
    error = info = '';
    try {
      res = await api.Inspect(q);
      if (res.list) {
        viewing = q.trim().toLowerCase();
        res = null;
      }
    } catch (e) {
      error = errText(e);
      res = null;
    }
    busy = false;
  }

  function routeText(r: InspectResult): string {
    const w = r.route?.winner;
    if (!w) return '';
    const to = w.action === 'direct' ? 'напрямую' : w.action === 'block' ? 'блокируется' : `через ${w.profile ? profileName(w.profile) : 'основной сервер'}`;
    const why = w.index < 0 ? 'ни одно правило не подошло, сработало «Всё остальное»' : `правило «${w.name}»`;
    return `Сейчас HyRoute: ${to} (${why}).`;
  }

  // Hysteria ACL snippet in priority order (specific lists first).
  function acl(hits: InspectHit[]): string {
    return hits.map((h) => `    - OUTBOUND(${h.tag})`).join('\n');
  }
  function hyroute(hits: InspectHit[]): string {
    return hits.map((h) => `${h.title || h.tag.replace(/^geo(site|ip):/, '')}: ${h.tag} -> vpn`).join('\n');
  }

  async function copy(text: string, what: string) {
    try {
      await api.CopyText(text);
      info = `Скопировано: ${what}`;
    } catch (e) {
      error = errText(e);
    }
  }

  function newRule(h: InspectHit) {
    adding = { name: h.title || h.tag.replace(/^geo(site|ip):/, ''), apps: [], domains: [h.tag], action: 'tunnel', profile: '', protocol: '' };
  }

  async function saveRule(r: Rule) {
    const s = await api.Settings();
    s.rules = (s.rules ?? []).map(toLists);
    s.rules.unshift(r);
    await api.SaveSettings(cleanSettings(s, mainProfile()?.id));
    adding = null;
    info = `Правило «${r.name}» добавлено в начало списка правил`;
    if (res) search(res.query);
  }

  const all = $derived(res ? [...res.site, ...res.ip] : []);

  // ---- ACL converter ----
  let aclText = $state('');
  let mode = $state<'domains' | 'rules'>('domains');
  let suffix = $state('+hyst');
  let actions = $state('');
  let conv = $state<ConvertResult | null>(null);
  let convError = $state('');

  async function convert() {
    convError = '';
    try {
      conv = await api.ConvertACL(aclText, mode, suffix, actions);
    } catch (e) {
      conv = null;
      convError = errText(e);
    }
  }
  const examples = ['chatgpt.com', 'youtube.com', 'rutracker.org', '149.154.167.51', 'geosite:openai', 'geoip:telegram'];
</script>

<div class="page-wrap">
  <header class="row">
    <div class="grow">
      <h1>Списки</h1>
      <p class="muted sub">
        В каких готовых списках (<code>geosite:…</code>, <code>geoip:…</code>) есть сайт или IP и что внутри списка. Поиск идёт по базе
        <b>{geo.sourceName || 'правил'}</b>.
      </p>
    </div>
    <div class="seg">
      <button class:on={tab === 'search'} onclick={() => (tab = 'search')}>Поиск</button>
      <button class:on={tab === 'acl'} onclick={() => (tab = 'acl')}>Конвертер ACL</button>
    </div>
  </header>

  {#if tab === 'search'}
    <section class="card">
      <form class="row" onsubmit={(e) => (e.preventDefault(), search())}>
        <input class="grow" bind:value={query} placeholder="Сайт, ссылка, IP, geosite:тег или geoip:тег" />
        <button class="primary" disabled={busy || !query.trim()}><Icon name="search" size={15} />{busy ? 'Ищу…' : 'Найти'}</button>
      </form>
      <div class="ex muted small">
        Например:
        {#each examples as ex}<button class="link" onclick={() => search(ex)}>{ex}</button>{/each}
      </div>
    </section>

    {#if error}<div class="note error">{error}</div>{/if}
    {#if info}<div class="note ok">{info}</div>{/if}

    {#if res}
      <section class="card">
        {#if res.host}<div><b>{hide(res.host)}</b>{#if res.ips.length}<span class="muted">&nbsp;· IP: {hide(res.ips.join(', '))}</span>{/if}</div>{/if}
        {#if res.route}<div class="route">{routeText(res)}</div>{/if}
        {#each res.errors as e}<div class="note warn small">{hide(e)}</div>{/each}
        {#if all.length}
          <div class="muted small hint">
            Сверху — самые точные списки, внизу — общие (весь реестр, регион). Правила проверяются сверху вниз, поэтому точные списки ставьте выше
            общих. «В правилах» — где список уже используется.
          </div>
        {/if}
      </section>

      {#each [{ t: 'Списки сайтов (geosite)', hits: res.site }, { t: 'Списки IP-адресов (geoip)', hits: res.ip }] as grp}
        {#if grp.hits.length}
          <section class="card">
            <div class="row">
              <h2 class="grow">{grp.t} <span class="muted">· {grp.hits.length}</span></h2>
              <button onclick={() => copy(acl(grp.hits), 'правила ACL для сервера Hysteria')} title="Строки «- OUTBOUND(geosite:…)» для acl в конфиге сервера, по приоритету">
                <Icon name="copy" size={14} />ACL Hysteria
              </button>
            </div>
            <div class="hits">
              {#each grp.hits as h (h.tag)}
                <div class="hit" class:broad={h.broad}>
                  <div class="grow">
                    <div class="top">
                      <code class="tag">{h.tag}</code>
                      {#if h.title}<span>{h.title}</span>{/if}
                      {#if h.broad}<span class="badge">общий</span>{/if}
                      <span class="faint small">{h.size.toLocaleString('ru-RU')} записей</span>
                    </div>
                    <div class="muted small">
                      совпало: <code>{hide(h.entry)}</code>{#if h.attrs} <code>{h.attrs}</code>{/if}{#if h.ip} · для {hide(h.ip)}{/if}
                    </div>
                    {#if h.usedBy?.length}<div class="used small"><Icon name="check" size={12} /> в правилах: {h.usedBy.join(', ')}</div>{/if}
                  </div>
                  <div class="acts">
                    <button onclick={() => (viewing = h.tag)} title="Всё, что входит в список">Открыть</button>
                    <button onclick={() => newRule(h)} title="Создать правило с этим списком"><Icon name="plus" size={14} />Правило</button>
                    <button class="icon" onclick={() => copy(`    - OUTBOUND(${h.tag})`, h.tag)} title="Копировать как ACL Hysteria"><Icon name="copy" size={14} /></button>
                  </div>
                </div>
              {/each}
            </div>
          </section>
        {/if}
      {/each}
      {#if !all.length && !res.errors.length}
        <div class="card muted">Ни в одном списке базы {res.sourceName} этого нет.</div>
      {/if}
      {#if all.length}
        <div class="row">
          <button onclick={() => copy(acl(all), 'все списки как ACL Hysteria')}><Icon name="copy" size={14} />Все как ACL Hysteria</button>
          <button onclick={() => copy(hyroute(all), 'все списки как правила HyRoute')}><Icon name="copy" size={14} />Все как правила HyRoute</button>
          <span class="muted small">В ACL стоит <code>OUTBOUND</code>: замените на имя выхода в конфиге сервера.</span>
        </div>
      {/if}
    {/if}
  {:else}
    <section class="card acl">
      <p class="muted small">
        Вставьте правила ACL сервера Hysteria (<code>- proxy(geosite:openai)</code>, <code>- direct(suffix:example.com)</code>…). Их можно превратить в
        список доменов вида <code>*.example.com +hyst</code> для других программ или в правила HyRoute.
      </p>
      <textarea bind:value={aclText} rows="9" spellcheck="false" placeholder={'acl:\n  inline:\n    - proxy(geosite:openai)\n    - proxy(suffix:telegram.org)\n    - direct(geoip:ru)\n    - direct(all)'}></textarea>
      <div class="opts">
        <div class="seg">
          <button class:on={mode === 'domains'} onclick={() => (mode = 'domains')}>Список доменов</button>
          <button class:on={mode === 'rules'} onclick={() => (mode = 'rules')}>Правила HyRoute</button>
        </div>
        {#if mode === 'domains'}
          <label>Суффикс <input class="short" bind:value={suffix} /></label>
        {/if}
        <label class="grow">Только действия <input bind:value={actions} placeholder="все; или через запятую: proxy, my_nl" /></label>
        <button class="primary" onclick={convert} disabled={!aclText.trim()}>Преобразовать</button>
      </div>
      <div class="muted small">
        {#if mode === 'domains'}
          <code>geosite:тег</code> раскрывается по базе {geo.sourceName}, поддомены сворачиваются до основного домена (<code>api.telegram.org</code> →
          <code>*.telegram.org</code>), повторы убираются. <code>geoip:</code> пропускается: диапазоны IP не превращаются в домены.
        {:else}
          <code>direct</code> → напрямую, <code>reject</code> → блок, остальные выходы → vpn (потом поменяйте на нужный сервер). Результат можно вставить в
          «Правила → Текстом».
        {/if}
      </div>
      {#if convError}<div class="note error">{convError}</div>{/if}
      {#if conv}
        <div class="row">
          <b class="grow">Результат: {conv.count} {mode === 'domains' ? 'строк' : 'правил'}</b>
          <button onclick={() => copy(conv!.text, 'результат')}><Icon name="copy" size={14} />Копировать</button>
        </div>
        <textarea readonly rows="10" value={conv.text}></textarea>
        {#each conv.warnings.slice(0, 30) as w}<div class="warn-t small">{w}</div>{/each}
        {#if conv.warnings.length > 30}<div class="muted small">…и ещё {conv.warnings.length - 30}</div>{/if}
      {/if}
      {#if info}<div class="note ok">{info}</div>{/if}
    </section>
  {/if}
</div>

{#if viewing}<ListViewer tag={viewing} onclose={() => (viewing = null)} />{/if}
{#if adding}
  <RuleEditor rule={adding} title="Новое правило" onsave={saveRule} onclose={() => (adding = null)} />
{/if}

<style>
  .page-wrap { display: grid; gap: 14px; max-width: 1000px; }
  header { align-items: flex-start; gap: 12px; }
  .sub { margin: 4px 0 0; }
  code { font-family: var(--mono); font-size: 12px; }
  .ex { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 4px 10px; align-items: center; }
  .link { background: none; padding: 0; color: var(--accent); font-family: var(--mono); font-size: 12px; }
  .route { margin-top: 6px; font-weight: 600; }
  .hint { margin-top: 8px; }
  h2 { margin: 0; font-size: 15px; }
  .hits { display: grid; gap: 2px; margin-top: 8px; }
  .hit { display: flex; gap: 10px; align-items: center; padding: 8px 10px; border-radius: var(--radius-sm); }
  .hit:hover { background: var(--surface-2); }
  .hit.broad .tag { color: var(--muted); }
  .top { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
  .tag { font-size: 13px; font-weight: 600; color: var(--accent); }
  .badge { font-size: 10.5px; padding: 0 6px; border-radius: 999px; background: var(--surface-3); color: var(--muted); }
  .used { color: var(--direct); display: flex; gap: 4px; align-items: center; margin-top: 2px; }
  .acts { display: flex; gap: 4px; flex: none; }
  .acts button { padding: 5px 10px; font-size: 12.5px; }
  .acl { display: grid; gap: 10px; }
  .acl p { margin: 0; }
  textarea { width: 100%; font-family: var(--mono); font-size: 12.5px; }
  .opts { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  .opts label { display: flex; gap: 6px; align-items: center; color: var(--muted); }
  .opts label input { flex: 1; }
  .short { width: 90px; }
  .warn-t { color: var(--warn); }
</style>
