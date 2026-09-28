<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, fmtBytes, fmtDuration, fmtTime, actionLabel, strategyLabel, cleanRule, dnsRuleLabel, type Flow, type Rule, type ConnFacts } from '../api';
  import { ui, hide, profileName, mainTarget } from '../state.svelte';
  import Icon from './Icon.svelte';
  import ConnMenu, { showConnResult, setConnNav } from './ConnMenu.svelte';
  import RuleEditor from './RuleEditor.svelte';
  import Explain from './Explain.svelte';
  import { ruleTitle } from '../ruletitle';

  let { go }: { go: (id: string) => void } = $props();
  // svelte-ignore state_referenced_locally
  setConnNav(go);

  // «Туннель → DE1 · Авто»: the server, then the group it was chosen by.
  function routeText(f: Flow): string {
    const r = actionLabel[f.route] ?? f.route;
    return f.route === 'tunnel' && f.profile ? `${r} → ${profileName(f.profile)}${f.group ? ` · ${profileName(f.group)}` : ''}` : r;
  }

  // «Авто (самый быстрый)».
  function groupText(id: string): string {
    const g = ui.groups.find((x) => x.id === id);
    return `${profileName(id)}${g ? ` (${strategyLabel[g.strategy].toLowerCase()})` : ''}`;
  }

  let active = $state<Flow[]>([]);
  let closed = $state<Flow[]>([]);
  let query = $state('');
  let route = $state('all');
  let showClosed = $state(true);
  let paused = $state(false);
  let error = $state('');
  let selected = $state<Flow | null>(null);
  // conn-rules: the menu of a row works on a snapshot of it (the table may
  // refresh or drop the row meanwhile); the rule editor and «Проверить
  // адрес» open from it as dialogs.
  let menu = $state<{ flow: Flow; anchor: { x: number; y: number }; el: HTMLElement | null } | null>(null);
  let draft = $state<{ rule: Rule; facts: ConnFacts; ruleset: string; udp: boolean } | null>(null);
  let explainQ = $state<{ app: string; target: string; proto: string; port: number; note: string } | null>(null);
  // Roving tabindex: one tab stop for the table (the selected row, else the
  // first); the arrows move between rows.
  let tbody = $state<HTMLElement>();
  let focusIndex = $state(0);

  // dns: DNS rows (queries HyRoute answered) are hidden unless «DNS-запросы»
  // is on (kept per viewer).
  function loadShowDNS(): boolean {
    try {
      return localStorage.getItem('hyroute.connDNS') === '1';
    } catch {
      return false;
    }
  }
  let showDNS = $state(loadShowDNS());
  function setShowDNS(on: boolean) {
    showDNS = on;
    try {
      localStorage.setItem('hyroute.connDNS', on ? '1' : '0');
    } catch {}
  }
  const dnsRows = $derived((showClosed ? [...active, ...closed] : active).filter((f) => f.stage === 'dns').length);

  // The rule cell: HyRoute's own DNS answers have their own texts; a rule
  // name may carry a site (Privacy mode).
  function ruleText(rule: string): string {
    return dnsRuleLabel[rule] ?? (!rule || rule === 'default' ? 'Всё остальное' : hide(rule));
  }

  async function load() {
    if (paused) return;
    try {
      const c = await api.Connections(2000);
      active = c.active;
      closed = c.closed;
      // The details show the selected flow as it is now (a pending route
      // gets decided, the flow closes); the last seen state once it is
      // gone from both lists.
      const id = selected?.id;
      if (id !== undefined) selected = c.active.find((f) => f.id === id) ?? c.closed.find((f) => f.id === id) ?? selected;
      error = '';
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(() => {
    load();
    const t = setInterval(load, 1000);
    return () => clearInterval(t);
  });

  const rows = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const all = showClosed ? [...active, ...closed] : active;
    return all
      .filter((f) => showDNS || f.stage !== 'dns') // dns
      .filter((f) => route === 'all' || f.route === route)
      .filter(
        (f) =>
          !q ||
          f.process.toLowerCase().includes(q) ||
          f.domain.toLowerCase().includes(q) ||
          f.dst.includes(q) ||
          f.rule.toLowerCase().includes(q) ||
          profileName(f.profile).toLowerCase().includes(q) ||
          (!!f.group && profileName(f.group).toLowerCase().includes(q)) ||
          f.outcome.toLowerCase().includes(q),
      )
      .slice(0, 1500);
  });

  // The row that holds the table's tab stop.
  const tabRow = $derived.by(() => {
    const i = selected ? rows.findIndex((x) => x.id === selected!.id) : -1;
    return i >= 0 ? i : Math.min(focusIndex, Math.max(rows.length - 1, 0));
  });

  // keyMenuAt: when the keyboard opened the menu. WebView2 also fires a
  // contextmenu event for the ContextMenu key and Shift+F10, which must not
  // open it a second time.
  let keyMenuAt = 0;
  // explainRet: the element that gets the focus back when «Проверить адрес»
  // closes.
  let explainRet: HTMLElement | null = null;
  let explainEl = $state<HTMLElement>();

  $effect(() => {
    if (explainQ && explainEl) explainEl.focus();
  });

  function closeExplain() {
    explainQ = null;
    if (explainRet?.isConnected) explainRet.focus();
    explainRet = null;
  }

  function openMenu(f: Flow, anchor: { x: number; y: number }, el: HTMLElement | null) {
    selected = f;
    menu = { flow: JSON.parse(JSON.stringify(f)), anchor, el };
  }

  function openAtRow(f: Flow, el: HTMLElement) {
    const r = el.getBoundingClientRect();
    openMenu(f, { x: r.left + 8, y: r.bottom }, el);
  }

  function rowEls(): HTMLElement[] {
    return [...(tbody?.querySelectorAll<HTMLElement>('tr') ?? [])];
  }

  function focusRow(i: number) {
    const list = rowEls();
    if (!list.length) return;
    focusIndex = Math.max(0, Math.min(i, list.length - 1));
    list[focusIndex].focus();
  }

  function rowKey(e: KeyboardEvent) {
    const list = rowEls();
    const at = list.indexOf(document.activeElement as HTMLElement);
    if (at < 0) return;
    switch (e.key) {
      case 'ArrowDown':
        focusRow(at + 1);
        break;
      case 'ArrowUp':
        focusRow(at - 1);
        break;
      case 'Home':
        focusRow(0);
        break;
      case 'End':
        focusRow(list.length - 1);
        break;
      case 'PageDown':
        focusRow(at + 10);
        break;
      case 'PageUp':
        focusRow(at - 10);
        break;
      case 'Enter':
      case ' ':
        selected = rows[at];
        break;
      case 'ContextMenu':
        keyMenuAt = performance.now();
        openAtRow(rows[at], list[at]);
        break;
      case 'F10':
        if (!e.shiftKey) return;
        keyMenuAt = performance.now();
        openAtRow(rows[at], list[at]);
        break;
      default:
        return;
    }
    e.preventDefault();
  }

  // The focused row left the table on a refresh: the focus goes to the row
  // now at its place, else to the table.
  let hadFocus = false;
  $effect.pre(() => {
    void rows;
    hadFocus = !!tbody && tbody.contains(document.activeElement);
  });
  $effect(() => {
    void rows;
    if (!hadFocus || !tbody || tbody.contains(document.activeElement)) return;
    const list = rowEls();
    if (list.length) list[Math.min(focusIndex, list.length - 1)].focus();
    else tbody.closest<HTMLElement>('.table')?.focus();
  });

  async function saveDraft(r: Rule) {
    const d = draft!;
    const res = await api.AddConnRule({ facts: d.facts, rule: cleanRule(r, mainTarget()?.id), source: 'editor', ruleset: d.ruleset });
    draft = null;
    const saved = res.rule;
    showConnResult(res, () => hide(ruleTitle(saved)), d.udp);
  }

  const srcName: Record<string, string> = { sni: 'по SNI (имя сайта в HTTPS)', host: 'по заголовку Host (HTTP)', dns: 'по кэшу DNS', query: 'из DNS-запроса', unknown: '' };

  function whyText(f: Flow): string {
    if (f.stage === 'dns') {
      // dns: a query HyRoute answered itself.
      const r = dnsRuleLabel[f.rule] ?? (!f.rule || f.rule === 'default' ? 'сработало «Всё остальное»' : `сработало правило «${hide(f.rule)}»`);
      return `DNS-запрос имени ${hide(f.domain)}: ${r}.${(f.count ?? 0) > 1 ? ` Запросов: ${f.count}.` : ''}`;
    }
    if (dnsRuleLabel[f.rule]) return `${dnsRuleLabel[f.rule]}.`; // dns: a browser's DoH connection
    const rule = f.excluded || f.rule.startsWith('exclusion') ? 'служебное исключение HyRoute' : !f.rule || f.rule === 'default' ? 'сработало «Всё остальное»' : `сработало правило «${hide(f.rule)}»`;
    const dom = f.domain ? `, сайт определён ${srcName[f.domainSrc] ?? f.domainSrc}` : ', сайт не определён';
    return rule[0].toUpperCase() + rule.slice(1) + dom + '.';
  }

  const srcLabel: Record<string, string> = { sni: 'SNI', host: 'Host', dns: 'DNS', query: 'запрос', unknown: '' };
  // dns: how the owner was found; «dnscache» is the Windows DNS client.
  const attribLabel: Record<string, string> = { dnscache: 'служба DNS Windows' };
</script>

<div class="wrap">
  <header>
    <h1>Соединения</h1>
    <p class="muted sub">
      Что сейчас открывают программы и куда это ушло. Нажмите на строку, чтобы увидеть, почему; правой кнопкой или кнопкой «…» — создать правило для этой
      программы или сайта.
    </p>
  </header>
  <div class="row toolbar">
    <input class="grow" placeholder="Фильтр: процесс, домен, адрес, правило" bind:value={query} />
    <select bind:value={route}>
      <option value="all">Все маршруты</option>
      <option value="tunnel">Туннель</option>
      <option value="direct">Напрямую</option>
      <option value="block">Блок</option>
      <option value="pending">Решается</option>
    </select>
    <label class="check"><input type="checkbox" bind:checked={showClosed} /> закрытые</label>
    <label class="check"><input type="checkbox" bind:checked={paused} /> пауза</label>
    {#if dnsRows > 0}
      <label class="check" title="Запросы, на которые ответил HyRoute. Имена серверов, служебные и локальные имена идут как раньше и здесь не показываются.">
        <input type="checkbox" checked={showDNS} onchange={(e) => setShowDNS((e.currentTarget as HTMLInputElement).checked)} /> DNS-запросы{showDNS ? '' : ` (${dnsRows})`}
      </label>
    {/if}
    <span class="muted">активных {active.length}, закрытых {closed.length}</span>
  </div>
  {#if error}<div class="note error">{error}</div>{/if}

  <div class="table panel" data-selectall tabindex="-1">
    <table>
      <thead>
        <tr>
          <th>Время</th><th>Процесс</th><th>Назначение</th><th>Домен</th><th>Правило</th><th>Маршрут</th><th>Исход</th>
          <th class="num">↑</th><th class="num">↓</th><th class="num">Длит.</th><th class="act" title="Действия"></th>
        </tr>
      </thead>
      <tbody bind:this={tbody}>
        {#each rows as f, i (f.id)}
          <tr
            class:closed={f.closed}
            class:sel={selected?.id === f.id}
            tabindex={i === tabRow ? 0 : -1}
            onfocus={() => (focusIndex = i)}
            onkeydown={rowKey}
            onclick={() => (selected = f)}
            oncontextmenu={(e) => {
              e.preventDefault();
              if (performance.now() - keyMenuAt < 500) return; // the key already opened it
              openMenu(f, { x: e.clientX, y: e.clientY }, e.currentTarget as HTMLElement);
            }}
          >
            <td class="mono">{fmtTime(f.start)}</td>
            <td title={f.path}>{f.process || `PID ${f.pid}`}</td>
            <td class="mono">{f.proto} {hide(f.dst)}</td>
            <td title={hide(f.domain)}>{hide(f.domain)}{#if (f.count ?? 0) > 1}<span class="muted"> ×{f.count}</span>{/if}{#if srcLabel[f.domainSrc]}<span class="src">{srcLabel[f.domainSrc]}</span>{/if}</td>
            <td title={ruleText(f.rule)}>{ruleText(f.rule)}{#if f.excluded}<span class="src">служебное</span>{/if}</td>
            <td class="route-{f.route}" title={routeText(f)}>{routeText(f)}</td>
            <td title={f.outcome}>{f.outcome}</td>
            <td class="num">{fmtBytes(f.sent)}</td>
            <td class="num">{fmtBytes(f.recv)}</td>
            <td class="num">{fmtDuration(f.duration)}</td>
            <td class="act">
              <button
                class="icon more"
                tabindex="-1"
                title="Действия"
                aria-label="Действия с соединением"
                onclick={(e) => {
                  e.stopPropagation();
                  const b = e.currentTarget as HTMLElement;
                  const r = b.getBoundingClientRect();
                  openMenu(f, { x: r.left, y: r.bottom }, b.closest('tr'));
                }}><Icon name="more" size={15} /></button
              >
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if rows.length === 0}<p class="muted empty">Соединений нет. Они появляются после подключения.</p>{/if}
  </div>

  {#if selected}
    <div class="card details">
      <div class="head">
      <div class="why route-{selected.route}"><b>{selected.process || `PID ${selected.pid}`}</b> → {hide(selected.domain) || hide(selected.dst)}: {routeText(selected)}</div>
      <div class="dbtns">
        <button
          onclick={(e) => {
            const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
            openMenu(selected!, { x: r.left, y: r.bottom }, e.currentTarget as HTMLElement);
          }}><Icon name="wand" size={15} />Создать правило…</button
        >
        <button class="icon" aria-label="Закрыть" onclick={() => (selected = null)}>×</button>
      </div>
      </div>
      <div class="muted">{whyText(selected)}</div>
      <div class="mono small facts">
        <span>{hide(selected.path || selected.process)} (PID {selected.pid})</span>
        <span>{selected.proto} {hide(selected.src)} → {hide(selected.dst)}</span>
        <span>исход: {selected.outcome} · процесс найден: {attribLabel[selected.attrib] ?? selected.attrib} · решение: {selected.stage}</span>
        {#if selected.group}<span>Группа: {groupText(selected.group)}</span>{/if}
        {#if selected.tooBig}
          <span>датаграмм больше предела Hysteria (около 4 КБ) отброшено: {selected.tooBig}</span>
        {/if}
      </div>
    </div>
  {/if}
</div>

{#if menu}
  {#key menu}
    <ConnMenu
      flow={menu.flow}
      anchor={menu.anchor}
      returnFocus={menu.el}
      onclose={() => (menu = null)}
      onedit={(rule, facts, ruleset) => (draft = { rule, facts, ruleset, udp: facts.proto.toLowerCase() === 'udp' })}
      onexplain={(q) => {
        explainRet = menu?.el ?? null;
        explainQ = q;
      }}
    />
  {/key}
{/if}

{#if draft}
  <RuleEditor rule={draft.rule} title="Новое правило из соединения" onsave={saveDraft} onclose={() => (draft = null)} />
{/if}

{#if explainQ}
  <div
    class="backdrop"
    role="presentation"
    onclick={(e) => e.target === e.currentTarget && closeExplain()}
    onkeydown={(e) => e.key === 'Escape' && closeExplain()}
  >
    <div class="dialog explain" role="dialog" aria-label="Проверить адрес" tabindex="-1" bind:this={explainEl}>
      <Explain initial={explainQ} current={() => null} onclose={closeExplain} />
    </div>
  </div>
{/if}

<style>
  .wrap { display: flex; flex-direction: column; height: 100%; gap: 10px; }
  .toolbar input { max-width: 420px; }
  .table { flex: 1; min-height: 0; overflow: auto; padding: 0; border-radius: var(--radius); outline: none; }
  table { font-size: 12.5px; }
  th {
    position: sticky;
    top: 0;
    background: var(--panel-2);
    text-align: left;
    font-weight: 600;
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  td {
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
    max-width: 260px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  tr { cursor: default; outline: none; }
  tr.closed td { opacity: 0.6; }
  tr.sel td { background: var(--panel-2); }
  tr:focus-visible td { background: var(--accent-soft); }
  .num { text-align: right; }
  .src { font-size: 10px; margin-left: 5px; padding: 0 4px; border-radius: 4px; background: var(--panel-2); color: var(--muted); }
  .empty { padding: 16px; }
  .details { position: relative; user-select: text; display: grid; gap: 4px; padding: 14px 16px; }
  .head { display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between; gap: 6px 12px; }
  .why { font-weight: 600; flex: 1 1 260px; min-width: 0; overflow-wrap: anywhere; }
  .facts { display: grid; gap: 2px; color: var(--muted); margin-top: 4px; }
  .sub { margin: 4px 0 0; }
  .dbtns { display: flex; gap: 6px; align-items: center; margin: -6px -8px 0 auto; }
  .act { width: 30px; padding: 0 4px; text-align: center; }
  .more { width: 24px; height: 22px; padding: 0; opacity: 0.55; }
  tr:hover .more,
  tr.sel .more { opacity: 1; }
  .explain { width: min(820px, 94vw); padding: 0; }
</style>
