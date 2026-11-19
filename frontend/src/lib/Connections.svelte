<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, errText, fmtBytes, fmtDuration, fmtTime, actionLabel, strategyLabel, cleanRule, dnsRuleLabel, type Flow, type Rule, type ConnFacts } from '../api';
  import { ui, hide, hideUserPath, profileName, mainTarget } from '../state.svelte';
  import Icon from './Icon.svelte';
  import ConnMenu, { showConnResult, setConnNav } from './ConnMenu.svelte';
  import RuleEditor from './RuleEditor.svelte';
  import Explain from './Explain.svelte';
  import ConnectionComparison from './ConnectionComparison.svelte';
  import { ruleTitle } from '../ruletitle';
  import { every } from '../poll';
  import { flowFailed, flowState, overviewGroups, overviewKey, usedTunnel } from './flowOverview';

  let { go }: { go: (id: string) => void } = $props();
  // svelte-ignore state_referenced_locally
  setConnNav(go);

  // «Туннель → DE1 · Авто»: the server, then the group it was chosen by.
  function routeText(f: Flow): string {
    const r = actionLabel[f.route] ?? f.route;
    return f.route === 'tunnel' && f.profile ? `${r} → ${f.profile === 'telegram-ws' ? 'Мост Telegram' : profileName(f.profile)}${f.group ? ` · ${profileName(f.group)}` : ''}` : r;
  }

  // «Авто (самый быстрый)».
  function groupText(id: string): string {
    const g = ui.groups.find((x) => x.id === id);
    return `${profileName(id)}${g ? ` (${strategyLabel[g.strategy].toLowerCase()})` : ''}`;
  }

  let active = $state<Flow[]>([]);
  let closed = $state<Flow[]>([]);
  let query = $state('');
  function savedView(): boolean {
    try { return localStorage.getItem('hyroute.connView') === 'detail'; } catch { return false; }
  }
  let detail = $state(savedView());
  let failedOnly = $state(false);
  let expanded = $state(false);
  let copyMessage = $state('');
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
      if (id !== undefined) {
        const same = (f: Flow) => f.id === id && f.start === selected?.start;
        selected = c.active.find(same) ?? c.closed.find(same) ?? selected;
      }
      error = '';
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(() => {
    load();
    return every(load, 1000);
  });

  const matching = $derived.by(() => {
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
          f.src.includes(q) || String(f.pid) === q || f.proto.toLowerCase() === q ||
          f.rule.toLowerCase().includes(q) ||
          profileName(f.profile).toLowerCase().includes(q) ||
          (!!f.group && profileName(f.group).toLowerCase().includes(q)) ||
          f.outcome.toLowerCase().includes(q),
      );
  });
  const failures = $derived(matching.filter(flowFailed));
  const flows = $derived((failedOnly ? failures : matching).slice(0, 1500));
  const groups = $derived(detail ? null : overviewGroups(flows));
  const rows = $derived.by(() => {
    if (!groups) return flows;
    const representatives = Array.from(groups.values(), (g) => g.flow);
    return [...representatives.filter(flowFailed), ...representatives.filter((f) => !flowFailed(f))];
  });
  const selectedGroup = $derived(!detail && selected ? overviewKey(selected) : '');
  function isSelected(f: Flow): boolean {
    return detail ? selected?.id === f.id && selected?.start === f.start : selectedGroup === overviewKey(f);
  }
  function choose(f: Flow) {
    if (isSelected(f)) return;
    selected = f;
    expanded = false;
    copyMessage = '';
  }
  async function filterChanged() {
    await tick();
    if (selected && !flows.some((f) => f.id === selected?.id && f.start === selected?.start)) selected = null;
    if (tableEl) tableEl.scrollTop = 0;
  }
  async function switchView(next: boolean) {
    if (detail === next) return;
    detail = next;
    try { localStorage.setItem('hyroute.connView', next ? 'detail' : 'overview'); } catch {}
    await tick();
    const i = rows.findIndex(isSelected);
    if (tableEl) tableEl.scrollTop = i < 0 ? 0 : Math.max(0, i * rowH - viewH / 2);
  }
  function simpleRoute(f: Flow): string {
    if (f.stage === 'dns') return 'Запрос DNS';
    if (usedTunnel(f)) {
      if (f.profile === 'telegram-ws') return 'Мост Telegram';
      return ['VPN', profileName(f.profile), f.failover && 'запасной'].filter(Boolean).join(' · ');
    }
    if (f.route === 'block') return ruleText(f.rule);
    if (f.route === 'direct' && (f.outcome === 'passed' || f.outcome === 'relayed')) return 'Без VPN';
    return f.route === 'tunnel' ? 'Попытка через VPN' : f.route === 'direct' ? 'Попытка без VPN' : 'Ещё не определено';
  }
  function summary(f: Flow): string {
    if (f.stage === 'dns') return whyText(f);
    if (f.tooBig && !f.sent) return 'Данные не прошли: размер пакета превышает предел туннеля.';
    if (f.outcome.includes('tunnel unavailable')) return 'VPN-сервер недоступен. Можно выбрать другой сервер для следующих подключений.';
    if (flowFailed(f)) return 'Попытка подключения завершилась ошибкой. Причина из журнала доступна в технических деталях.';
    if (f.route === 'block') return 'HyRoute заблокировал соединение. ' + whyText(f);
    if (usedTunnel(f) && f.failover) return 'Соединение прошло через запасной сервер. Менять настройки не требуется.';
    if (usedTunnel(f) && f.profile === 'telegram-ws') return 'Telegram подключился через встроенный мост HyRoute.';
    if (usedTunnel(f)) return 'Программа подключилась через VPN.';
    if (f.outcome === 'passed' || f.route === 'direct' && f.outcome === 'relayed') return 'HyRoute пропустил трафик напрямую.';
    return flowState(f);
  }
  async function copyFacts(f: Flow) {
    try {
      await navigator.clipboard.writeText([hideUserPath(f.path || f.process), 'PID ' + f.pid, f.proto,
        hide(f.src), hide(f.dst), hide(f.domain), ruleText(f.rule), routeText(f), hide(f.outcome)].join(' · '));
      copyMessage = 'Скопировано';
    } catch { copyMessage = 'Не удалось скопировать'; }
  }

  // Only the rows in view (and some around them) are drawn: 1500 rows
  // redrawn every second kept the window at most of a processor core. The
  // rows are one line each, so their height is one number; spacers above
  // and below keep the scroll bar the size of the whole table.
  const BUFFER = 15;
  let scrollTop = $state(0);
  let viewH = $state(600);
  let rowH = $state(27);
  let tableEl = $state<HTMLElement>();
  const first = $derived(Math.max(0, Math.min(Math.floor(scrollTop / rowH) - BUFFER, rows.length - 1)));
  const last = $derived(Math.min(rows.length, Math.ceil((scrollTop + viewH) / rowH) + BUFFER));
  const drawn = $derived(rows.slice(first, last));
  $effect(() => {
    void drawn;
    const r = tbody?.querySelector<HTMLElement>('tr[data-i]');
    if (r && r.offsetHeight > 0 && Math.abs(r.offsetHeight - rowH) > 0.5) rowH = r.offsetHeight;
  });

  // The row that holds the table's tab stop; the first drawn row while it
  // is scrolled away.
  const tabRow = $derived.by(() => {
    const i = selected ? rows.findIndex(isSelected) : -1;
    const want = i >= 0 ? i : Math.min(focusIndex, Math.max(rows.length - 1, 0));
    return want >= first && want < last ? want : first;
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
    if (!detail && selected && isSelected(f)) f = selected;
    if (!isSelected(f)) { expanded = false; copyMessage = ''; }
    selected = f;
    menu = { flow: JSON.parse(JSON.stringify(f)), anchor, el };
  }

  function openAtRow(f: Flow, el: HTMLElement) {
    const r = el.getBoundingClientRect();
    openMenu(f, { x: r.left + 8, y: r.bottom }, el);
  }

  function rowEl(i: number): HTMLElement | null {
    return tbody?.querySelector<HTMLElement>(`tr[data-i="${i}"]`) ?? null;
  }

  // focusRow scrolls a row that is not drawn into view first.
  async function focusRow(i: number) {
    if (!rows.length) return;
    focusIndex = Math.max(0, Math.min(i, rows.length - 1));
    if (!rowEl(focusIndex) && tableEl) {
      tableEl.scrollTop = Math.max(0, focusIndex * rowH - viewH / 2);
      scrollTop = tableEl.scrollTop;
      await tick();
    }
    const el = rowEl(focusIndex);
    el?.focus();
    el?.scrollIntoView({ block: 'nearest' });
  }

  function rowKey(e: KeyboardEvent) {
    const at = Number((document.activeElement as HTMLElement | null)?.dataset.i ?? -1);
    if (at < 0 || !rows[at]) return;
    const el = rowEl(at)!;
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
        focusRow(rows.length - 1);
        break;
      case 'PageDown':
        focusRow(at + 10);
        break;
      case 'PageUp':
        focusRow(at - 10);
        break;
      case 'Enter':
      case ' ':
        choose(rows[at]);
        break;
      case 'ContextMenu':
        keyMenuAt = performance.now();
        openAtRow(rows[at], el);
        break;
      case 'F10':
        if (!e.shiftKey) return;
        keyMenuAt = performance.now();
        openAtRow(rows[at], el);
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
    const el = rows.length ? rowEl(Math.min(focusIndex, rows.length - 1)) : null;
    if (el) el.focus();
    else tableEl?.focus();
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
      {detail ? 'Каждая строка — отдельная запись. Выберите её, чтобы сравнить маршруты.' : 'Какие программы выходят в интернет и как они подключаются.'}
    </p>
  </header>
  <div class="row toolbar">
    <div class="seg" role="group" aria-label="Вид соединений">
      <button class:on={!detail} aria-pressed={!detail} onclick={() => switchView(false)}>Обзор</button>
      <button class:on={detail} aria-pressed={detail} onclick={() => switchView(true)}>Подробно</button>
    </div>
    <input class="grow" aria-label="Поиск соединений" placeholder="Программа, сайт или IP" bind:value={query} oninput={filterChanged} />
    <label class="check"><input type="checkbox" bind:checked={paused} /> Пауза</label>
  </div>
  <div class="row toolbar">
    <div class="seg" role="group" aria-label="Исход соединения">
      <button class:on={!failedOnly} aria-pressed={!failedOnly} onclick={() => { failedOnly = false; filterChanged(); }}>Все</button>
      <button class:on={failedOnly} aria-pressed={failedOnly} onclick={() => { failedOnly = true; filterChanged(); }}>Не подключились · {failures.length}</button>
    </div>
    {#if detail || route !== 'all'}
    <select aria-label="Маршрут" bind:value={route} onchange={filterChanged}>
      <option value="all">Все маршруты</option>
      <option value="tunnel">Туннель</option>
      <option value="direct">Напрямую</option>
      <option value="block">Блок</option>
      <option value="pending">Решается</option>
    </select>
    {/if}
    {#if detail || !showClosed}<label class="check"><input type="checkbox" bind:checked={showClosed} onchange={filterChanged} /> Закрытые</label>{/if}
    {#if (detail || showDNS) && (dnsRows > 0 || showDNS)}
      <label class="check" title="Запросы, на которые ответил HyRoute. Имена серверов, служебные и локальные имена идут как раньше и здесь не показываются.">
        <input type="checkbox" checked={showDNS} onchange={(e) => { setShowDNS((e.currentTarget as HTMLInputElement).checked); filterChanged(); }} /> DNS-запросы{showDNS ? '' : ` (${dnsRows})`}
      </label>
    {/if}
    {#if detail}<span class="muted">активных {active.length}, закрытых {closed.length}</span>{/if}
  </div>
  {#if error}<div class="note error">{error}</div>{/if}

  <div class="table panel" data-selectall tabindex="-1" bind:this={tableEl} bind:clientHeight={viewH} onscroll={(e) => (scrollTop = (e.currentTarget as HTMLElement).scrollTop)}>
    <table class:overview={!detail}>
      <thead>
        <tr>
          {#if detail}
          <th>Начало</th><th>Процесс</th><th>Назначение</th><th>Правило / маршрут</th><th>Исход</th>
          <th class="num">Трафик ↓ / ↑</th><th class="num">Длит.</th><th class="act" title="Действия"></th>
          {:else}
          <th>Сайт / программа</th><th>Что произошло</th><th>Как подключилось</th><th class="act" title="Действия"></th>
          {/if}
        </tr>
      </thead>
      <tbody bind:this={tbody}>
        {#if first > 0}<tr class="spacer" aria-hidden="true" style:height="{first * rowH}px"><td colspan={detail ? 8 : 4}></td></tr>{/if}
        {#each drawn as f, k (detail ? f.id : overviewKey(f))}
          {@const i = first + k}
          <tr
            data-i={i}
            class:closed={detail && f.closed}
            class:sel={isSelected(f)}
            tabindex={i === tabRow ? 0 : -1}
            onfocus={() => (focusIndex = i)}
            onkeydown={rowKey}
            onclick={() => choose(f)}
            oncontextmenu={(e) => {
              e.preventDefault();
              if (performance.now() - keyMenuAt < 500) return; // the key already opened it
              openMenu(f, { x: e.clientX, y: e.clientY }, e.currentTarget as HTMLElement);
            }}
          >
            {#if detail}
            <td class="mono">{fmtTime(f.start)}</td>
            <td title={hideUserPath(f.path)}>{hide(f.process) || 'Не определён'}<small>PID {f.pid}</small></td>
            <td title={hide(f.domain) || hide(f.dst)}>{hide(f.domain) || 'Имя неизвестно'}{#if (f.count ?? 0) > 1}<span class="muted"> ×{f.count}</span>{/if}{#if srcLabel[f.domainSrc]}<span class="src">{srcLabel[f.domainSrc]}</span>{/if}<small class="mono">{f.proto} {hide(f.dst)}</small></td>
            <td title={ruleText(f.rule)}>{ruleText(f.rule)}{#if f.excluded}<span class="src">служебное</span>{/if}<small class="route-{f.route}" title={routeText(f)}>{flowFailed(f) ? 'Попытка · ' : ''}{routeText(f)}</small></td>
            <td title={hide(f.outcome)}>{hide(f.outcome)}</td>
            <td class="num">{fmtBytes(f.recv)} / {fmtBytes(f.sent)}</td>
            <td class="num">{fmtDuration(f.duration)}</td>
            {:else}
            {@const count = groups?.get(overviewKey(f))?.count ?? 1}
            <td title={hide(f.domain || f.dst)}><b>{hide(f.domain || f.dst)}</b><small>{hide(f.process) || `PID ${f.pid}`}{count > 1 ? ' · ×' + count : ''}</small></td>
            <td class:bad-text={flowFailed(f)}><span class="rowstate"><Icon name={flowFailed(f) ? 'alert' : f.route === 'block' ? 'shield' : 'activity'} size={14}/>{flowState(f)}</span></td>
            <td title={simpleRoute(f)}>{simpleRoute(f)}</td>
            {/if}
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
        {#if last < rows.length}<tr class="spacer" aria-hidden="true" style:height="{(rows.length - last) * rowH}px"><td colspan={detail ? 8 : 4}></td></tr>{/if}
      </tbody>
    </table>
    {#if rows.length === 0}<p class="muted empty">{failedOnly ? 'Неудачных подключений по этому фильтру нет.' : query || route !== 'all' ? 'Совпадений нет.' : 'Соединений нет. Они появляются после подключения.'}</p>{/if}
  </div>

  {#if selected}
    <div class="card details">
      <div class="head">
      <div class="why"><b>{hide(selected.process) || `PID ${selected.pid}`}</b> · {hide(selected.domain) || hide(selected.dst)}{#if selected.stage === 'dns'}: {routeText(selected)}{/if}</div>
      <div class="dbtns">
        <button
          onclick={(e) => {
            const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
            openMenu(selected!, { x: r.left, y: r.bottom }, e.currentTarget as HTMLElement);
          }}><Icon name="wand" size={15} />{!detail && flowFailed(selected) && selected.route === 'tunnel' ? 'Выбрать другой сервер…' : 'Изменить маршрут…'}</button
        >
        <button class="icon" aria-label="Закрыть" onclick={() => (selected = null)}>×</button>
      </div>
      </div>
      <div>{detail ? whyText(selected) : summary(selected)}</div>
      {#if !detail}<button class="link more-facts" aria-expanded={expanded} onclick={() => (expanded = !expanded)}>Технические детали</button>{/if}
      {#if detail || expanded}
      {#if selected.stage !== 'dns'}
        <ConnectionComparison flow={selected} />
      {/if}
      <div class="mono small facts">
        <span>{hideUserPath(selected.path || selected.process)} (PID {selected.pid})</span>
        <span>{selected.proto} {hide(selected.src)} → {hide(selected.dst)}</span>
        <span>исход: {hide(selected.outcome)} · процесс найден: {attribLabel[selected.attrib] ?? selected.attrib} · решение: {selected.stage}</span>
        {#if selected.group}<span>Группа: {groupText(selected.group)}</span>{/if}
        {#if selected.tooBig}
          <span>датаграмм больше предела Hysteria (около 4 КБ) отброшено: {selected.tooBig}</span>
        {/if}
      </div>
      <div class="row"><button class="link" onclick={() => selected && copyFacts(selected)}><Icon name="copy" size={14}/>Скопировать детали</button><span role="status" class="muted small">{copyMessage}</span></div>
      {/if}
    </div>
  {/if}
</div>

{#if menu}
  {#key menu}
    <ConnMenu
      flow={menu.flow}
      anchor={menu.anchor}
      returnFocus={menu?.el ?? null}
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
  .overview { width: 100%; table-layout: fixed; }
  .overview th:first-child { width: 39%; }
  .overview .act { width: 30px; }
  .overview td { padding: 6px 8px; }
  .overview td b, .overview td small { display: block; overflow: hidden; text-overflow: ellipsis; }
  .overview td small { color: var(--muted); }
  td small { display: block; color: var(--muted); overflow: hidden; text-overflow: ellipsis; }
  .rowstate { display: inline-flex; align-items: center; gap: 6px; }
  .more-facts { justify-self: start; }
  .details { max-height: 50%; overflow: auto; }
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
  tr.spacer td { padding: 0; border: none; }
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
