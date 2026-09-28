<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, fmtBytes, fmtDuration, fmtTime, actionLabel, type Flow } from '../api';
  import { hide, profileName } from '../state.svelte';
  import RuleFromFlow from './RuleFromFlow.svelte';
  import Icon from './Icon.svelte';

  function routeText(f: Flow): string {
    const r = actionLabel[f.route] ?? f.route;
    return f.route === 'tunnel' && f.profile ? `${r} → ${profileName(f.profile)}` : r;
  }

  let active = $state<Flow[]>([]);
  let closed = $state<Flow[]>([]);
  let query = $state('');
  let route = $state('all');
  let showClosed = $state(true);
  let paused = $state(false);
  let error = $state('');
  let selected = $state<Flow | null>(null);
  // The connection a rule is being made from (a snapshot: the row may go).
  let ruleFrom = $state<Flow | null>(null);
  // Right-click on a row: the same, at once.
  let menu = $state<{ f: Flow; x: number; y: number } | null>(null);

  // Mandatory exclusions (HyRoute, Hysteria, the system DNS) take no rules.
  const canRule = (f: Flow) => !f.excluded && !f.rule.startsWith('exclusion');

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
      .filter((f) => route === 'all' || f.route === route)
      .filter(
        (f) =>
          !q ||
          f.process.toLowerCase().includes(q) ||
          f.domain.toLowerCase().includes(q) ||
          f.dst.includes(q) ||
          f.rule.toLowerCase().includes(q) ||
          profileName(f.profile).toLowerCase().includes(q) ||
          f.outcome.toLowerCase().includes(q),
      )
      .slice(0, 1500);
  });

  const srcName: Record<string, string> = { sni: 'по SNI (имя сайта в HTTPS)', host: 'по заголовку Host (HTTP)', dns: 'по кэшу DNS', unknown: '' };

  function whyText(f: Flow): string {
    const rule = !f.rule || f.rule === 'default' ? 'сработало «Всё остальное»' : f.rule.startsWith('exclusion') ? 'служебное исключение HyRoute' : `сработало правило «${f.rule}»`;
    const dom = f.domain ? `, сайт определён ${srcName[f.domainSrc] ?? f.domainSrc}` : ', сайт не определён';
    return rule[0].toUpperCase() + rule.slice(1) + dom + '.';
  }

  const srcLabel: Record<string, string> = { sni: 'SNI', host: 'Host', dns: 'DNS', unknown: '' };
</script>

<div class="wrap">
  <header>
    <h1>Соединения</h1>
    <p class="muted sub">
      Что сейчас открывают программы и куда это ушло. Нажмите на строку, чтобы увидеть, почему; правой кнопкой — создать правило для этой программы или
      сайта.
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
    <span class="muted">активных {active.length}, закрытых {closed.length}</span>
  </div>
  {#if error}<div class="note error">{error}</div>{/if}

  <div class="table panel" data-selectall>
    <table>
      <thead>
        <tr>
          <th>Время</th><th>Процесс</th><th>Назначение</th><th>Домен</th><th>Правило</th><th>Маршрут</th><th>Исход</th>
          <th class="num">↑</th><th class="num">↓</th><th class="num">Длит.</th>
        </tr>
      </thead>
      <tbody>
        {#each rows as f (f.id)}
          <tr
            class:closed={f.closed}
            class:sel={selected?.id === f.id}
            onclick={() => (selected = f)}
            oncontextmenu={(e) => {
              e.preventDefault();
              selected = f;
              menu = canRule(f) ? { f: JSON.parse(JSON.stringify(f)), x: e.clientX, y: e.clientY } : null;
            }}
          >
            <td class="mono">{fmtTime(f.start)}</td>
            <td title={f.path}>{f.process || `PID ${f.pid}`}</td>
            <td class="mono">{f.proto} {hide(f.dst)}</td>
            <td title={hide(f.domain)}>{hide(f.domain)}{#if srcLabel[f.domainSrc]}<span class="src">{srcLabel[f.domainSrc]}</span>{/if}</td>
            <td title={f.rule}>{!f.rule || f.rule === 'default' ? 'Всё остальное' : f.rule}</td>
            <td class="route-{f.route}" title={routeText(f)}>{routeText(f)}</td>
            <td title={f.outcome}>{f.outcome}</td>
            <td class="num">{fmtBytes(f.sent)}</td>
            <td class="num">{fmtBytes(f.recv)}</td>
            <td class="num">{fmtDuration(f.duration)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if rows.length === 0}<p class="muted empty">Соединений нет. Они появляются после подключения.</p>{/if}
  </div>

  {#if selected}
    <div class="card details">
      <button class="icon close" onclick={() => (selected = null)}>×</button>
      <div class="why route-{selected.route}"><b>{selected.process || `PID ${selected.pid}`}</b> → {hide(selected.domain) || hide(selected.dst)}: {routeText(selected)}</div>
      <div class="muted">{whyText(selected)}</div>
      <div class="mono small facts">
        <span>{hide(selected.path || selected.process)} (PID {selected.pid})</span>
        <span>{selected.proto} {hide(selected.src)} → {hide(selected.dst)}</span>
        <span>исход: {selected.outcome} · процесс найден: {selected.attrib} · решение: {selected.stage}</span>
      </div>
      {#if canRule(selected)}
        <div class="row">
          <button onclick={() => (ruleFrom = JSON.parse(JSON.stringify(selected)))}><Icon name="plus" size={15} />Создать правило…</button>
          <span class="muted small">например, пустить эту программу или сайт через другой сервер или напрямую</span>
        </div>
      {/if}
    </div>
  {/if}
</div>

{#if menu}
  <div class="menu-shade" role="presentation" onclick={() => (menu = null)} oncontextmenu={(e) => (e.preventDefault(), (menu = null))}></div>
  <div class="menu" style="left: {Math.min(menu.x, window.innerWidth - 220)}px; top: {Math.min(menu.y, window.innerHeight - 60)}px">
    <button
      onclick={() => {
        ruleFrom = menu!.f;
        menu = null;
      }}><Icon name="plus" size={15} />Создать правило…</button
    >
  </div>
{/if}

{#if ruleFrom}
  <RuleFromFlow flow={ruleFrom} onclose={() => (ruleFrom = null)} />
{/if}

<style>
  .wrap { display: flex; flex-direction: column; height: 100%; gap: 10px; }
  .toolbar input { max-width: 420px; }
  .table { flex: 1; min-height: 0; overflow: auto; padding: 0; border-radius: var(--radius); }
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
  tr { cursor: default; }
  tr.closed td { opacity: 0.6; }
  tr.sel td { background: var(--panel-2); }
  .num { text-align: right; }
  .src { font-size: 10px; margin-left: 5px; padding: 0 4px; border-radius: 4px; background: var(--panel-2); color: var(--muted); }
  .empty { padding: 16px; }
  .details { position: relative; user-select: text; display: grid; gap: 4px; padding: 14px 16px; }
  .why { font-weight: 600; }
  .facts { display: grid; gap: 2px; color: var(--muted); margin-top: 4px; }
  .sub { margin: 4px 0 0; }
  .close { position: absolute; right: 8px; top: 8px; }
  .details .row { margin-top: 6px; }
  .menu-shade { position: fixed; inset: 0; z-index: 40; }
  .menu { position: fixed; z-index: 41; display: grid; padding: 4px; min-width: 200px; border-radius: var(--radius-sm); background: var(--surface); border: 1px solid var(--border); box-shadow: 0 8px 24px rgb(0 0 0 / 0.28); }
  .menu button { justify-content: flex-start; background: none; }
  .menu button:hover { background: var(--accent-soft); }
</style>
