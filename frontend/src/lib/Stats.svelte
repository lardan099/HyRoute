<script lang="ts">
  // «Статистика»: how much traffic went through HyRoute, by program, site,
  // server and group (internal/stats). Direct ↓ is never shown: HyRoute does
  // not see it.
  import { onMount } from 'svelte';
  import { api, errText, fmtBytes, plural, statConns, statVPN, type StatCounters, type StatRow, type StatsMode, type StatsReport } from '../api';
  import { ui, hide, profileName, settle } from '../state.svelte';
  import Help from './Help.svelte';

  type Tab = 'apps' | 'servers' | 'groups';
  type SortKey = 'label' | 'vpn' | 'du' | 'conns' | 'f' | 'tu' | 'td' | 'fo' | 'drops';

  const periods = [
    { v: 'today', l: 'Сегодня' },
    { v: 'yesterday', l: 'Вчера' },
    { v: '7d', l: '7 дней' },
    { v: '30d', l: '30 дней' },
  ];

  let period = $state('today');
  let report = $state<StatsReport | null>(null);
  let error = $state('');
  let modeError = $state('');
  let query = $state('');
  let tab = $state<Tab>(storedTab());
  let sort = $state<{ key: SortKey; desc: boolean }>({ key: 'vpn', desc: true });
  let all = $state(false);

  function storedTab(): Tab {
    try {
      const v = localStorage.getItem('hyroute.stats.tab');
      if (v === 'apps' || v === 'servers' || v === 'groups') return v;
    } catch {}
    return 'apps';
  }

  function setTab(t: Tab) {
    tab = t;
    all = false;
    sort = { key: 'vpn', desc: true };
    try {
      localStorage.setItem('hyroute.stats.tab', t);
    } catch {}
  }

  // ---- loading ----

  // Every request bumps seq: an answer for an earlier period never replaces
  // a newer one. A poll tick is skipped while a request is in flight.
  let seq = 0;
  let inflight: Promise<void> | null = null;

  async function fetchReport() {
    const my = ++seq;
    try {
      const r = await api.Stats(period);
      if (my === seq) {
        report = r;
        error = '';
      }
    } catch (e) {
      if (my === seq) error = hide(errText(e));
    }
  }

  function start(): Promise<void> {
    const p = fetchReport().finally(() => {
      if (inflight === p) inflight = null;
    });
    inflight = p;
    return p;
  }

  function tick() {
    if (inflight || document.hidden) return;
    start();
  }

  async function reload() {
    if (inflight) await inflight;
    await start();
  }

  function setPeriod(p: string) {
    if (!p || p === period) return;
    period = p;
    all = false;
    reload();
  }

  const thisMonth = () => new Date().toLocaleDateString('sv-SE').slice(0, 7); // YYYY-MM, local
  // The period includes today: it grows while HyRoute is connected.
  const live = $derived(period === 'today' || period === '7d' || period === '30d' || period === thisMonth());

  onMount(() => {
    start();
    const onVisible = () => {
      if (!document.hidden) tick();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => document.removeEventListener('visibilitychange', onVisible);
  });

  $effect(() => {
    if (!live) return;
    const t = setInterval(tick, 5000);
    return () => clearInterval(t);
  });

  // ---- texts ----

  const conns = (n: number) => `${n} ${plural(n, 'соединение', 'соединения', 'соединений')}`;
  const tries = (n: number) => `${n} ${plural(n, 'попытка', 'попытки', 'попыток')}`;

  function dateOf(day: string): Date {
    const [y, m, d] = day.split('-').map(Number);
    return new Date(y, m - 1, d);
  }
  const dm = (day: string) => day.slice(8, 10) + '.' + day.slice(5, 7);
  const dmy = (day: string) => dm(day) + '.' + day.slice(0, 4);
  const dayMonth = (day: string) => dateOf(day).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' });
  const monthName = (m: string) =>
    dateOf(m + '-01')
      .toLocaleDateString('ru-RU', { month: 'long', year: 'numeric' })
      .replace(/\s*г\.$/, '');

  function periodText(r: StatsReport): string {
    if (/^\d{4}-\d{2}$/.test(r.period)) return monthName(r.period);
    if (r.from === r.to) return dayMonth(r.from);
    if (r.from.slice(0, 7) === r.to.slice(0, 7)) return `${Number(r.from.slice(8))}–${dayMonth(r.to)}`;
    return `${dayMonth(r.from)} – ${dayMonth(r.to)}`;
  }

  const isMonth = $derived(/^\d{4}-\d{2}$/.test(period));
  const months = $derived.by(() => {
    const m = report?.months ?? [];
    return m.includes(thisMonth()) ? m : [thisMonth(), ...m];
  });

  const disconnected = $derived(ui.status?.state === 'disconnected' || ui.status?.state === 'error');
  const total = $derived<StatCounters>(report?.total ?? {});
  const empty = $derived(
    !!report && !report.apps.length && !report.servers.length && !report.groups.length && !statConns(total) && !statVPN(total) && !total.du,
  );

  const refusedTitle =
    'Соединения, которые не открылись: сервер был недоступен или не ответил, сайт не принял соединение через сервер, не удалось подключиться напрямую или датаграммы UDP были больше, чем передаёт Hysteria. Их трафик не считается';

  const errorLines = $derived.by(() => {
    const e = report?.events ?? {};
    return [
      { v: total.f ?? 0, l: 'Отклонено соединений', t: refusedTitle, info: false },
      { v: total.fo ?? 0, l: 'Ушло на запасной сервер', t: 'Соединение пошло не через основной сервер правила или группы, потому что тот был недоступен', info: true },
      { v: e.drops ?? 0, l: 'Обрывы связи с сервером', t: 'Сколько раз работавший сервер терял связь (заметно, если дольше нескольких секунд)', info: false },
      { v: e.engineFails ?? 0, l: 'Сбои перехвата', t: 'Отказы движка перехвата, после которых HyRoute переподключался', info: false },
    ].filter((x) => x.v > 0);
  });

  // ---- chart ----

  const bars = $derived(report && report.days.length > 1 ? report.days : []);
  const peak = $derived(Math.max(1, ...bars.map(statVPN)));
  function barTitle(d: StatCounters & { day: string }): string {
    return `${dm(d.day)}: через VPN ${fmtBytes(statVPN(d))} (↑ ${fmtBytes(d.tu ?? 0)} ↓ ${fmtBytes(d.td ?? 0)}), напрямую ↑ ≈${fmtBytes(d.du ?? 0)}, соединений ${statConns(d)}`;
  }

  // ---- tables ----

  const tabs = $derived.by(() => {
    const t: { v: Tab; l: string }[] = [
      { v: 'apps', l: 'Программы' },
      { v: 'servers', l: 'Серверы' },
    ];
    // History of deleted groups stays reachable.
    if ((report?.groups.length ?? 0) > 0 || ui.groups.length > 0) t.push({ v: 'groups', l: 'Группы' });
    return t;
  });
  const shownTab = $derived<Tab>(tabs.some((t) => t.v === tab) ? tab : 'apps');

  function label(t: Tab, r: StatRow): { text: string; title: string } {
    if (r.k === '*') {
      const what = { apps: 'Программы', servers: 'Серверы', groups: 'Группы' }[t];
      return { text: 'Остальные', title: `${what}, не вошедшие в список за этот период` };
    }
    switch (t) {
      case 'apps':
        if (r.k === '') return { text: 'Программа не определена', title: 'Соединения, владельца которых HyRoute не нашёл' };
        if (r.k.startsWith('proxy:')) return { text: `Прокси «${hide(r.n || r.k.slice(6))}»${r.gone ? ' (удалён)' : ''}`, title: 'Локальный прокси' };
        return { text: hide(r.n || r.k.split('\\').pop() || r.k), title: hide(r.k) };
      case 'servers':
        if (r.k === '') return { text: 'Сервер не выбран', title: 'Соединения, которые правила отправили в VPN, когда основной сервер не был выбран: они отклонены' };
        if (r.gone) return { text: `${hide(r.n) || 'сервер'} (удалён)`, title: '' };
        return { text: r.n ? hide(r.n) : profileName(r.k), title: '' };
      case 'groups':
        if (r.gone) return { text: `${hide(r.n) || 'группа'} (удалена)`, title: '' };
        return { text: r.n ? hide(r.n) : profileName(r.k), title: '' };
    }
    return { text: hide(r.k), title: '' };
  }

  function value(r: StatRow, k: SortKey): number {
    switch (k) {
      case 'vpn':
        return statVPN(r);
      case 'du':
        return r.du ?? 0;
      case 'conns':
        return shownTab === 'servers' || shownTab === 'groups' ? (r.tc ?? 0) + (r.f ?? 0) : statConns(r);
      case 'f':
        return r.f ?? 0;
      case 'tu':
        return r.tu ?? 0;
      case 'td':
        return r.td ?? 0;
      case 'fo':
        return r.fo ?? 0;
      case 'drops':
        return r.drops ?? 0;
    }
    return 0;
  }

  const rows = $derived.by(() => {
    if (!report) return [];
    const t = shownTab;
    const q = query.trim().toLowerCase();
    const list = report[t]
      .map((r) => ({ r, ...label(t, r) }))
      .filter((x) => !q || x.text.toLowerCase().includes(q));
    const { key, desc } = sort;
    const dir = desc ? -1 : 1;
    list.sort((a, b) => {
      // «Остальные» stays last.
      if ((a.r.k === '*') !== (b.r.k === '*')) return a.r.k === '*' ? 1 : -1;
      if (key === 'label') return dir * a.text.localeCompare(b.text, 'ru');
      const d = value(a.r, key) - value(b.r, key);
      if (d) return dir * d;
      return value(b.r, 'conns') - value(a.r, 'conns');
    });
    return list;
  });
  const visible = $derived(all ? rows : rows.slice(0, 100));

  function sortBy(k: SortKey) {
    sort = sort.key === k ? { key: k, desc: !sort.desc } : { key: k, desc: k !== 'label' };
  }
  const arrow = (k: SortKey) => (sort.key === k ? (sort.desc ? ' ↓' : ' ↑') : '');

  // ---- collection ----

  // The select's value: «Не выбран» while mode.json could not be read (the
  // collection is off then, and «Выключен» must still be choosable).
  const modeValue = () => (report?.modeUnread ? '?' : report?.mode === 'off' ? 'off' : 'on');

  async function setMode(e: Event) {
    await settle(
      e,
      async (el) => {
        const m = el.value as StatsMode;
        if (m === modeValue()) return;
        try {
          await api.SetStatsMode(m);
          modeError = '';
        } catch (err) {
          // «Режим применён, но не сохранён: …»
          const t = hide(errText(err));
          modeError = t.charAt(0).toUpperCase() + t.slice(1);
        }
        await reload();
      },
      modeValue,
    );
  }

  async function reset() {
    if (!confirm('Удалить всю статистику? Это нельзя отменить.')) return;
    try {
      await api.ResetStats();
    } catch (e) {
      error = hide(errText(e));
      return;
    }
    await reload();
  }
</script>

<div class="page-wrap">
  <header>
    <h1>Статистика</h1>
    <p class="muted sub">Сколько трафика прошло через HyRoute: по программам и серверам.</p>
  </header>

  <Help id="stats" title="Что здесь считается">
    <p>
      Сколько трафика прошло через VPN и напрямую: по программам и серверам. Статистика хранится только на этом компьютере и никуда не
      отправляется.
    </p>
    <ul>
      <li>Какие сайты вы открывали, статистика не запоминает: только сколько трафика прошло и через какую программу и сервер.</li>
      <li>Выключить сбор можно внизу страницы, в «Сборе статистики».</li>
      <li>Трафик напрямую считается примерно и только отправленный (↑).</li>
    </ul>
  </Help>

  <div class="row toolbar">
    <div class="seg" role="group" aria-label="Период">
      {#each periods as p}
        <button class:on={period === p.v} aria-pressed={period === p.v} onclick={() => setPeriod(p.v)}>{p.l}</button>
      {/each}
    </div>
    <select aria-label="Месяц" value={isMonth ? period : ''} onchange={(e) => setPeriod((e.currentTarget as HTMLSelectElement).value)}>
      {#if !isMonth}<option value="">Месяц…</option>{/if}
      {#each months as m}<option value={m}>{monthName(m)}</option>{/each}
    </select>
    <input class="grow search" placeholder="Поиск: программа, сервер" bind:value={query} />
  </div>

  {#if report}
    <div class="muted small period">
      {periodText(report)}{#if report.since && report.since > report.from}<span> · Статистика собирается с {dmy(report.since)}</span>{/if}
    </div>
    {#if disconnected}<div class="muted small">HyRoute отключён: новые данные не собираются.</div>{/if}
  {/if}

  {#if report?.mode === 'off' && !report?.modeUnread}<div class="note info">Сбор статистики выключен. Уже собранная статистика показана ниже.</div>{/if}
  {#if report?.modeUnread}
    <div class="note warn">Не удалось прочитать режим сбора статистики, поэтому сбор выключен. Выберите режим в «Сбор статистики» внизу страницы.</div>
  {:else if report?.storeError}
    <div class="note warn">Не всё в порядке с файлами статистики: {hide(report.storeError)}</div>
  {/if}
  {#if error}<div class="note error">{error}</div>{/if}

  {#if !report}
    {#if !error}<p class="muted">Загрузка…</p>{/if}
  {:else}
    <div class="cards">
      <section class="card stat">
        <span class="muted">Через VPN</span>
        <b>{fmtBytes(statVPN(total))}</b>
        <span class="small">↑ {fmtBytes(total.tu ?? 0)} · ↓ {fmtBytes(total.td ?? 0)}</span>
        <span class="muted small">{conns(total.tc ?? 0)}</span>
      </section>
      <section class="card stat">
        <span class="muted">Напрямую</span>
        <b>↑ {fmtBytes(total.du ?? 0)}</b>
        <span
          class="small hint"
          title="HyRoute не перехватывает входящие пакеты прямых соединений, поэтому видит только отправленное, и то примерно: с повторными отправками. Прямые TCP-соединения, открытые до подключения или переподключения HyRoute, а также долго простаивавшие, не считаются совсем, поэтому за долгий сеанс реальный объём больше."
          >примерно, входящий не считается</span
        >
        <span class="muted small hint" title="Попытки прямых соединений: HyRoute не знает, ответил ли сайт">{tries(total.dc ?? 0)}</span>
      </section>
      <section class="card stat">
        <span class="muted">Заблокировано</span>
        <b>{total.bc ?? 0}</b>
        <span
          class="small hint"
          title="Соединения, которые HyRoute не пропустил: по правилам «Блокировать», QUIC, пока домен неизвестен (если QUIC блокируется), и IPv6 к серверам, которые его не поддерживают"
          >соединений: правила, QUIC, IPv6 для VPN</span
        >
      </section>
      <section class="card stat">
        <span class="muted">Ошибки</span>
        {#each errorLines as x}
          <span class="small hint" class:bad={!x.info} title={x.t}>{x.l}: {x.v}</span>
        {:else}
          <span class="small muted">Ошибок не было</span>
        {/each}
      </section>
    </div>

    {#if empty}
      <p class="muted empty">За этот период статистики нет. Она собирается, пока HyRoute подключён.</p>
    {:else}
      {#if bars.length}
        <section class="card chart">
          <h2>По дням</h2>
          <div class="bars" class:dense={bars.length > 20}>
            {#each bars as d (d.day)}
              <div class="bar" title={barTitle(d)}>
                <div class="fill" class:zero={!statVPN(d)} style="height: {statVPN(d) ? Math.max(1, (statVPN(d) / peak) * 100) : 0}%"></div>
              </div>
            {/each}
          </div>
          <div class="axis muted small">
            <span>{dm(bars[0].day)}</span>
            {#if bars.length > 2}<span>{dm(bars[Math.floor((bars.length - 1) / 2)].day)}</span>{/if}
            <span>{dm(bars[bars.length - 1].day)}</span>
          </div>
        </section>
      {/if}

      <div class="seg tabs" role="tablist" aria-label="Разрез">
        {#each tabs as t}
          <button role="tab" aria-selected={shownTab === t.v} class:on={shownTab === t.v} onclick={() => setTab(t.v)}>{t.l}</button>
        {/each}
      </div>

      <div class="table panel">
        <table>
          <thead>
            <tr>
              {#if shownTab === 'apps'}
                <th><button class="th" onclick={() => sortBy('label')}>Программа{arrow('label')}</button></th>
                <th class="num"><button class="th" onclick={() => sortBy('vpn')}>Через VPN{arrow('vpn')}</button></th>
                <th class="num"><button class="th" title="примерно, не меньше" onclick={() => sortBy('du')}>Напрямую ↑{arrow('du')}</button></th>
                <th class="num"><button class="th" onclick={() => sortBy('conns')}>Соединений{arrow('conns')}</button></th>
                <th class="num"><button class="th" title={refusedTitle} onclick={() => sortBy('f')}>Отклонено{arrow('f')}</button></th>
              {:else}
                <th><button class="th" onclick={() => sortBy('label')}>{shownTab === 'servers' ? 'Сервер' : 'Группа'}{arrow('label')}</button></th>
                <th class="num"><button class="th" onclick={() => sortBy('tu')}>↑{arrow('tu')}</button></th>
                <th class="num"><button class="th" onclick={() => sortBy('td')}>↓{arrow('td')}</button></th>
                <th class="num"><button class="th" onclick={() => sortBy('conns')}>Соединений{arrow('conns')}</button></th>
                <th class="num"><button class="th" title={refusedTitle} onclick={() => sortBy('f')}>Отклонено{arrow('f')}</button></th>
                <th class="num">
                  <button
                    class="th"
                    title="Соединения, которые пришли на этот {shownTab === 'servers' ? 'сервер' : 'группу'} как на запасной"
                    onclick={() => sortBy('fo')}>Запасной{arrow('fo')}</button
                  >
                </th>
                {#if shownTab === 'servers'}<th class="num"><button class="th" onclick={() => sortBy('drops')}>Обрывы{arrow('drops')}</button></th>{/if}
              {/if}
            </tr>
          </thead>
          <tbody>
            {#each visible as x (x.r.k)}
              {@const r = x.r}
              <tr>
                <td class="name" title={x.title || x.text}>{x.text}</td>
                {#if shownTab === 'apps'}
                  <td class="num" title="↑ {fmtBytes(r.tu ?? 0)} ↓ {fmtBytes(r.td ?? 0)}">{fmtBytes(statVPN(r))}</td>
                  <td class="num" title="примерно, не меньше">{r.du ? fmtBytes(r.du) : ''}</td>
                  <td class="num" title="VPN {r.tc ?? 0} · напрямую (попыток) {r.dc ?? 0} · блок {r.bc ?? 0} · отклонено {r.f ?? 0}">{statConns(r)}</td>
                  <td class="num">{r.f || ''}</td>
                {:else}
                  <td class="num">{fmtBytes(r.tu ?? 0)}</td>
                  <td class="num">{fmtBytes(r.td ?? 0)}</td>
                  <td class="num">{(r.tc ?? 0) + (r.f ?? 0)}</td>
                  <td class="num">{r.f || ''}</td>
                  <td class="num">{r.fo || ''}</td>
                  {#if shownTab === 'servers'}<td class="num">{r.drops || ''}</td>{/if}
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
        {#if !rows.length}<p class="muted none">{query.trim() ? 'Ничего не найдено.' : 'Пусто.'}</p>{/if}
      </div>
      {#if !all && rows.length > 100}
        <button class="ghost more" onclick={() => (all = true)}>Показать все ({rows.length})</button>
      {/if}
    {/if}

    <section class="card">
      <h2>Сбор статистики</h2>
      <div class="row">
        <select aria-label="Сбор статистики" value={modeValue()} onchange={setMode}>
          {#if report.modeUnread}<option value="?" disabled>Не выбран</option>{/if}
          <option value="on">Включён</option>
          <option value="off">Выключен</option>
        </select>
        <span class="grow"></span>
        <button class="danger" onclick={reset}>Сбросить статистику</button>
      </div>
      {#if modeError}<div class="note warn">{modeError}</div>{/if}
      <p class="muted small">
        Статистика хранится только на этом компьютере, в папке %APPDATA%\HyRoute\stats: по дням за последние 90 дней, по месяцам за 2 года.
        Считаются данные программ без заголовков и шифрования, поэтому у провайдера и в панели VPN объём немного больше. У прямых соединений
        HyRoute видит только отправленное, и то примерно и не всё. Служебный трафик (DNS Windows, сам HyRoute и Hysteria) не считается.
      </p>
    </section>
  {/if}
</div>

<style>
  .page-wrap { display: grid; gap: 12px; }
  .sub { margin: 4px 0 0; }
  .toolbar select { min-width: 160px; }
  .search { max-width: 340px; }
  .period { display: flex; flex-wrap: wrap; gap: 4px; }
  .cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
  .stat { display: grid; align-content: start; gap: 4px; padding: 14px 16px; }
  .stat b { font-size: 22px; font-weight: 700; }
  .hint { cursor: help; }
  .bad { color: var(--block); }
  .empty { margin: 24px 0; text-align: center; }
  .chart { padding: 16px; }
  .chart h2 { margin-bottom: 10px; }
  .bars { display: flex; align-items: flex-end; gap: 4px; height: 140px; }
  .bars.dense { gap: 2px; }
  .bar { flex: 1; min-width: 0; height: 100%; display: flex; align-items: flex-end; border-bottom: 1px solid var(--border); }
  .fill { width: 100%; border-radius: 3px 3px 0 0; background: var(--accent); }
  .fill.zero { height: 1px !important; background: var(--border); }
  .axis { display: flex; justify-content: space-between; margin-top: 6px; }
  .tabs { justify-self: start; }
  .table { overflow: auto; padding: 0; border-radius: var(--radius); }
  table { font-size: 12.5px; }
  th { background: var(--panel-2); text-align: left; font-weight: 600; padding: 0; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .th { width: 100%; justify-content: inherit; background: none; padding: 6px 8px; font: inherit; color: inherit; border-radius: 0; }
  th.num .th { justify-content: flex-end; }
  td { padding: 4px 8px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  td.name { max-width: 360px; overflow: hidden; text-overflow: ellipsis; }
  .num { text-align: right; }
  .none { padding: 12px 16px; margin: 0; }
  .more { justify-self: start; }
  @media (max-width: 1000px) {
    .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
  @media (max-width: 600px) {
    .cards { grid-template-columns: 1fr; }
    .search { max-width: none; }
  }
</style>
