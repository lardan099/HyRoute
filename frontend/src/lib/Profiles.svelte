<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, fmtBytes, type ProfileSummary, type Profile, type ImportResult } from '../api';
  import { ui, hide } from '../state.svelte';
  import Icon from './Icon.svelte';
  import ProfileEditor from './ProfileEditor.svelte';
  import CheckProfile from './CheckProfile.svelte';
  import Help from './Help.svelte';
  import Groups from './Groups.svelte';

  let { onchange }: { onchange: () => void } = $props();

  // groups: the page has two tabs, «Серверы» and «Группы» (remembered).
  function storedTab(): 'servers' | 'groups' {
    try {
      return localStorage.getItem('hyroute.serversTab') === 'groups' ? 'groups' : 'servers';
    } catch {
      return 'servers';
    }
  }
  let tab = $state(storedTab());
  function setTab(t: 'servers' | 'groups') {
    tab = t;
    try {
      localStorage.setItem('hyroute.serversTab', t);
    } catch {}
  }
  // Groups are edited in the full interface; the simple one only picks
  // them as targets.
  const view = $derived(ui.expert ? tab : 'servers');

  // The list is the shared one: App reloads it on every change the backend
  // reports, a background subscription update included, so the page never
  // shows (and moves by) a list that is no longer there.
  const list = $derived(ui.profiles);

  // The list's view, the window's own (not settings), as on «Правила»: a
  // search over names, addresses, subscriptions and protocols, and rows in
  // one line. dense: the user's choice once made, else by the list's
  // length.
  let query = $state('');
  let compact = $state<boolean | null>(storedCompact());
  const q = $derived(query.trim().toLowerCase());
  const dense = $derived(compact ?? list.length > 8);
  const has = (text: string | undefined) => (text ?? '').toLowerCase().includes(q);
  const found = $derived(q ? list.filter((p) => has(p.name) || has(p.server) || has(p.sourceName) || has(p.protocol) || has(p.transport)) : list);

  // «Проверить все»: the backend measures the servers in the background
  // and the results come with the list (pingMs, pingErr, pingAt). byPing
  // shows the list by them, the fastest first; the order of the servers
  // itself stays, and is not changed while the list is shown so.
  const left = $derived(list.filter((p) => p.pinging).length);
  const pinging = $derived(left > 0);
  const measured = $derived(list.some((p) => p.pingAt));
  let byPing = $state(false);
  let mine = $state(false); // a run of all servers started here: its end sorts the list
  const ranked = $derived(byPing && measured);
  // Those that answered by their delay, then those not measured, then
  // those that did not answer.
  const rank = (p: ProfileSummary) => (p.pingMs ? p.pingMs : p.pingAt ? 2e9 : 1e9);
  const shown = $derived(ranked ? [...found].sort((a, b) => rank(a) - rank(b)) : found);
  // fixed: why the servers cannot be moved now ('' they can).
  const fixed = $derived(q ? 'Очистите поиск, чтобы менять порядок' : ranked ? 'Включите «Свой порядок», чтобы менять порядок' : '');

  $effect(() => {
    if (!mine || pinging) return;
    mine = false;
    if (measured) byPing = true;
  });

  async function ping(ids: string[]) {
    error = '';
    info = '';
    try {
      await api.PingServers(ids);
      await load();
      if (!ids.length) mine = true;
    } catch (e) {
      error = errText(e);
    }
  }

  function pingTitle(p: ProfileSummary): string {
    const at = new Date((p.pingAt ?? 0) * 1000).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' });
    const what = p.pingMs ? `Пинг ${p.pingMs} мс: время ответа на короткий запрос через сервер` : `Сервер не ответил: ${hide(p.pingErr ?? '')}`;
    return `${what}. Измерено в ${at}. Щёлкните, чтобы измерить заново.`;
  }
  // Servers of more than one place (subscriptions, added by hand): a
  // compact list says where each run of them comes from.
  const places = $derived(new Set(list.map((p) => p.source || '')).size);

  function storedCompact(): boolean | null {
    try {
      const v = localStorage.getItem('hyroute.serversCompact');
      return v === '1' ? true : v === '0' ? false : null;
    } catch {
      return null;
    }
  }

  function setCompact(on: boolean) {
    compact = on;
    try {
      localStorage.setItem('hyroute.serversCompact', on ? '1' : '0');
    } catch {}
  }

  function usedText(p: ProfileSummary): string {
    return p.usedBy.length ? 'Используют: ' + p.usedBy.map((u) => hide(u)).join(', ') : 'Не используется правилами';
  }
  let adding = $state(false);
  let text = $state('');
  let result = $state<ImportResult | null>(null);
  let error = $state('');
  let info = $state('');
  let editing = $state<Profile | null>(null);
  let editingSource = $state(''); // the subscription name of the edited server
  let checking = $state<ProfileSummary | null>(null);

  async function load() {
    try {
      ui.profiles = await api.Profiles();
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(load);

  async function after() {
    await load();
    onchange();
  }

  async function doImport(fromClipboard: boolean) {
    error = '';
    info = '';
    result = null;
    try {
      result = fromClipboard ? await api.ImportClipboard() : await api.ImportURIs(text);
      // The clipboard import leaves the field alone. After the field's own
      // import it keeps only the links that failed, to fix them in place
      // (added and already known ones are done with).
      if (!fromClipboard && result.added.length > 0) text = failedLinks(text, result.errors);
      await after();
      if (!fromClipboard && !result.added.length && result.skipped.length && !result.errors.length) text = '';
      if ((result.added.length || result.skipped.length) && !result.errors.length && !result.warnings.length) adding = false;
      if (result.added.length) info = `Добавлено серверов: ${result.added.length} — ${result.added.map((p) => p.name).join(', ')}`;
    } catch (e) {
      error = errText(e);
    }
  }

  // failedLinks returns the hysteria2:// / hy2:// / vless:// links of text that the
  // import errors ("ссылка N: …", N counting those links) name, one per
  // line. It splits links the way the backend's splitLinks does; text it
  // finds no links in (a base64 list) gives ''.
  function failedLinks(text: string, errors: string[]): string {
    const bad = new Set(errors.map((e) => Number(/^ссылка (\d+):/.exec(e)?.[1])));
    const out: string[] = [];
    let n = 0;
    for (const line of text.trim().split(/[\r\n]+/)) {
      // Go's \s: a link starts a line or follows a space or tab.
      const starts = [...line.matchAll(/(?:^|[\t\f ])([A-Za-z][A-Za-z0-9+.\-]*:\/\/)/g)];
      starts.forEach((m, i) => {
        const scheme = m[1].slice(0, -3).toLowerCase();
        if (scheme !== 'hysteria2' && scheme !== 'hy2' && scheme !== 'vless') return;
        n++;
        const end = i + 1 < starts.length ? starts[i + 1].index : line.length;
        if (bad.has(n)) out.push(line.slice(m.index + m[0].length - m[1].length, end).trim());
      });
    }
    return out.join('\n');
  }

  async function run(f: () => Promise<unknown>, ok = '') {
    error = '';
    info = '';
    try {
      await f();
      info = ok;
      await after();
    } catch (e) {
      error = errText(e);
    }
  }

  async function edit(p: ProfileSummary) {
    try {
      editing = await api.Profile(p.id);
      editingSource = p.source ? p.sourceName : '';
    } catch (e) {
      error = errText(e);
    }
  }

  function create() {
    adding = false;
    editingSource = '';
    editing = { id: '', name: '', host: '', ports: '443', auth: '', tls: {}, obfs: {}, hop: {}, bandwidth: {}, congestion: {}, quic: {}, pinServerIP: true };
  }

  // move shifts a server one place up (-1) or down (+1) from where it is
  // now: MoveProfile takes an absolute index, and a background
  // subscription update may have reordered the list since it was shown.
  function move(id: string, by: -1 | 1) {
    run(async () => {
      const cur = await api.Profiles();
      const i = cur.findIndex((x) => x.id === id);
      if (i < 0) throw new Error('Сервер уже удалён');
      if (i + by >= 0 && i + by < cur.length) await api.MoveProfile(id, i + by);
    });
  }

  // HyRoute Server, the panel for one's own Hysteria servers: started on
  // this computer and opened in the browser.
  let panelBusy = $state(false);
  let panelError = $state('');
  async function openPanel() {
    panelBusy = true;
    panelError = '';
    try {
      await api.OpenServerPanel();
    } catch (e) {
      panelError = errText(e);
    } finally {
      panelBusy = false;
    }
  }

  function remove(p: ProfileSummary) {
    if (confirm(`Удалить сервер «${hide(p.name)}»?`)) run(() => api.DeleteProfile(p.id));
  }

  // A manual server that a subscription also brings: the subscription's
  // copy stays up to date, this one can go. Rules and proxies that use it
  // are named by the refusal (switch them to the subscription's copy).
  function removeCopy(p: ProfileSummary) {
    const q = `Удалить ручную копию «${hide(p.name)}»?\n\nТот же сервер есть в подписке «${hide(p.duplicateSub ?? '')}» как «${hide(p.duplicateOf ?? '')}» и обновляется вместе с ней.`;
    if (confirm(q)) run(() => api.DeleteProfile(p.id), 'Копия удалена');
  }

  function tunnel(id: string) {
    return ui.status?.tunnels?.find((t) => t.id === id);
  }

  const stateText: Record<string, string> = { connected: 'работает', connecting: 'подключается', failed: 'ошибка', stopped: 'остановлен' };
  function tone(state: string): string {
    return state === 'connected' ? 'ok' : state === 'connecting' ? 'wait' : 'bad';
  }
</script>

<div class="page-wrap">
  <header class="row">
    <div class="grow">
      <h1>Серверы</h1>
      {#if view === 'servers'}
        <p class="muted sub">
          Серверы Hysteria 2 и VLESS. Работает только тот, который нужен правилам, и несколько могут работать одновременно. ★ — основной сервер.
        </p>
      {/if}
    </div>
    {#if view === 'servers'}<button class="primary" onclick={() => (adding = !adding)}><Icon name="plus" size={16} />Добавить сервер</button>{/if}
  </header>
  {#if ui.expert}
    <div class="seg tabs" role="tablist">
      <button role="tab" aria-selected={view === 'servers'} class:on={view === 'servers'} onclick={() => setTab('servers')}>Серверы</button>
      <button role="tab" aria-selected={view === 'groups'} class:on={view === 'groups'} onclick={() => setTab('groups')}>Группы</button>
    </div>
  {/if}

  {#if view === 'groups'}
    <Groups {onchange} />
  {:else}

  <Help id="servers" title="Что здесь">
    <p>
      Сервер — это компьютер вашего VPN-сервиса, через который идёт трафик. Здесь все ваши серверы. <b>Звёздочка</b> отмечает основной: через
      него идёт VPN, если в правиле не выбран другой сервер. Щёлкните по звёздочке, чтобы сделать сервер основным.
    </p>
    <ul>
      <li><b>«Проверить все»</b> измеряет пинг каждого сервера и ставит самые быстрые наверх: чем меньше миллисекунд, тем лучше. «Нет ответа» — сервер сейчас не работает.</li>
      <li><b>«Проверить»</b> в строке сервера проверяет его подробно: подключение, внешний IP, задержка, UDP.</li>
      <li>Новый сервер: «Добавить сервер» и вставьте ссылку <code>hysteria2://…</code> или <code>vless://…</code>. Ссылка подписки (<code>https://…</code>) добавляется на странице «Подписки».</li>
      <li>Серверы из подписки обновляются сами, их не нужно добавлять заново.</li>
    </ul>
  </Help>

  {#if adding}
    <section class="card">
      <h2>Добавить сервер</h2>
      <textarea rows="4" class:masked={ui.privacy} placeholder="Вставьте ссылки hysteria2://…, hy2://… или vless://… (по одной на строку) или конфиг Clash, sing-box, Xray" bind:value={text}></textarea>
      <div class="row" style="margin-top: 10px">
        <button class="primary" onclick={() => doImport(false)} disabled={!text.trim()}>Добавить</button>
        <button onclick={() => doImport(true)}><Icon name="clipboard" size={16} />Из буфера обмена</button>
        <div class="grow"></div>
        <button class="ghost" onclick={create}>Заполнить вручную</button>
      </div>
      <p class="muted small">Ссылка подписки (https://…) добавляется на странице «Подписки».</p>
    </section>
  {/if}

  {#if result}
    {#each result.warnings as w}<div class="note warn">{hide(w)}</div>{/each}
    {#if result.skipped.length}
      <div class="note info">
        Не добавлены — такие серверы уже есть:
        <ul class="skipped">{#each result.skipped as w}<li>{hide(w)}</li>{/each}</ul>
      </div>
    {/if}
    {#each result.errors as w}<div class="note error">{hide(w)}</div>{/each}
  {/if}
  {#if error}<div class="note error">{hide(error)}</div>{/if}
  {#if info}<div class="note ok">{hide(info)}</div>{/if}

  {#if list.length === 0}
    <div class="card empty">
      <Icon name="server" size={28} />
      <div><b>Серверов пока нет.</b><p class="muted">Нажмите «Добавить сервер» и вставьте ссылку от вашего VPN.</p></div>
    </div>
  {/if}

  {#if list.length > 1}
    <div class="row tools">
      <input class="grow search" type="text" placeholder="Найти сервер: название, адрес, подписка" bind:value={query} />
      {#if q}<span class="muted small found">{shown.length} из {list.length}</span>{/if}
      {#if pinging}
        <button onclick={() => api.PingStop()} title="Остановить проверку: серверы, до которых она не дошла, останутся как были"><Icon name="x" size={15} />Остановить · осталось {left}</button>
      {:else}
        <button onclick={() => ping([])} title="Измерить пинг всех серверов: короткий запрос через каждый. Список встанет по пингу, самые быстрые наверху"
          ><Icon name="zap" size={15} />Проверить все</button
        >
      {/if}
      {#if measured}
        <div class="seg">
          <button class:on={!byPing} onclick={() => (byPing = false)} title="Серверы в вашем порядке">Свой порядок</button>
          <button class:on={byPing} onclick={() => (byPing = true)} title="Сначала серверы с меньшим пингом, в конце — те, что не ответили">По пингу</button>
        </div>
      {/if}
      <div class="seg">
        <button class:on={!dense} onclick={() => setCompact(false)} title="Название, под ним адрес и кем используется">Крупно</button>
        <button class:on={dense} onclick={() => setCompact(true)} title="Сервер в одну строку: на экране помещается втрое больше">Компактно</button>
      </div>
    </div>
  {/if}

  <div class="list" class:dense>
    {#if q && !shown.length}<div class="card muted">Такого сервера нет.</div>{/if}
    {#each shown as p, j (p.id)}
      {@const i = list.indexOf(p)}
      {@const t = tunnel(p.id)}
      {#if dense && places > 1 && !ranked && (j === 0 || (shown[j - 1].source || '') !== (p.source || ''))}
        <div class="place muted small">{p.source ? `Подписка «${hide(p.sourceName)}»` : 'Добавлены вручную'}</div>
      {/if}
      <div class="srv card" class:main={p.main} class:missing={p.missing}>
        <button class="icon star" class:on={p.main} onclick={() => run(() => api.SetMain(p.id))} title={p.main ? 'Основной сервер' : 'Сделать основным'}>
          <Icon name="star" size={18} />
        </button>
        <div class="grow info">
          <div class="name ellipsis" title={dense ? usedText(p) : undefined}>{hide(p.name)}</div>
          <div class="meta">
            <span class="mono ellipsis">{hide(p.server)}</span>
            {#if p.source && !(dense && places > 1 && !ranked)}<span class="badge"><Icon name="rss" size={11} />{hide(p.sourceName)}</span>{/if}
            {#if p.missing}<span class="badge warn-b" title="Сервер пропал из подписки, но его используют правила">нет в подписке</span>{/if}
            {#if p.duplicateOf && p.duplicateSub && !p.source}
              <span class="badge warn-b" title="Тот же адрес, пароль и настройки, что у «{hide(p.duplicateOf)}» из подписки «{hide(p.duplicateSub)}»: та копия обновляется вместе с подпиской">есть в подписке «{hide(p.duplicateSub)}»</span>
              <button class="link small" onclick={() => removeCopy(p)}>Удалить копию</button>
            {:else if p.duplicateOf}<span class="badge warn-b" title="Тот же адрес, пароль и настройки, что у «{hide(p.duplicateOf)}»: копию можно удалить">дубль «{hide(p.duplicateOf)}»</span>{/if}
            {#if p.protocol === 'vless'}<span class="badge" title="VLESS через Xray">VLESS · {p.transport}</span>{/if}
            {#if p.flow}<span class="badge" title={p.flow}>Vision</span>{/if}
            {#if p.obfs}<span class="badge">{p.obfs}</span>{/if}
            {#if p.pinned}<span class="badge" title="Сертификат проверяется по отпечатку">pin</span>{:else if p.insecure}<span class="badge warn-b" title="Сертификат не проверяется">insecure</span>{/if}
          </div>
          {#if !dense}<div class="muted small ellipsis">{usedText(p)}</div>{/if}
        </div>
        {#if t}
          <div class="state" title={hide(t.message)}>
            <span class="dot {tone(t.state)}"></span>{stateText[t.state] ?? t.state}
            <span class="faint small mono">↓ {fmtBytes(t.recv)}</span>
          </div>
        {/if}
        {#if p.pinging}
          <span class="ping faint" title="Проверяется">···</span>
        {:else if p.pingAt}
          <button class="ping" class:fast={!!p.pingMs && p.pingMs <= 250} class:slow={!!p.pingMs && p.pingMs > 600} class:dead={!p.pingMs} disabled={pinging} onclick={() => ping([p.id])} title={pingTitle(p)}
            >{p.pingMs ? `${p.pingMs} мс` : 'нет ответа'}</button
          >
        {:else if measured || pinging}
          <span class="ping"></span>
        {/if}
        <button class:icon={dense} onclick={() => (checking = p)} title="Запустить и проверить: подключение, внешний IP, задержка, UDP"
          ><Icon name="zap" size={dense ? 16 : 15} />{#if !dense}Проверить{/if}</button
        >
        <div class="acts">
          <button class="icon" onclick={() => edit(p)} title="Изменить"><Icon name="edit" size={16} /></button>
          <button class="icon" onclick={() => run(() => api.CopyURI(p.id), 'Ссылка скопирована (в ней пароль сервера)')} title="Копировать ссылку"><Icon name="copy" size={16} /></button>
          <button class="icon" onclick={() => move(p.id, -1)} disabled={i === 0 || !!fixed} title={fixed || 'Выше'}><Icon name="up" size={16} /></button>
          <button class="icon" onclick={() => move(p.id, 1)} disabled={i === list.length - 1 || !!fixed} title={fixed || 'Ниже'}><Icon name="down" size={16} /></button>
          <button class="icon danger" onclick={() => remove(p)} title="Удалить"><Icon name="trash" size={16} /></button>
        </div>
      </div>
    {/each}
  </div>

  <section class="card own">
    <Icon name="server" size={22} />
    <div class="grow">
      <b>Свой сервер Hysteria</b>
      <p class="muted small">
        Панель HyRoute Server сама ставит Hysteria на ваш VPS по SSH, настраивает её и выдаёт ссылки для HyRoute. Она работает на этом компьютере и
        открывается в браузере; остановить — закрыть её окно на панели задач.
      </p>
      {#if panelError}<div class="note error">{panelError}</div>{/if}
    </div>
    <button onclick={openPanel} disabled={panelBusy}>{panelBusy ? 'Запуск…' : 'Открыть панель'}</button>
  </section>
  {/if}
</div>

{#if checking}
  <CheckProfile id={checking.id} name={checking.name} onclose={() => (checking = null)} />
{/if}

{#if editing}
  <ProfileEditor
    profile={editing}
    sourceName={editingSource}
    onclose={() => (editing = null)}
    onsaved={() => {
      editing = null;
      after();
    }}
  />
{/if}

<style>
  /* minmax(0, …): a row of long names and badges is cut, it never widens the page. */
  .page-wrap { display: grid; grid-template-columns: minmax(0, 1fr); gap: 16px; max-width: 1000px; }
  .tabs { justify-self: start; }
  header { align-items: flex-start; }
  .sub { margin: 4px 0 0; }
  textarea { width: 100%; }
  .tools { gap: 10px; align-items: center; flex-wrap: wrap; }
  .tools button { white-space: nowrap; }
  .search { max-width: 460px; }
  .found { white-space: nowrap; }
  .list { display: grid; grid-template-columns: minmax(0, 1fr); gap: 8px; }
  /* Rows in one line: the name, the address, then what fits of the rest. */
  .list.dense { gap: 4px; }
  .list.dense .srv { padding: 3px 10px; gap: 8px; }
  .list.dense .info { display: flex; align-items: baseline; gap: 10px; min-width: 0; }
  .list.dense .name { flex: none; max-width: 44%; font-size: 13.5px; }
  .list.dense .meta { flex: 1; min-width: 0; flex-wrap: nowrap; overflow: hidden; }
  .list.dense .meta > :global(*) { flex: none; }
  .list.dense .meta > .mono { flex: 0 1 auto; min-width: 70px; }
  .list.dense .state { font-size: 12.5px; }
  .place { margin: 8px 2px 0; }
  .place:first-child { margin-top: 0; }
  .srv { display: flex; align-items: center; gap: 12px; padding: 12px 14px; }
  .srv.main { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); }
  .srv.missing { border-style: dashed; }
  .skipped { margin: 4px 0 0; padding-left: 18px; }
  .star { color: var(--faint); }
  .star.on { color: var(--warn); }
  .star.on :global(svg) { fill: currentColor; }
  .info { display: grid; gap: 3px; }
  .name { font-weight: 650; font-size: 14.5px; }
  .meta { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; font-size: 12px; color: var(--muted); }
  .warn-b { color: var(--warn); }
  .state { display: flex; align-items: center; gap: 6px; font-size: 13px; white-space: nowrap; }
  /* The ping: a column of its own, so that the numbers stand one under another. */
  .ping { flex: none; min-width: 78px; padding: 2px 4px; background: none; border: 0; justify-content: flex-end; text-align: right; font-size: 13px; font-variant-numeric: tabular-nums; white-space: nowrap; color: var(--text); }
  button.ping:hover:not(:disabled) { text-decoration: underline; background: none; }
  button.ping:disabled { opacity: 1; cursor: default; }
  .ping.fast { color: var(--direct); }
  .ping.slow { color: var(--warn); }
  .ping.dead { color: var(--block); }
  .list.dense .ping { font-size: 12.5px; }
  .acts { display: flex; }
  .empty { display: flex; gap: 16px; align-items: center; color: var(--muted); }
  .own { display: flex; gap: 14px; align-items: center; color: var(--muted); }
  .own b { color: var(--text); }
  .own p { margin: 4px 0 0; }
  .own .note { margin-top: 8px; }
  .empty b { color: var(--text); }
  .empty p { margin: 4px 0 0; }
  textarea.masked { -webkit-text-security: disc; }
</style>
