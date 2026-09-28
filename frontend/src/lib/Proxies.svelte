<script lang="ts">
  // Local proxies: a port per entry that programs with a proxy setting use
  // to go out through a chosen server.
  import { onMount } from 'svelte';
  import { api, errText, fmtBytes, isGroupId, type ProxyInput, type ProxyView } from '../api';
  import { ui, hide, settle, mainTarget, mainText } from '../state.svelte';
  import { trackUnsaved } from '../state.svelte'; // backup
  import Icon from './Icon.svelte';
  import TargetOptions from './TargetOptions.svelte';

  let list = $state<ProxyView[]>([]);
  let error = $state('');
  let ok = $state('');
  let editing = $state<ProxyInput | null>(null);
  let editingFrom = ''; // backup: the form as opened
  trackUnsaved(() => editing !== null && JSON.stringify(editing) !== editingFrom); // backup
  let saving = $state(false);
  let showPass = $state(false);

  async function load() {
    try {
      list = await api.Proxies();
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(() => {
    load();
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  });

  const online = $derived(ui.status != null && ui.status.state !== 'disconnected' && !(ui.status.state === 'error' && !ui.status.stats));

  function genPassword(): string {
    const a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const b = new Uint32Array(16);
    crypto.getRandomValues(b);
    return Array.from(b, (x) => a[x % a.length]).join('');
  }

  function nextPort(): number {
    const used = new Set(list.map((p) => p.port));
    let p = 10801;
    while (used.has(p)) p++;
    return p;
  }

  // Mirrors LocalProxy.UDPOn: on by default here, off for LAN proxies.
  const udpOn = (p: ProxyInput) => p.udp === 'on' || (p.udp !== 'off' && !p.lan);

  function add() {
    editing = { id: '', name: '', enabled: true, profile: '', port: nextPort(), lan: false, username: '', password: '', udp: '' };
    editingFrom = JSON.stringify(editing);
    showPass = true;
  }

  function edit(p: ProxyView) {
    editing = { id: p.id, name: p.name, enabled: p.enabled, profile: p.profile, port: p.port, lan: p.lan, username: p.username, password: p.password, udp: p.udp ?? '' };
    editingFrom = JSON.stringify(editing);
    showPass = false;
  }

  async function save() {
    if (!editing) return;
    saving = true;
    error = '';
    try {
      await api.SaveProxy({ ...editing, port: +editing.port });
      editing = null;
      await load();
    } catch (e) {
      error = errText(e);
    }
    saving = false;
  }

  async function toggle(p: ProxyView) {
    error = '';
    try {
      // Field by field: whatever is left out (udp) would return to its default.
      await api.SaveProxy({ id: p.id, name: p.name, enabled: !p.enabled, profile: p.profile, port: p.port, lan: p.lan, username: p.username, password: p.password, udp: p.udp });
      await load();
    } catch (e) {
      error = errText(e);
    }
  }

  async function remove(p: ProxyView) {
    if (!confirm(`Удалить прокси «${p.name}»? Программы, настроенные на порт ${p.port}, перестанут подключаться.`)) return;
    try {
      await api.DeleteProxy(p.id);
      await load();
    } catch (e) {
      error = errText(e);
    }
  }

  function url(p: ProxyView, scheme: string, addr: string): string {
    const auth = p.username ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@` : '';
    return `${scheme}://${auth}${addr}`;
  }

  async function copy(text: string) {
    try {
      await api.CopyText(text);
      ok = 'Скопировано';
      setTimeout(() => (ok = ''), 1500);
    } catch (e) {
      error = errText(e);
    }
  }

  const stateText: Record<string, string> = { off: 'выключен', waiting: 'ждёт подключения HyRoute', listening: 'работает', error: 'ошибка' };
  const tone = (p: ProxyView) => (p.state === 'listening' ? 'ok' : p.state === 'error' ? 'bad' : p.state === 'waiting' ? 'wait' : '');
  const main = $derived(mainTarget());
  // «через группу «Авто»», «через DE1», «через основной сервер — …».
  function via(p: ProxyView): string {
    if (!p.profile) return `основной сервер${main ? ' — ' + mainText(main) : ''}`;
    if (isGroupId(p.profile)) return p.profileName ? `группу «${hide(p.profileName)}»` : 'удалённую группу';
    return hide(p.profileName) || 'удалённый сервер';
  }
</script>

<div class="layout">
  <header class="row">
    <div class="grow">
      <h1>Локальные прокси</h1>
      <p class="muted sub">
        Порт на этом компьютере для программ, в которых можно указать прокси: терминалы бирж, браузеры, боты. Каждый прокси ведёт через свой
        сервер, независимо от правил. Один порт понимает и SOCKS5 (с UDP), и HTTP.
      </p>
    </div>
    <button class="primary" onclick={add} disabled={ui.profiles.length === 0}><Icon name="plus" size={16} />Прокси</button>
  </header>

  {#if error}<div class="note error">{hide(error)}</div>{/if}
  {#if ok}<div class="note ok">{ok}</div>{/if}
  {#if list.length && !online}
    <div class="note info">Прокси работают, пока HyRoute подключён. Включите HyRoute на главной — порты откроются, серверы прокси запустятся сами.</div>
  {/if}

  {#if list.length === 0}
    <section class="card empty">
      <Icon name="server" size={22} />
      <div>
        <b>Прокси пока нет</b>
        <p class="muted small">
          Например: терминал Binance через сервер в Японии на порту 10801, а терминал Bybit через Сингапур на 10802. В программе указываете
          <code>127.0.0.1</code> и порт, тип SOCKS5 или HTTP — подходят оба. UDP передаётся только через SOCKS5.
        </p>
      </div>
    </section>
  {/if}

  {#each list as p (p.id)}
    <section class="card proxy" class:off={!p.enabled}>
      <div class="row top">
        <label class="switch" title={p.enabled ? 'Выключить' : 'Включить'}>
          <input type="checkbox" checked={p.enabled} onchange={(e) => settle(e, () => toggle(p), () => p.enabled)} /><span></span>
        </label>
        <div class="grow">
          <div class="name"><b>{p.name}</b> <span class="dot {tone(p)}"></span> <span class="muted small">{stateText[p.state]}</span></div>
          <div class="muted small">
            через {via(p)}
            {#if p.username}· с паролем{:else}· без пароля{/if}
            {#if p.udpOn}· UDP{/if}
            {#if p.lan}· доступен из локальной сети{/if}
          </div>
        </div>
        <button class="icon" onclick={() => edit(p)} title="Изменить"><Icon name="edit" size={16} /></button>
        <button class="icon danger" onclick={() => remove(p)} title="Удалить"><Icon name="trash" size={16} /></button>
      </div>
      {#if p.error}<div class="note error small">{hide(p.error)}</div>{/if}
      {#if p.udpError}<div class="note error small">{hide(p.udpError)}</div>{/if}
      {#if p.udpBlocked === 'server'}
        <div class="note info small">Сервер {hide(p.profileName)} не разрешает UDP: UDP через этот прокси не передаётся.</div>
      {:else if p.udpBlocked === 'group'}
        <div class="note info small">Ни один сервер группы {hide(p.profileName)} сейчас не передаёт UDP.</div>
      {/if}
      <div class="addrs">
        {#each p.addresses as a, i}
          <div class="addr">
            <code class="grow">{hide(a)}</code>
            {#if i > 0}<span class="faint small">из сети</span>{/if}
            <button class="mini" onclick={() => copy(url(p, 'socks5', a))} title={hide(url(p, 'socks5', a))}>socks5://</button>
            <button class="mini" onclick={() => copy(url(p, 'http', a))} title={hide(url(p, 'http', a))}>http://</button>
            <button class="mini" onclick={() => copy(a)} title="Адрес и порт"><Icon name="copy" size={13} /></button>
          </div>
        {/each}
      </div>
      {#if p.state === 'listening'}
        <div class="faint small">
          Соединений сейчас {p.active}, всего {p.total}{#if p.udpServed}
            · UDP-сессий {p.udpActive} (всего {p.udpTotal}){/if} · ↑ {fmtBytes(p.sent)} ↓ {fmtBytes(p.recv)}{#if p.udpDropped > 0}
            <span
              title="Больше предела Hysteria (около 4 КБ, меньше для длинных доменных имён), от чужого адреса или другой программы, разбитые на части (FRAG) или когда сервер недоступен. Подробности — в журнале HyRoute."
            >
              · отброшено UDP-пакетов {p.udpDropped}</span
            >{/if}
        </div>
      {/if}
    </section>
  {/each}
</div>

{#if editing}
  <div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && (editing = null)}>
    <div class="dialog ed">
      <div class="row">
        <h2 class="grow">{editing.id ? 'Прокси' : 'Новый прокси'}</h2>
        <button class="icon" onclick={() => (editing = null)}><Icon name="x" /></button>
      </div>
      <div class="form">
        <label for="pn">Название</label>
        <input id="pn" bind:value={editing.name} placeholder="Например, «Binance — Япония»" />

        <label for="ps">Через сервер</label>
        <select id="ps" bind:value={editing.profile}>
          <option value="">Основной{main ? ` — ${mainText(main)}` : ''}</option>
          <TargetOptions current={editing.profile} />
        </select>

        <label for="pp">Порт</label>
        <div class="portrow">
          <input id="pp" type="number" min="1024" max="65535" bind:value={editing.port} style="width: 120px" />
          <span class="muted small">В программе: <code>127.0.0.1:{editing.port}</code>, тип SOCKS5 или HTTP.</span>
        </div>

        <span class="lbl">Логин и пароль</span>
        <div class="auth">
          <input bind:value={editing.username} placeholder="логин" autocomplete="off" />
          <input bind:value={editing.password} type={showPass ? 'text' : 'password'} placeholder="пароль" autocomplete="new-password" />
          <button class="icon" onclick={() => (showPass = !showPass)} title={showPass ? 'Скрыть' : 'Показать'}><Icon name="eye" size={16} /></button>
          <button
            onclick={() => {
              if (!editing) return;
              if (!editing.username) editing.username = 'hyroute';
              editing.password = genPassword();
              showPass = true;
            }}>Придумать</button
          >
        </div>

        <span></span>
        <label class="check"
          ><input type="checkbox" bind:checked={editing.lan} onchange={() => editing && (editing.udp = '')} /> Доступен из локальной сети (телефон, другой компьютер)</label
        >
        {#if editing.lan}
          <span></span>
          <p class="muted small">Нужен пароль. Windows пустит подключения только из домашней или рабочей сети, не из общественной.</p>
        {/if}

        <span></span>
        <label class="check"
          ><input
            type="checkbox"
            checked={udpOn(editing)}
            onchange={(e) => editing && (editing.udp = e.currentTarget.checked ? 'on' : 'off')}
          /> Передавать UDP (SOCKS5)</label
        >
        <span></span>
        <p class="muted small">
          Для игр, звонков, торрент-клиентов и других программ, которые шлют UDP через SOCKS5. HTTP-прокси передаёт только TCP.
          {#if editing.lan}
            Из локальной сети UDP принимается только с устройства, которое вошло по паролю (с этого компьютера — только от той же программы);
            брандмауэр откроет этот порт и для UDP.
          {:else if editing.username}
            UDP принимается только от той же программы, которая вошла по паролю.
          {:else}
            Без пароля UDP через прокси может передавать любая программа этого компьютера — как и TCP.
          {/if}
          При включении или выключении доступа из локальной сети UDP возвращается к значению по умолчанию.
        </p>
      </div>
      {#if error}<div class="note error">{hide(error)}</div>{/if}
      <div class="actions">
        <button onclick={() => (editing = null)}>Отмена</button>
        <button class="primary" onclick={save} disabled={saving}>Сохранить</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .layout { display: grid; gap: 14px; max-width: 1000px; }
  .sub { margin: 4px 0 0; }
  header { align-items: flex-start; }
  .empty { display: flex; gap: 14px; align-items: flex-start; }
  .empty > :global(svg) { color: var(--accent); flex: none; margin-top: 2px; }
  .empty p { margin: 4px 0 0; }
  .proxy { display: grid; gap: 10px; }
  .proxy.off { opacity: 0.65; }
  .top { align-items: center; gap: 12px; }
  .name { display: flex; align-items: center; gap: 8px; }
  .addrs { display: grid; gap: 4px; }
  .addr { display: flex; align-items: center; gap: 6px; padding: 5px 8px; border-radius: var(--radius-sm); background: var(--surface-2); }
  .addr code { font-family: var(--mono); font-size: 13px; }
  .mini { padding: 3px 8px; font-size: 12px; font-family: var(--mono); background: var(--surface); }
  .danger { color: var(--block); }
  .ed { width: min(620px, 94vw); }
  .form { display: grid; grid-template-columns: 130px minmax(0, 1fr); gap: 10px 12px; align-items: center; margin-top: 12px; }
  .form > * { min-width: 0; }
  .form > input,
  .form > select { width: 100%; }
  .portrow { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 10px; }
  .form p { margin: 0; }
  .auth { display: flex; gap: 6px; align-items: center; }
  .auth input { flex: 1; min-width: 0; width: 100%; }
  .switch { position: relative; width: 34px; height: 20px; flex: none; cursor: pointer; }
  .switch input { opacity: 0; width: 0; height: 0; position: absolute; }
  .switch span { position: absolute; inset: 0; border-radius: 10px; background: var(--surface-3); transition: background 0.15s; }
  .switch span::after { content: ''; position: absolute; top: 3px; left: 3px; width: 14px; height: 14px; border-radius: 50%; background: #fff; transition: transform 0.15s; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25); }
  .switch input:checked + span { background: var(--accent); }
  .switch input:checked + span::after { transform: translateX(14px); }
  @media (max-width: 640px) {
    .form { grid-template-columns: 1fr; }
  }
</style>
