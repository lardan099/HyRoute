<script lang="ts">
  import { onMount } from 'svelte';
  import { api, onEvent, errText, type Updates } from './api';
  import { ui, hide, setPrivacy, applyTheme, noteSettingsRev, setExpert, setupDone, setupStep } from './state.svelte';
  import Icon from './lib/Icon.svelte';
  import Home from './lib/Home.svelte';
  import Rules from './lib/Rules.svelte';
  import Profiles from './lib/Profiles.svelte';
  import Subscriptions from './lib/Subscriptions.svelte';
  import Connections from './lib/Connections.svelte';
  import Logs from './lib/Logs.svelte';
  import System from './lib/System.svelte';
  import Lists from './lib/Lists.svelte';
  import Proxies from './lib/Proxies.svelte';
  import Traffic from './lib/Traffic.svelte';
  import UpdateDialog from './lib/UpdateDialog.svelte';
  import Toasts from './lib/Toasts.svelte';
  import Setup from './lib/Setup.svelte';

  // expert: the page is shown only in the full interface.
  const pages = [
    { id: 'home', label: 'Главная', icon: 'home' },
    { id: 'rules', label: 'Правила', icon: 'rules' },
    { id: 'servers', label: 'Серверы', icon: 'server' },
    { id: 'subs', label: 'Подписки', icon: 'rss' },
    { id: 'proxies', label: 'Прокси', icon: 'zap', expert: true },
    { id: 'lists', label: 'Списки', icon: 'database', expert: true },
    { id: 'connections', label: 'Соединения', icon: 'activity', expert: true },
    { id: 'traffic', label: 'Статистика', icon: 'chart' },
    { id: 'logs', label: 'Журнал', icon: 'log', expert: true },
    { id: 'settings', label: 'Настройки', icon: 'settings' },
  ];
  const shown = $derived(pages.filter((p) => ui.expert || !p.expert));

  function stored(): string {
    try {
      const v = localStorage.getItem('hyroute.page');
      return pages.some((p) => p.id === v) ? v! : 'home';
    } catch {
      return 'home';
    }
  }

  let stay = $state(stored());
  // A page the simple mode hides opens Главная (the stored one stays for
  // the full interface).
  const page = $derived(shown.some((p) => p.id === stay) ? stay : 'home');
  let setup = $state(false);
  let actionError = $state('');
  let updates = $state<Updates | null>(null);
  let notice = $state('');
  let showUpdate = $state(false);
  let coreLater = $state(false);

  function go(id: string) {
    stay = id;
    try {
      localStorage.setItem('hyroute.page', id);
    } catch {}
  }

  async function refresh() {
    try {
      ui.status = await api.Status();
      noteSettingsRev(ui.status.settingsRev);
    } catch (e) {
      actionError = errText(e);
    }
  }

  let firstProfiles = true;
  async function refreshProfiles() {
    let loaded = true;
    try {
      ui.profiles = await api.Profiles();
    } catch {
      loaded = false;
    }
    try {
      ui.groups = (await api.Groups()).groups;
    } catch {}
    if (!loaded || !firstProfiles) return;
    firstProfiles = false;
    // Settings that did not load (profiles.json of another user or machine)
    // look like a new copy: no servers. Nothing is decided then: the full
    // interface for this run only, and no setup over the banner that says
    // what is wrong.
    let loadError = ui.status?.loadError;
    if (!ui.status)
      try {
        loadError = (await api.Status()).loadError;
      } catch {}
    if (loadError) {
      if (ui.expert === null) ui.expert = true;
      return;
    }
    // Before the simple mode there was only the full interface: a copy that
    // already has servers keeps it. A new one starts simple.
    if (ui.expert === null) setExpert(ui.profiles.length > 0);
    // The setup opens by itself on the first start of the simple mode, and
    // in either mode where it stopped: after the restart «Установить» makes
    // in the middle of it, or a quit.
    if (setupStep() !== '' || (!ui.expert && !setupDone() && ui.profiles.length === 0)) setup = true;
  }

  async function refreshUpdates() {
    try {
      const u = await api.Updates();
      // Offer a HyRoute update once per run unless postponed ("Позже").
      if (u.app && !u.appSkipped && (!updates?.app || updates.app.version !== u.app.version)) showUpdate = true;
      updates = u;
    } catch {}
  }

  onMount(() => {
    applyTheme();
    refresh();
    refreshProfiles();
    refreshUpdates();
    api.StartupNotice().then((n) => (notice = n)).catch(() => {});
    const t = setInterval(refresh, 1000);
    const tu = setInterval(refreshUpdates, 3000);
    const off = onEvent('status', () => {
      refresh();
      refreshProfiles();
    });
    // The settings changed (payload: the new revision): pages holding a
    // copy of the rules reload.
    const offSettings = onEvent('settings', (r) => noteSettingsRev(r));
    return () => {
      clearInterval(t);
      clearInterval(tu);
      off();
      offSettings();
    };
  });

  const st = $derived(ui.status);
  const online = $derived(st != null && st.state !== 'disconnected' && !(st.state === 'error' && !st.stats));
  // A kill switch block closes the internet whatever the state: the window
  // opened at logon on the last page must not say just «Отключено».
  const blocking = $derived(st?.killSwitch === 'blocking');
  const tone = $derived.by(() => {
    if (blocking) return 'bad';
    if (!st || st.state === 'disconnected') return 'off';
    if (st.state === 'error' || st.state === 'tunnel-down') return 'bad';
    if (st.state === 'connected' && !st.noTunnel) return 'ok';
    return 'wait';
  });
  const stateText: Record<string, string> = {
    off: 'Отключено',
    ok: 'Подключено',
    wait: 'Подключение…',
    bad: 'Есть проблема',
  };

  async function reconnect() {
    try {
      await api.Reconnect();
    } catch (e) {
      actionError = errText(e);
    }
    refresh();
  }

  // The kill switch banner on the pages without their own note (Главная
  // and Настройки have one): the same actions as the card on Главная.
  let ksBusy = $state(false);
  async function ksConnect() {
    ksBusy = true;
    try {
      if (online) await api.Reconnect();
      else await api.Connect();
    } catch (e) {
      actionError = errText(e);
    }
    ksBusy = false;
    refresh();
  }

  async function ksRelease() {
    try {
      await api.ReleaseKillSwitch();
    } catch (e) {
      actionError = errText(e);
    }
    refresh();
  }

  // installCore serves the banner and Settings. updates.coreBusy comes only
  // with the next poll, and a second click before it would get «нет
  // доступного обновления ядра» while the first install goes on.
  let coreInstalling = $state(false);
  async function installCore() {
    coreInstalling = true;
    try {
      await api.InstallCore();
    } finally {
      coreInstalling = false;
      refreshUpdates();
    }
  }
</script>

<div class="app" inert={setup}>
  <aside>
    <div class="brand">
      <span class="logo"><Icon name="shield" size={18} stroke={2.2} /></span>
      HyRoute
    </div>
    <nav>
      {#each shown as p (p.id)}
        <button class="nav" class:active={page === p.id} onclick={() => go(p.id)}>
          <Icon name={p.icon} />
          <span>{p.label}</span>
          {#if p.id === 'rules' && st?.warnings?.length}<span class="count warn">{st.warnings.length}</span>{/if}
          {#if p.id === 'settings' && (updates?.app || updates?.coreUpdate)}<span class="count">1</span>{/if}
        </button>
      {/each}
    </nav>
    <div class="grow"></div>
    <button class="side-status tone-{tone}" onclick={() => go('home')} title="Главная">
      <span class="dot"></span>
      <span class="ellipsis">{blocking ? 'Интернет закрыт' : st?.noTunnel && tone === 'wait' ? 'Без туннеля' : stateText[tone]}</span>
    </button>
    <button
      class="nav privacy"
      class:on={ui.privacy}
      onclick={() => setPrivacy(!ui.privacy)}
      title="Скрыть IP-адреса, сайты, адреса серверов и ссылки подписок (для скриншотов и отправки логов)"
    >
      <Icon name={ui.privacy ? 'eye-off' : 'eye'} />
      <span>{ui.privacy ? 'Данные скрыты' : 'Скрыть данные'}</span>
    </button>
  </aside>

  <main tabindex="-1">
    <div class="banners">
      {#if actionError}
        <div class="note error row"><span class="grow">{hide(actionError)}</span><button class="icon" onclick={() => (actionError = '')}><Icon name="x" size={16} /></button></div>
      {/if}
      {#if notice}
        <div class="note ok row"><span class="grow">{notice}</span><button class="icon" onclick={() => (notice = '')}><Icon name="x" size={16} /></button></div>
      {/if}
      {#if st?.loadError}
        <div class="note error">Настройки не загружены: {hide(st.loadError)}</div>
      {/if}
      {#if blocking && page !== 'home'}
        <div class="note warn row">
          <span class="grow">Kill switch закрыл интернет: HyRoute перестал маршрутизировать трафик без команды «Отключить». Подключитесь снова или откройте интернет.</span>
          <button class="primary" onclick={ksConnect} disabled={ksBusy || st?.state === 'starting' || ui.profiles.length === 0}>Подключиться</button>
          <button onclick={ksRelease}>Открыть интернет</button>
        </div>
      {/if}
      {#if updates?.coreUpdate && !coreLater}
        <div class="note info row">
          <Icon name="download" size={16} />
          <span class="grow">Доступно ядро Hysteria <b>{updates.coreUpdate.version}</b> (сейчас {updates.core.version}).{online ? ' Текущие соединения не прервутся.' : ''}</span>
          <button class="primary" onclick={() => installCore().catch((e) => (actionError = errText(e)))} disabled={updates.coreBusy || coreInstalling}>
            {updates.coreBusy || coreInstalling ? `Загрузка ${Math.round(updates.coreProgress * 100)}%` : 'Обновить'}
          </button>
          <button class="ghost" onclick={() => (coreLater = true)}>Позже</button>
        </div>
      {/if}
      {#if updates?.coreNeedsReconnect && online}
        <div class="note warn row"><span class="grow">Ядро Hysteria обновлено и заработает после переподключения.</span><button onclick={reconnect}>Переподключить</button></div>
      {/if}
    </div>

    <div class="page">
      {#if page === 'home'}
        <Home {go} onsetup={() => (setup = true)} />
      {:else if page === 'rules'}
        <Rules />
      {:else if page === 'servers'}
        <Profiles onchange={refreshProfiles} />
      {:else if page === 'subs'}
        <Subscriptions onchange={refreshProfiles} />
      {:else if page === 'proxies'}
        <Proxies />
      {:else if page === 'lists'}
        <Lists />
      {:else if page === 'connections'}
        <Connections />
      {:else if page === 'traffic'}
        <Traffic />
      {:else if page === 'logs'}
        <Logs />
      {:else}
        <System {updates} onupdates={refreshUpdates} oninstall={() => (showUpdate = true)} {installCore} {coreInstalling} onsetup={() => (setup = true)} />
      {/if}
    </div>
  </main>
  <Toasts />
</div>

{#if setup}
  <Setup {go} onclose={() => (setup = false)} />
{:else if showUpdate && updates?.app}
  <UpdateDialog {updates} onclose={() => (showUpdate = false)} onchange={refreshUpdates} />
{/if}

<style>
  .app { display: flex; height: 100%; }

  aside {
    width: 212px;
    flex: none;
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 16px 12px;
    background: var(--surface);
    border-right: 1px solid var(--border);
  }

  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 16px; padding: 4px 8px 16px; letter-spacing: 0.2px; }
  .logo {
    width: 30px;
    height: 30px;
    border-radius: 9px;
    display: grid;
    place-items: center;
    color: #fff;
    background: linear-gradient(135deg, var(--accent), color-mix(in srgb, var(--accent) 55%, #b06cff));
  }
  :global(:root[data-accent='rainbow']) .logo { background: linear-gradient(135deg, #ff4d4d, #ffb84d, #4dd97a, #4db8ff, #a64dff); }

  nav { display: flex; flex-direction: column; gap: 2px; }

  .nav {
    justify-content: flex-start;
    gap: 12px;
    background: transparent;
    padding: 9px 12px;
    color: var(--muted);
    font-weight: 500;
    width: 100%;
  }
  .nav:hover:not(:disabled) { background: var(--surface-2); color: var(--text); }
  .nav.active { background: var(--accent-soft); color: var(--accent); font-weight: 600; }
  :global(:root[data-accent='rainbow']) .nav.active {
    background: linear-gradient(90deg, rgba(255, 77, 77, 0.14), rgba(77, 184, 255, 0.14), rgba(166, 77, 255, 0.16));
  }

  .count { margin-left: auto; font-size: 11px; min-width: 18px; height: 18px; border-radius: 9px; background: var(--accent); color: #fff; display: grid; place-items: center; padding: 0 5px; }
  .count.warn { background: var(--warn); }

  .side-status {
    justify-content: flex-start;
    gap: 10px;
    padding: 10px 12px;
    background: var(--surface-2);
    font-weight: 600;
    font-size: 13px;
    min-width: 0;
  }
  .tone-ok .dot { background: var(--direct); box-shadow: 0 0 0 4px color-mix(in srgb, var(--direct) 20%, transparent); }
  .tone-wait .dot { background: var(--warn); }
  .tone-bad .dot { background: var(--block); }

  .privacy.on { color: var(--accent); }

  main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .banners { padding: 0 28px; }
  .banners:not(:empty) { padding-top: 14px; }
  .banners .note { margin: 0 0 8px; }
  .page { flex: 1; min-height: 0; overflow: auto; padding: 24px 28px 28px; }
</style>
