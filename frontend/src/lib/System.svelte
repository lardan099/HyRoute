<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, fmtDateTime, optionsOf, type SystemInfo, type Prefs, type Updates, type Settings, type AutostartInfo, type EngineOptions } from '../api';
  import { ui, hide, setTheme, setAccent, settle, setExpert, resetHelp, type Theme, type Accent } from '../state.svelte';
  import Icon from './Icon.svelte';
  import GeoSettings from './GeoSettings.svelte';

  let {
    updates,
    onupdates,
    oninstall,
    installCore,
    coreInstalling,
    onsetup,
  }: {
    updates: Updates | null;
    onupdates: () => void;
    oninstall: () => void;
    installCore: () => Promise<void>;
    coreInstalling: boolean;
    onsetup: () => void;
  } = $props();

  const status = $derived(ui.status);
  let routing = $state<Settings | null>(null);
  let needsReconnect = $state(false);

  const themes: { v: Theme; l: string }[] = [
    { v: 'system', l: 'Как в Windows' },
    { v: 'light', l: 'Светлая' },
    { v: 'dark', l: 'Тёмная' },
    { v: 'midnight', l: 'Полночь' },
  ];
  const accents: { v: Accent; c: string; l: string }[] = [
    { v: 'blue', c: '#2f6fed', l: 'Синий' },
    { v: 'violet', c: '#7c3aed', l: 'Фиолетовый' },
    { v: 'teal', c: '#0d9488', l: 'Бирюзовый' },
    { v: 'orange', c: '#ea580c', l: 'Оранжевый' },
    { v: 'pink', c: '#db2777', l: 'Розовый' },
    { v: 'rainbow', c: 'conic-gradient(#ff4d4d, #ffb84d, #4dd97a, #4db8ff, #a64dff, #ff4d4d)', l: 'Радуга (да, та самая подсветка)' },
  ];

  function opt(v: boolean | undefined): boolean {
    return v ?? true;
  }

  // Each switch sends all engine options (never the rules: a rule change
  // made elsewhere meanwhile stays), so a quick second click must build on
  // the first one: the change is shown at once, saves go one after another
  // in click order (as on the Rules page), and the saved copy is read back
  // after the last of them.
  let routingSaving: Promise<unknown> = Promise.resolve();
  let routingPending = 0;
  async function saveRouting(patch: EngineOptions) {
    if (!routing) return;
    const next = { ...optionsOf(routing), ...patch };
    routing = { ...routing, ...patch };
    error = '';
    ok = '';
    routingPending++;
    const job = routingSaving.then(() => api.SaveEngineOptions(next));
    routingSaving = job.catch(() => {});
    try {
      const res = await job;
      needsReconnect = res.needsReconnect;
      ok = 'Сохранено';
    } catch (e) {
      error = errText(e);
    }
    if (--routingPending === 0) {
      try {
        const r = await api.Settings();
        if (routingPending === 0) routing = r;
      } catch (e) {
        error = errText(e);
      }
    }
  }

  let info = $state<SystemInfo | null>(null);
  let prefs = $state<Prefs>({});
  let error = $state('');
  let ok = $state('');
  let diag = $state('');
  let autostart = $state<AutostartInfo | null>(null);

  // A copy read while a save is queued is older than what is on screen and
  // would undo the click, so it is dropped: the save reads its own back.
  async function load() {
    try {
      info = await api.System();
      const p = await api.Prefs();
      if (prefsPending === 0) prefs = p;
      autostart = await api.Autostart();
      const r = await api.Settings();
      if (routingPending === 0) routing = r;
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(load);

  async function run(f: () => Promise<unknown>, msg: string) {
    error = '';
    ok = '';
    try {
      await f();
      ok = msg;
      await load();
      onupdates();
    } catch (e) {
      error = errText(e);
    }
  }

  // Like saveRouting: shown at once, saved in click order, read back after
  // the last save.
  let prefsSaving: Promise<unknown> = Promise.resolve();
  let prefsPending = 0;
  async function savePrefs(patch: Partial<Prefs>) {
    const next = { ...prefs, ...patch };
    prefs = next;
    error = '';
    ok = '';
    prefsPending++;
    const job = prefsSaving.then(() => api.SavePrefs(next));
    prefsSaving = job.catch(() => {});
    try {
      await job;
      ok = 'Настройки сохранены';
    } catch (e) {
      error = errText(e);
    }
    if (--prefsPending === 0) {
      try {
        const p = await api.Prefs();
        if (prefsPending === 0) prefs = p;
      } catch (e) {
        error = errText(e);
      }
      onupdates();
    }
  }

  let diagMasked = false; // diag was made in Privacy mode

  async function showDiag() {
    const masked = ui.privacy;
    try {
      diag = await api.Diagnostics(masked);
      diagMasked = masked;
    } catch (e) {
      error = errText(e);
    }
  }

  // The report is masked on the Go side when asked for in Privacy mode, so
  // it is made again when the mode is switched: turning it on must not
  // leave an open copy on screen.
  $effect(() => {
    if (diag && ui.privacy !== diagMasked) {
      diag = '';
      showDiag();
    }
  });

  const offline = $derived(!status || status.state === 'disconnected' || status.state === 'error');
  const updateMode = $derived(prefs.updateCheck || (updates?.dev ? 'manual' : 'auto'));
</script>

<div class="layout">
  <header>
    <h1>Настройки</h1>
  </header>
  {#if error}<div class="note error">{hide(error)}</div>{/if}
  {#if ok}<div class="note ok">{ok}</div>{/if}

  <section class="card">
    <h2><Icon name="sparkles" size={17} /> Режим интерфейса</h2>
    <div class="seg">
      <button class:on={!ui.expert} onclick={() => setExpert(false)}>Простой</button>
      <button class:on={!!ui.expert} onclick={() => setExpert(true)}>Для опытных</button>
    </div>
    <p class="muted small mode">
      {#if ui.expert}
        Все страницы и настройки: локальные прокси, списки сайтов, соединения, журнал, правила текстом, базы правил и тонкая настройка
        маршрутизации.
      {:else}
        Только самое нужное и подсказки простыми словами. Локальные прокси, списки сайтов, соединения, журнал и тонкие настройки спрятаны, их
        открывает режим «Для опытных». Правила, серверы и подключение в обоих режимах одни и те же.
      {/if}
    </p>
    <div class="row">
      <button onclick={onsetup}><Icon name="wand" size={16} />Пройти настройку заново</button>
      {#if !ui.expert}
        <button
          class="ghost"
          onclick={() => {
            resetHelp();
            ok = 'Закрытые подсказки снова показываются';
          }}>Вернуть закрытые подсказки</button
        >
      {/if}
    </div>
  </section>

  <section class="card">
    <h2><Icon name="palette" size={17} /> Внешний вид</h2>
    <div class="opts">
      <span class="muted">Тема</span>
      <div class="seg">
        {#each themes as t}<button class:on={ui.theme === t.v} onclick={() => setTheme(t.v)}>{t.l}</button>{/each}
      </div>
      <span class="muted">Акцент</span>
      <div class="row">
        {#each accents as a}
          <button class="swatch" class:on={ui.accent === a.v} style="background: {a.c}" title={a.l} aria-label={a.l} onclick={() => setAccent(a.v)}></button>
        {/each}
      </div>
    </div>
  </section>

  <section class="card">
    <h2><Icon name="download" size={17} /> Обновления</h2>
    {#if updates}
      <div class="kv">
        <span class="muted">HyRoute</span>
        <span>
          <b>{updates.current}</b>
          {#if updates.app}
            → доступна <b>{updates.app.version}</b>
            {#if updates.appStage === 'downloading'}(загрузка {Math.round(updates.appProgress * 100)}%){/if}
          {:else if updates.checked && !updates.checked.startsWith('0001') && !updates.appError}
            <span class="muted">— последняя версия</span>
          {/if}
          {#if updates.dev}<span class="muted"> (сборка без релизного тега)</span>{/if}
        </span>
        {#if updates.appError}<span></span><span class="err">{updates.appError}</span>{/if}

        <span class="muted">Ядро Hysteria</span>
        <span>
          <b>{updates.core.version}</b>
          <span class="muted">{updates.core.updated ? '(обновлённое)' : '(встроенное)'}</span>
          {#if updates.coreUpdate}→ доступно <b>{updates.coreUpdate.version}</b>{/if}
          {#if updates.coreBusy}(загрузка {Math.round(updates.coreProgress * 100)}%){/if}
        </span>
        {#if updates.core.error}<span></span><span class="err">{updates.core.error}</span>{/if}
        {#if updates.coreError}<span></span><span class="err">{updates.coreError}</span>{/if}

        <span class="muted">Проверено</span><span>{fmtDateTime(updates.checked)}</span>
      </div>
      {#if updates.coreNeedsReconnect && !offline}
        <div class="note warn">Новое ядро Hysteria будет использовано после переподключения.</div>
      {/if}
      <div class="row">
        <button class="primary" onclick={() => run(() => api.CheckUpdates(), '')} disabled={updates.checking}>
          {updates.checking ? 'Проверка…' : 'Проверить обновления'}
        </button>
        {#if updates.app}
          <button onclick={oninstall}>Установить HyRoute {updates.app.version}…</button>
        {/if}
        {#if updates.coreUpdate}
          <button onclick={() => run(installCore, 'Ядро Hysteria обновлено')} disabled={updates.coreBusy || coreInstalling}>Обновить ядро Hysteria</button>
        {/if}
        {#if updates.core.previous}
          <button onclick={() => confirm(`Вернуть ядро ${updates!.core.previous}?`) && run(() => api.RollbackCore(), 'Ядро возвращено')}>
            Откатить ядро ({updates.core.previous})
          </button>
        {/if}
      </div>
      <div class="opts">
        <label class="check"><input type="radio" name="upd" value="auto" checked={updateMode === 'auto'} onchange={(e) => settle(e, () => savePrefs({ updateCheck: 'auto' }), () => updateMode)} /> Проверять автоматически</label>
        <span class="muted">При запуске и раз в 12 часов. Устанавливается только после вашего подтверждения.</span>
        <label class="check"><input type="radio" name="upd" value="manual" checked={updateMode === 'manual'} onchange={(e) => settle(e, () => savePrefs({ updateCheck: 'manual' }), () => updateMode)} /> Только вручную</label>
        <span class="muted">По кнопке «Проверить обновления».</span>
        <label for="chan">Канал</label>
        <select id="chan" disabled title="Канал Beta появится позже"><option>Stable</option></select>
      </div>
      <p class="muted small">
        Обновления берутся из GitHub Releases ({updates.repo || 'не задан'}; ядро — apernet/hysteria) и проверяются по SHA256.
        HyRoute устанавливает новую версию отдельной программой после выхода и возвращает прежнюю, если новая не запустилась.
      </p>
    {/if}
  </section>

  <section class="card">
    <h2><Icon name="power" size={17} /> Запуск</h2>
    {#if autostart}
      <label class="check">
        <input type="checkbox" checked={autostart.enabled} disabled={!autostart.allowed && !autostart.enabled}
          onchange={(e) => settle(e, (el) => run(() => api.SetAutostart(el.checked), 'Сохранено'), () => autostart?.enabled)} />
        Запускать HyRoute при входе в Windows
      </label>
      <p class="muted small">
        HyRoute запустится в трее (или свёрнутым, если трей выключен ниже). Windows не спрашивает разрешения администратора: запуск идёт через
        задачу «HyRoute (&lt;SID&gt;)» в Планировщике заданий, у каждого пользователя Windows своя.
      </p>
      {#if !autostart.allowed}
        <div class="note warn small">
          Доступно, когда HyRoute лежит в Program Files, в папке, куда могут писать только администраторы: задача запускает его с правами
          администратора, и программу из папки, куда может писать любая программа, так запускать нельзя. Перенести можно кнопкой на главной.
        </div>
      {/if}
      {#if autostart.enabled && !autostart.current}
        <div class="note warn small row">
          <span class="grow">Автозапуск запускает другую копию: {autostart.command}</span>
          {#if autostart.allowed}<button onclick={() => run(() => api.SetAutostart(true), 'Автозапуск указывает на эту копию')}>Запускать эту</button>{/if}
        </div>
      {/if}
      {#if autostart.error}<div class="note error small">{autostart.error}</div>{/if}
    {/if}
    <label class="check">
      <input type="checkbox" checked={prefs.closeToTray ?? true} onchange={(e) => settle(e, (el) => savePrefs({ closeToTray: el.checked }), () => prefs.closeToTray ?? true)} />
      Кнопка × сворачивает HyRoute в трей
    </label>
    <p class="muted small">Окно открывается щелчком по значку в трее. Выйти из программы — «Выход» в меню значка (правая кнопка мыши).</p>
    <label class="check">
      <input type="checkbox" checked={prefs.autoConnect ?? false} onchange={(e) => settle(e, (el) => savePrefs({ autoConnect: el.checked }), () => prefs.autoConnect ?? false)} />
      Подключаться сразу после запуска
    </label>
    <p class="muted small">
      Вместе с автозапуском HyRoute сам восстановит подключение после перезагрузки. Если включён kill switch, до этого момента интернет открыт:
      перезагрузка снимает его блокировку.
    </p>
  </section>

  {#if routing}
    <section class="card">
      <h2><Icon name="shield" size={17} /> Kill switch</h2>
      <label class="check"><input type="checkbox" checked={routing.killSwitch ?? false} onchange={(e) => settle(e, (el) => saveRouting({ killSwitch: el.checked }), () => routing?.killSwitch ?? false)} />
        Закрывать интернет, если HyRoute перестал работать</label>
      <p class="muted small">
        Если HyRoute закроется во время подключения (окно закрыто, «Снять задачу» в диспетчере задач, сбой) или откажет драйвер перехвата,
        трафик не пойдёт напрямую: Windows заблокирует соединения, пока вы снова не подключитесь или не нажмёте «Открыть интернет». Если отказал
        движок перехвата, HyRoute через 5 секунд переподключится сам (не больше 3 раз за 10 минут), блокировка держится всё это время.
        Блокировку снимают кнопки «Отключить» и «Открыть интернет», выключение этой настройки и перезагрузка Windows, а завершение работы и
        выход из Windows — если HyRoute в этот момент запущен. Если он уже закрыт, при быстром запуске Windows блокировка переживёт выключение.
        Во время блокировки работают локальная сеть, DNS-запросы Windows (и зашифрованный DNS к DNS-серверам адаптеров на момент подключения),
        сам HyRoute и Hysteria.
      </p>
      {#if routing.killSwitch && info && !info.protectedLocation}
        <div class="note warn small">
          HyRoute не в Program Files или его папку могут менять программы без прав администратора, поэтому после выключения компьютера он сам не
          покажет оставшуюся блокировку: интернета не будет, пока вы не запустите HyRoute. Что сделать, написано на главной.
        </div>
      {/if}
      {#if status?.killSwitch === 'armed'}
        <p class="small"><span class="dot ok"></span> Включён и защищает текущее подключение.</p>
      {:else if status?.killSwitch === 'blocking'}
        <div class="note warn row">
          <span class="grow">Интернет сейчас закрыт kill switch.</span>
          <button onclick={() => run(() => api.ReleaseKillSwitch(), 'Интернет открыт')}>Открыть интернет</button>
        </div>
      {:else if routing.killSwitch && !offline}
        <p class="muted small">Включится при следующем подключении.</p>
      {/if}
      {#if status?.killSwitchError}<div class="note error">Kill switch: {hide(status.killSwitchError)}</div>{/if}
    </section>
  {/if}

  {#if ui.expert}
  <GeoSettings />

  <section class="card">
    <h2><Icon name="log" size={17} /> Журнал на диске</h2>
    <div class="opts">
      <label class="check"><input type="checkbox" checked={prefs.logsToDisk ?? true} onchange={(e) => settle(e, (el) => savePrefs({ logsToDisk: el.checked }), () => prefs.logsToDisk ?? true)} /> Хранить логи на диске</label>
      <span class="muted">Выключено — логи только в памяти (последние 10 000 строк) и пропадают при выходе.</span>
      <label for="lmax">Размер файла, МБ</label>
      <input id="lmax" type="number" min="1" max="200" style="width: 90px" value={prefs.logMaxMB || 5} onchange={(e) => settle(e, (el) => savePrefs({ logMaxMB: +el.value }), () => prefs.logMaxMB || 5)} />
      <label for="lkeep">Старых файлов</label>
      <input id="lkeep" type="number" min="1" max="20" style="width: 90px" value={prefs.logKeep || 3} onchange={(e) => settle(e, (el) => savePrefs({ logKeep: +el.value }), () => prefs.logKeep || 3)} />
    </div>
    <p class="muted small">
      Общий лог — hyroute.log, у каждого профиля свой hysteria-&lt;id&gt;.log. При достижении размера файл переименовывается в .1, .2…, самые старые удаляются.
      Пароли, ключи подписок и SOCKS-данные в логи не попадают.
    </p>
    <div class="row">
      <button onclick={() => run(() => api.OpenLogDir(), '')}>Открыть папку логов</button>
      <button class="danger" onclick={() => confirm('Удалить все логи (в памяти и на диске)?') && run(() => api.ClearLogs(), 'Логи очищены')}>Очистить логи</button>
    </div>
  </section>
  {/if}

  <section class="card">
    <h2><Icon name="info" size={17} /> Диагностика</h2>
    <p class="muted small">
      Версии, состояние профилей, подписок, драйвера и брандмауэра, последние ошибки. Пароли и ключи подписок вырезаны всегда;
      {ui.privacy ? 'IP-адреса и серверы скрыты (включено скрытие данных 🙈).' : 'чтобы скрыть и IP-адреса с серверами, включите 👁 в шапке.'}
    </p>
    <div class="row">
      <button onclick={showDiag}>Показать</button>
      <button class="primary" onclick={() => run(() => api.CopyDiagnostics(ui.privacy), 'Диагностика скопирована')}>Скопировать диагностику</button>
    </div>
    {#if diag}<textarea class="diag" readonly rows="16">{diag}</textarea>{/if}
  </section>

  {#if routing && ui.expert}
    <section class="card">
      <h2><Icon name="rules" size={17} /> Маршрутизация (для опытных)</h2>
      <div class="opts2">
        <label class="check"><input type="checkbox" checked={opt(routing.exactWebDomains)} onchange={(e) => settle(e, (el) => saveRouting({ exactWebDomains: el.checked }), () => opt(routing?.exactWebDomains))} />
          Точное определение сайта</label>
        <span class="muted small">Для HTTP/HTTPS сайт берётся только из самого соединения (SNI/Host). Кэш DNS путает сайты на общих адресах CDN.</span>
        <label class="check"><input type="checkbox" checked={opt(routing.blockQUIC)} onchange={(e) => settle(e, (el) => saveRouting({ blockQUIC: el.checked }), () => opt(routing?.blockQUIC))} />
          Блокировать QUIC с неизвестным сайтом</label>
        <span class="muted small">Браузер переходит на обычный HTTPS, где сайт виден. *</span>
        <label class="check"><input type="checkbox" checked={opt(routing.blockIPv6Tunnel)} onchange={(e) => settle(e, (el) => saveRouting({ blockIPv6Tunnel: el.checked }), () => opt(routing?.blockIPv6Tunnel))} />
          Не пускать IPv6 в VPN</label>
        <span class="muted small">Программа переходит на IPv4. *</span>
        <label class="check"><input type="checkbox" checked={opt(routing.preferRemoteDNS)} onchange={(e) => settle(e, (el) => saveRouting({ preferRemoteDNS: el.checked }), () => opt(routing?.preferRemoteDNS))} />
          Узнавать адрес сайта на сервере</label>
        <span class="muted small">Через VPN передаётся имя сайта, а не IP: сервер сам найдёт ближайший адрес. *</span>
      </div>
      <p class="muted small">* действует после переподключения.</p>
      {#if needsReconnect && !offline}<div class="note warn">Изменения вступят в силу после переподключения.</div>{/if}
    </section>
  {/if}

  {#if info}
    {#if info.missing.length}
      <div class="note error">
        Нет файлов: {info.missing.join(', ')}. HyRoute скачает их при следующем запуске (нужен интернет) или возьмёт из полного архива HyRoute.
      </div>
    {/if}

    {#if ui.expert}
    <details class="card adv">
      <summary><Icon name="settings" size={17} /> Система: драйвер, брандмауэр, файлы</summary>
      <h3>Драйвер WinDivert</h3>
      <p>{info.driver}{status?.stats?.driverVersion ? ` · версия ${status.stats.driverVersion}` : ''}</p>
      {#if info.legacy.length}
        <div class="note warn">Запущены драйверы WinDivert 1.x ({info.legacy.join(', ')}): порядок обработки пакетов относительно HyRoute не определён.</div>
      {/if}
      <p class="muted">
        zapret и GoodbyeDPI используют ту же службу WinDivert и работают вместе с HyRoute: HyRoute видит пакеты раньше них (приоритет 1000),
        а трафик, отправленный напрямую, дальше обрабатывают они.
      </p>
      <button onclick={() => run(() => api.DeleteStaleDriverService(), 'Служба удалена')} disabled={!info.driverStale}>
        Удалить устаревшую службу WinDivert
      </button>

      <h3>Брандмауэр</h3>
      <p>
        Правило «{info.firewallRule}»: <b>{info.firewallRuleOK ? 'есть' : 'нет'}</b>. HyRoute создаёт его, чтобы Windows Firewall пропускал
        локальные соединения к relay, и проверяет при каждом подключении.
      </p>
      <button onclick={() => run(() => api.RemoveFirewallRule(), 'Правило удалено')} disabled={!offline || !info.firewallRuleOK}>Удалить правило брандмауэра</button>
      {#if !offline}<span class="muted"> сначала отключитесь</span>{/if}

      <h3>Данные</h3>
      <div class="kv">
        <span class="muted">Настройки и профили</span><span class="mono">{info.dataDir}</span>
        <span class="muted">Программа</span><span class="mono">{info.programDir}</span>
        <span class="muted">Ядро Hysteria</span><span class="mono">{info.hysteriaPath}</span>
        <span class="muted">Сборка</span><span class="mono">{updates?.current ?? ''} ({info.build})</span>
      </div>
      <p class="muted">Пароли профилей и ссылки подписок зашифрованы средствами Windows (DPAPI) и расшифровываются только под вашей учётной записью.</p>
      <button onclick={() => run(() => api.OpenDataDir(), '')}>Открыть папку</button>
      <p class="muted small credits">Флаги стран — Twemoji (© Twitter, CC-BY 4.0). Иконки по мотивам Lucide (ISC).</p>
    </details>
    {/if}
  {/if}
</div>

<style>
  .layout { display: grid; gap: 16px; max-width: 900px; }
  h2 { display: flex; align-items: center; gap: 8px; }
  .swatch { width: 28px; height: 28px; border-radius: 50%; padding: 0; border: 2px solid var(--surface); box-shadow: 0 0 0 1px var(--border); }
  .swatch.on { box-shadow: 0 0 0 2px var(--text); }
  .opts2 { display: grid; grid-template-columns: max-content 1fr; gap: 10px 18px; align-items: center; }
  .adv summary { cursor: pointer; font-weight: 650; display: flex; align-items: center; gap: 8px; }
  .credits { margin-top: 14px; }
  .mode { margin: 10px 0 12px; }
  p { margin: 0 0 10px; user-select: text; }
  .small { font-size: 12px; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin-bottom: 10px; user-select: text; }
  .err { color: var(--block); }
  .opts { display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; align-items: center; margin: 12px 0 8px; }
  .diag { width: 100%; margin-top: 10px; font-size: 12px; }
</style>
