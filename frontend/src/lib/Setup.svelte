<script lang="ts">
  // The step-by-step setup of the simple mode: every step says in plain
  // words what it does and why. It opens by itself on the first start
  // (App.svelte) and from «Настройки → Пройти настройку заново».
  import { onMount } from 'svelte';
  import {
    api,
    errText,
    plural,
    optionsOf,
    type CheckResult,
    type Settings,
    type SystemInfo,
    type AutostartInfo,
    type Prefs,
    type GroupView,
  } from '../api';
  // Setup reads and writes the same settings as the pages, each save built
  // on a fresh copy (its revision), so it never undoes a change made
  // elsewhere meanwhile.
  import { ui, hide, mainTarget, mainText, setupStep, setSetupStep, finishSetup } from '../state.svelte';
  import Icon from './Icon.svelte';
  import TargetOptions from './TargetOptions.svelte';
  import RouteWizard from './RouteWizard.svelte';

  let { onclose, go }: { onclose: () => void; go: (page: string) => void } = $props();

  const all = [
    { id: 'hello', label: 'Знакомство' },
    { id: 'install', label: 'Установка' },
    { id: 'server', label: 'Сервер' },
    { id: 'check', label: 'Проверка' },
    { id: 'mode', label: 'Что через VPN' },
    { id: 'launch', label: 'Запуск' },
    { id: 'done', label: 'Готово' },
  ];

  let sys = $state<SystemInfo | null>(null);
  // «Установка» only for a copy outside Program Files.
  const steps = $derived(all.filter((s) => s.id !== 'install' || (sys != null && !sys.protectedLocation)));
  let step = $state(all.some((s) => s.id === setupStep()) ? setupStep() : 'hello');
  const at = $derived(Math.max(0, steps.findIndex((s) => s.id === step)));
  let error = $state('');
  let busy = $state(false);

  function goto(id: string) {
    step = id;
    error = '';
    setSetupStep(id);
  }

  function next() {
    const n = steps[at + 1];
    if (n) goto(n.id);
  }

  function back() {
    const p = steps[at - 1];
    if (p) goto(p.id);
  }

  function skip() {
    finishSetup();
    onclose();
  }

  onMount(() => {
    setSetupStep(step);
    api.System().then((s) => {
      sys = s;
      // Came back after «Установить», or already installed.
      if (step === 'install' && s.protectedLocation) goto('server');
    }).catch(() => {});
  });

  // ---- install ----
  const inTarget = $derived(sys != null && sys.programDir.toLowerCase() === sys.moveTarget.toLowerCase());

  async function install() {
    busy = true;
    error = '';
    // The new copy opens the setup at the next step.
    setSetupStep('server');
    try {
      await api.MoveToProgramFiles(); // this copy exits, the new one starts
    } catch (e) {
      setSetupStep('install');
      error = errText(e);
      busy = false;
    }
  }

  // ---- server ----
  let link = $state('');
  let added = $state('');

  async function paste() {
    error = '';
    try {
      link = (await api.ClipboardText()).trim();
      if (!link) error = 'В буфере обмена пусто. Сначала скопируйте ссылку (выделите её и нажмите Ctrl+C).';
    } catch (e) {
      error = errText(e);
    }
  }

  const otherProto = /^\s*(vless|vmess|trojan|ss|ssr|tuic|wireguard|wg|hysteria|socks5?|https?proxy):\/\//i;

  async function addLink() {
    const t = link.trim();
    error = '';
    added = '';
    if (!t) return;
    busy = true;
    try {
      if (/(hysteria2|hy2):\/\//i.test(t)) {
        const r = await api.ImportURIs(t);
        if (r.added.length) {
          added = `Добавлено: ${r.added.map((p) => hide(p.name)).join(', ')}.`;
          link = '';
        }
        if (!r.added.length && r.skipped.length && !r.errors.length) {
          added = `Такой сервер уже добавлен: ${r.skipped.map(hide).join('; ')}.`;
          link = '';
        }
        if (r.errors.length) error = `Не все ссылки подошли: ${r.errors.map(hide).join('; ')}`;
      } else if (/^https?:\/\//i.test(t)) {
        const pv = await api.PreviewSubscription(t);
        if (pv.count === 0) {
          error = pv.ignoredTotal
            ? `В этой подписке нет серверов Hysteria 2, только серверы других видов (${Object.keys(pv.ignored).join(', ')}). HyRoute работает только с Hysteria 2: попросите у VPN-сервиса ссылку на Hysteria 2.`
            : 'По этой ссылке не нашлось ни одного сервера. Проверьте, что скопировали её целиком, или попросите новую.';
        } else {
          const s = await api.AddSubscription({ token: pv.token, name: pv.title || 'Моя подписка', enabled: true, interval: '24h' });
          added = `Подписка «${hide(s.name)}» добавлена: ${s.profiles} ${plural(s.profiles, 'сервер', 'сервера', 'серверов')}. HyRoute будет обновлять её сам раз в сутки.`;
          link = '';
        }
      } else if (otherProto.test(t)) {
        error = 'Это ссылка другого вида VPN, не Hysteria 2. HyRoute работает только с Hysteria 2: попросите у вашего VPN-сервиса ссылку, которая начинается с hysteria2://, или ссылку подписки.';
      } else {
        error = 'Это не похоже на ссылку. Ссылка сервера начинается с hysteria2:// или hy2://, ссылка подписки — с https://. Скопируйте её целиком.';
      }
      ui.profiles = await api.Profiles();
    } catch (e) {
      error = errText(e);
    }
    busy = false;
  }

  // ---- check ----
  let check = $state<CheckResult | null>(null);
  let checking = $state(false);
  let checkedId = '';
  let details = $state(false);
  // groups: the main may be a server group: its servers are probed
  // instead (a group has no single server to connect to).
  const main = $derived(mainTarget());
  let groupCheck = $state<GroupView | null>(null);
  const groupUp = $derived(groupCheck?.memberViews.filter((m) => !m.missing && !m.probeError && m.latencyMs > 0) ?? []);
  const checkBad = $derived(check ? !check.ok : groupCheck ? groupUp.length === 0 : false);

  async function runCheck() {
    const m = mainTarget();
    if (!m || m.unloaded) return;
    checking = true;
    check = null;
    groupCheck = null;
    error = '';
    details = false;
    checkedId = m.id;
    try {
      if (m.group) {
        const g = await api.ProbeGroup(m.id);
        if (checkedId === m.id) groupCheck = g;
      } else {
        const r = await api.CheckProfile(m.id);
        if (checkedId === m.id) check = r;
      }
    } catch (e) {
      error = errText(e);
    }
    checking = false;
  }

  async function pickMain(id: string) {
    try {
      await api.SetMain(id);
      ui.profiles = await api.Profiles();
      ui.status = await api.Status(); // mainTarget reads the main from it
      runCheck();
    } catch (e) {
      error = errText(e);
    }
  }

  $effect(() => {
    if (step === 'check' && !check && !groupCheck && !checking && !error && main && !main.unloaded) runCheck();
  });

  function speed(ms: number): string {
    if (ms < 80) return 'отлично';
    if (ms < 200) return 'хорошо';
    return 'сервер далеко, сайты будут открываться чуть медленнее';
  }

  const failed = $derived(check?.steps.find((s) => !s.ok && !s.skip));

  // ---- mode ----
  // What goes through the VPN is its own step-by-step (RouteWizard).
  let modeTitle = $state('как было настроено');
  let settings = $state<Settings | null>(null);

  $effect(() => {
    if (step === 'launch' && !settings)
      api
        .Settings()
        .then((s) => (settings = s))
        .catch((e) => (error = errText(e)));
  });

  // ---- launch ----
  let auto = $state<AutostartInfo | null>(null);
  let prefs = $state<Prefs>({});
  let wantAutostart = $state(true);
  let wantConnect = $state(true);
  let wantKill = $state(false);
  let launchLoaded = false;

  $effect(() => {
    if (step !== 'launch' || launchLoaded) return;
    launchLoaded = true;
    Promise.all([api.Autostart(), api.Prefs()])
      .then(([a, p]) => {
        auto = a;
        prefs = p;
        wantAutostart = a.allowed ? true : a.enabled;
        wantConnect = true;
      })
      .catch((e) => (error = errText(e)));
  });

  $effect(() => {
    if (settings && step === 'launch') wantKill = settings.killSwitch ?? false;
  });

  async function applyLaunch() {
    busy = true;
    error = '';
    try {
      if (auto?.allowed && wantAutostart !== auto.enabled) await api.SetAutostart(wantAutostart);
      await api.SavePrefs({ ...(await api.Prefs()), autoConnect: wantConnect });
      const cur = await api.Settings();
      if ((cur.killSwitch ?? false) !== wantKill) await api.SaveEngineOptions({ ...optionsOf(cur), killSwitch: wantKill });
      next();
    } catch (e) {
      error = errText(e);
    }
    busy = false;
  }

  // ---- done ----
  async function connect() {
    busy = true;
    error = '';
    try {
      await api.Connect();
      finishSetup();
      go('home');
      onclose();
    } catch (e) {
      error = errText(e);
    }
    busy = false;
  }

  function later() {
    finishSetup();
    go('home');
    onclose();
  }
</script>

<div class="setup">
  <div class="top">
    <span class="logo"><Icon name="shield" size={18} stroke={2.2} /></span>
    <b>Настройка HyRoute</b>
    <div class="grow"></div>
    {#if step !== 'done'}<button class="ghost" onclick={skip}>Пропустить настройку</button>{/if}
  </div>

  <ol class="progress">
    {#each steps as s, i (s.id)}
      <li class:now={i === at} class:past={i < at}>
        <span class="num">{#if i < at}<Icon name="check" size={13} stroke={3} />{:else}{i + 1}{/if}</span>
        <span class="lbl">{s.label}</span>
      </li>
    {/each}
  </ol>

  {#if step === 'mode'}
    <RouteWizard
      onback={back}
      ondone={(t) => {
        modeTitle = t;
        next();
      }}
      onkeep={() => {
        modeTitle = 'как было настроено';
        next();
      }}
    />
  {:else}
  <div class="body">
    {#if ui.status?.loadError}<div class="note error">Настройки не загружены: {hide(ui.status.loadError)}</div>{/if}
    {#if step === 'hello'}
      <h1>Добро пожаловать!</h1>
      <p class="lead">
        HyRoute — VPN, в котором вы сами выбираете, что через него пускать: отдельные сервисы и программы или весь интернет. Всё остальное
        работает напрямую, как без VPN.
      </p>
      <p>
        Сейчас мы вместе всё настроим. Это займёт пару минут, и на каждом шаге будет написано, что делать. Ничего сломать нельзя: любую настройку
        потом можно поменять.
      </p>
      <div class="box">
        <Icon name="clipboard" size={20} />
        <div>
          <b>Что понадобится</b>
          <p>
            Ссылка на ваш VPN-сервер или ссылка подписки. Её дают там, где вы купили VPN (на сайте, в Telegram-боте или письме), или человек,
            который настроил вам сервер. Приготовьте её, она понадобится на третьем шаге.
          </p>
        </div>
      </div>
      <p class="muted small">
        Сейчас HyRoute показывает только самое нужное и подробно объясняет каждый шаг. Если вы разбираетесь в сетях, все страницы и тонкие
        настройки включаются в «Настройки → Режим интерфейса».
      </p>
    {:else if step === 'install'}
      <h1>Установим HyRoute как обычную программу</h1>
      {#if sys && inTarget}
        <p class="lead">
          HyRoute уже лежит в {sys.programDir}, но права этой папки разрешают менять файлы программам без прав администратора. Откройте свойства
          папки, вкладку «Безопасность», и оставьте запись и изменение только администраторам. Или пропустите этот шаг: HyRoute будет работать,
          но не сможет запускаться вместе с Windows.
        </p>
      {:else if sys}
        <p class="lead">
          Сейчас HyRoute запущен из папки <span class="path">{sys.programDir}</span> — скорее всего, из «Загрузок» или с рабочего стола.
        </p>
        <p>
          HyRoute работает с правами администратора, поэтому ему нужно лежать в защищённой папке Program Files: туда без вашего разрешения не
          может писать ни одна программа, и никто не подменит HyRoute незаметно.
        </p>
        <div class="box">
          <Icon name="info" size={20} />
          <div>
            <b>Что произойдёт, когда вы нажмёте «Установить»</b>
            <p>
              HyRoute скопирует себя в <span class="path">{sys.moveTarget}</span>, добавит ярлык в меню «Пуск» и перезапустится оттуда. Окно
              закроется на пару секунд и откроется снова, а настройка продолжится со следующего шага. Скачанный архив и папку, из которой вы
              запустили HyRoute, потом можно удалить.
            </p>
          </div>
        </div>
      {/if}
    {:else if step === 'server'}
      <h1>Добавьте ваш VPN-сервер</h1>
      <p class="lead">Вам должны были дать ссылку. Она бывает двух видов, подходит любая:</p>
      <ul class="kinds">
        <li><b>ссылка на сервер</b> — начинается с <code>hysteria2://</code> или <code>hy2://</code>;</li>
        <li><b>ссылка подписки</b> — начинается с <code>https://</code>. По ней HyRoute сам получит список серверов и будет его обновлять.</li>
      </ul>
      <p>
        Скопируйте ссылку целиком (обычно она длинная, это нормально) и нажмите «Вставить из буфера». Или щёлкните по полю и нажмите
        <kbd>Ctrl</kbd>+<kbd>V</kbd>.
      </p>
      <textarea
        rows="3"
        class:masked={ui.privacy}
        placeholder="hysteria2://…  или  https://…"
        bind:value={link}
        onkeydown={(e) => e.key === 'Enter' && !e.shiftKey && (e.preventDefault(), addLink())}
      ></textarea>
      <div class="row">
        <button onclick={paste} disabled={busy}><Icon name="clipboard" size={16} />Вставить из буфера</button>
        <button class="primary" onclick={addLink} disabled={busy || !link.trim()}>{busy ? 'Добавляю…' : 'Добавить'}</button>
      </div>
      {#if added}<div class="note ok">{added}</div>{/if}
      {#if ui.profiles.length}
        <p class="muted small">
          Серверов добавлено: {ui.profiles.length}{ui.profiles.length <= 4 ? ` (${ui.profiles.map((p) => hide(p.name)).join(', ')})` : ''}. Можно
          переходить дальше.
        </p>
      {/if}
    {:else if step === 'check'}
      <h1>Проверим, что сервер работает</h1>
      {#if ui.profiles.length > 1 || ui.groups.length > 0 || main?.group}
        <p class="lead">
          У вас {ui.profiles.length} {plural(ui.profiles.length, 'сервер', 'сервера', 'серверов')}. Выберите основной: через него пойдёт трафик VPN.
          Обычно лучше всего работает ближайший к вам. Поменять его можно в любой момент на главной.
        </p>
        <select class="big-select" value={main?.id ?? ''} onchange={(e) => pickMain((e.currentTarget as HTMLSelectElement).value)} disabled={checking}>
          {#if main?.unloaded}<option value={main.id} disabled>основная группа не загружена</option>{/if}
          <TargetOptions current={main?.unloaded ? '' : main?.id} />
        </select>
      {:else}
        <p class="lead">HyRoute ненадолго подключится к серверу и проверит, что через него открывается интернет.</p>
      {/if}

      {#if main?.unloaded}
        <div class="verdict bad">
          <Icon name="alert" size={22} />
          <div>
            <b>Основная группа не загружена</b>
            <p>groups.json не читается, поэтому проверить её нельзя. Выберите выше сервер или исправьте файл.</p>
          </div>
        </div>
      {:else if checking}
        <div class="verdict wait">
          <span class="spin"></span>{main?.group ? `Проверяю серверы группы «${main.name}»…` : `Подключаюсь к серверу${main ? ` «${main.name}»` : ''}…`} Это может
          занять до 30 секунд.
        </div>
      {:else if groupCheck}
        {#if groupUp.length}
          <div class="verdict ok">
            <Icon name="check" size={22} stroke={2.6} />
            <div>
              <b>Группа работает</b>
              <p>
                Отвечают {groupUp.length} из {groupCheck.memberViews.length}
                {plural(groupCheck.memberViews.length, 'сервера', 'серверов', 'серверов')}, самый быстрый — {Math.min(...groupUp.map((m) => m.latencyMs))} мс.
              </p>
            </div>
          </div>
        {:else}
          <div class="verdict bad">
            <Icon name="alert" size={22} />
            <div>
              <b>Ни один сервер группы «{main?.name}» не ответил</b>
              <p>Проверьте, что интернет работает без VPN, или выберите выше один сервер: его проверка покажет, что не так.</p>
            </div>
          </div>
        {/if}
        <ul class="steps">
          {#each groupCheck.memberViews as m (m.id)}
            <li class:bad={!!m.probeError}>{m.probeError ? '✗' : m.latencyMs ? '✓' : '–'} {hide(m.name)}: {m.probeError ? hide(m.probeError) : m.latencyMs ? `${m.latencyMs} мс` : 'нет ответа'}</li>
          {/each}
        </ul>
      {:else if check?.ok}
        <div class="verdict ok">
          <Icon name="check" size={22} stroke={2.6} />
          <div>
            <b>Сервер работает</b>
            {#if check.externalIP}<p>Через VPN сайты будут видеть адрес {hide(check.externalIP)}, а не ваш.</p>{/if}
            {#if check.latencyMs}<p>Задержка {check.latencyMs} мс — {speed(check.latencyMs)}.</p>{/if}
          </div>
        </div>
      {:else if check}
        <div class="verdict bad">
          <Icon name="alert" size={22} />
          <div>
            <b>Не получилось подключиться к серверу</b>
            {#if failed}<p>{failed.name}: {hide(failed.detail)}</p>{/if}
          </div>
        </div>
        <div class="box">
          <Icon name="info" size={20} />
          <div>
            <b>Что можно сделать</b>
            <ul>
              <li>Проверьте, что интернет работает без VPN (откройте любой сайт).</li>
              <li>Ссылка могла устареть или скопироваться не целиком. Попросите новую у того, кто её дал, и добавьте на шаге «Сервер».</li>
              {#if ui.profiles.length > 1}<li>Выберите выше другой сервер: проверка запустится сама.</li>{/if}
              <li>Можно пропустить проверку и настроить остальное, а сервер поправить потом.</li>
            </ul>
          </div>
        </div>
        <button class="link" onclick={() => (details = !details)}>{details ? 'Скрыть подробности' : 'Подробности для техподдержки'}</button>
        {#if details}
          <ul class="steps">
            {#each check.steps as s}<li class:bad={!s.ok && !s.skip}>{s.ok ? '✓' : s.skip ? '–' : '✗'} {s.name}: {hide(s.detail)}</li>{/each}
          </ul>
        {/if}
      {/if}
      {#if (check || groupCheck) && !checking}<div class="row"><button onclick={runCheck}><Icon name="refresh" size={16} />Проверить ещё раз</button></div>{/if}
    {:else if step === 'launch'}
      <h1>Запуск и защита</h1>
      <p class="lead">Последние настройки. Если не уверены — оставьте как есть.</p>
      <div class="opts">
        {#if auto?.allowed}
          <label class="opt">
            <input type="checkbox" bind:checked={wantAutostart} />
            <span><b>Запускать HyRoute вместе с Windows</b>
              <span>HyRoute будет запускаться сам, когда вы входите в Windows, и тихо ждать в трее — у часов в правом нижнем углу экрана.</span></span
            >
          </label>
        {:else if auto}
          <div class="note warn small">
            Запуск вместе с Windows доступен, только когда HyRoute установлен в Program Files (шаг «Установка»). Его можно включить потом в «Настройках».
          </div>
        {/if}
        <label class="opt">
          <input type="checkbox" bind:checked={wantConnect} />
          <span><b>Сразу подключаться после запуска</b>
            <span>Не нужно каждый раз нажимать кнопку: VPN включится сам, как только HyRoute запустится.</span></span
          >
        </label>
        <label class="opt">
          <input type="checkbox" bind:checked={wantKill} />
          <span><b>Kill switch: не пускать интернет мимо VPN</b>
            <span>
              Если HyRoute вдруг закроется или сломается, Windows закроет интернет, чтобы ничего не ушло без VPN. Интернет вернётся, когда вы снова
              подключитесь или нажмёте «Открыть интернет». Нужно, если важно, чтобы ни один запрос не прошёл мимо VPN. Не уверены — не включайте.
            </span></span
          >
        </label>
      </div>
      {#if prefs.closeToTray ?? true}
        <div class="box">
          <Icon name="info" size={20} />
          <div>
            <b>Куда пропадает окно</b>
            <p>
              Крестик в углу окна не закрывает HyRoute, а прячет его в трей — к часам в правом нижнем углу экрана (иногда значок спрятан под
              стрелочкой <b>^</b>). Щелчок по значку открывает окно снова. Чтобы выйти из HyRoute совсем: правая кнопка мыши по значку → «Выход».
            </p>
          </div>
        </div>
      {/if}
    {:else if step === 'done'}
      <h1>Всё готово!</h1>
      <div class="summary">
        <div><span class="muted">Сервер</span><b>{mainText() || 'не добавлен'}</b></div>
        <div><span class="muted">Через VPN</span><b>{modeTitle}</b></div>
        {#if auto}<div><span class="muted">Запуск с Windows</span><b>{wantAutostart && auto.allowed ? 'да' : 'нет'}</b></div>{/if}
      </div>
      <p class="lead">Осталось включить VPN. Потом включать и выключать его можно большой кнопкой на главной странице.</p>
      <div class="box">
        <Icon name="info" size={20} />
        <div>
          <b>Если какой-то сайт не открывается</b>
          <ul>
            <li>Откройте «Правила» и внизу страницы нажмите «Проверить адрес»: введите сайт, и HyRoute покажет, идёт ли он через VPN и почему.</li>
            <li>Чтобы отправить сайт или программу через VPN, в «Правилах» нажмите «Шаблоны» (YouTube, Discord, ChatGPT и другие) или «Правило».</li>
            <li>Настройку можно пройти заново: «Настройки → Пройти настройку заново».</li>
          </ul>
        </div>
      </div>
    {/if}

    {#if error}<div class="note error">{hide(error)}</div>{/if}
  </div>

  <div class="nav">
    {#if at > 0 && step !== 'done'}<button onclick={back} disabled={busy}>Назад</button>{/if}
    <div class="grow"></div>
    {#if step === 'hello'}
      <button class="primary big" onclick={next}>Начать<Icon name="arrow" size={16} /></button>
    {:else if step === 'install'}
      <button class="ghost" onclick={next} disabled={busy}>Пропустить</button>
      {#if sys && !inTarget}<button class="primary big" onclick={install} disabled={busy}>{busy ? 'Устанавливаю…' : 'Установить'}</button>{/if}
    {:else if step === 'server'}
      <button class="primary big" onclick={next} disabled={busy || ui.profiles.length === 0} title={ui.profiles.length ? '' : 'Сначала добавьте сервер'}
        >Дальше<Icon name="arrow" size={16} /></button
      >
    {:else if step === 'check'}
      <button class="primary big" onclick={next} disabled={checking && !check && !groupCheck}>{checkBad ? 'Всё равно дальше' : 'Дальше'}<Icon name="arrow" size={16} /></button>
    {:else if step === 'launch'}
      <button class="primary big" onclick={applyLaunch} disabled={busy || !auto}>{busy ? 'Сохраняю…' : 'Дальше'}<Icon name="arrow" size={16} /></button>
    {:else if step === 'done'}
      <button class="ghost" onclick={later} disabled={busy}>Закрыть, подключусь потом</button>
      <button class="primary big" onclick={connect} disabled={busy || ui.profiles.length === 0}><Icon name="power" size={18} />{busy ? 'Подключаюсь…' : 'Включить VPN'}</button>
    {/if}
  </div>
  {/if}
</div>

<style>
  .setup {
    position: fixed;
    inset: 0;
    z-index: 30;
    background: var(--bg);
    display: flex;
    flex-direction: column;
    animation: fade 0.15s ease-out;
  }
  .top { display: flex; align-items: center; gap: 10px; padding: 14px 24px; font-size: 15px; min-height: 66px; }
  .logo {
    width: 30px;
    height: 30px;
    border-radius: 9px;
    display: grid;
    place-items: center;
    color: #fff;
    background: linear-gradient(135deg, var(--accent), color-mix(in srgb, var(--accent) 55%, #b06cff));
  }

  .progress { list-style: none; display: flex; justify-content: center; gap: 6px; margin: 0; padding: 4px 24px 18px; flex-wrap: wrap; }
  .progress li { display: flex; align-items: center; gap: 6px; color: var(--faint); font-size: 12.5px; }
  .progress li + li::before { content: ''; width: 22px; height: 2px; border-radius: 1px; background: var(--border); margin-right: 2px; }
  .num {
    width: 22px;
    height: 22px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    font-size: 11.5px;
    font-weight: 700;
    background: var(--surface-2);
    color: var(--muted);
  }
  .progress li.now { color: var(--text); font-weight: 600; }
  .progress li.now .num { background: var(--accent); color: #fff; }
  .progress li.past .num { background: var(--accent-soft); color: var(--accent); }
  .progress li.past { color: var(--muted); }

  .body { flex: 1; overflow: auto; width: 100%; max-width: 760px; margin: 0 auto; padding: 8px 28px 20px; display: flex; flex-direction: column; gap: 12px; user-select: text; }
  .body h1 { font-size: 26px; margin-bottom: 2px; }
  .body p { margin: 0; }
  .lead { font-size: 15px; }
  .small { font-size: 12.5px; }
  .path { font-family: var(--mono); font-size: 12.5px; background: var(--surface-2); padding: 1px 6px; border-radius: 4px; word-break: break-all; }
  code, kbd { font-family: var(--mono); font-size: 12.5px; background: var(--surface-2); padding: 1px 6px; border-radius: 4px; }
  kbd { border: 1px solid var(--border); border-bottom-width: 2px; }
  .kinds { margin: 0; padding-left: 20px; display: grid; gap: 4px; }
  textarea { width: 100%; font-size: 13px; }
  textarea.masked { -webkit-text-security: disc; }

  .box { display: flex; gap: 12px; padding: 14px 16px; border-radius: var(--radius); background: var(--accent-soft); }
  .box > :global(svg) { color: var(--accent); flex: none; margin-top: 1px; }
  .box p { margin-top: 4px; }
  .box ul { margin: 6px 0 0; padding-left: 18px; display: grid; gap: 4px; }

  .big-select { font-size: 15px; padding: 9px 12px; max-width: 460px; }

  .verdict { display: flex; gap: 12px; align-items: flex-start; padding: 14px 16px; border-radius: var(--radius); font-size: 14px; }
  .verdict b { font-size: 16px; }
  .verdict p { margin-top: 2px; }
  .verdict.ok { background: var(--ok-bg); color: var(--direct); }
  .verdict.bad { background: var(--danger-bg); color: var(--block); }
  .verdict.wait { background: var(--surface-2); align-items: center; }
  .verdict :global(svg) { flex: none; }
  .spin { width: 18px; height: 18px; border-radius: 50%; border: 2.5px solid var(--border); border-top-color: var(--accent); animation: rot 0.8s linear infinite; flex: none; }
  @keyframes rot { to { transform: rotate(360deg); } }
  .steps { list-style: none; padding: 0; margin: 0; display: grid; gap: 4px; font-size: 12.5px; color: var(--muted); }
  .steps li.bad { color: var(--block); }
  .link { justify-self: start; align-self: flex-start; }

  .opts { display: grid; gap: 10px; }
  .opt { display: flex; gap: 12px; align-items: flex-start; padding: 14px 16px; border-radius: var(--radius); background: var(--surface); border: 1px solid var(--border); cursor: pointer; }
  .opt input { margin-top: 3px; flex: none; width: 17px; height: 17px; }
  .opt > span { display: grid; gap: 3px; }
  .opt > span > span { color: var(--muted); font-size: 13px; }

  .summary { display: grid; grid-template-columns: max-content 1fr; gap: 6px 18px; padding: 14px 16px; border-radius: var(--radius); background: var(--surface); border: 1px solid var(--border); }
  .summary > div { display: contents; }

  .nav { display: flex; align-items: center; gap: 8px; padding: 14px 28px 18px; border-top: 1px solid var(--border); background: var(--surface); }
  .nav .big { padding: 10px 22px; font-size: 15px; font-weight: 600; }

  @media (max-width: 720px) {
    .progress .lbl { display: none; }
    .progress li.now .lbl { display: inline; }
  }
</style>
