<script lang="ts">
  // The rules, step by step: what goes through the VPN, what goes direct
  // and what is blocked, each step explained. Part of the setup and the
  // «Пошагово» button on the Rules page. The user chooses everything; the
  // steps only put it into rules in a working order.
  import { onMount } from 'svelte';
  import { api, errText, plural, cleanSettings, cleanFallback, type Action, type Rule, type Settings, type RunningApp } from '../api';
  import { ui, hide, mainProfile, profileName } from '../state.svelte';
  import { templates, ruleFromTemplate, type Template } from './templates';
  import { itemLabel, isSpecial, isAddress, shortLabel, loadGeo } from '../geo.svelte';
  import { appLabel } from '../ruletitle';
  import Icon from './Icon.svelte';
  import AppPicker from './AppPicker.svelte';
  import GeoPicker from './GeoPicker.svelte';

  let { onback, ondone }: { onback: () => void; ondone: (summary: string) => void } = $props();

  type Way = 'tunnel' | 'direct';
  const tpl = (id: string) => templates.find((t) => t.id === id)!;

  // ---- what the user chose ----
  // only: only the chosen goes through the VPN; all: everything but the chosen.
  let base = $state<'only' | 'all' | ''>('');
  let picked = $state<string[]>([]); // services (only) or direct lists (all)
  let apps = $state<{ pattern: string; label: string; way: Way }[]>([]);
  let sites = $state<{ item: string; way: Way }[]>([]);
  let blocks = $state<string[]>([]);
  // The server of each group that goes through the VPN ('' = main).
  let server = $state<Record<string, string>>({});
  let reserve = $state(true);
  let replace = $state(false);
  let settings = $state<Settings | null>(null);
  let error = $state('');
  let busy = $state(false);

  onMount(() => {
    loadGeo();
    api.Settings()
      .then((s) => (settings = s))
      .catch((e) => (error = errText(e)));
  });

  const hasRules = $derived((settings?.rules?.length ?? 0) > 0);
  const main = $derived(mainProfile());
  const way: Way = $derived(base === 'all' ? 'direct' : 'tunnel');

  // ---- services and lists ----
  const aiApps: Template = { id: 'ai-apps', name: 'Нейросети — программы', hint: '', apps: ['ChatGPT.exe', 'claude.exe'], domains: [], group: 'Сервисы' };
  const aiSites: Template = { ...tpl('ai'), name: 'Нейросети — сайты' };
  interface Tile {
    id: string;
    title: string;
    hint: string;
    best?: boolean;
    rules: Template[];
  }
  const services: Tile[] = [
    { id: 'ai', title: 'Нейросети', hint: 'ChatGPT, Claude, Gemini, Copilot и другие — сайты и программы', best: true, rules: [aiSites, aiApps] },
    { id: 'telegram', title: 'Telegram', hint: 'программа, веб-версия и серверы Telegram', best: true, rules: [tpl('telegram-app'), tpl('telegram')] },
    { id: 'youtube', title: 'YouTube', hint: 'сайт, видео и приложение', rules: [tpl('youtube')] },
    { id: 'discord', title: 'Discord', hint: 'программа с голосовыми каналами и сайт', rules: [tpl('discord-app'), tpl('discord')] },
    { id: 'meta', title: 'Instagram, Facebook, WhatsApp', hint: 'все сервисы Meta', rules: [tpl('meta')] },
    { id: 'x', title: 'X (Twitter)', hint: 'сайт и медиа', rules: [tpl('x')] },
    { id: 'spotify', title: 'Spotify', hint: 'программа и сайт', rules: [tpl('spotify-app'), tpl('spotify')] },
    { id: 'netflix', title: 'Netflix', hint: 'сайт и видео', rules: [tpl('netflix')] },
    { id: 'twitch', title: 'Twitch', hint: 'сайт и трансляции', rules: [tpl('twitch')] },
    { id: 'linkedin', title: 'LinkedIn', hint: 'сайт', rules: [tpl('linkedin')] },
    { id: 'ru-blocked', title: 'Всё заблокированное в России', hint: 'сайты и адреса из реестра блокировок, список обновляется сам', rules: [tpl('ru-blocked')] },
  ];
  const directLists: Tile[] = [
    {
      id: 'ru-inside',
      title: 'Банки, Госуслуги и сайты, которые работают только из России',
      hint: 'с зарубежного адреса они часто не открываются или просят подтверждение',
      best: true,
      rules: [tpl('ru-inside')],
    },
    { id: 'ru-all', title: 'Все российские сайты', hint: 'зона .ru, Яндекс, VK, российские сети: открываются быстрее и не тратят трафик VPN', rules: [tpl('ru-all')] },
  ];
  const blockTiles: Tile[] = [
    { id: 'ads', title: 'Реклама', hint: 'рекламные сети в браузере и программах. Если из-за этого сломается какой-то сайт, правило можно выключить', rules: [tpl('ads')] },
    { id: 'telemetry', title: 'Телеметрия Windows', hint: 'сбор данных Microsoft. Может мешать обновлениям Windows и магазину приложений', rules: [tpl('telemetry')] },
  ];
  const tiles = $derived(base === 'all' ? directLists : services);

  function toggle(list: string[], id: string): string[] {
    return list.includes(id) ? list.filter((x) => x !== id) : [...list, id];
  }

  // ---- programs ----
  let pickingApps = $state(false);

  function addApp(pattern: string, label: string) {
    if (apps.some((a) => a.pattern.toLowerCase() === pattern.toLowerCase())) return;
    apps = [...apps, { pattern, label, way }];
  }

  function addRunning(a: RunningApp) {
    addApp(a.name, a.description || a.name.replace(/\.exe$/i, ''));
  }

  async function browse() {
    try {
      const path = await api.BrowseExe();
      if (path) addApp(path, path.split('\\').pop()?.replace(/\.exe$/i, '') ?? path);
    } catch (e) {
      error = errText(e);
    }
  }

  // ---- sites ----
  let siteInput = $state('');
  let pickingLists = $state(false);

  // "https://www.example.com/page" -> ".example.com": the site and its
  // subdomains, as the rule editor adds it.
  function addSites(text: string) {
    for (const raw of text.split(/[\s,;]+/)) {
      let s = raw.trim();
      if (!s) continue;
      if (isSpecial(s)) {
        addSite(s.replace(/^[a-z]+:/i, (p) => p.toLowerCase()));
        continue;
      }
      s = s.toLowerCase();
      try {
        if (/^[a-z]+:\/\//.test(s)) s = new URL(s).hostname;
      } catch {}
      s = s.replace(/\/.*$/, '').replace(/:\d+$/, '');
      const ip = s.replace(/^\[(.*)\]$/, '$1');
      if (isAddress(ip)) addSite(ip);
      else if (s) addSite(s.startsWith('.') || s.startsWith('*.') ? s : '.' + s.replace(/^www\./, ''));
    }
    siteInput = '';
  }

  function addSite(item: string) {
    if (!sites.some((x) => x.item === item)) sites = [...sites, { item, way }];
  }

  function siteText(item: string): string {
    const l = itemLabel(item);
    return l?.geo ? `список «${l.text}»` : hide(shortLabel(item));
  }

  // ---- the rules ----
  interface Group {
    key: string; // server[key]
    title: string;
    rules: Rule[];
  }

  function fromTemplates(ts: Template[]): Rule[] {
    return ts.map(ruleFromTemplate);
  }

  const tunnelWord = (w: Way) => (w === 'tunnel' ? 'через VPN' : 'напрямую');

  // groups are the rules in their order: the home network, the user's own
  // sites and programs (above the lists, which may hold the same names),
  // blocks, then the lists. «Работает только из России» stays above the
  // services, as in the ready-made schemes (the lists overlap).
  const groups = $derived.by((): Group[] => {
    const g: Group[] = [{ key: '', title: 'Домашняя сеть', rules: fromTemplates([tpl('lan')]) }];
    for (const w of ['tunnel', 'direct'] as Way[]) {
      const ss = sites.filter((x) => x.way === w);
      if (ss.length) g.push({ key: 'sites-' + w, title: `Мои сайты ${tunnelWord(w)}`, rules: [{ name: `Мои сайты ${tunnelWord(w)}`, apps: [], domains: ss.map((x) => x.item), action: w, profile: '' }] });
    }
    for (const w of ['tunnel', 'direct'] as Way[]) {
      const aa = apps.filter((x) => x.way === w);
      if (aa.length)
        g.push({
          key: 'apps-' + w,
          title: `Мои программы ${tunnelWord(w)}`,
          rules: [{ name: `Мои программы ${tunnelWord(w)}`, apps: aa.map((a) => ({ pattern: a.pattern, inheritChildren: true })), domains: [], action: w, profile: '' }],
        });
    }
    for (const t of blockTiles) if (blocks.includes(t.id)) g.push({ key: t.id, title: t.title, rules: fromTemplates(t.rules) });
    if (base === 'all') {
      for (const t of directLists) if (picked.includes(t.id)) g.push({ key: t.id, title: t.title, rules: fromTemplates(t.rules) });
    } else {
      for (const t of services) if (picked.includes(t.id)) g.push({ key: t.id, title: t.title, rules: fromTemplates(t.rules) });
    }
    return g;
  });

  // The groups that go through the VPN, and «всё остальное» when it does:
  // the server step lists them.
  const vpnGroups = $derived([
    ...groups.filter((g) => g.rules.some((r) => r.action === 'tunnel')),
    ...(base === 'all' ? [{ key: 'rest', title: 'Весь остальной интернет', rules: [] }] : []),
  ]);

  function reserveOf(profile: string): string[] {
    if (!reserve) return [];
    return cleanFallback(
      ui.profiles.map((p) => p.id),
      profile,
      main?.id,
    );
  }

  function built(): Rule[] {
    return groups.flatMap((g) =>
      g.rules.map((r) => {
        if (r.action !== 'tunnel') return r;
        const profile = server[g.key] ?? '';
        return { ...r, profile, fallback: reserveOf(profile) };
      }),
    );
  }

  const restAction: Action = $derived(base === 'all' ? 'tunnel' : 'direct');

  function serverName(id: string): string {
    return id ? profileName(id) : main ? hide(main.name) : 'основной сервер';
  }

  // What a rule takes, in words: a template's hint, else its items.
  function ruleText(r: Rule): string {
    const t = [...templates, aiSites].find((x) => x.name === r.name && x.hint);
    if (t) return t.hint.replace(/ → .*$/, '');
    return [...(r.apps ?? []).map((a) => appLabel(a.pattern)), ...(r.domains ?? []).map((d) => (itemLabel(d)?.geo ? `«${itemLabel(d)!.text}»` : hide(shortLabel(d))))].join(', ');
  }

  // ---- steps ----
  const steps = $derived([
    { id: 'intro', label: 'Как это устроено' },
    { id: 'base', label: 'Основа' },
    { id: 'lists', label: base === 'all' ? 'Что напрямую' : 'Сервисы' },
    { id: 'apps', label: 'Программы' },
    { id: 'sites', label: 'Сайты' },
    { id: 'block', label: 'Блокировка' },
    ...(ui.profiles.length > 1 ? [{ id: 'servers', label: 'Серверы' }] : []),
    { id: 'sum', label: 'Итог' },
  ]);
  let step = $state('intro');
  const at = $derived(Math.max(0, steps.findIndex((s) => s.id === step)));

  function next() {
    error = '';
    if (step === 'sites' && siteInput.trim()) addSites(siteInput);
    const n = steps[at + 1];
    if (n) step = n.id;
  }

  function back() {
    error = '';
    if (at === 0) return onback();
    step = steps[at - 1].id;
  }

  const nothing = $derived(base === 'only' && !picked.length && !apps.some((a) => a.way === 'tunnel') && !sites.some((s) => s.way === 'tunnel'));

  function summary(): string {
    if (base === 'all') return 'весь интернет' + (groups.some((g) => g.rules.some((r) => r.action === 'direct') && g.key !== '') ? ', кроме выбранного' : '');
    const names = services.filter((t) => picked.includes(t.id)).map((t) => t.title);
    const n = apps.filter((a) => a.way === 'tunnel').length;
    const m = sites.filter((s) => s.way === 'tunnel').length;
    if (n) names.push(`${n} ${plural(n, 'программа', 'программы', 'программ')}`);
    if (m) names.push(`${m} ${plural(m, 'сайт', 'сайта', 'сайтов')}`);
    return names.join(', ') || 'ничего';
  }

  async function save() {
    busy = true;
    error = '';
    try {
      // Built on a fresh copy: it carries the revision Go checks the save against.
      const cur = await api.Settings();
      const next: Settings = JSON.parse(JSON.stringify(cur));
      next.rules = replace ? built() : [...built(), ...(cur.rules ?? [])];
      next.defaultAction = restAction;
      next.defaultProfile = restAction === 'tunnel' ? (server.rest ?? '') : '';
      next.defaultFallback = restAction === 'tunnel' ? reserveOf(server.rest ?? '') : [];
      await api.SaveSettings(cleanSettings(next, main?.id));
      ondone(summary());
    } catch (e) {
      error = errText(e);
    }
    busy = false;
  }
</script>

<div class="wz">
  <div class="body">
    <div class="sub">
      <span>Шаг {at + 1} из {steps.length} · {steps[at].label}</span>
      <span class="bar"><span style="width: {((at + 1) / steps.length) * 100}%"></span></span>
    </div>

    {#if step === 'intro'}
      <h1>Настроим, что пускать через VPN</h1>
      <p class="lead">
        Каждое соединение с интернетом — сайт в браузере, сообщение в Telegram, игра — HyRoute отправляет одним из трёх путей. Какой путь у чего,
        выбираете вы: сейчас по шагам соберём это в правила.
      </p>
      <div class="ways">
        <div class="way tunnel">
          <b><Icon name="shield" size={16} /> Через VPN</b>
          <span>Через ваш сервер. Сайт видит адрес сервера, а не ваш, и открываются сервисы, заблокированные в России.</span>
        </div>
        <div class="way direct">
          <b><Icon name="arrow" size={16} /> Напрямую</b>
          <span>Как без VPN. Быстрее и не тратит трафик VPN, сайт видит ваш обычный адрес.</span>
        </div>
        <div class="way block">
          <b><Icon name="ban" size={16} /> Заблокировать</b>
          <span>Соединение не пройдёт вообще. Так убирают, например, рекламу.</span>
        </div>
      </div>
      <p>
        На каждом шаге можно ничего не выбирать и просто нажать «Дальше». В конце покажем, что получилось, а поменять всё можно в любой момент на
        странице «Правила».
      </p>
    {:else if step === 'base'}
      <h1>Как вы будете пользоваться VPN?</h1>
      <p class="lead">Это главный выбор: от него зависит, о чём будут следующие шаги.</p>
      <div class="choices">
        <button class="choice" class:on={base === 'only'} onclick={() => (base = 'only')}>
          <span class="radio"></span>
          <span class="ctext">
            <span class="ctitle">Только для того, что я выберу</span>
            <span>Через VPN пойдут только выбранные вами сервисы, программы и сайты. Весь остальной интернет — напрямую, как без VPN.</span>
            <span class="muted small">Подходит, если VPN нужен для нескольких вещей: например, нейросети, Telegram и YouTube.</span>
          </span>
        </button>
        <button class="choice" class:on={base === 'all'} onclick={() => (base = 'all')}>
          <span class="radio"></span>
          <span class="ctext">
            <span class="ctitle">Для всего, кроме того, что я выберу</span>
            <span>Весь интернет пойдёт через VPN, как в обычном VPN. Напрямую — только то, что вы выберете.</span>
            <span class="muted small">Подходит, если нужно, чтобы через VPN шло всё, но, например, банки и Госуслуги открывались без него.</span>
          </span>
        </button>
      </div>
    {:else if step === 'lists'}
      {#if base === 'all'}
        <h1>Что оставить напрямую?</h1>
        <p class="lead">
          Некоторые сайты не работают или работают хуже, когда видят зарубежный адрес сервера. Отметьте, что пускать мимо VPN. Списки сайтов
          HyRoute скачает сам и будет обновлять.
        </p>
      {:else}
        <h1>Какие сервисы пустить через VPN?</h1>
        <p class="lead">
          Для каждого сервиса уже известны его сайты, адреса и программа: списки берутся из базы и обновляются сами, вписывать ничего не нужно.
          Отметьте нужные.
        </p>
      {/if}
      {#each [true, false] as best (best)}
        {@const list = tiles.filter((t) => !!t.best === best)}
        {#if list.length}
          <div class="group">{best ? 'Рекомендуем' : 'Ещё'}</div>
          <div class="tiles">
            {#each list as t (t.id)}
              <button class="tile" class:on={picked.includes(t.id)} onclick={() => (picked = toggle(picked, t.id))} aria-pressed={picked.includes(t.id)}>
                <span class="check">{#if picked.includes(t.id)}<Icon name="check" size={14} stroke={3} />{/if}</span>
                <span class="ttext"><b>{t.title}</b><span>{t.hint}</span></span>
              </button>
            {/each}
          </div>
        {/if}
      {/each}
      <p class="muted small">
        Домашняя сеть (роутер, принтер, NAS) всегда идёт напрямую, это HyRoute добавит сам.{base === 'only'
          ? ' Нужного сервиса нет? Его можно добавить на шаге «Сайты» — там есть поиск по готовым спискам.'
          : ''}
      </p>
    {:else if step === 'apps'}
      <h1>{base === 'all' ? 'Пустить какие-то программы мимо VPN?' : 'Пустить через VPN целые программы?'}</h1>
      <p class="lead">
        Правило на программу действует на всё, что она делает: на любых сайтах и серверах. Так удобно для игр, лаунчеров, торрент-клиентов и
        мессенджеров. Программы, которые запускает выбранная (лаунчер → игра, браузер → его вкладки), тоже попадут под правило.
      </p>
      <p>Если такое не нужно, просто нажмите «Дальше».</p>
      <div class="row">
        <button onclick={() => (pickingApps = true)}><Icon name="app" size={16} />Выбрать из запущенных…</button>
        <button onclick={browse}><Icon name="folder" size={16} />Найти файл программы…</button>
      </div>
      <p class="muted small">Нужной программы нет в списке запущенных — запустите её и откройте список снова, или найдите её .exe-файл.</p>
      {#if apps.length}
        <div class="items">
          {#each apps as a, i (a.pattern)}
            <div class="item">
              <Icon name="app" size={16} />
              <span class="grow ellipsis" title={a.pattern}><b>{a.label}</b> <span class="muted small">{appLabel(a.pattern)}</span></span>
              <div class="seg">
                <button class:on={a.way === 'tunnel'} onclick={() => (apps[i].way = 'tunnel')}>Через VPN</button>
                <button class:on={a.way === 'direct'} onclick={() => (apps[i].way = 'direct')}>Напрямую</button>
              </div>
              <button class="icon" title="Убрать" onclick={() => (apps = apps.filter((_, j) => j !== i))}><Icon name="x" size={15} /></button>
            </div>
          {/each}
        </div>
      {/if}
    {:else if step === 'sites'}
      <h1>{base === 'all' ? 'Пустить какие-то сайты мимо VPN?' : 'Пустить через VPN отдельные сайты?'}</h1>
      <p class="lead">
        Впишите адрес сайта, например <code>example.com</code>, или вставьте ссылку прямо из браузера — HyRoute возьмёт из неё адрес. Правило
        сработает для сайта и всех его поддоменов (www., m., api.) в любой программе.
      </p>
      <div class="row">
        <input
          class="grow"
          bind:value={siteInput}
          placeholder="example.com или ссылка на страницу"
          onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), addSites(siteInput))}
        />
        <button class="primary" onclick={() => addSites(siteInput)} disabled={!siteInput.trim()}>Добавить</button>
      </div>
      <div class="row">
        <button onclick={() => (pickingLists = true)}><Icon name="database" size={16} />Найти в готовых списках…</button>
        <span class="muted small">Готовые списки сервисов: Google, GitHub, Steam, TikTok и сотни других.</span>
      </div>
      {#if sites.length}
        <div class="items">
          {#each sites as s, i (s.item)}
            <div class="item">
              <Icon name={itemLabel(s.item)?.geo ? 'database' : 'globe'} size={16} />
              <span class="grow ellipsis">{siteText(s.item)}</span>
              <div class="seg">
                <button class:on={s.way === 'tunnel'} onclick={() => (sites[i].way = 'tunnel')}>Через VPN</button>
                <button class:on={s.way === 'direct'} onclick={() => (sites[i].way = 'direct')}>Напрямую</button>
              </div>
              <button class="icon" title="Убрать" onclick={() => (sites = sites.filter((_, j) => j !== i))}><Icon name="x" size={15} /></button>
            </div>
          {/each}
        </div>
      {/if}
    {:else if step === 'block'}
      <h1>Заблокировать что-нибудь?</h1>
      <p class="lead">Необязательно. Заблокированное не откроется ни через VPN, ни напрямую.</p>
      <div class="tiles">
        {#each blockTiles as t (t.id)}
          <button class="tile" class:on={blocks.includes(t.id)} onclick={() => (blocks = toggle(blocks, t.id))} aria-pressed={blocks.includes(t.id)}>
            <span class="check">{#if blocks.includes(t.id)}<Icon name="check" size={14} stroke={3} />{/if}</span>
            <span class="ttext"><b>{t.title}</b><span>{t.hint}</span></span>
          </button>
        {/each}
      </div>
    {:else if step === 'servers'}
      <h1>Через какие серверы?</h1>
      <p class="lead">
        У вас {ui.profiles.length} {plural(ui.profiles.length, 'сервер', 'сервера', 'серверов')}. Для каждого пункта можно выбрать свой: например,
        нейросети через США, а YouTube через ближайший. Если не уверены — оставьте «Основной».
      </p>
      {#if vpnGroups.length}
        <div class="items">
          {#each vpnGroups as g (g.key)}
            <div class="item">
              <span class="grow ellipsis"><b>{g.title}</b></span>
              <select value={server[g.key] ?? ''} onchange={(e) => (server[g.key] = (e.currentTarget as HTMLSelectElement).value)}>
                <option value="">Основной{main ? ` — ${hide(main.name)}` : ''}</option>
                {#each ui.profiles as p (p.id)}<option value={p.id}>{hide(p.name)}</option>{/each}
              </select>
            </div>
          {/each}
        </div>
      {:else}
        <p class="muted">Через VPN ничего не идёт, выбирать нечего.</p>
      {/if}
      <label class="opt">
        <input type="checkbox" bind:checked={reserve} />
        <span><b>Подстраховка: если сервер не работает, пускать через другие по очереди</b>
          <span>Без подстраховки соединения через неработающий сервер не пройдут. Напрямую, мимо VPN, они не уйдут в любом случае.</span></span
        >
      </label>
    {:else if step === 'sum'}
      <h1>Проверим, что получилось</h1>
      <p class="lead">
        Вот правила, которые мы собрали. HyRoute проверяет их сверху вниз и берёт первое подходящее, поэтому ваши сайты и программы стоят выше
        готовых списков.
      </p>
      <ol class="rules">
        {#each built() as r, i (i)}
          <li>
            <span class="n">{i + 1}</span>
            <span class="grow">
              <b>{r.name}</b>
              <span class="muted small">{ruleText(r)}</span>
            </span>
            <span class="pill {r.action}">{r.action === 'direct' ? 'Напрямую' : r.action === 'block' ? 'Заблокировать' : `Через ${serverName(r.profile ?? '')}`}</span>
          </li>
        {/each}
        <li class="rest">
          <span class="n">*</span>
          <span class="grow"><b>Всё остальное</b> <span class="muted small">то, что не подошло ни под одно правило выше</span></span>
          <span class="pill {restAction}">{restAction === 'tunnel' ? `Через ${serverName(server.rest ?? '')}` : 'Напрямую'}</span>
        </li>
      </ol>
      {#if nothing}
        <div class="note warn">Через VPN сейчас не идёт ничего. Вернитесь назад и отметьте хоть что-нибудь — или так и задумано?</div>
      {/if}
      {#if hasRules}
        <div class="group">У вас уже есть {settings!.rules.length} {plural(settings!.rules.length, 'правило', 'правила', 'правил')}</div>
        <div class="choices">
          <button class="choice small-choice" class:on={!replace} onclick={() => (replace = false)}>
            <span class="radio"></span>
            <span class="ctext"><span class="ctitle">Добавить новые правила перед моими</span><span class="muted small">Ваши правила останутся ниже и сработают для всего, что не подошло под новые.</span></span>
          </button>
          <button class="choice small-choice" class:on={replace} onclick={() => (replace = true)}>
            <span class="radio"></span>
            <span class="ctext"><span class="ctitle">Заменить мои правила новыми</span><span class="muted small">Старые правила удалятся.</span></span>
          </button>
        </div>
      {/if}
      <p class="muted small">Потом всё можно поменять на странице «Правила»: включить или выключить правило, поменять сервер, порядок, добавить новое.</p>
    {/if}

    {#if error}<div class="note error">{hide(error)}</div>{/if}
  </div>

  <div class="nav">
    <button onclick={back} disabled={busy}>Назад</button>
    <div class="grow"></div>
    {#if step === 'sum'}
      <button class="primary big" onclick={save} disabled={busy || !settings}>{busy ? 'Сохраняю…' : 'Сохранить правила'}<Icon name="check" size={16} /></button>
    {:else}
      <button class="primary big" onclick={next} disabled={step === 'base' && !base}>Дальше<Icon name="arrow" size={16} /></button>
    {/if}
  </div>
</div>

{#if pickingApps}
  <AppPicker chosen={apps.map((a) => a.pattern)} onpick={addRunning} onclose={() => (pickingApps = false)} />
{/if}
{#if pickingLists}
  <GeoPicker chosen={sites.map((s) => s.item)} onpick={addSite} onclose={() => (pickingLists = false)} />
{/if}

<style>
  .wz { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .body { flex: 1; overflow: auto; width: 100%; max-width: 760px; margin: 0 auto; padding: 8px 28px 20px; display: flex; flex-direction: column; gap: 12px; user-select: text; }
  .body h1 { font-size: 26px; margin-bottom: 2px; }
  .body p { margin: 0; }
  .lead { font-size: 15px; }
  code { font-family: var(--mono); font-size: 12.5px; background: var(--surface-2); padding: 1px 6px; border-radius: 4px; }

  .sub { display: grid; gap: 6px; font-size: 12.5px; color: var(--muted); }
  .bar { height: 4px; border-radius: 2px; background: var(--surface-2); overflow: hidden; }
  .bar span { display: block; height: 100%; background: var(--accent); transition: width 0.2s; }

  .ways { display: grid; gap: 8px; }
  .way { display: grid; gap: 2px; padding: 12px 14px; border-radius: var(--radius); border: 1px solid var(--border); background: var(--surface); }
  .way b { display: flex; align-items: center; gap: 6px; }
  .way span { color: var(--muted); font-size: 13px; }
  .way.tunnel b { color: var(--tunnel); }
  .way.direct b { color: var(--direct); }
  .way.block b { color: var(--block); }

  .choices { display: grid; gap: 10px; }
  .choice { display: flex; align-items: flex-start; gap: 14px; padding: 14px 16px; text-align: left; white-space: normal; justify-content: flex-start; background: var(--surface); border: 1.5px solid var(--border); border-radius: var(--radius); }
  .choice.small-choice { padding: 10px 14px; }
  .choice:hover:not(:disabled) { background: var(--surface); border-color: color-mix(in srgb, var(--accent) 45%, var(--border)); }
  .choice.on { border-color: var(--accent); background: color-mix(in srgb, var(--accent) 6%, var(--surface)); }
  .radio { width: 18px; height: 18px; border-radius: 50%; border: 2px solid var(--faint); flex: none; margin-top: 2px; }
  .choice.on .radio { border-color: var(--accent); background: radial-gradient(var(--accent) 45%, transparent 50%); }
  .ctext { display: grid; gap: 4px; }
  .ctitle { font-weight: 650; font-size: 15px; }

  .group { font-size: 12px; font-weight: 650; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin-top: 6px; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 8px; }
  .tile { display: flex; align-items: flex-start; gap: 12px; padding: 12px 14px; text-align: left; white-space: normal; justify-content: flex-start; background: var(--surface); border: 1.5px solid var(--border); border-radius: var(--radius); }
  .tile:hover:not(:disabled) { background: var(--surface); border-color: color-mix(in srgb, var(--accent) 45%, var(--border)); }
  .tile.on { border-color: var(--accent); background: color-mix(in srgb, var(--accent) 8%, var(--surface)); }
  .check { width: 20px; height: 20px; border-radius: 6px; border: 2px solid var(--faint); flex: none; display: grid; place-items: center; margin-top: 1px; color: #fff; }
  .tile.on .check { background: var(--accent); border-color: var(--accent); }
  .ttext { display: grid; gap: 2px; }
  .ttext span { color: var(--muted); font-size: 12.5px; }

  .items { display: grid; gap: 6px; }
  .item { display: flex; align-items: center; gap: 10px; padding: 8px 10px 8px 14px; border-radius: var(--radius-sm); background: var(--surface); border: 1px solid var(--border); }
  .item > :global(svg) { color: var(--muted); flex: none; }
  .item select { max-width: 280px; }

  .opt { display: flex; gap: 12px; align-items: flex-start; padding: 14px 16px; border-radius: var(--radius); background: var(--surface); border: 1px solid var(--border); cursor: pointer; }
  .opt input { margin-top: 3px; flex: none; width: 17px; height: 17px; }
  .opt > span { display: grid; gap: 3px; }
  .opt > span > span { color: var(--muted); font-size: 13px; }

  .rules { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
  .rules li { display: flex; align-items: center; gap: 12px; padding: 10px 12px; border-radius: var(--radius-sm); background: var(--surface); border: 1px solid var(--border); }
  .rules li.rest { border-style: dashed; }
  .rules .grow { display: grid; gap: 2px; min-width: 0; }
  .rules .grow .small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .n { width: 22px; height: 22px; border-radius: 50%; display: grid; place-items: center; font-size: 11.5px; font-weight: 700; background: var(--surface-2); color: var(--muted); flex: none; }

  .nav { display: flex; align-items: center; gap: 8px; padding: 14px 28px 18px; border-top: 1px solid var(--border); background: var(--surface); }
  .nav .big { padding: 10px 22px; font-size: 15px; font-weight: 600; }
</style>
