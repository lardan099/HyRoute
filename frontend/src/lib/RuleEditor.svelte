<script lang="ts">
  // One rule: what (programs and/or sites) -> where (VPN server, direct,
  // block). Saved as soon as the user presses "Сохранить".
  import { api, errText, cleanFallback, isGroupId, strategyLabel, type Rule, type Action, type RunningApp } from '../api';
  import { ui, hide, mainTarget, mainText, profileName } from '../state.svelte';
  import Icon from './Icon.svelte';
  import TargetOptions from './TargetOptions.svelte';
  import GeoPicker from './GeoPicker.svelte';
  import AppPicker from './AppPicker.svelte';
  import FallbackPicker from './FallbackPicker.svelte';
  import { itemLabel, isSpecial, isAddress, shortLabel, loadGeo, geo } from '../geo.svelte';

  let { rule, title, onsave, onclose }: { rule: Rule; title: string; onsave: (r: Rule) => Promise<void>; onclose: () => void } = $props();

  // svelte-ignore state_referenced_locally
  let r = $state<Rule>(JSON.parse(JSON.stringify(rule)));
  r.apps ??= [];
  r.domains ??= [];
  r.protocol ??= '';
  r.ports ??= '';
  r.profile ??= '';
  r.fallback ??= [];
  let siteInput = $state('');
  let appInput = $state('');
  let error = $state('');
  let saving = $state(false);
  let advanced = $state(!!r.protocol || !!r.ports);
  let picking = $state(false);
  let pickingApps = $state(false);
  loadGeo();

  // "https://www.youtube.com/watch" -> "youtube.com"-style host.
  function cleanSite(s: string): string {
    s = s.trim().toLowerCase();
    try {
      if (/^[a-z]+:\/\//.test(s)) s = new URL(s).hostname;
    } catch {}
    s = s.replace(/\/.*$/, '').replace(/:\d+$/, '');
    return s;
  }

  function addSites(text: string) {
    const add = (t: string) => {
      if (!r.domains!.some((x) => x.toLowerCase() === t.toLowerCase())) r.domains!.push(t);
    };
    for (let raw of text.split(/[\s,;]+/)) {
      if (isSpecial(raw)) {
        // geosite:, geoip:, IP, network…: kept as written.
        add(raw.replace(/^[a-z]+:/i, (p) => p.toLowerCase()));
        continue;
      }
      let s = cleanSite(raw);
      if (!s) continue;
      // An IP from a link or with a port (https://1.2.3.4/…, [2a01::1]:443)
      // is an address rule: as a site (".1.2.3.4") it would never match.
      const ip = s.replace(/^\[(.*)\]$/, '$1');
      if (isAddress(ip)) {
        add(ip);
        continue;
      }
      // Default: the site and every subdomain (what people usually mean).
      if (!s.startsWith('.') && !s.startsWith('*.')) s = '.' + s.replace(/^www\./, '');
      if (!r.domains!.includes(s)) r.domains!.push(s);
    }
    siteInput = '';
  }

  function addApps(text: string) {
    for (let a of text.split(/[,;\n]+/)) {
      a = a.trim().replace(/^"|"$/g, '');
      if (!a) continue;
      if (!/[\\/.*?]/.test(a)) a += '.exe';
      if (!r.apps!.some((x) => x.pattern.toLowerCase() === a.toLowerCase())) r.apps!.push({ pattern: a, inheritChildren: true });
    }
    appInput = '';
  }

  // ---- suggestions from running programs under the program field ----
  let appSug = $state<RunningApp[]>([]);
  let appSel = $state(-1);
  let appOpen = $state(false);
  let sugSeq = 0;
  let sugTimer: ReturnType<typeof setTimeout> | undefined;

  // enterPick is the suggestion Enter takes for the typed q: the program
  // named exactly so ("java" or "java.exe"), else the first match of a
  // partly typed name ("tele"). A full file name, a path or a mask
  // (C:\Games\*) is kept as typed unless an item is chosen with the arrows.
  function enterPick(q: string, list: RunningApp[]): number {
    if (!q || /[\\/*?]/.test(q) || !list.length) return -1;
    const stem = (n: string) => n.toLowerCase().replace(/\.exe$/, '');
    const exact = list.findIndex((a) => stem(a.name) === stem(q));
    if (exact >= 0) return exact;
    return q.includes('.') ? -1 : 0;
  }

  function suggestApps() {
    clearTimeout(sugTimer);
    const q = appInput.trim();
    // Until the answer for this text comes, Enter adds the text as typed,
    // not a suggestion for what was typed before.
    appSel = -1;
    sugTimer = setTimeout(async () => {
      const my = ++sugSeq;
      try {
        const list = await api.RunningApps(q, false, 12);
        if (my !== sugSeq || q !== appInput.trim()) return;
        appSug = list.filter((a) => !r.apps!.some((x) => x.pattern.toLowerCase() === a.name.toLowerCase())).slice(0, 8);
        appSel = enterPick(q, appSug);
      } catch {
        appSug = [];
      }
    }, q ? 120 : 0);
  }

  function addRunning(a: RunningApp) {
    if (!r.apps!.some((x) => x.pattern.toLowerCase() === a.name.toLowerCase())) r.apps!.push({ pattern: a.name, inheritChildren: true });
    if (!r.name) r.name = a.description || a.name.replace(/\.exe$/i, '');
  }

  function pickSuggestion(a: RunningApp) {
    addRunning(a);
    appInput = '';
    suggestApps();
  }

  async function browse() {
    try {
      const path = await api.BrowseExe();
      if (path) {
        r.apps!.push({ pattern: path, inheritChildren: true });
        if (!r.name) r.name = path.split('\\').pop()?.replace(/\.exe$/i, '') ?? '';
      }
    } catch (e) {
      error = errText(e);
    }
  }

  // Chip cycle: site + subdomains -> only this address -> only subdomains.
  function cycleSite(i: number) {
    const d = r.domains![i];
    if (itemLabel(d)) return;
    if (d.startsWith('*.')) r.domains![i] = '.' + d.slice(2);
    else if (d.startsWith('.')) r.domains![i] = d.slice(1);
    else r.domains![i] = '*.' + d;
  }

  function siteLabel(d: string): { host: string; mode: string; tip: string } {
    if (d.startsWith('*.')) return { host: d.slice(2), mode: 'только поддомены', tip: `Только поддомены: www.${d.slice(2)}, api.${d.slice(2)}…, но не сам ${d.slice(2)}` };
    if (d.startsWith('.')) return { host: d.slice(1), mode: '+ поддомены', tip: `${d.slice(1)} и все поддомены (www., api., cdn. …)` };
    return { host: d, mode: 'только этот адрес', tip: `Только ${d}, без поддоменов` };
  }

  function appLabel(p: string): string {
    return /[*?]/.test(p) ? p : (p.split('\\').pop() ?? p);
  }

  const main = $derived(mainTarget());
  // The fallbacks routing uses: struck-through ones go on save.
  const fallback = $derived(cleanFallback(r.fallback, r.profile, main?.id));
  const empty = $derived(r.apps!.length === 0 && r.domains!.length === 0 && !r.ports!.trim());
  const portList = $derived(r.ports!.split(/[\s,;]+/).filter(Boolean));
  // As Go rules.ParsePorts: "443", "80, 443", "27000-27200".
  const portsBad = $derived(
    portList.find((f) => {
      const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(f);
      const lo = m ? +m[1] : 0;
      const hi = m?.[2] ? +m[2] : lo;
      return !m || lo < 1 || hi > 65535 || lo > hi;
    }) ?? '',
  );

  const where: { v: Action; l: string; d: string; icon: string }[] = [
    { v: 'tunnel', l: 'Через VPN', d: 'через выбранный сервер', icon: 'shield' },
    { v: 'direct', l: 'Напрямую', d: 'мимо VPN, как обычно', icon: 'arrow' },
    { v: 'block', l: 'Заблокировать', d: 'соединение не пройдёт', icon: 'ban' },
  ];

  const sentence = $derived.by(() => {
    const apps = r.apps!.map((a) => appLabel(a.pattern));
    // Lists from the database read as «YouTube», plain sites as is (masked
    // in Privacy mode, as in the chips).
    const sites = r.domains!.map((d) => (itemLabel(d)?.geo ? `«${shortLabel(d)}»` : hide(itemLabel(d) ? shortLabel(d) : siteLabel(d).host)));
    let who = '';
    if (apps.length && sites.length) who = `${apps.join(', ')}, когда открывает ${sites.join(', ')}`;
    else if (apps.length) who = `Всё от ${apps.join(', ')}`;
    else if (sites.length) who = `${sites.join(', ')} — в любой программе,`;
    else if (portList.length) who = 'Любая программа, любой сайт';
    else return 'Добавьте программу, сайт или порт.';
    const p = r.protocol === 'tcp' ? 'TCP' : r.protocol === 'udp' ? 'UDP' : '';
    const proto = portList.length ? ` (${p ? p + ', ' : ''}порт ${portList.join(', ')})` : p ? ` (только ${p})` : '';
    // A group: «группу «Авто» (самый быстрый)».
    const via = (id: string) => {
      if (!isGroupId(id)) return profileName(id);
      const g = ui.groups.find((x) => x.id === id);
      return `группу «${profileName(id)}»${g ? ` (${strategyLabel[g.strategy].toLowerCase()})` : ''}`;
    };
    const target = r.profile || main?.id || '';
    const to =
      r.action === 'direct'
        ? 'напрямую, мимо VPN'
        : r.action === 'block'
          ? 'блокируется'
          : `через ${r.profile ? via(r.profile) : main ? `основной сервер (${mainText(main)})` : 'основной сервер — он не выбран!'}` +
            (fallback.length
              ? `, если ${isGroupId(target) ? 'она недоступна' : 'он недоступен'} — ${fallback.map((id) => (id ? (isGroupId(id) ? `группа «${profileName(id)}»` : profileName(id)) : 'основной')).join(', затем ')}`
              : '');
    return `${who}${proto} → ${to}`;
  });

  async function save() {
    if (siteInput.trim()) addSites(siteInput);
    if (appInput.trim()) addApps(appInput);
    if (empty || portsBad) return;
    saving = true;
    error = '';
    try {
      await onsave(r);
    } catch (e) {
      error = errText(e);
    }
    saving = false;
  }

  // Only a click that starts on the backdrop closes the editor: selecting
  // text in a field and letting go outside the dialog also ends in a click
  // on it, and the rule would be lost unsaved.
  let downOnBackdrop = false;
</script>

<div
  class="backdrop"
  role="presentation"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && onclose()}
>
  <div class="dialog editor">
    <div class="row head">
      <h2 class="grow">{title}</h2>
      <button class="icon" onclick={onclose}><Icon name="x" /></button>
    </div>

    <input class="name" bind:value={r.name} placeholder="Название, например «YouTube» (необязательно)" />

    <div class="step"><span class="n">1</span> Что направить</div>

    <div class="field">
      <div class="lbl"><Icon name="globe" size={16} /> Сайты и адреса</div>
      <div class="chips">
        {#each r.domains! as d, i (d + i)}
          {@const il = itemLabel(d)}
          {#if il}
            <span class="chip" class:geo={il.geo} class:miss={!!il.missing} title={il.geo ? il.tip : hide(il.tip)}>
              {#if il.geo}<Icon name={il.missing ? 'alert' : 'database'} size={13} />{/if}
              <span class="ellipsis">{il.geo ? il.text : hide(il.text)}</span>
              <span class="mode static">{il.kind}</span>
              <button class="x" onclick={() => r.domains!.splice(i, 1)} title="Убрать"><Icon name="x" size={13} /></button>
            </span>
          {:else}
            {@const l = siteLabel(d)}
            <span class="chip">
              <span class="ellipsis">{hide(l.host)}</span>
              <button class="mode" title={hide(l.tip) + ' — нажмите, чтобы изменить'} onclick={() => cycleSite(i)}>{l.mode}</button>
              <button class="x" onclick={() => r.domains!.splice(i, 1)} title="Убрать"><Icon name="x" size={13} /></button>
            </span>
          {/if}
        {/each}
        <input
          class="chip-input"
          bind:value={siteInput}
          placeholder={r.domains!.length ? 'ещё сайт…' : 'youtube.com, instagram.com …'}
          onkeydown={(e) => {
            if (e.key === 'Enter' || e.key === ',' || e.key === ' ') {
              e.preventDefault();
              addSites(siteInput);
            } else if (e.key === 'Backspace' && !siteInput && r.domains!.length) r.domains!.pop();
          }}
          onpaste={(e) => {
            const t = e.clipboardData?.getData('text') ?? '';
            if (/[\s,;]/.test(t.trim())) {
              e.preventDefault();
              // The list takes the selection's place: a site typed but not
              // yet added stays, as a site of its own.
              const el = e.currentTarget;
              const from = el.selectionStart ?? siteInput.length;
              const to = el.selectionEnd ?? from;
              addSites([siteInput.slice(0, from), t, siteInput.slice(to)].join(' '));
            }
          }}
          onblur={() => siteInput.trim() && addSites(siteInput)}
        />
        <button class="browse" onclick={() => (picking = true)} title="YouTube, Telegram, заблокированное в России, реклама…"><Icon name="database" size={15} />Готовые списки…</button>
      </div>
      {#each r.domains!.map((d) => ({ d, il: itemLabel(d) })).filter((x) => x.il?.missing) as x (x.d)}
        <div class="note warn small">«{x.il!.text}» ({x.d}): {x.il!.missing}. Правило сохранится, но этот список не сработает, пока в «Настройки → Базы правил» не выбрана база, где он есть.</div>
      {/each}
      {#if r.domains!.some((d) => itemLabel(d)?.geo)}
        <div class="hint">Готовые списки берутся из базы правил <b>{geo.sourceName || '—'}</b>. Базу можно сменить в «Настройки → Базы правил».</div>
      {/if}
      <div class="hint">
        Сайт (<code>youtube.com</code> — вместе с www., m., cdn.; нажмите на метку, чтобы изменить), адрес страницы целиком или сразу список через пробел.
        Ещё можно: готовый список сервиса из базы (<code>geosite:youtube</code>), IP или сеть (<code>192.168.0.0/16</code>), все IP страны
        (<code>geoip:ru</code>), любое имя со словом (<code>keyword:torrent</code>).
      </div>
    </div>

    <div class="field">
      <div class="lbl"><Icon name="app" size={16} /> Программы</div>
      <div class="chips">
        {#each r.apps! as a, i (a.pattern + i)}
          <span class="chip" title={a.pattern}>
            <span class="ellipsis">{appLabel(a.pattern)}</span>
            <button
              class="mode"
              title={a.inheritChildren ? 'Вместе с процессами, которые запускает эта программа (лаунчер → игра, браузер → его вкладки). Нажмите, чтобы отключить.' : 'Только сама программа. Нажмите, чтобы включить её дочерние процессы.'}
              onclick={() => (a.inheritChildren = !a.inheritChildren)}>{a.inheritChildren ? '+ дочерние' : 'только она'}</button
            >
            <button class="x" onclick={() => r.apps!.splice(i, 1)} title="Убрать"><Icon name="x" size={13} /></button>
          </span>
        {/each}
        <input
          class="chip-input"
          bind:value={appInput}
          placeholder={r.apps!.length ? 'ещё программа…' : 'начните вводить: tele, disc, steam… или C:\\Games\\*'}
          onfocus={() => {
            appOpen = true;
            suggestApps();
          }}
          oninput={() => {
            appOpen = true;
            suggestApps();
          }}
          onkeydown={(e) => {
            const open = appOpen && appSug.length > 0;
            if (open && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
              e.preventDefault();
              const n = appSug.length;
              appSel = e.key === 'ArrowDown' ? (appSel + 1) % n : appSel <= 0 ? n - 1 : appSel - 1;
            } else if (e.key === 'Escape' && open) {
              e.preventDefault();
              e.stopPropagation();
              appOpen = false;
            } else if (e.key === 'Enter' || e.key === ',') {
              e.preventDefault();
              if (open && appSel >= 0 && e.key === 'Enter') pickSuggestion(appSug[appSel]);
              else {
                addApps(appInput);
                suggestApps();
              }
            } else if (e.key === 'Backspace' && !appInput && r.apps!.length) r.apps!.pop();
          }}
          onblur={() => {
            appOpen = false;
            if (appInput.trim()) addApps(appInput);
          }}
        />
        <button class="browse" onclick={() => (pickingApps = true)}><Icon name="app" size={15} />Запущенные…</button>
        <button class="browse" onclick={browse}><Icon name="folder" size={15} />Обзор…</button>
        {#if appOpen && appSug.length}
          <div class="sug" role="listbox">
            {#if !appInput.trim()}<div class="sug-h">Запущенные программы</div>{/if}
            {#each appSug as a, i (a.path)}
              <button
                class="sug-i"
                class:sel={i === appSel}
                role="option"
                aria-selected={i === appSel}
                title={a.path}
                onmousedown={(e) => e.preventDefault()}
                onmouseenter={() => (appSel = i)}
                onclick={() => pickSuggestion(a)}
              >
                <b class="ellipsis">{a.description || a.name.replace(/\.exe$/i, '')}</b>
                <code>{a.name}</code>
                {#if a.windowed}<span class="dotw" title="есть окно"></span>{/if}
              </button>
            {/each}
          </div>
        {/if}
      </div>
      <div class="hint">Начните вводить имя, и HyRoute подскажет из запущенных программ. Ещё можно: имя файла (discord → Discord.exe), полный путь или папка с * — <code>C:\Games\*</code> значит всё внутри папки.</div>
    </div>

    {#if r.apps!.length && r.domains!.length}
      <div class="note info small">Указаны и программы, и сайты: правило сработает, только когда эти программы открывают эти сайты. Чтобы программа шла через VPN целиком, оставьте сайты пустыми или сделайте два правила.</div>
    {/if}

    <div class="step"><span class="n">2</span> Куда</div>
    <div class="where">
      {#each where as w}
        <button class="opt {w.v}" class:on={r.action === w.v} onclick={() => (r.action = w.v)}>
          <Icon name={w.icon} size={20} />
          <span class="t">{w.l}</span>
          <span class="d">{w.d}</span>
        </button>
      {/each}
    </div>
    {#if r.action === 'tunnel'}
      <div class="row server">
        <span class="muted">Сервер</span>
        <select
          class="grow"
          value={r.profile}
          onchange={(e) => {
            r.profile = (e.currentTarget as HTMLSelectElement).value;
            // The rule's own server is no fallback for itself.
            r.fallback = cleanFallback(r.fallback, r.profile, main?.id);
          }}
        >
          <option value="">Основной{main ? ` — ${mainText(main)}` : ' (не выбран)'}</option>
          <TargetOptions current={r.profile} />
        </select>
      </div>
      <div class="server">
        <FallbackPicker value={r.fallback!} primary={r.profile ?? ''} onchange={(v) => (r.fallback = v)} />
      </div>
      <div class="hint">
        {#if fallback.length}
          Если сервер правила недоступен, новые соединения идут через первый доступный запасной. Если недоступны все — соединение не пройдёт,
          напрямую оно не уйдёт.
        {:else}
          Запасной сервер подхватит соединения, если этот сервер недоступен. Без запасного они не пройдут.
        {/if}
      </div>
    {/if}

    <details bind:open={advanced} class="adv">
      <summary>Дополнительно</summary>
      <div class="row">
        <span class="muted">Протокол</span>
        <div class="seg">
          <button class:on={!r.protocol} onclick={() => (r.protocol = '')}>Любой</button>
          <button class:on={r.protocol === 'tcp'} onclick={() => (r.protocol = 'tcp')}>TCP</button>
          <button class:on={r.protocol === 'udp'} onclick={() => (r.protocol = 'udp')}>UDP</button>
        </div>
        <span class="muted small">TCP — сайты и большинство программ, UDP — игры, звонки, QUIC. Если не уверены — «Любой».</span>
      </div>
      <div class="row">
        <span class="muted">Порт</span>
        <input class="ports" bind:value={r.ports} placeholder="любой" />
        <span class="muted small grow">
          Порт сервера, куда идёт соединение: <code>22</code> (SSH), <code>443, 8443</code> или диапазон <code>27000-27200</code>. Пусто — любой.
        </span>
      </div>
      {#if portsBad}<div class="note error small">«{portsBad}» — не порт: нужно число от 1 до 65535 или диапазон вида 27000-27200.</div>{/if}
      {#if !r.apps!.length && !r.domains!.length && portList.length}
        <div class="note info small">Ни программы, ни сайта нет: правило сработает для любой программы и любого сайта на этом порту.</div>
      {/if}
    </details>

    <div class="summary"><Icon name="info" size={16} /> {sentence}</div>
    {#if pickingApps}
      <AppPicker chosen={r.apps!.map((a) => a.pattern)} onpick={addRunning} onclose={() => (pickingApps = false)} />
    {/if}
    {#if picking}
      <GeoPicker
        chosen={r.domains!}
        onpick={(it) => {
          r.domains!.push(it);
          if (!r.name) r.name = itemLabel(it)?.text ?? '';
        }}
        onclose={() => (picking = false)}
      />
    {/if}
    {#if error}<div class="note error">{error}</div>{/if}

    <div class="actions">
      <button onclick={onclose}>Отмена</button>
      <button class="primary" onclick={save} disabled={saving || !!portsBad || (empty && !siteInput.trim() && !appInput.trim())}>Сохранить</button>
    </div>
  </div>
</div>

<style>
  .editor { width: min(720px, 94vw); display: grid; gap: 12px; }
  .head h2 { margin: 0; }
  .name { font-size: 15px; font-weight: 600; padding: 10px 12px; }
  .step { display: flex; align-items: center; gap: 10px; font-weight: 650; margin-top: 6px; }
  .n { width: 22px; height: 22px; border-radius: 50%; background: var(--accent-soft); color: var(--accent); display: grid; place-items: center; font-size: 12px; }
  .field { display: grid; gap: 6px; }
  .lbl { display: flex; align-items: center; gap: 6px; color: var(--muted); font-weight: 500; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; padding: 6px; border-radius: var(--radius-sm); background: var(--surface-2); min-height: 42px; }
  .chip { display: inline-flex; align-items: center; gap: 4px; max-width: 100%; padding: 3px 4px 3px 10px; border-radius: 999px; background: var(--surface); border: 1px solid var(--border); font-size: 13px; }
  .chip .mode { padding: 1px 8px; font-size: 11px; border-radius: 999px; background: var(--accent-soft); color: var(--accent); }
  .chip .mode.static { background: var(--surface-3); color: var(--muted); }
  .chip.geo { border-color: color-mix(in srgb, var(--accent) 40%, var(--border)); }
  .chip.geo > :global(svg) { color: var(--accent); flex: none; }
  .chip.miss { border-color: var(--warn); }
  .chip.miss > :global(svg) { color: var(--warn); }
  .chip .x { padding: 2px; min-width: 0; background: none; color: var(--muted); }
  .chip .x:hover { color: var(--block); background: none; }
  .chip-input { flex: 1; min-width: 160px; background: transparent !important; border: none !important; padding: 5px 6px; }
  .browse { padding: 5px 10px; background: var(--surface); }
  .chips { position: relative; }
  .sug { position: absolute; left: 0; right: 0; top: calc(100% + 4px); z-index: 20; display: grid; gap: 1px; padding: 4px; border-radius: var(--radius-sm); background: var(--surface); border: 1px solid var(--border); box-shadow: 0 8px 24px rgb(0 0 0 / 0.28); max-height: 290px; overflow: auto; }
  .sug-h { font-size: 11px; font-weight: 650; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; padding: 4px 8px 2px; }
  .sug-i { display: flex; align-items: baseline; gap: 10px; justify-content: flex-start; padding: 6px 8px; background: none; text-align: left; min-width: 0; }
  .sug-i.sel { background: var(--accent-soft); }
  .sug-i b { font-weight: 550; min-width: 0; }
  .sug-i code { color: var(--faint); flex: none; }
  .dotw { width: 7px; height: 7px; border-radius: 50%; background: var(--direct); margin-left: auto; flex: none; align-self: center; }
  .hint { font-size: 12px; color: var(--muted); }
  code { font-family: var(--mono); font-size: 11.5px; }
  .where { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .opt { flex-direction: column; align-items: flex-start; gap: 2px; padding: 12px 14px; border: 1.5px solid var(--border); background: var(--surface); text-align: left; white-space: normal; }
  .opt .t { font-weight: 650; color: var(--text); }
  .opt .d { font-size: 12px; color: var(--muted); }
  .opt.tunnel { color: var(--tunnel); }
  .opt.direct { color: var(--direct); }
  .opt.block { color: var(--block); }
  .opt.on.tunnel { border-color: var(--tunnel); background: color-mix(in srgb, var(--tunnel) 9%, var(--surface)); }
  .opt.on.direct { border-color: var(--direct); background: color-mix(in srgb, var(--direct) 9%, var(--surface)); }
  .opt.on.block { border-color: var(--block); background: color-mix(in srgb, var(--block) 8%, var(--surface)); }
  .server select { font-size: 14px; }
  .adv summary { cursor: pointer; color: var(--muted); font-weight: 500; }
  .adv .row { margin-top: 10px; }
  .ports { width: 150px; }
  .summary { display: flex; gap: 8px; align-items: flex-start; padding: 10px 12px; border-radius: var(--radius-sm); background: var(--accent-soft); font-size: 13px; }
  .summary :global(svg) { flex: none; margin-top: 1px; color: var(--accent); }
  .actions { margin-top: 4px; }
</style>
