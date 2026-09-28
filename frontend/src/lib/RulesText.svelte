<script lang="ts">
  // Many rules at once as text: edit the whole list, or add a batch.
  import { onMount } from 'svelte';
  import { api, errText, guardOf, isStale, plural, type RulesTextResult, type RulesTextView } from '../api';
  import { ui, hide } from '../state.svelte';
  import Icon from './Icon.svelte';
  import { geo, loadGeo, missingText } from '../geo.svelte';

  let { onclose, onsaved }: { onclose: () => void; onsaved: () => void } = $props();

  let mode = $state<'all' | 'add'>('all');
  let allText = $state('');
  // view: the text «Все правила» started from, with its revision (a replace
  // sends it back; Go refuses it if the rules changed elsewhere since).
  let view: RulesTextView | null = null;
  let addText = $state('');
  let res = $state<RulesTextResult | null>(null);
  let error = $state('');
  let saving = $state(false);

  const text = $derived(mode === 'all' ? allText : addText);

  // Privacy mode: the text is shown masked and read-only (no editor, hints
  // or parse results, which name sites and servers) until «Показать и
  // редактировать». That lasts for this visit: turning Privacy mode on again
  // or reopening the page masks it again.
  let revealed = $state(false);
  const masked = $derived(ui.privacy && !revealed);
  $effect(() => {
    if (!ui.privacy) revealed = false;
  });
  const shownError = $derived(masked ? hide(error) : error);

  function reveal() {
    closeMenu();
    revealed = true;
  }

  const example = $derived(`# Пример: пишите по строке, срабатывает первое подходящее сверху
# geosite:… и geoip:… — готовые списки из базы ${geo.sourceName || 'правил'} (Настройки → Базы правил)

Локальная сеть: geoip:private -> напрямую
Заблокированное: geosite:ru-blocked geoip:ru-blocked -> vpn
YouTube: geosite:youtube -> ${ui.profiles[0]?.name ?? 'Нидерланды'}
discord -> vpn
Реклама: geosite:category-ads-all -> блок

[chrome.exe]
instagram.com -> vpn`);

  onMount(async () => {
    loadGeo();
    try {
      view = await api.RulesText();
      allText = view.text;
    } catch (e) {
      error = errText(e);
    }
  });

  let timer: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    const t = text;
    clearTimeout(timer);
    timer = setTimeout(async () => {
      try {
        res = t.trim() ? await api.ParseRulesText(t) : null;
      } catch {}
    }, 250);
  });

  async function save() {
    saving = true;
    error = '';
    try {
      // Adding a batch goes after whatever the list is now: no revision.
      const r = await api.ApplyRulesText(text, mode === 'all', guardOf(mode === 'all' && view ? view : {}));
      res = r;
      onsaved();
      stale = null;
    } catch (e) {
      error = errText(e);
      if (isStale(e) && mode === 'all') {
        // The rules changed elsewhere. The text the user tried to save stays
        // in the editor (it may be a rewrite of the whole list); only the
        // revision is renewed, so saving again replaces the new rules with
        // it on purpose. The current rules are one click away (swapStale).
        try {
          const fresh = await api.RulesText();
          view = fresh;
          stale = { other: fresh.text, mine: true };
        } catch {}
      }
    }
    saving = false;
  }

  // stale: after a refused replace, the text not shown in the editor
  // (mine: the editor shows the text the user tried to save and other is
  // the current rules; otherwise the other way round). Swapping loses
  // neither.
  let stale = $state<{ other: string; mine: boolean } | null>(null);
  function swapStale() {
    if (!stale) return;
    const shown = allText;
    allText = stale.other;
    stale = { other: shown, mine: !stale.mine };
  }

  const lines = $derived(text.split('\n').length);
  // "* -> …" changes the default route: only the whole list may do that
  // (ApplyRulesText refuses it when adding).
  const defaultInAdd = $derived(mode === 'add' && !!res?.hasDefault);

  // ---- autocomplete after "->": servers, vpn, напрямую, блок ----
  type Opt = { label: string; insert: string; hint: string };
  let ta = $state<HTMLTextAreaElement>();
  // v is the text the menu was made for: from and to point into it.
  let menu = $state<{ items: Opt[]; sel: number; x: number; y: number; from: number; to: number; v: string; raw?: boolean; q?: string } | null>(null);
  let geoSeq = 0;

  // Autocomplete for "geosite:…" / "geoip:…": popular categories with
  // titles first, then every matching category of the database.
  function geoMenu(el: HTMLTextAreaElement, kind: 'site' | 'ip', q: string, from: number, to: number) {
    const my = ++geoSeq;
    const v = el.value;
    const pop = geo.popular
      .filter((c) => c.kind === kind && (!q || c.name.includes(q) || c.title.toLowerCase().includes(q)))
      .map((c) => ({ label: c.name, insert: c.name, hint: missingText(c) ? `${c.title} · нет в ${geo.sourceName}` : c.title }));
    api
      .GeoCategories(kind, q)
      .catch(() => [] as string[])
      .then((names) => {
        if (my !== geoSeq || el.value !== v) return;
        const seen = new Set(pop.map((o) => o.insert));
        const items = [...pop, ...names.filter((n) => !seen.has(n)).map((n) => ({ label: n, insert: n, hint: kind === 'ip' ? 'IP' : 'сайты' }))].slice(0, 40);
        if (!items.length || (items.length === 1 && items[0].insert === q)) {
          menu = null;
          return;
        }
        const xy = caretXY(el, from);
        menu = { items, sel: 0, x: el.offsetLeft + Math.min(xy.x, el.clientWidth - 260), y: el.offsetTop + xy.y, from, to, v, raw: true };
      });
  }

  // Program names from running processes: "tele" -> telegram.exe.
  let appSeq = 0;
  function appMenu(el: HTMLTextAreaElement, q: string, from: number, to: number) {
    const my = ++appSeq;
    const v = el.value;
    api
      .RunningApps(q, false, 10)
      .catch(() => [])
      .then((list) => {
        if (my !== appSeq || el.value !== v) return;
        const items = list.map((a) => ({ label: a.name.toLowerCase(), insert: a.name.toLowerCase(), hint: a.description || 'программа' }));
        // The program named exactly as typed comes first: "java" is
        // java.exe, not javaw.exe.
        const exact = (o: Opt) => (o.insert.replace(/\.exe$/, '') === q.toLowerCase() ? 0 : 1);
        items.sort((a, b) => exact(a) - exact(b));
        if (!items.length || (items.length === 1 && items[0].insert === q.toLowerCase())) {
          menu = null;
          return;
        }
        const xy = caretXY(el, from);
        menu = { items, sel: 0, x: el.offsetLeft + Math.min(xy.x, el.clientWidth - 260), y: el.offsetTop + xy.y, from, to, v, raw: true };
      });
  }

  // closeMenu also drops the answers still on their way: a late one would
  // open the menu again for the text it was asked for.
  function closeMenu() {
    menu = null;
    geoSeq++;
    appSeq++;
  }

  function setText(v: string) {
    if (mode === 'all') allText = v;
    else addText = v;
  }

  function options(): Opt[] {
    // Names are compared trimmed and in any case, as in parseTarget.
    const key = (n: string) => n.trim().toLowerCase();
    const count = new Map<string, number>();
    for (const p of ui.profiles) count.set(key(p.name), (count.get(key(p.name)) ?? 0) + 1);
    const servers = ui.profiles.map((p) => ({
      label: p.name,
      // Empty and duplicate names, names with | and #, and names that read
      // as a target word ("Direct", "VPN", "Блок") are written as id: (as
      // in targetWord).
      insert:
        !key(p.name) ||
        (count.get(key(p.name)) ?? 0) > 1 ||
        /[|#\n,→"]|->|=>/.test(p.name) ||
        /^(direct|напрямую|прямо|block|блок|заблокировать|блокировать|vpn|tunnel|туннель|впн|основной|main|id:.*)$/i.test(p.name.trim())
          ? 'id:' + p.id
          : p.name.trim(),
      hint: [p.main ? '★ основной' : '', p.sourceName, p.missing ? 'нет в подписке' : ''].filter(Boolean).join(' · ') || 'сервер',
    }));
    // Groups: группа:Имя (id: when the name repeats or does not read back,
    // as in targetWord).
    const gcount = new Map<string, number>();
    for (const g of ui.groups) gcount.set(key(g.name), (gcount.get(key(g.name)) ?? 0) + 1);
    const groups = ui.groups.map((g) => {
      const n = g.members.length - g.missing;
      return {
        label: 'группа:' + g.name,
        insert:
          !key(g.name) ||
          (gcount.get(key(g.name)) ?? 0) > 1 ||
          /[|#\n,→"]|->|=>/.test(g.name) ||
          /^(direct|напрямую|прямо|block|блок|заблокировать|блокировать|vpn|tunnel|туннель|впн|основной|main)$/i.test(g.name.trim())
            ? 'id:' + g.id
            : 'группа:' + g.name.trim(),
        hint: [`группа · ${n} ${plural(n, 'сервер', 'сервера', 'серверов')}`, ui.status?.mainId === g.id ? '★ основная' : ''].filter(Boolean).join(' · '),
      };
    });
    return [
      ...servers,
      ...groups,
      { label: 'vpn', insert: 'vpn', hint: 'основной сервер' },
      { label: 'напрямую', insert: 'напрямую', hint: 'мимо VPN' },
      { label: 'блок', insert: 'блок', hint: 'заблокировать' },
    ];
  }

  // Pixel position of a caret inside the textarea (mirror-div technique).
  function caretXY(el: HTMLTextAreaElement, pos: number): { x: number; y: number } {
    const cs = getComputedStyle(el);
    const div = document.createElement('div');
    for (const k of ['fontFamily', 'fontSize', 'fontWeight', 'lineHeight', 'letterSpacing', 'tabSize', 'paddingTop', 'paddingLeft', 'paddingRight', 'borderTopWidth', 'borderLeftWidth', 'boxSizing'] as const) {
      (div.style as any)[k] = (cs as any)[k];
    }
    div.style.position = 'absolute';
    div.style.visibility = 'hidden';
    div.style.whiteSpace = 'pre';
    div.textContent = el.value.slice(0, pos);
    const mark = document.createElement('span');
    mark.textContent = '\u200b';
    div.appendChild(mark);
    document.body.appendChild(div);
    const x = mark.offsetLeft - el.scrollLeft;
    const y = mark.offsetTop - el.scrollTop + parseFloat(cs.lineHeight || '20');
    div.remove();
    return { x, y };
  }

  function updateMenu() {
    const el = ta;
    if (!el || el.selectionStart !== el.selectionEnd) {
      closeMenu();
      return;
    }
    const v = el.value;
    const pos = el.selectionStart;
    const ls = v.lastIndexOf('\n', pos - 1) + 1;
    let le = v.indexOf('\n', pos);
    if (le < 0) le = v.length;
    const before = v.slice(ls, pos);
    const g = before.match(/(?:^|[\s,;])(geosite|geoip):([^\s,;]*)$/i);
    if (g && !before.trimStart().startsWith('#') && !/(->|→|=>)/.test(before)) {
      const q = g[2].toLowerCase();
      const from = pos - g[2].length;
      const after = v.slice(pos, le).match(/^[^\s,;]*/)?.[0] ?? '';
      geoMenu(el, g[1].toLowerCase() === 'geoip' ? 'ip' : 'site', q, from, pos + after.length);
      return;
    }
    geoSeq++;
    // A word before "->" (or inside [ ]) that looks like a program name.
    const w = before.match(/(?:^|[\s,;[])([^\s,;[\]:/\\=*]{2,})$/);
    if (w && !before.trimStart().startsWith('#') && !/(->|→|=>)/.test(before)) {
      const word = w[1];
      const dot = word.indexOf('.');
      if (dot < 0 || 'exe'.startsWith(word.slice(dot + 1).toLowerCase())) {
        const after = v.slice(pos, le).match(/^[^\s,;\]]*/)?.[0] ?? '';
        appMenu(el, word.slice(0, dot < 0 ? undefined : dot), pos - word.length, pos + after.length);
        return;
      }
    }
    appSeq++;
    // The server being typed: after the last "->" or comma of the target
    // ("-> DE -> N", "-> DE, N").
    const m = /(->|→|=>)/.test(before) ? before.match(/(->|→|=>|,)([^|,>→]*)$/) : null;
    if (!m || before.trimStart().startsWith('#')) {
      menu = null;
      return;
    }
    const typed = m[2];
    const lead = typed.length - typed.trimStart().length;
    const from = pos - typed.length + lead;
    const rest = v.slice(pos, le);
    const stop = rest.search(/\||,|->|→|=>/);
    const to = pos + (stop >= 0 ? rest.slice(0, stop) : rest).trimEnd().length;
    const q = v.slice(from, to).trim().toLowerCase();
    const items = options().filter((o) => !q || o.label.toLowerCase().includes(q) || o.insert.toLowerCase().includes(q));
    // Typed in full ("vpn", "DE"): Enter ends the line, it must not swap the
    // word for a server that merely contains it ("MyVPN DE", "DE 2").
    if (!items.length || items.some((o) => o.insert.toLowerCase() === q)) {
      menu = null;
      return;
    }
    // A server whose name is typed in full (written as id: when the name
    // repeats) comes first.
    const exact = (o: Opt) => (o.label.toLowerCase() === q ? 0 : 1);
    items.sort((a, b) => exact(a) - exact(b));
    const xy = caretXY(el, from);
    const sel = menu && !menu.raw && menu.q === q ? Math.min(menu.sel, items.length - 1) : 0;
    menu = { items, sel, x: el.offsetLeft + Math.min(xy.x, el.clientWidth - 260), y: el.offsetTop + xy.y, from, to, v, q };
  }

  function pick(o: Opt) {
    const el = ta;
    if (!el || !menu) return;
    const v = el.value;
    if (menu.v !== v) {
      closeMenu();
      return;
    }
    const lead = menu.raw || v[menu.from - 1] === ' ' ? '' : ' ';
    const next = v.slice(0, menu.from) + lead + o.insert + v.slice(menu.to);
    const caret = menu.from + lead.length + o.insert.length;
    // Set the value and caret synchronously: keys typed right after the
    // pick must land after the inserted text.
    el.value = next;
    el.setSelectionRange(caret, caret);
    setText(next);
    closeMenu();
    el.focus();
  }

  function onKey(e: KeyboardEvent) {
    if (!menu) {
      if (e.key === ' ' && e.ctrlKey) {
        e.preventDefault();
        updateMenu();
      }
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const n = menu.items.length;
      menu.sel = (menu.sel + (e.key === 'ArrowDown' ? 1 : n - 1)) % n;
    } else if (e.key === 'Enter' || e.key === 'Tab') {
      // The menu is still for the text before the last keys (the answer
      // for the new text is on its way): the key works as usual rather
      // than put the item over the wrong part.
      if (menu.v !== ta?.value) {
        closeMenu();
        return;
      }
      e.preventDefault();
      pick(menu.items[menu.sel]);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      closeMenu();
    }
  }

  // Only a click that starts on the backdrop closes the dialog: selecting
  // text and letting go outside it also ends in a click on the backdrop,
  // and every unsaved edit would be lost.
  let downOnBackdrop = false;
</script>

<div
  class="backdrop"
  role="presentation"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && onclose()}
>
  <div class="dialog big">
    <div class="row head">
      <h2 class="grow">Правила текстом</h2>
      <div class="seg">
        <button class:on={mode === 'all'} onclick={() => (mode = 'all')}>Все правила</button>
        <button class:on={mode === 'add'} onclick={() => (mode = 'add')}>Добавить пачкой</button>
      </div>
      <button class="icon" onclick={onclose}><Icon name="x" /></button>
    </div>
    <p class="muted small intro">
      {#if mode === 'all'}
        Здесь весь список: правьте как текст — добавляйте, удаляйте, меняйте порядок строк. При сохранении он заменит текущие правила.
      {:else}
        Вставьте сколько угодно правил — они добавятся в конец списка. Текущие правила не меняются.
      {/if}
    </p>

    <div class="cols">
      <div class="editor">
        {#if masked}
          <pre class="ro">{hide(text)}</pre>
          <div class="status muted privacy">
            <Icon name="eye-off" size={15} />{lines} строк · включено «Скрыть данные»: сайты, адреса и серверы замаскированы, текст только для просмотра
          </div>
        {:else}
          <div class="ta-wrap">
            <textarea
              bind:this={ta}
              value={text}
              spellcheck="false"
              wrap="off"
              placeholder={mode === 'add' ? example : ''}
              oninput={(e) => {
                setText((e.currentTarget as HTMLTextAreaElement).value);
                updateMenu();
              }}
              onkeydown={onKey}
              onkeyup={(e) => ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key) && updateMenu()}
              onclick={updateMenu}
              onscroll={() => (menu = null)}
              onblur={() => setTimeout(closeMenu, 150)}
            ></textarea>
            {#if menu}
              <div class="ac" style="left: {menu.x}px; top: {menu.y}px">
                {#each menu.items as o, i}
                  <button class:sel={i === menu.sel} onmousedown={(e) => { e.preventDefault(); pick(o); }} onmousemove={() => menu && menu.sel !== i && (menu.sel = i)}>
                    <span class="ellipsis">{o.label}</span><span class="hint">{o.hint}</span>
                  </button>
                {/each}
                <div class="keys">↑↓ выбрать · Enter/Tab вставить · Esc закрыть</div>
              </div>
            {/if}
          </div>
          <div class="status">
            {#if res}
              {#if res.errors.length}
                <div class="errs">
                  {#each res.errors.slice(0, 20) as e}<div><b>строка {e.line}:</b> {e.text}</div>{/each}
                  {#if res.errors.length > 20}<div>…и ещё {res.errors.length - 20}</div>{/if}
                </div>
              {:else if defaultInAdd}
                <div class="errs"><div>Строка «* -&gt; …» меняет «Всё остальное» и работает только в «Все правила»: уберите её здесь.</div></div>
              {:else}
                <div class="ok"><Icon name="check" size={15} /> {res.summary}</div>
              {/if}
              {#if res.warnings?.length}
                <div class="warns">
                  {#each res.warnings.slice(0, 8) as w}<div><b>строка {w.line}:</b> {w.text}</div>{/each}
                </div>
              {/if}
            {:else}
              <span class="muted">{lines} строк</span>
            {/if}
          </div>
        {/if}
      </div>

      <div class="help">
        <b>Как писать</b>
        <p><code>что -&gt; куда</code> — одна строка, одно правило.</p>
        <p><b>Что:</b> сайты и программы через пробел или запятую.</p>
        <ul>
          <li><code>youtube.com</code> — сайт с поддоменами</li>
          <li><code>=site.com</code> — только этот адрес</li>
          <li><code>*.ru</code> — все сайты в зоне .ru</li>
          <li><code>discord</code> или <code>discord.exe</code> — программа</li>
          <li><code>=game.exe</code> — программа без запущенных ею процессов</li>
          <li><code>app:my.app</code> — программа с именем как написано (без <code>.exe</code> или похожим на сайт)</li>
          <li><code>"C:\Games\*"</code> — всё из папки</li>
        </ul>
        <p><b>Готовые списки</b> из базы <b>{geo.sourceName || 'правил'}</b> (сменить: Настройки → Базы правил):</p>
        <ul>
          <li><code>geosite:youtube</code> — все домены сервиса (набираете <code>geosite:</code> — появится список)</li>
          <li><code>geosite:ru-blocked</code> — заблокированное в России</li>
          <li><code>geoip:ru</code> — все IP России, <code>geoip:private</code> — локальная сеть</li>
          <li><code>192.168.0.0/16</code>, <code>1.2.3.4</code> — сеть или адрес</li>
          <li><code>keyword:torrent</code> — любой сайт со словом в имени</li>
        </ul>
        <p><b>Куда:</b> <code>vpn</code> (основной сервер или группа), имя сервера или его часть, группа — <code>группа:Имя</code>, <code>напрямую</code>, <code>блок</code>. Запасные серверы — следом через стрелку или запятую: <code>-&gt; DE -&gt; NL</code> (если DE недоступен — NL, если недоступны оба — соединение не пройдёт, напрямую не уйдёт). В конце можно дописать <code>-&gt; блок</code>, это то же самое. После <code>-&gt;</code> появится список серверов — выберите стрелками и Enter (или Ctrl+Пробел).</p>
        <p><b>Для одной программы:</b> строка <code>[chrome.exe]</code>, под ней правила только для Chrome. <code>[*]</code> — снова для всех.</p>
        <p><b>Всё остальное:</b> <code>* -&gt; vpn</code> (только в «Все правила»)</p>
        <p><b>Опции</b> после <code>|</code>: <code>tcp</code>, <code>udp</code>, <code>выкл</code>, <code>без дочерних</code>.</p>
        <p><b>Название:</b> <code>YouTube: youtube.com -&gt; vpn</code>. Строки с <code>#</code> — комментарии.</p>
      </div>
    </div>

    {#if error}<div class="note error">{shownError}</div>{/if}
    {#if stale && mode === 'all' && !masked}
      <div class="note info">
        {#if stale.mine}
          В редакторе ваш текст, он не потерян: «Сохранить список» ещё раз заменит им правила, изменённые в другом месте.
        {:else}
          В редакторе текущие правила. Ваш текст можно вернуть.
        {/if}
        <button class="link" onclick={swapStale}>{stale.mine ? 'Показать текущие правила' : 'Вернуть мой текст'}</button>
      </div>
    {/if}
    <div class="actions">
      <button onclick={onclose}>Отмена</button>
      {#if masked}
        <button class="primary" onclick={reveal}><Icon name="eye" size={16} />Показать и редактировать</button>
      {:else}
        <button class="primary" onclick={save} disabled={saving || !text.trim() || !!res?.errors.length || defaultInAdd}>
          {mode === 'all' ? 'Сохранить список' : 'Добавить правила'}
        </button>
      {/if}
    </div>
  </div>
</div>

<style>
  .big { width: min(1080px, 96vw); }
  .head { gap: 12px; }
  .head h2 { margin: 0; }
  .intro { margin: 6px 0 12px; }
  .cols { display: grid; grid-template-columns: 1fr 300px; gap: 16px; }
  .editor { display: flex; flex-direction: column; gap: 8px; min-width: 0; }
  .ta-wrap { position: relative; }
  .ac {
    position: absolute;
    z-index: 5;
    width: 300px;
    max-height: 260px;
    overflow: auto;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow-lg);
    padding: 4px;
  }
  .ac button { width: 100%; justify-content: space-between; gap: 10px; background: none; padding: 6px 8px; font-size: 13px; }
  .ac button.sel { background: var(--accent-soft); color: var(--accent); }
  .ac .hint { font-size: 11px; color: var(--muted); white-space: nowrap; }
  .ac .keys { font-size: 10.5px; color: var(--faint); padding: 4px 8px 2px; border-top: 1px solid var(--border); margin-top: 2px; }
  textarea { width: 100%; height: 52vh; font-size: 13px; line-height: 1.55; tab-size: 4; resize: none; }
  .ro {
    margin: 0;
    height: 52vh;
    overflow: auto;
    padding: 7px 10px;
    border-radius: var(--radius-sm);
    background: var(--surface-2);
    font-family: var(--mono);
    font-size: 13px;
    line-height: 1.55;
    tab-size: 4;
    user-select: text;
  }
  .privacy { display: flex; align-items: center; gap: 6px; }
  .status { font-size: 12.5px; min-height: 22px; }
  .errs { color: var(--block); display: grid; gap: 2px; max-height: 110px; overflow: auto; }
  .ok { color: var(--direct); display: flex; align-items: center; gap: 6px; }
  .warns { color: var(--warn); display: grid; gap: 2px; max-height: 80px; overflow: auto; margin-top: 4px; }
  .help { font-size: 12.5px; background: var(--surface-2); border-radius: var(--radius-sm); padding: 12px 14px; overflow: auto; max-height: 58vh; }
  .help p { margin: 8px 0; }
  .help ul { margin: 4px 0 8px; padding-left: 16px; display: grid; gap: 3px; }
  code { font-family: var(--mono); font-size: 12px; background: var(--surface); padding: 0 4px; border-radius: 3px; }
</style>
