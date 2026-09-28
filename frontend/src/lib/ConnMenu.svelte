<script module lang="ts">
  // The result of a rule made from a connection, as a toast: what was made
  // and where it stands, with «Открыть правило» and «Отменить». Shared by
  // the menu's quick items and the editor path of «Соединения».
  import { api, errText, type ConnRuleResult, type Rule } from '../api';
  import { ui, hide, targetText } from '../state.svelte';
  import { toast, setFold, expireUndo, type ToastAction } from '../toast.svelte';
  import { ruleTitle, type RuleRef } from '../ruletitle';

  // nav switches the page (App's go); Connections sets it on mount, the
  // toasts outlive the page.
  let nav: (id: string) => void = () => {};
  export function setConnNav(go: (id: string) => void) {
    nav = go;
  }

  setFold('connrule', (n) => ({
    text: () => `Ещё ${n()} правил создано из «Соединений» — см. «Правила».`,
    actions: [{ label: () => 'Открыть «Правила»', run: () => nav('rules') }],
  }));

  // whereText is where a rule sends its connections.
  export function whereText(r: { action: string; profile?: string }): string {
    if (r.action === 'direct') return 'напрямую';
    if (r.action === 'block') return 'блок';
    return r.profile ? `через ${targetText(r.profile)}` : 'через основной сервер';
  }

  // refTitle is the Rules-page title of a rule the result names.
  function refTitle(res: ConnRuleResult, i: number): string {
    const ref = (res.refs ?? []).find((x) => x.index === i);
    return ref ? hide(ruleTitle(ref.rule)) : `правило ${i + 1}`;
  }

  function titles(res: ConnRuleResult, list: number[], route = false): string {
    const shown = list.slice(0, 3).map((i) => {
      const r = (res.refs ?? []).find((x) => x.index === i)?.rule;
      return `«${refTitle(res, i)}»${route && r ? ` (${whereText(r)})` : ''}`;
    });
    return shown.join(', ') + (list.length > 3 ? ` и ещё ${list.length - 3}` : '');
  }

  // openRule opens a rule of the result on «Правила», if its rule profile
  // is still the active one.
  function openRule(res: ConnRuleResult, ref: RuleRef) {
    if (res.ruleset === (ui.status?.ruleset?.token ?? '')) {
      ui.focusRule = { ...ref, rev: res.rev };
      nav('rules');
      return;
    }
    nav('rules');
    toast({ tone: 'info', text: () => `Правило в профиле правил «${hide(res.rulesetName)}», сейчас активен другой.` });
  }

  // undoAction is the «Отменить» of a result. A failure after which Go
  // keeps the entry (the rule profile switched, a write failed) shows an
  // error toast that keeps «Отменить», so the user can retry; the final
  // refusals (gone, deleted, edited) show a plain error.
  function undoAction(res: ConnRuleResult): ToastAction {
    return {
      label: () => 'Отменить',
      undo: true,
      run: async () => {
        try {
          await api.UndoConnRule(res.undo);
        } catch (e) {
          const msg = errText(e);
          if (/^(Отменить уже нельзя|Правило не найдено|Правило уже изменено)/.test(msg)) throw e;
          toast({ tone: 'error', text: () => hide(msg), actions: [undoAction(res)], group: 'connrule', seq: res.seq || undefined });
          if (res.seq) expireUndo('connrule', res.seq);
          return;
        }
        toast({ tone: 'ok', text: () => 'Отменено.' });
      },
    };
  }

  // showConnResult shows the toast of a result; what names the rule's items
  // («весь сайт example.com»), udp says how a flow that the rule may miss
  // is missed.
  export function showConnResult(res: ConnRuleResult, what: () => string, udp: boolean) {
    const saved: Rule = res.rule;
    const text = () => {
      if (res.kind === 'added') return `Правило добавлено: ${what()} → ${whereText(saved)}.`;
      if (res.kind === 'changed') return `Правило «${hide(ruleTitle(saved))}» изменено: теперь ${whereText(saved)}.`;
      return `Уже так: правило «${hide(ruleTitle(saved))}» ведёт ${whereText(saved)}.`;
    };
    const detail = () => {
      const l: string[] = [];
      if (res.kind === 'added')
        l.push(res.aboveIndex >= 0 ? `Стоит над правилом «${refTitle(res, res.aboveIndex)}».` : 'Стоит в конце списка, над «Всё остальное».');
      if (res.overriddenBy?.length) l.push(`Выше остаются правила, которые забирают часть этих соединений: ${titles(res, res.overriddenBy)}.`);
      if (res.narrowed?.length) l.push(`Правило стоит выше этих правил и забирает часть их соединений: ${titles(res, res.narrowed, true)}.`);
      if (res.notEffective)
        l.push(`Это соединение правило ${udp ? 'не поймает' : 'может не поймать'}: у адреса несколько сайтов с разными правилами. Для него надёжнее «Только IP».`);
      if (res.unchanged) l.push('Маршрут этого соединения не меняется: правило закрепляет его.');
      if (res.placedByRule) l.push('Это правило не подходит к выбранному соединению: оно поставлено над первым правилом, которое могло бы забрать его соединения.');
      if (res.shadowed?.length) l.push(`Ниже больше не сработают: ${titles(res, res.shadowed)}.`);
      if (res.rulesetName) l.push(`Профиль правил: «${hide(res.rulesetName)}».`);
      if (res.kind !== 'same') l.push('Действует для новых соединений.');
      return l.join(' ');
    };
    const actions: ToastAction[] = [
      { label: () => 'Открыть правило', run: () => openRule(res, { id: res.ruleId, index: res.index, rule: res.rule }) },
    ];
    const over = res.overriddenBy?.[0];
    const ref = (res.refs ?? []).find((x) => x.index === over);
    if (ref) actions.push({ label: () => `Открыть «${hide(ruleTitle(ref.rule))}»`, run: () => openRule(res, { id: ref.rule.id ?? '', index: ref.index, rule: ref.rule }) });
    if (res.undo) actions.push(undoAction(res));
    toast({ tone: 'ok', text, detail, actions, group: 'connrule', seq: res.seq || undefined });
    if (res.seq) expireUndo('connrule', res.seq);
  }
</script>

<script lang="ts">
  // The menu of a Connections row: a rule from what the row shows (site,
  // host, IP, program, target), placed by Go right above the rule that
  // decides the connection now. It works on a snapshot of the row.
  import { onMount, tick } from 'svelte';
  import { cleanRule, connFacts, isGroupId, type Action, type ConnFacts, type ConnRuleInfo, type ConnScope, type Flow } from '../api';
  import { mainTarget, mainText, profileName } from '../state.svelte';
  import Icon from './Icon.svelte';

  let {
    flow,
    anchor,
    returnFocus = null,
    onclose,
    onedit,
    onexplain,
  }: {
    flow: Flow;
    anchor: { x: number; y: number };
    returnFocus?: HTMLElement | null;
    onclose: () => void;
    onedit: (draft: Rule, facts: ConnFacts, ruleset: string) => void;
    onexplain: (q: { app: string; target: string; proto: string; port: number; note: string }) => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  const f = flow;
  const facts = connFacts(f);
  const udp = f.proto.toLowerCase() === 'udp';

  let info = $state<ConnRuleInfo | null>(null);
  let loadErr = $state('');
  let busy = $state(false);
  let scopeIdx = $state(0);
  let sub = $state<'dest' | 'app' | null>(null);
  let menuEl = $state<HTMLElement>();
  let subEl = $state<HTMLElement>();
  let pos = $state({ left: 0, top: 0 });
  let subPos = $state({ left: 0, top: 0 });
  let destBtn = $state<HTMLElement>();
  let appBtn = $state<HTMLElement>();

  // svelte-ignore state_referenced_locally
  pos = { left: anchor.x, top: anchor.y };

  const scopes = $derived<ConnScope[]>(info?.scopes ?? []);
  const scope = $derived<ConnScope | undefined>(scopes[scopeIdx]);

  function remembered(): string {
    try {
      return localStorage.getItem('hyroute.connScope') ?? 'site';
    } catch {
      return 'site';
    }
  }

  function remember(kind: string) {
    try {
      localStorage.setItem('hyroute.connScope', kind);
    } catch {}
  }

  // label: the ASCII form in Privacy mode (the masking covers it for sure).
  function label(s: ConnScope): string {
    return ui.privacy ? hide(s.ascii) : s.label;
  }

  function scopeText(s: ConnScope): string {
    if (s.kind === 'site') return `Весь сайт ${label(s)}`;
    if (s.kind === 'ip') return `Только IP ${label(s)}`;
    if (s.kind === 'alias') return `Только ${label(s)} (CDN-имя)`;
    return `Только ${label(s)}`;
  }

  // what names the rule's items for the toast (evaluated when shown).
  function scopeWhat(s: ConnScope): () => string {
    const c = { ...s };
    if (c.kind === 'site') return () => `весь сайт ${label(c)}`;
    if (c.kind === 'ip') return () => `адрес ${label(c)}`;
    return () => label(c);
  }

  onMount(() => {
    (async () => {
      try {
        const i = await api.ConnRuleInfo(facts);
        const sc = i.scopes ?? [];
        const want = remembered();
        let d = sc.findIndex((s) => s.kind === want);
        if (d < 0) d = sc.findIndex((s) => s.kind !== 'alias');
        scopeIdx = Math.max(0, d);
        info = i;
      } catch (e) {
        loadErr = errText(e);
      }
      await tick();
      place();
      focusFirst(menuEl);
    })();
    const down = (e: PointerEvent) => {
      const t = e.target as Node;
      if (!menuEl?.contains(t) && !subEl?.contains(t)) close(false);
    };
    const wheel = (e: Event) => {
      const t = e.target as Node;
      if (!menuEl?.contains(t) && !subEl?.contains(t)) close(false);
    };
    const gone = () => close(false);
    window.addEventListener('pointerdown', down, true);
    window.addEventListener('wheel', wheel, true);
    window.addEventListener('scroll', wheel, true);
    window.addEventListener('blur', gone);
    window.addEventListener('resize', gone);
    return () => {
      window.removeEventListener('pointerdown', down, true);
      window.removeEventListener('wheel', wheel, true);
      window.removeEventListener('scroll', wheel, true);
      window.removeEventListener('blur', gone);
      window.removeEventListener('resize', gone);
    };
  });

  // place keeps the menu inside the window.
  function place() {
    if (!menuEl) return;
    const r = menuEl.getBoundingClientRect();
    pos = {
      left: Math.max(4, Math.min(anchor.x, window.innerWidth - r.width - 4)),
      top: Math.max(4, Math.min(anchor.y, window.innerHeight - r.height - 4)),
    };
  }

  let closed = false;
  function close(refocus = true) {
    if (closed) return;
    closed = true;
    onclose();
    if (refocus) returnFocus?.focus();
  }

  function items(el: HTMLElement | undefined): HTMLElement[] {
    return [...(el?.querySelectorAll<HTMLElement>('[role^="menuitem"]') ?? [])];
  }

  function focusFirst(el: HTMLElement | undefined) {
    (items(el).find((x) => x.getAttribute('aria-disabled') !== 'true') ?? items(el)[0])?.focus();
  }

  // subItem is the menu item that opens a submenu (inside its wrapper).
  function subItem(which: 'dest' | 'app' | null): HTMLElement | null {
    return (which === 'dest' ? destBtn : which === 'app' ? appBtn : undefined)?.querySelector<HTMLElement>('[role="menuitem"]') ?? null;
  }

  async function openSub(which: 'dest' | 'app', focus: boolean) {
    const btn = subItem(which);
    if (!btn || btn.getAttribute('aria-disabled') === 'true') return;
    sub = which;
    await tick();
    const r = btn.getBoundingClientRect();
    const w = subEl?.getBoundingClientRect().width ?? 240;
    const h = subEl?.getBoundingClientRect().height ?? 200;
    const left = r.right + w + 4 <= window.innerWidth ? r.right : Math.max(4, r.left - w);
    subPos = { left, top: Math.max(4, Math.min(r.top, window.innerHeight - h - 4)) };
    if (focus) focusFirst(subEl);
  }

  function closeSub() {
    const btn = subItem(sub);
    sub = null;
    btn?.focus();
  }

  function onkey(e: KeyboardEvent, inSub: boolean) {
    const list = items(inSub ? subEl : menuEl);
    const at = list.indexOf(document.activeElement as HTMLElement);
    const move = (i: number) => list[(i + list.length) % list.length]?.focus();
    switch (e.key) {
      case 'ArrowDown':
        move(at + 1);
        break;
      case 'ArrowUp':
        move(at < 0 ? -1 : at - 1);
        break;
      case 'Home':
        move(0);
        break;
      case 'End':
        move(-1);
        break;
      case 'Enter':
      case ' ':
        (document.activeElement as HTMLElement | null)?.click();
        break;
      case 'ArrowRight': {
        const el = document.activeElement as HTMLElement | null;
        if (!inSub && el?.dataset.sub) openSub(el.dataset.sub as 'dest' | 'app', true);
        break;
      }
      case 'ArrowLeft':
        if (inSub) closeSub();
        break;
      case 'Escape':
        if (inSub) closeSub();
        else close();
        break;
      case 'Tab':
        close();
        return;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  }

  // Why the rule items are off ('' = on).
  const ruleOff = $derived(
    !info ? loadErr || 'Загрузка…' : info.excluded || info.blocked || '',
  );
  const noTargets = $derived(ui.profiles.length === 0 && ui.groups.length === 0);
  const appOff = $derived(ruleOff || (info && !info.app ? 'Программа не определена' : ''));
  const destOff = $derived(ruleOff || (!scope ? 'Нет адреса для правила' : ''));
  const noun = $derived(scope?.kind === 'ip' ? 'адрес' : 'сайт');

  const dest = $derived.by(() => {
    const host = scopes.find((s) => s.kind === 'host');
    const ip = f.dst.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
    if (info?.ech === 'public') return `${hide(ip)} (ECH: ${hide(info.echName)})`;
    if (host) return label(host);
    return hide(ip);
  });

  function currentLine(i: ConnRuleInfo): string {
    if (i.excluded) return i.excluded;
    const c = i.current;
    const route = c.action === 'direct' ? 'напрямую' : c.action === 'block' ? 'блок' : c.profile ? `через ${targetText(c.profile)}` : 'через основной сервер';
    const rule = c.rule ? `«${hide(ruleTitle(c.rule))}»` : '«Всё остальное»';
    if (c.ambiguous) return `Сейчас по правилам без имени сайта: ${route} · ${rule} (у адреса несколько сайтов с разными правилами)`;
    return `Сейчас по правилам: ${route} · ${rule}`;
  }

  const main = $derived(mainTarget());
  const curTarget = $derived(info?.current.action === 'tunnel' ? info.current.profile : '');

  function editDraft(): Rule {
    return { name: '', apps: [], domains: scope ? [scope.pattern] : [], action: 'tunnel', profile: '' };
  }

  async function quick(kind: 'dest' | 'app', action: Action, profile = '') {
    if (!info || busy) return;
    const i = info;
    let rule: Rule;
    let what: () => string;
    if (kind === 'dest') {
      if (destOff || !scope) return;
      rule = { name: '', domains: [scope.pattern], action, profile };
      what = scopeWhat(scope);
    } else {
      if (appOff) return;
      rule = { name: '', apps: [{ pattern: i.app, inheritChildren: !i.appLauncher }], action, profile };
      const app = i.app;
      what = i.appLauncher ? () => `только сам ${app}` : () => `${app} и программы, запущенные из него`;
      if (i.appSystem) {
        const where = whereText({ action, profile });
        let q = `${app} — часть Windows: через этот процесс работают многие службы. Всё равно направить весь его трафик ${where}?`;
        if (!i.appLauncher) q += ` Правило распространится и на все программы, запущенные из ${app}.`;
        if (!confirm(q)) return;
      }
    }
    busy = true;
    try {
      const res = await api.AddConnRule({ facts, rule: cleanRule(rule, main?.id), source: 'quick', ruleset: i.ruleset });
      close();
      showConnResult(res, what, udp);
    } catch (e) {
      close();
      toast({ tone: 'error', text: () => `Не удалось создать правило: ${hide(errText(e))}` });
    } finally {
      busy = false;
    }
  }

  function explain() {
    const i = info;
    const port = Number(/:(\d+)$/.exec(f.dst)?.[1] ?? 0);
    const note = i?.hasParents
      ? 'Правила с «+ дочерние» проверяются здесь только по самой программе: в меню учитывалась и цепочка запуска, поэтому ответы могут различаться.'
      : '';
    const fallback = (f.domain || '').split(',')[0].trim() || f.dst.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
    if (i?.dnsQuery) {
      onexplain({ app: i.appNote ? '' : f.path || f.process, target: i.explainTarget, proto: 'tcp', port: 0, note });
    } else {
      onexplain({ app: f.path || f.process, target: i?.explainTarget || fallback, proto: f.proto.toLowerCase(), port, note });
    }
    close(false);
  }

  function edit() {
    if (ruleOff || !info) return;
    onedit(editDraft(), facts, info.ruleset);
    close(false);
  }

  function pickScope(i: number) {
    scopeIdx = i;
    if (scopes[i].kind !== 'alias') remember(scopes[i].kind);
  }
</script>

{#snippet item(text: string, off: string, run: () => void, extra?: { sub?: 'dest' | 'app'; danger?: boolean; inSub?: boolean })}
  <div
    role="menuitem"
    tabindex="-1"
    class="mi"
    class:danger={extra?.danger}
    aria-disabled={off ? 'true' : undefined}
    aria-haspopup={extra?.sub ? 'menu' : undefined}
    aria-expanded={extra?.sub ? sub === extra.sub : undefined}
    data-sub={extra?.sub}
    title={off || undefined}
    onclick={() => {
      if (off || busy) return;
      if (extra?.sub) openSub(extra.sub, true);
      else run();
    }}
    onkeydown={() => {}}
    onpointerenter={() => {
      if (extra?.sub && !off) openSub(extra.sub, false);
      else if (!extra?.inSub && sub) sub = null;
    }}
  >
    <span class="grow">{text}</span>{#if extra?.sub}<span class="arrow">▸</span>{/if}
  </div>
{/snippet}

<div
  class="cmenu"
  role="menu"
  tabindex="-1"
  aria-label="Действия с соединением"
  bind:this={menuEl}
  style="left: {pos.left}px; top: {pos.top}px"
  onkeydown={(e) => onkey(e, false)}
>
  <div class="head">
    <div class="h1">{f.process || `PID ${f.pid}`} → {dest}</div>
    {#if info}<div class="h2">{currentLine(info)}</div>{/if}
  </div>
  {#if !info && !loadErr}<div class="hint">Загрузка…</div>{/if}
  {#if loadErr}<div class="hint err">{hide(loadErr)}</div>{/if}
  {#if info?.blocked}<div class="hint err">{hide(info.blocked)}</div>{/if}

  {#if info && scopes.length > 1}
    <div class="sep"></div>
    <div class="lbl">К чему относится</div>
    {#each scopes as s, i (s.pattern)}
      <div role="menuitemradio" tabindex="-1" class="mi radio" aria-checked={i === scopeIdx} onclick={() => pickScope(i)} onkeydown={() => {}}>
        <span class="dot">{i === scopeIdx ? '●' : '○'}</span><span class="grow">{scopeText(s)}</span>
      </div>
    {/each}
  {/if}
  {#if info}
    {#if info.dnsName}<div class="hint">Имя сайта взято из DNS-кэша и может быть неточным: у одного IP бывает несколько сайтов.</div>{/if}
    {#if info.current.ambiguous}
      <div class="hint">
        У адреса несколько сайтов с разными правилами: без имени в самом соединении HyRoute решает без сайта, поэтому правило для сайта это соединение {udp
          ? 'не поймает'
          : 'может не поймать'}. Надёжнее «Только IP».
      </div>
    {:else if info.sites > 1}
      <div class="hint">У адреса несколько сайтов — выберите нужный.</div>
    {/if}
    {#if info.ech === 'public'}
      <div class="hint">
        Сайт скрыт ECH: видно только имя провайдера ({hide(info.echName)}). Правило на это имя затронуло бы все сайты за ним, поэтому доступно только правило по IP.
      </div>
    {:else if info.ech === 'hidden'}
      <div class="hint">{scopes.some((s) => s.kind !== 'ip') ? 'Сайт скрыт ECH: имя взято из DNS-кэша.' : 'Сайт скрыт ECH: имя неизвестно.'}</div>
    {/if}
    {#if info.sharedIP && scope?.kind === 'ip'}
      <div class="hint">
        Этот IP общий для {info.ech === 'public' ? 'нескольких сайтов (провайдер ECH)' : info.addrSites > 1 ? `${info.addrSites} сайтов` : 'нескольких сайтов'}: правило по IP затронет их все.
      </div>
    {/if}
  {/if}

  <div class="sep"></div>
  <div bind:this={destBtn} class="wrap">
    {@render item('Всегда через', destOff || (noTargets ? 'Нет серверов — добавьте на странице «Серверы»' : ''), () => {}, { sub: 'dest' })}
  </div>
  {@render item('Всегда напрямую', destOff, () => quick('dest', 'direct'))}
  {@render item(`Блокировать этот ${noun}`, destOff, () => quick('dest', 'block'), { danger: true })}

  <div class="sep"></div>
  {#if info?.appNote}
    <div class="hint">{info.appNote}</div>
  {:else}
    {@const app = info?.app || 'программа'}
    <div bind:this={appBtn} class="wrap">
      {@render item(
        info?.appLauncher ? `Только сам ${app} через` : `Всё приложение ${app} через`,
        appOff || (noTargets ? 'Нет серверов — добавьте на странице «Серверы»' : ''),
        () => {},
        { sub: 'app' },
      )}
    </div>
    {@render item(info?.appLauncher ? `Только сам ${app} напрямую` : `Всё приложение ${app} напрямую`, appOff, () => quick('app', 'direct'))}
    {#if info?.appLauncher}<div class="hint">{app} запускает другие программы: правило не распространяется на них.</div>{/if}
  {/if}

  <div class="sep"></div>
  {@render item('Настроить правило…', ruleOff, edit)}
  {@render item('Проверить адрес', '', explain)}
</div>

{#if sub}
  {@const kind = sub}
  <div
    class="cmenu sub"
    role="menu"
    tabindex="-1"
    aria-label="Куда"
    bind:this={subEl}
    style="left: {subPos.left}px; top: {subPos.top}px"
    onkeydown={(e) => onkey(e, true)}
  >
    {@render item(
      `${curTarget && curTarget === main?.id ? '✓ ' : ''}Основной сервер${main ? ` — ${mainText(main)}` : ''}`,
      main ? '' : 'Основной сервер не выбран',
      () => quick(kind, 'tunnel', ''),
      { inSub: true },
    )}
    {#if ui.profiles.length}<div class="sep"></div>{/if}
    {#each ui.profiles as p (p.id)}
      {@render item(
        `${curTarget === p.id ? '✓ ' : ''}${hide(p.name)}${p.missing ? ' (нет в подписке)' : ''}`,
        p.missing ? 'Сервер пропал из подписки' : '',
        () => quick(kind, 'tunnel', p.id),
        { inSub: true },
      )}
    {/each}
    {#if ui.groups.length}
      <div class="sep"></div>
      <div class="lbl">Группы серверов</div>
      {#each ui.groups as g (g.id)}
        {@render item(`${curTarget === g.id ? '✓ ' : ''}${profileName(g.id)} (группа)`, '', () => quick(kind, 'tunnel', g.id), { inSub: true })}
      {/each}
    {/if}
  </div>
{/if}

<style>
  .cmenu {
    position: fixed;
    z-index: 60;
    min-width: 260px;
    max-width: min(460px, 94vw);
    max-height: calc(100vh - 8px);
    overflow: auto;
    padding: 4px;
    border-radius: var(--radius-sm);
    background: var(--surface);
    border: 1px solid var(--border);
    box-shadow: var(--shadow-lg);
    font-size: 13px;
    outline: none;
  }
  .cmenu.sub { z-index: 61; min-width: 220px; }
  .head { padding: 6px 10px 4px; display: grid; gap: 2px; }
  .h1 { font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .h2 { color: var(--muted); font-size: 12px; }
  .lbl { padding: 4px 10px 2px; color: var(--muted); font-size: 11.5px; font-weight: 600; }
  .mi {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    border-radius: 6px;
    cursor: default;
    outline: none;
  }
  .mi:hover:not([aria-disabled='true']),
  .mi:focus { background: var(--accent-soft); }
  .mi[aria-disabled='true'] { opacity: 0.5; }
  .mi.danger:not([aria-disabled='true']) { color: var(--block); }
  .dot { width: 12px; color: var(--muted); }
  .arrow { color: var(--muted); }
  .sep { height: 1px; background: var(--border); margin: 4px 6px; }
  .hint { padding: 2px 10px 4px; color: var(--muted); font-size: 11.5px; }
  .hint.err { color: var(--block); }
</style>
