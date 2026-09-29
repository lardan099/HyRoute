<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, toLists, cleanSettings, cleanFallback, isGroupId, portsText, isEditToken, plural, tokenStale, editGone, newRuleID, type Settings, type Rule, type LintIssue, type RulesetsView } from '../api';
  import { ui, hide, profileName, mainTarget, mainText } from '../state.svelte';
  import Icon from './Icon.svelte';
  import TargetOptions from './TargetOptions.svelte';
  import RuleEditor from './RuleEditor.svelte';
  import FallbackPicker from './FallbackPicker.svelte';
  import Explain from './Explain.svelte';
  import RulesText from './RulesText.svelte';
  import Help from './Help.svelte';
  import RouteWizard from './RouteWizard.svelte';
  import RulesetBar, { showSwitchResult, showRulesetError } from './RulesetBar.svelte';
  import RulesetDialog from './RulesetDialog.svelte';
  import { templates, ruleFromTemplate, schemes, applyScheme, schemeTemplates, type Scheme } from './templates';
  import { itemLabel, loadGeo, geo } from '../geo.svelte';
  import { ruleTitle as title, appLabel, siteLabel, locateRule, sameRule } from '../ruletitle';
  import { toast } from '../toast.svelte';

  let s = $state<Settings | null>(null);
  let error = $state('');
  let lint = $state<LintIssue[]>([]);
  // token: the rules the editor was opened for; it never follows a reload.
  // orig (conn-rules): the rule as it was when the editor opened (null for a
  // new one): a save finds it again by it (locateRule), wherever the rule
  // is now; lost: it was changed or removed elsewhere, «Сохранить» adds the
  // draft as a new rule.
  let editing = $state<{ index: number; rule: Rule; title: string; token: string; orig: Rule | null; lost?: boolean } | null>(null);
  // rulesets: edit mode (an inactive profile opened without switching to
  // it), the profile list from the bar, and a note after edit mode ended.
  let editId = $state<string | null>(null);
  let rsView = $state<RulesetsView | null>(null);
  let rsNote = $state<{ kind: 'on' | 'gone'; name: string } | null>(null);
  let schemeDialog = $state<{ view: RulesetsView; scheme: Scheme } | null>(null);
  const editName = $derived(rsView?.list.find((r) => r.id === editId)?.name ?? '');
  const editError = $derived(rsView?.list.find((r) => r.id === editId)?.error ?? '');
  const activeName = $derived(ui.status?.ruleset?.name || 'Основной');
  let picking = $state(false);
  let asText = $state(false);
  let wizard = $state(false);
  let dragFrom = $state<number | null>(null);
  let dragOver = $state<number | null>(null);
  // The list a drag started on: a drop on a reloaded list is cancelled.
  let dragList: Settings | null = null;

  // Every change bumps edits; a load started before a newer change would
  // bring back the list without it.
  let edits = 0;
  let saving: Promise<unknown> = Promise.resolve();
  // rev/editRev: the revision of the rules on screen. Every save sends it,
  // and Go refuses one built on rules changed elsewhere meanwhile (a rule
  // from «Соединения», «Главная», the CLI…); pending counts saves in flight.
  let rev = $state(0);
  let editRev = $state(0);
  let pending = $state(0);
  let reloading = $state(false);
  // triedAt: ui.settingsRev when the last idle reload started. A change
  // reported during a reload is caught up after it; a failed reload is not
  // retried until the revision grows again. triedToken, triedEditAt: the
  // same for a change of the active profile and, in edit mode, of the
  // profile list's revision.
  let triedAt = 0;
  let triedToken = '';
  let triedEditAt = 0;

  // readRules is the page's copy: the active rules, or in edit mode the
  // edited profile's. That profile may have become the active one (Go then
  // returns the active view) or been deleted: edit mode ends with a note.
  async function readRules(): Promise<Settings> {
    const want = editId;
    if (!want) return api.Settings();
    const name = editName;
    try {
      const v = await api.RulesetSettings(want);
      if (want === editId && !isEditToken(v.ruleset)) {
        editId = null;
        rsNote = { kind: 'on', name };
      }
      return v;
    } catch (e) {
      if (want !== editId || errText(e) !== 'Профиль правил не найден') throw e;
      editId = null;
      rsNote = { kind: 'gone', name };
      return api.Settings();
    }
  }

  // loads counts the loads: a newer one (another profile opened) wins.
  let loads = 0;
  async function load() {
    const my = edits;
    const seq = ++loads;
    try {
      const v = await readRules();
      if (my !== edits || seq !== loads) return;
      v.rules = (v.rules ?? []).map(toLists);
      s = v;
      rev = v.rev ?? 0;
      editRev = v.editRev ?? 0;
      const l = await api.LintRules(cleanSettings(v, mainTarget()?.id));
      if (my === edits) lint = l;
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(() => {
    load();
    loadGeo();
  });

  // The rules changed elsewhere: reload, but only while nothing is being
  // edited here (no save in flight, no editor, no text, no drag). A save
  // from a stale list is refused and reloads by itself.
  // rulesets: the active profile changed (a switch from the tray, the CLI,
  // a network rule) also reloads; in edit mode the profile list's revision
  // does (the edited profile was edited elsewhere, switched to or deleted).
  $effect(() => {
    if (!s || pending || editing || asText || wizard || dragFrom !== null || reloading) return;
    const r = ui.status?.ruleset;
    if (editId) {
      if (!r || r.rev <= editRev || r.rev <= triedEditAt) return;
      triedEditAt = r.rev;
    } else if (r && tokenStale(s.ruleset, r) && r.token !== triedToken) {
      triedToken = r.token;
    } else {
      if (ui.settingsRev <= rev || ui.settingsRev <= triedAt) return;
      triedAt = ui.settingsRev;
    }
    reloading = true;
    load().finally(() => (reloading = false));
  });

  // rulesets: edit mode starts or ends (the bar, the banner). The old
  // copy goes at once: until the chosen rules load there is nothing to
  // edit, so no click lands in the profile that was on screen.
  function setEdit(id: string | null) {
    rsNote = null;
    error = '';
    editId = id;
    s = null;
    lint = [];
    load();
  }

  // «Включить его»: after the page's own queued saves.
  async function activateEdited() {
    const id = editId;
    if (!id) return;
    try {
      await saving;
      showSwitchResult(await api.SwitchRuleset(id));
      setEdit(null);
    } catch (e) {
      showRulesetError(e);
    }
  }

  // «Новым профилем» from «Шаблоны».
  async function schemeAsProfile(sc: Scheme) {
    try {
      const view = await api.Rulesets();
      picking = false;
      schemeDialog = { view, scheme: sc };
    } catch (e) {
      error = errText(e);
    }
  }

  // The text of a stale open editor (its rules are no longer the page's).
  const staleText = $derived(
    `Профиль правил сменился на «${hide(activeName)}», пока было открыто это окно: изменения сюда не сохранятся. Закройте окно и откройте заново.`,
  );
  // staleFor: the stale text for an editor opened with token ('' = fresh);
  // an edited profile deleted elsewhere gets its own.
  function staleFor(token: string): string {
    const r = ui.status?.ruleset;
    if (!tokenStale(token, r, rsView)) return '';
    if (r && editGone(token, r, rsView)) return 'Этот профиль правил удалили, пока было открыто это окно: изменения сюда не сохранятся. Закройте окно.';
    return staleText;
  }

  async function useScheme(sc: Scheme) {
    if (!s) return;
    const rest = sc.rest === 'direct' ? 'напрямую' : 'через VPN';
    if (!confirm(`«${sc.name}»\n\nПравила схемы добавятся в начало списка, «Всё остальное» станет «${rest}». Ваши правила останутся ниже.`)) return;
    picking = false;
    await persist(applyScheme(s, sc)).catch(() => {});
  }

  const tplGroups = ['Россия', 'Сервисы', 'Полезное'] as const;

  // missingLists: the template's lists that the database in use lacks.
  function missingLists(domains: string[]): string {
    const miss = domains.map((d) => itemLabel(d)).filter((l) => l?.missing);
    if (!miss.length) return '';
    return miss[0]!.missing;
  }

  // Every change is saved at once: there is no separate "Save" step. The
  // list shows it right away, so a quick next click (a switch, "Ниже")
  // builds on it, and saves go one after another in click order. The saved
  // list is reloaded after the last one. Each save sends the revision the
  // previous one produced (read when the job runs).
  async function persist(next: Settings) {
    error = '';
    s = next;
    const my = ++edits;
    pending++;
    const job = saving.then(async () => {
      const res = await api.SaveSettings({ ...cleanSettings(next, mainTarget()?.id), rev, editRev });
      rev = res.rev;
      editRev = res.editRev ?? 0;
      return res;
    });
    saving = job.catch(() => {});
    try {
      await job;
    } catch (e) {
      error = errText(e);
      throw e;
    } finally {
      if (my === edits) await load();
      pending--;
    }
  }

  function clone(): Settings {
    return JSON.parse(JSON.stringify(s));
  }

  // saveRule saves with the token the editor was opened with: after a
  // switch it is refused, never written into another profile. It never
  // trusts the index alone: the rule is found again by what it was when
  // the editor opened (the list may have changed: a rule from
  // «Соединения», an undo, a reload after a refused save).
  async function saveRule(r: Rule) {
    const ed = editing!;
    const next = clone();
    next.ruleset = ed.token;
    if (ed.orig && !ed.lost) {
      const cur = next.rules[ed.index];
      const at = cur && sameRule(cur, ed.orig) ? ed.index : locateRule(next.rules, { id: ed.orig.id ?? '', index: ed.index, rule: ed.orig });
      if (at < 0) {
        ed.index = -1;
        ed.lost = true;
        return; // the editor stays open with the draft and says why
      }
      ed.index = at;
    }
    // The same conditions and route as another rule: not saved twice.
    const d = await api.DuplicateRule(next.rules, r, ed.orig && !ed.lost ? ed.index : -1);
    if (d >= 0) {
      const off = next.rules[d].enabled === false ? ' (выключено — включите его)' : '';
      throw new Error(`Такое правило уже есть: №${d + 1} «${title(next.rules[d])}»${off}. Измените условия или действие, или закройте редактор.`);
    }
    if (ed.orig && !ed.lost) next.rules[ed.index] = r;
    else next.rules.push({ ...r, id: r.id || newRuleID() });
    await persist(next);
    editing = null;
  }

  function openEditor(index: number, rule: Rule, t: string) {
    editing = { index, rule, title: t, token: s?.ruleset ?? '', orig: index >= 0 ? JSON.parse(JSON.stringify(rule)) : null };
  }

  // conn-rules: «Открыть правило» of a toast. Runs once the list is loaded,
  // and when set while the page is already shown.
  $effect(() => {
    if (s && ui.focusRule) openFocused();
  });

  function openFocused() {
    if (editId) {
      setEdit(null); // the rule is in the active rules
      return;
    }
    const want = ui.focusRule!;
    ui.focusRule = null;
    const i = locateRule(s!.rules, want);
    if (i < 0) {
      toast({ tone: 'info', text: () => 'Правило не найдено: список правил изменился.' });
      return;
    }
    if (editing) {
      toast({ tone: 'info', text: () => 'Закройте редактор правила, чтобы открыть другое.' });
      return;
    }
    openEditor(i, JSON.parse(JSON.stringify(s!.rules[i])), 'Правило');
  }

  function move(from: number, to: number) {
    if (!s || to < 0 || to >= s.rules.length || from === to) return;
    const next = clone();
    const [r] = next.rules.splice(from, 1);
    next.rules.splice(to, 0, r);
    persist(next).catch(() => {});
  }

  function toggle(i: number) {
    const next = clone();
    next.rules[i].enabled = next.rules[i].enabled === false;
    persist(next).catch(() => {});
  }

  function remove(i: number) {
    if (!confirm(`Удалить правило «${title(s!.rules[i])}»?`)) return;
    const next = clone();
    next.rules.splice(i, 1);
    persist(next).catch(() => {});
  }

  function setDefault(action: 'tunnel' | 'direct' | 'block', profile = '') {
    const next = clone();
    next.defaultAction = action;
    next.defaultProfile = profile;
    // The route's own server is no fallback for itself.
    next.defaultFallback = cleanFallback(next.defaultFallback, profile, mainTarget()?.id);
    persist(next).catch(() => {});
  }

  function setDefaultFallback(fb: string[]) {
    const next = clone();
    next.defaultFallback = fb;
    persist(next).catch(() => {});
  }

  function newRule(): Rule {
    return { id: newRuleID(), name: '', apps: [], domains: [], action: 'tunnel', profile: '', protocol: '' };
  }

  function routeLabel(r: { action: string; profile?: string; fallback?: string[] }): string {
    if (r.action === 'direct') return 'Напрямую';
    if (r.action === 'block') return 'Заблокировать';
    const name = r.profile ? (isGroupId(r.profile) ? `${profileName(r.profile)} (группа)` : profileName(r.profile)) : mainText() || 'Основной сервер';
    // Fallbacks routing skips (struck through in the editor) do not count.
    const n = cleanFallback(r.fallback, r.profile, mainTarget()?.id).length;
    return n ? `${name} +${n} запасн.` : name;
  }

  function problem(r: Rule): string {
    if (r.action !== 'tunnel' || r.enabled === false) return '';
    if (!r.profile) return mainTarget() ? '' : 'Основной сервер не выбран: соединения будут отклоняться';
    if (isGroupId(r.profile)) {
      if (ui.status?.groupsNote) return 'Группы не загружены (groups.json): соединения будут отклоняться';
      const g = ui.groups.find((x) => x.id === r.profile);
      if (!g) return 'Группа удалена: соединения будут отклоняться. Выберите другую.';
      if (g.members.length === g.missing) return `В группе «${hide(g.name)}» нет серверов: соединения будут отклоняться`;
      return '';
    }
    const p = ui.profiles.find((x) => x.id === r.profile);
    if (!p) return 'Сервер удалён: соединения будут отклоняться. Выберите другой.';
    if (p.missing) return `Сервер «${hide(p.name)}» пропал из подписки. Выберите замену.`;
    return '';
  }

  const main = $derived(mainTarget());
</script>

<div class="page-wrap">
  <header class="row">
    <div class="grow">
      <h1>Правила</h1>
      <p class="muted sub">Что пускать через VPN, что напрямую, а что блокировать. Проверяются сверху вниз, срабатывает первое подходящее.</p>
    </div>
    {#if ui.expert || (ui.status?.ruleset?.count ?? 0) >= 2}
      <RulesetBar
        editing={editId}
        beforeSwitch={() => saving.then(() => {})}
        onedit={setEdit}
        onchanged={load}
        onerror={(m) => (error = m)}
        onview={(v) => (rsView = v)}
      />
    {/if}
    {#if ui.expert}<button onclick={() => (asText = true)} disabled={!s} title="Много правил сразу: весь список текстом или добавить пачкой"><Icon name="log" size={16} />Текстом</button>{/if}
    <button
      onclick={() => (wizard = true)}
      disabled={!s || !!editId}
      title={editId ? 'Пошагово настраивает включённый профиль правил: вернитесь к нему' : 'Все правила по шагам с объяснениями: сервисы, программы, сайты, блокировка, серверы'}
      ><Icon name="wand" size={16} />Пошагово</button
    >
    <button onclick={() => (picking = true)} disabled={!s}><Icon name="sparkles" size={16} />Шаблоны</button>
    <button class="primary" onclick={() => openEditor(-1, newRule(), 'Новое правило')} disabled={!s}><Icon name="plus" size={16} />Правило</button>
  </header>

  <Help id="rules" title="Что такое правила">
    <p>
      Правило говорит HyRoute, куда отправлять программу или сайт: <b>через VPN</b>, <b>напрямую</b> (как без VPN) или <b>заблокировать</b>.
      Например: «YouTube → через VPN», «Госуслуги → напрямую», «Реклама → блок».
    </p>
    <ul>
      <li>
        Проще всего настроить всё кнопкой <b>«Пошагово»</b>: HyRoute по очереди спросит про сервисы, программы, сайты, блокировку и серверы и
        объяснит каждый шаг. Отдельный сервис можно добавить кнопкой <b>«Шаблоны»</b>.
      </li>
      <li>Правила проверяются сверху вниз, и срабатывает первое подходящее. Порядок меняется стрелками справа или перетаскиванием.</li>
      <li><b>«Всё остальное»</b> внизу решает, куда идёт всё, что не подошло ни под одно правило.</li>
      <li>Сайт не открывается или идёт не туда? Внизу страницы есть <b>«Проверить адрес»</b>: введите сайт, и HyRoute покажет, какое правило сработало.</li>
    </ul>
  </Help>

  {#if editId}
    <div class="note warn edit-banner">
      <Icon name="eye" size={16} />
      <div class="grow">
        Вы правите профиль правил «{hide(editName)}» — он не включён. Изменения сохраняются в нём; соединения идут по «{hide(activeName)}».
      </div>
      <button onclick={activateEdited} disabled={!!editError}>Включить его</button>
      <button onclick={() => setEdit(null)}>Вернуться к «{hide(activeName)}»</button>
    </div>
    {#if editError}
      <div class="note error">Профиль не загружается: {hide(editError)}. Исправьте правила здесь — после сохранения его можно будет включить.</div>
    {:else if s?.warnings?.length}
      {@const n = s.warnings.length}
      <div class="note warn">
        В профиле {n} {plural(n, 'правило', 'правила', 'правил')} с удалёнными или пропавшими серверами: такие соединения будут отклоняться.
      </div>
    {/if}
  {:else if rsNote}
    <div class="note info">{rsNote.kind === 'on' ? `Профиль «${hide(rsNote.name)}» включён` : `Профиль правил «${hide(rsNote.name)}» удалён`}</div>
  {/if}

  {#if error}<div class="note error">{hide(error)}</div>{/if}

  {#if s}
    <div class="list">
      {#each s.rules as r, i (i + ':' + JSON.stringify(r))}
        {@const pr = problem(r)}
        {@const li = lint.filter((x) => x.index === i)}
        {@const more = Math.max(0, (r.apps?.length ?? 0) - 3) + Math.max(0, (r.domains?.length ?? 0) - 4)}
        <div
          class="rule card"
          class:off={r.enabled === false}
          class:over={dragOver === i && dragFrom !== i}
          role="listitem"
          ondragover={(e) => {
            e.preventDefault();
            dragOver = i;
          }}
          ondrop={(e) => {
            e.preventDefault();
            if (dragFrom != null && s === dragList) move(dragFrom, i);
            dragFrom = dragOver = null;
            dragList = null;
          }}
        >
          <span
            class="grip"
            draggable="true"
            role="button"
            tabindex="-1"
            title="Перетащите, чтобы изменить порядок"
            ondragstart={(e) => {
              dragFrom = i;
              dragList = s;
              e.dataTransfer?.setData('text/plain', String(i));
            }}
            ondragend={() => (dragFrom = dragOver = null)}><Icon name="grip" size={16} /></span
          >
          <label class="switch" title={r.enabled === false ? 'Выключено' : 'Включено'}>
            <input type="checkbox" checked={r.enabled !== false} onchange={() => toggle(i)} />
            <span></span>
          </label>
          <button class="body" onclick={() => openEditor(i, JSON.parse(JSON.stringify(r)), 'Правило')}>
            <span class="t ellipsis">{title(r)}</span>
            <span class="what">
              {#each (r.apps ?? []).slice(0, 3) as a}<span class="tag"><Icon name="app" size={12} />{appLabel(a.pattern)}</span>{/each}
              {#each (r.domains ?? []).slice(0, 4) as d}
                {@const il = itemLabel(d)}
                <span class="tag" class:geo={il?.geo} class:miss={!!il?.missing} title={il?.geo ? il.tip : hide(il?.tip)}
                  ><Icon name={il?.missing ? 'alert' : il?.geo ? 'database' : 'globe'} size={12} />{il?.geo ? siteLabel(d) : hide(siteLabel(d))}{#if il?.geo}<span
                      class="src">{il.kind}</span
                    >{/if}</span
                >
              {/each}
              {#if more}<span class="tag more">+{more}</span>{/if}
              {#if portsText(r)}<span class="tag" title={portsText(r)}>{portsText(r, 3)}</span>{/if}
            </span>
          </button>
          <Icon name="arrow" size={16} />
          <span class="pill {r.action}" title={routeLabel(r)}>{routeLabel(r)}</span>
          <div class="acts">
            <button class="icon" onclick={() => move(i, i - 1)} disabled={i === 0} title="Выше"><Icon name="up" size={16} /></button>
            <button class="icon" onclick={() => move(i, i + 1)} disabled={i === s.rules.length - 1} title="Ниже"><Icon name="down" size={16} /></button>
            <button class="icon danger" onclick={() => remove(i)} title="Удалить"><Icon name="trash" size={16} /></button>
          </div>
          {#if pr || li.length}
            <div class="problems">
              {#if pr}<span><Icon name="alert" size={14} /> {pr}</span>{/if}
              {#each li as x}<span class:info={x.severity === 'info'}><Icon name={x.severity === 'info' ? 'info' : 'alert'} size={14} /> {x.text}</span>{/each}
            </div>
          {/if}
        </div>
      {/each}

      {#if s.rules.length === 0}
        <div class="empty card">
          <Icon name="rules" size={28} />
          <div>
            <b>Правил пока нет.</b>
            <p class="muted">
              Проще всего начать с кнопки «Пошагово»: HyRoute по очереди спросит, что пускать через VPN, и объяснит каждый шаг. Ещё есть «Шаблоны»: там готовые схемы («через VPN только заблокированное в России») и сервисы (YouTube, Discord,
              ChatGPT…). Или создайте правило сами{ui.expert ? ', или вставьте сразу много кнопкой «Текстом»' : ''}.
            </p>
          </div>
        </div>
      {/if}

      <div class="rest card">
        <div class="grow">
          <b>Всё остальное</b>
          <div class="muted small">Трафик, для которого не подошло ни одно правило.</div>
        </div>
        <div class="seg">
          <button class:on={s.defaultAction === 'tunnel'} onclick={() => setDefault('tunnel', s!.defaultProfile ?? '')}>Через VPN</button>
          <button class:on={s.defaultAction === 'direct'} onclick={() => setDefault('direct')}>Напрямую</button>
          <button class:on={s.defaultAction === 'block'} onclick={() => setDefault('block')}>Блок</button>
        </div>
        {#if s.defaultAction === 'tunnel'}
          <select value={s.defaultProfile ?? ''} onchange={(e) => setDefault('tunnel', (e.currentTarget as HTMLSelectElement).value)}>
            <option value="">Основной{main ? ` — ${mainText(main)}` : ''}</option>
            <TargetOptions current={s.defaultProfile} />
          </select>
        {/if}
      </div>
      {#if s.defaultAction === 'tunnel'}
        <div class="rest-fb">
          <FallbackPicker value={s.defaultFallback ?? []} primary={s.defaultProfile ?? ''} onchange={setDefaultFallback} />
        </div>
      {/if}
    </div>

    <Explain current={() => (s ? cleanSettings(s, main?.id) : null)} />
  {/if}
</div>

{#if editing}
  <RuleEditor
    rule={editing.rule}
    title={editing.title}
    stale={staleFor(editing.token)}
    note={editing.lost ? 'Это правило изменили или удалили в другом месте. «Сохранить» добавит черновик как новое правило в конец списка.' : ''}
    onsave={saveRule}
    onclose={() => (editing = null)}
  />
{/if}

{#if schemeDialog}
  <RulesetDialog
    mode="create"
    view={schemeDialog.view}
    scheme={schemeDialog.scheme}
    beforeSwitch={() => saving.then(() => {})}
    onclose={() => (schemeDialog = null)}
    ondone={(res) => {
      schemeDialog = null;
      if (res?.switch) showSwitchResult(res.switch);
      else if (res) {
        const { id, name } = res.view;
        toast({ tone: 'ok', text: () => `Создан профиль правил «${hide(name)}»`, actions: [{ label: () => 'Открыть', run: () => setEdit(id) }] });
      }
      load();
    }}
  />
{/if}

{#if asText}
  <RulesText
    target={s?.ruleset ?? ''}
    rulesetName={editId ? editName : activeName}
    list={rsView}
    onclose={() => (asText = false)}
    onsaved={() => {
      asText = false;
      load();
    }}
  />
{/if}

{#if wizard}
  <div class="wizard">
    <div class="wtop">
      <b class="grow">Настройка правил по шагам</b>
      <button class="ghost" onclick={() => (wizard = false)}><Icon name="x" size={16} />Закрыть</button>
    </div>
    <RouteWizard
      onback={() => (wizard = false)}
      ondone={() => {
        wizard = false;
        load();
      }}
    />
  </div>
{/if}

{#if picking}
  <div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && (picking = false)}>
    <div class="dialog">
      <div class="row"><h2 class="grow">Шаблоны</h2><button class="icon" onclick={() => (picking = false)}><Icon name="x" /></button></div>
      <div class="base">
        <Icon name="database" size={16} />
        <div>
          Списки сайтов и адресов в шаблонах (<code>geosite:…</code>, <code>geoip:…</code>) берутся из базы правил <b>{geo.sourceName || '—'}</b>.
          <span class="muted">Сменить базу: «Настройки → Базы правил».</span>
        </div>
      </div>
      <div class="tscroll">
        <div class="tgroup">Готовые схемы — одной кнопкой</div>
        {#if ui.expert}<p class="muted small lead">Схему можно применить к текущим правилам или сохранить отдельным профилем правил, не трогая текущие.</p>{/if}
        <div class="schemes">
          {#each schemes as sc (sc.id)}
            {@const miss = missingLists(schemeTemplates(sc).flatMap((t) => t.domains))}
            <div class="tpl scheme">
              <b>{sc.name}</b><span class="muted small">{sc.hint}</span>
              {#if sc.source && sc.source !== geo.sources.find((x) => x.short === geo.sourceName)?.id}
                <span class="warn-t small"><Icon name="alert" size={12} /> рассчитана на базу {geo.sources.find((x) => x.id === sc.source)?.short ?? sc.source}: выберите её в «Настройки → Базы правил»</span>
              {:else if miss}<span class="warn-t small"><Icon name="alert" size={12} /> часть списков {miss}</span>{/if}
              <span class="row scheme-acts">
                <button onclick={() => useScheme(sc)}>Добавить к текущим</button>
                {#if ui.expert}<button onclick={() => schemeAsProfile(sc)}>Новым профилем</button>{/if}
              </span>
            </div>
          {/each}
        </div>
        <p class="muted small">
          Отдельные правила: откроется готовое правило, останется проверить, куда его направить. Списки сайтов берутся из базы правил и обновляются
          сами. У сервисов с программой два шаблона: «программа» ведёт через VPN весь её трафик, «сайт» — только сайт в браузере.
        </p>
        {#each tplGroups as g}
          <div class="tgroup">{g}</div>
          <div class="tpls">
            {#each templates.filter((t) => t.group === g) as t (t.id)}
              {@const miss = missingLists(t.domains)}
              <button
                class="tpl"
                onclick={() => {
                  picking = false;
                  openEditor(-1, ruleFromTemplate(t), `Новое правило: ${t.name}`);
                }}
              >
                <b>{t.name}</b><span class="muted small">{t.hint}</span>
                <span class="faint small mono">{[...(t.apps ?? []), ...t.domains].join(' ')}</span>
                {#if miss}<span class="warn-t small"><Icon name="alert" size={12} /> {miss}</span>{/if}
              </button>
            {/each}
          </div>
        {/each}
      </div>
    </div>
  </div>
{/if}

<style>
  .wizard { position: fixed; inset: 0; z-index: 30; background: var(--bg); display: flex; flex-direction: column; animation: fade 0.15s ease-out; }
  .wtop { display: flex; align-items: center; gap: 10px; padding: 14px 24px; font-size: 15px; }
  .page-wrap { display: grid; gap: 16px; max-width: 1000px; }
  header { align-items: flex-start; gap: 10px; }
  .sub { margin: 4px 0 0; }
  .list { display: grid; gap: 8px; }

  .rule { display: flex; align-items: center; gap: 10px; padding: 10px 12px; flex-wrap: wrap; }
  .rule.over { border-color: var(--accent); border-style: dashed; }
  .rule.off .body, .rule.off .pill { opacity: 0.45; }
  .grip { cursor: grab; color: var(--faint); display: grid; }
  .body { flex: 1; min-width: 0; flex-direction: column; align-items: flex-start; gap: 4px; background: none; padding: 2px 4px; text-align: left; }
  .body:hover:not(:disabled) { background: none; }
  .body:hover .t { color: var(--accent); }
  .t { font-weight: 600; max-width: 100%; }
  .what { display: flex; flex-wrap: wrap; gap: 4px; }
  .tag { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; padding: 1px 8px; border-radius: 999px; background: var(--surface-2); color: var(--muted); }
  .rule > :global(svg) { color: var(--faint); flex: none; }
  .acts { display: flex; gap: 0; }
  .problems { flex-basis: 100%; display: grid; gap: 2px; padding-left: 68px; font-size: 12.5px; color: var(--warn); }
  .problems span { display: flex; gap: 6px; align-items: center; }
  .problems span.info { color: var(--muted); }

  .switch { position: relative; width: 34px; height: 20px; flex: none; cursor: pointer; }
  .switch input { opacity: 0; width: 0; height: 0; position: absolute; }
  .switch span { position: absolute; inset: 0; border-radius: 10px; background: var(--surface-3); transition: background 0.15s; }
  .switch span::after { content: ''; position: absolute; top: 3px; left: 3px; width: 14px; height: 14px; border-radius: 50%; background: #fff; transition: transform 0.15s; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25); }
  .switch input:checked + span { background: var(--accent); }
  .switch input:checked + span::after { transform: translateX(14px); }

  .empty { display: flex; gap: 16px; align-items: center; color: var(--muted); }
  .empty b { color: var(--text); }
  .empty p { margin: 4px 0 0; }

  .rest-fb { padding: 6px 16px 0; }
  .rest { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-top: 6px; border-style: dashed; }

  .tpls { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .schemes { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 8px; }
  .scheme { border: 1.5px solid color-mix(in srgb, var(--accent) 35%, var(--border)); }
  .tgroup { font-size: 12px; font-weight: 650; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin: 14px 0 6px; }
  .tscroll { max-height: 64vh; overflow: auto; padding-right: 4px; }
  .base { display: flex; gap: 10px; align-items: flex-start; padding: 10px 12px; margin: 6px 0 4px; border-radius: var(--radius-sm); background: var(--accent-soft); font-size: 12.5px; }
  .base > :global(svg) { color: var(--accent); flex: none; margin-top: 1px; }
  .base code, .mono { font-family: var(--mono); font-size: 11px; }
  .warn-t { color: var(--warn); display: inline-flex; gap: 4px; align-items: center; }
  .tag.geo { color: var(--accent); background: var(--accent-soft); }
  .tag.miss { color: var(--warn); background: color-mix(in srgb, var(--warn) 12%, transparent); }
  .tag .src { font-size: 10.5px; opacity: 0.65; margin-left: 2px; }
  .tag .src::before { content: '· '; }
  .tpl { flex-direction: column; align-items: flex-start; gap: 2px; padding: 12px 14px; background: var(--surface-2); text-align: left; white-space: normal; }
  /* rulesets */
  div.tpl { display: flex; border-radius: var(--radius-sm); }
  .scheme-acts { margin-top: 8px; gap: 6px; }
  .scheme-acts button { background: var(--surface); padding: 5px 10px; font-size: 12.5px; }
  .scheme-acts button:hover:not(:disabled) { background: var(--surface-3); }
  .lead { margin: 0 0 8px; }
  .edit-banner { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .edit-banner > :global(svg) { flex: none; }
  .edit-banner button { background: var(--surface); }
</style>
