<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, toLists, cleanSettings, cleanFallback, type Settings, type Rule, type LintIssue } from '../api';
  import { ui, hide, profileName, mainProfile } from '../state.svelte';
  import Icon from './Icon.svelte';
  import RuleEditor from './RuleEditor.svelte';
  import FallbackPicker from './FallbackPicker.svelte';
  import Explain from './Explain.svelte';
  import RulesText from './RulesText.svelte';
  import { templates, ruleFromTemplate, schemes, applyScheme, schemeTemplates, type Scheme } from './templates';
  import { itemLabel, shortLabel, loadGeo, geo } from '../geo.svelte';

  let s = $state<Settings | null>(null);
  let error = $state('');
  let lint = $state<LintIssue[]>([]);
  let editing = $state<{ index: number; rule: Rule; title: string } | null>(null);
  let picking = $state(false);
  let asText = $state(false);
  let dragFrom = $state<number | null>(null);
  let dragOver = $state<number | null>(null);

  // Every change bumps edits; a load started before a newer change would
  // bring back the list without it.
  let edits = 0;
  let saving: Promise<unknown> = Promise.resolve();

  async function load() {
    const my = edits;
    try {
      const v = await api.Settings();
      if (my !== edits) return;
      v.rules = (v.rules ?? []).map(toLists);
      s = v;
      const l = await api.LintRules(cleanSettings(v, mainProfile()?.id));
      if (my === edits) lint = l;
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(() => {
    load();
    loadGeo();
  });

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
  // list is reloaded after the last one.
  async function persist(next: Settings) {
    error = '';
    s = next;
    const my = ++edits;
    const job = saving.then(() => api.SaveSettings(cleanSettings(next, mainProfile()?.id)));
    saving = job.catch(() => {});
    try {
      await job;
    } catch (e) {
      error = errText(e);
      throw e;
    } finally {
      if (my === edits) await load();
    }
  }

  function clone(): Settings {
    return JSON.parse(JSON.stringify(s));
  }

  async function saveRule(index: number, r: Rule) {
    const next = clone();
    if (index < 0) next.rules.push(r);
    else next.rules[index] = r;
    await persist(next);
    editing = null;
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
    next.defaultFallback = cleanFallback(next.defaultFallback, profile, mainProfile()?.id);
    persist(next).catch(() => {});
  }

  function setDefaultFallback(fb: string[]) {
    const next = clone();
    next.defaultFallback = fb;
    persist(next).catch(() => {});
  }

  function newRule(): Rule {
    return { name: '', apps: [], domains: [], action: 'tunnel', profile: '', protocol: '' };
  }

  function appLabel(p: string): string {
    return /[*?]/.test(p) ? p : (p.split('\\').pop() ?? p);
  }

  function siteLabel(d: string): string {
    return shortLabel(d);
  }

  // title of a rule without a name is made of its items: sites are masked in
  // Privacy mode as in the tags below (lists from the database are not).
  function title(r: Rule): string {
    if (r.name) return r.name;
    const a = (r.apps ?? []).map((x) => appLabel(x.pattern));
    const d = (r.domains ?? []).map((x) => (itemLabel(x)?.geo ? siteLabel(x) : hide(siteLabel(x))));
    return [...a, ...d].slice(0, 2).join(', ') + (a.length + d.length > 2 ? '…' : '') || 'Правило';
  }

  function routeLabel(r: { action: string; profile?: string; fallback?: string[] }): string {
    if (r.action === 'direct') return 'Напрямую';
    if (r.action === 'block') return 'Заблокировать';
    const name = r.profile ? profileName(r.profile) : hide(mainProfile()?.name ?? 'Основной сервер');
    // Fallbacks routing skips (struck through in the editor) do not count.
    const n = cleanFallback(r.fallback, r.profile, mainProfile()?.id).length;
    return n ? `${name} +${n} запасн.` : name;
  }

  function problem(r: Rule): string {
    if (r.action !== 'tunnel' || r.enabled === false) return '';
    if (!r.profile) return mainProfile() ? '' : 'Основной сервер не выбран: соединения будут отклоняться';
    const p = ui.profiles.find((x) => x.id === r.profile);
    if (!p) return 'Сервер удалён: соединения будут отклоняться. Выберите другой.';
    if (p.missing) return `Сервер «${hide(p.name)}» пропал из подписки. Выберите замену.`;
    return '';
  }

  const main = $derived(mainProfile());
</script>

<div class="page-wrap">
  <header class="row">
    <div class="grow">
      <h1>Правила</h1>
      <p class="muted sub">Что пускать через VPN, что напрямую, а что блокировать. Проверяются сверху вниз, срабатывает первое подходящее.</p>
    </div>
    <button onclick={() => (asText = true)} title="Много правил сразу: весь список текстом или добавить пачкой"><Icon name="log" size={16} />Текстом</button>
    <button onclick={() => (picking = true)}><Icon name="sparkles" size={16} />Шаблоны</button>
    <button class="primary" onclick={() => (editing = { index: -1, rule: newRule(), title: 'Новое правило' })}><Icon name="plus" size={16} />Правило</button>
  </header>

  {#if error}<div class="note error">{error}</div>{/if}

  {#if s}
    <div class="list">
      {#each s.rules as r, i (i + ':' + JSON.stringify(r))}
        {@const pr = problem(r)}
        {@const li = lint.filter((x) => x.index === i)}
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
            if (dragFrom != null) move(dragFrom, i);
            dragFrom = dragOver = null;
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
              e.dataTransfer?.setData('text/plain', String(i));
            }}
            ondragend={() => (dragFrom = dragOver = null)}><Icon name="grip" size={16} /></span
          >
          <label class="switch" title={r.enabled === false ? 'Выключено' : 'Включено'}>
            <input type="checkbox" checked={r.enabled !== false} onchange={() => toggle(i)} />
            <span></span>
          </label>
          <button class="body" onclick={() => (editing = { index: i, rule: JSON.parse(JSON.stringify(r)), title: 'Правило' })}>
            <span class="t ellipsis">{title(r)}</span>
            <span class="what">
              {#each (r.apps ?? []).slice(0, 3) as a}<span class="tag"><Icon name="app" size={12} />{appLabel(a.pattern)}</span>{/each}
              {#each (r.domains ?? []).slice(0, 4) as d}
                {@const il = itemLabel(d)}
                <span class="tag" class:geo={il?.geo} class:miss={!!il?.missing} title={il?.tip ?? ''}
                  ><Icon name={il?.missing ? 'alert' : il?.geo ? 'database' : 'globe'} size={12} />{il?.geo ? siteLabel(d) : hide(siteLabel(d))}{#if il?.geo}<span
                      class="src">{il.kind}</span
                    >{/if}</span
                >
              {/each}
              {#if (r.apps?.length ?? 0) + (r.domains?.length ?? 0) > 7}<span class="tag more">+{(r.apps?.length ?? 0) + (r.domains?.length ?? 0) - 7}</span>{/if}
              {#if r.protocol}<span class="tag">{r.protocol.toUpperCase()}</span>{/if}
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
              {#each li as x}<span><Icon name="alert" size={14} /> {x.text}</span>{/each}
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
              Проще всего начать с кнопки «Шаблоны»: там готовые схемы («через VPN только заблокированное в России») и сервисы (YouTube, Discord,
              ChatGPT…). Или создайте правило сами, или вставьте сразу много кнопкой «Текстом».
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
            <option value="">Основной{main ? ` — ${hide(main.name)}` : ''}</option>
            {#each ui.profiles as p (p.id)}<option value={p.id}>{hide(p.name)}</option>{/each}
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
  <RuleEditor rule={editing.rule} title={editing.title} onsave={(r) => saveRule(editing!.index, r)} onclose={() => (editing = null)} />
{/if}

{#if asText}
  <RulesText
    onclose={() => (asText = false)}
    onsaved={() => {
      asText = false;
      load();
    }}
  />
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
        <div class="schemes">
          {#each schemes as sc (sc.id)}
            {@const miss = missingLists(schemeTemplates(sc).flatMap((t) => t.domains))}
            <button class="tpl scheme" onclick={() => useScheme(sc)}>
              <b>{sc.name}</b><span class="muted small">{sc.hint}</span>
              {#if sc.source && sc.source !== geo.sources.find((x) => x.short === geo.sourceName)?.id}
                <span class="warn-t small"><Icon name="alert" size={12} /> рассчитана на базу {geo.sources.find((x) => x.id === sc.source)?.short ?? sc.source}: выберите её в «Настройки → Базы правил»</span>
              {:else if miss}<span class="warn-t small"><Icon name="alert" size={12} /> часть списков {miss}</span>{/if}
            </button>
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
                  editing = { index: -1, rule: ruleFromTemplate(t), title: `Новое правило: ${t.name}` };
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
</style>
