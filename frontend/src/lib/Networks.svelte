<script lang="ts">
  // «Сети»: network rules. HyRoute connects, disconnects or switches the rule
  // profile when the computer moves to another network (internal/app/netmodes.go).
  import { onMount } from 'svelte';
  import {
    api,
    errText,
    onEvent,
    cleanNetModes,
    netActionText,
    netAt,
    netAdapterLabel,
    netCategoryLabel,
    netConnectLabel,
    netUnknownWarn,
    netUnknownRulesetNote,
    type NetConnect,
    type NetInfo,
    type NetModes,
    type NetModesView,
    type NetRule,
  } from '../api';
  import { ui, hide, hideNet, netText, settle } from '../state.svelte';
  import Icon from './Icon.svelte';
  import NetRuleEditor from './NetRuleEditor.svelte';

  let { go }: { go: (page: string) => void } = $props();

  let view = $state<NetModesView | null>(null);
  let loading = $state(true);
  let refreshing = $state(false);
  let error = $state('');
  let saved = $state('');
  let editing = $state<NetRule | null>(null);
  let applying = $state(false);

  // refresh: fresh=true reads the networks now (mount, «Обновить»), false
  // takes the loop's last read (status events).
  async function refresh(fresh: boolean) {
    if (fresh) refreshing = true;
    try {
      view = await api.NetModes(fresh);
    } catch (e) {
      error = errText(e);
    }
    loading = false;
    refreshing = false;
  }

  onMount(() => {
    refresh(true);
    // Status events come often: at most one cached read per 2 s.
    let last = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const off = onEvent('status', () => {
      if (timer) return;
      timer = setTimeout(
        () => {
          timer = undefined;
          last = Date.now();
          refresh(false);
        },
        Math.max(0, 2000 - (Date.now() - last)),
      );
    });
    return () => {
      off();
      clearTimeout(timer);
    };
  });

  const cfg = $derived(view?.config);
  const broken = $derived(!!view?.loadError);
  const active = $derived(view?.current.active ?? null);
  const names = $derived(cfg?.rules.map((r) => r.name) ?? []);
  const doneText = 'Сохранено. Сработает при следующей смене сети или по кнопке «Применить сейчас».';

  // Saves go one after another, each on the copy the one before returned.
  let chain: Promise<unknown> = Promise.resolve();
  function persist(edit: (c: NetModes) => void, throwErr = false): Promise<void> {
    const job = chain.then(async () => {
      if (!view) return;
      const next: NetModes = JSON.parse(JSON.stringify(view.config));
      edit(next);
      try {
        view = await api.SaveNetModes(cleanNetModes(next));
        error = '';
        saved = doneText;
      } catch (e) {
        if (throwErr) throw e;
        error = errText(e);
        saved = '';
        await refresh(false);
      }
    });
    chain = job.catch(() => {});
    return job;
  }

  // The checkbox goes through the same chain: a rule save answered after it
  // cannot bring back the old `enabled`.
  function setEnabled(on: boolean): Promise<void> {
    const job = chain.then(async () => {
      error = '';
      try {
        view = await api.SetNetModesEnabled(on);
        saved = on ? 'Правила сетей включены. Сработают при следующей смене сети или по кнопке «Применить сейчас».' : 'Правила сетей выключены.';
      } catch (e) {
        error = errText(e);
      }
    });
    chain = job.catch(() => {});
    return job;
  }

  function newRule(): NetRule {
    return { id: '', name: '', match: {}, connect: '' };
  }

  // «Создать правило для этой сети»: this network, and disconnect in a
  // private network, connect elsewhere. Only for a network Windows has
  // identified: the name of one it has not («Идентификация…») may be shared
  // by other networks.
  const forThisBlock = $derived(!active ? '' : !active.id || !active.identified ? 'Windows ещё не опознала эту сеть — подождите или нажмите «Обновить»' : '');
  function forThisNetwork() {
    const a = active;
    if (!a || forThisBlock) return;
    const r = newRule();
    r.match.networks = [{ id: a.id, name: a.name }];
    r.connect = a.category === 'private' ? 'disconnect' : 'connect';
    editing = r;
  }

  async function saveRule(r: NetRule, unknownConnect?: boolean) {
    await persist((c) => {
      const i = c.rules.findIndex((x) => r.id && x.id === r.id);
      if (i >= 0) c.rules[i] = r;
      else c.rules.push(r);
      if (unknownConnect) c.unknown.connect = 'connect';
    }, true);
    editing = null;
  }

  function toggleRule(r: NetRule, on: boolean) {
    return persist((c) => {
      const x = c.rules.find((y) => y.id === r.id);
      if (x) x.enabled = on ? undefined : false;
    });
  }

  function move(i: number, by: -1 | 1) {
    persist((c) => {
      const j = i + by;
      if (j < 0 || j >= c.rules.length) return;
      [c.rules[i], c.rules[j]] = [c.rules[j], c.rules[i]];
    });
  }

  function remove(r: NetRule) {
    if (!confirm(`Удалить правило сети «${hideNet(r.name)}»?`)) return;
    persist((c) => {
      c.rules = c.rules.filter((x) => x.id !== r.id);
    });
  }

  function setUnknown(part: 'connect' | 'ruleset', v: string) {
    return persist((c) => {
      if (part === 'connect') c.unknown.connect = v as NetConnect;
      else c.unknown.ruleset = v;
    });
  }

  // confirmOff asks before a rule that disconnects; the key of the confirmed
  // rule ('' = none to confirm, null = the user declined).
  function confirmOff(mt: NetModesView['match']): string | null {
    if (mt?.connect !== 'disconnect') return '';
    const name = mt.unknown ? 'Неизвестная сеть' : hideNet(mt.name);
    if (!confirm(`Правило «${name}» отключит HyRoute: весь трафик пойдёт напрямую, kill switch снимет блокировку. Продолжить?`)) return null;
    return mt.unknown ? 'unknown' : mt.ruleId;
  }

  async function apply() {
    let key = confirmOff(view?.match ?? null);
    if (key === null) return;
    applying = true;
    error = '';
    try {
      // The server decides on a fresh read: a disconnect other than the one
      // confirmed comes back unapplied with confirm set.
      for (let i = 0; i < 3; i++) {
        const v = await api.ApplyNetModes(key);
        view = v;
        if (!v.confirm) break;
        key = confirmOff(v.match);
        if (key === null) break;
      }
      saved = '';
    } catch (e) {
      error = errText(e);
    }
    applying = false;
  }

  function conditions(r: NetRule): string {
    const m = r.match;
    const parts: string[] = [];
    if (m.networks?.length) parts.push('Эта сеть: ' + m.networks.map((k) => hideNet(k.name) || 'без имени').join(', '));
    if (m.ssids?.length) parts.push('Wi-Fi: ' + m.ssids.map(hideNet).join(', '));
    if (m.names?.length) parts.push('Имя: ' + m.names.map(hideNet).join(', '));
    if (m.categories?.length) parts.push(m.categories.map((c) => netCategoryLabel[c]).join(', '));
    if (m.adapters?.length) parts.push(m.adapters.map((a) => netAdapterLabel[a]).join(', '));
    return parts.join(' · ');
  }

  const kindIcon = (n: NetInfo) => (n.adapter === 'wifi' ? 'wifi' : n.adapter === 'ethernet' ? 'server' : n.adapter === 'mobile' ? 'rss' : 'globe');
  const categoryText = (n: NetInfo) => (n.category ? netCategoryLabel[n.category] : 'не определён');

  const matchText = $derived.by(() => {
    const mt = view?.match;
    if (!mt) return '';
    if (!mt.connect && !mt.ruleset) return '— ничего не менять';
    const who = mt.unknown ? '«Неизвестная сеть»' : `«${hideNet(mt.name)}»`;
    const parts: string[] = [];
    if (mt.ruleset) {
      const rs = view?.rulesets?.find((x) => x.id === mt.ruleset);
      parts.push(rs ? `профиль правил «${hide(rs.name)}»` : 'профиль правил (удалён)');
    }
    if (mt.connect === 'connect') parts.push('подключить');
    if (mt.connect === 'disconnect') parts.push('отключить');
    return `${who}: ${parts.join(', ')}`;
  });

  const lastAt = $derived(netAt(view?.state));
  const unknownWarn = $derived(cfg ? netUnknownWarn(cfg) : null);
  const unknownRsNote = $derived(cfg ? netUnknownRulesetNote(cfg) : null);
  const unknownDeleted = $derived(!!cfg?.unknown.ruleset && view?.rulesets != null && !view.rulesets.some((x) => x.id === cfg.unknown.ruleset));
  const connects: NetConnect[] = ['', 'connect', 'disconnect'];
</script>

<div class="layout">
  <header class="row">
    <div class="grow">
      <h1>Сети</h1>
      <p class="muted sub">
        HyRoute сам подключается, отключается или переключает профиль правил, когда компьютер переходит в другую сеть. Правила проверяются сверху
        вниз, срабатывает первое подходящее. Правило срабатывает при смене сети и при запуске HyRoute. Если вы сами подключились, отключились или
        сменили профиль правил, это действует до следующей смены сети.
      </p>
    </div>
    {#if cfg}
      <label class="check big">
        <input type="checkbox" checked={cfg.enabled} disabled={broken} onchange={(e) => settle(e, (el) => setEnabled(el.checked), () => view?.config.enabled ?? false)} />
        Действовать по сети
      </label>
    {/if}
  </header>

  {#if error}<div class="note error">{netText(error, view?.state, names)}</div>{/if}
  {#if saved}<div class="note ok">{saved}</div>{/if}

  {#if loading && !view}
    <p class="muted">Загрузка…</p>
  {:else if view && cfg}
    {#if view.loadError}
      <div class="note error">
        networks.json не загружен: {netText(view.loadError, view.state, names)}. Правила сетей не действуют. Исправьте или удалите файл и перезапустите HyRoute.
      </div>
    {/if}
    {#if !view.available}
      <div class="note warn">Определение сети недоступно: {hide(view.unavailable)}</div>
    {:else if view.unavailable}
      <div class="note warn">{hide(view.unavailable)}</div>
    {/if}

    <section class="card">
      <div class="row">
        <h2 class="grow">Сейчас</h2>
        <button class="icon" onclick={() => refresh(true)} disabled={refreshing} title="Обновить" aria-label="Обновить"><Icon name="refresh" size={16} /></button>
      </div>
      {#if !active}
        <p class="muted">Нет подключения к сети.</p>
      {:else}
        <div class="netname"><Icon name={kindIcon(active)} size={18} /> <b>{hideNet(active.name) || 'Сеть без имени'}</b></div>
        <div class="kv">
          {#if active.adapter === 'wifi' && (active.ssid || active.ssidDenied)}
            <span class="k">Wi-Fi</span><span>{active.ssidDenied ? 'Windows не сообщает имя Wi-Fi' : hideNet(active.ssid)}</span>
          {/if}
          <span class="k">Тип сети</span><span>{categoryText(active)}</span>
          <span class="k">Подключение</span><span>{netAdapterLabel[active.adapter]} · {hideNet(active.adapterName)}</span>
          <span class="k">Подходит</span><span>{matchText}</span>
          <span class="k">Windows опознала сеть</span><span>{active.identified ? 'да' : 'ещё нет'}</span>
          {#if lastAt}
            <span class="k">Последнее действие</span>
            <span>
              {lastAt.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })} — {netText(view.state.text, view.state, names)}
              {#if view.state.error}<span class="err">{hide(netText(view.state.error, view.state, names))}</span>{/if}
            </span>
          {/if}
        </div>
      {/if}
      {#if view.state.override && !view.state.restored}
        <div class="note info small">Вы подключались, отключались или меняли профиль правил вручную — правила сетей снова сработают при смене сети.</div>
      {:else if view.state.restored}
        <div class="note info small">После обновления или переноса HyRoute вернул прежнее состояние — правила сетей снова сработают при смене сети.</div>
      {/if}
      {#if view.state.pending && cfg.enabled}
        <p class="muted small">Сеть определяется — отключение и смена профиля правил ждут, пока Windows её опознает.</p>
      {/if}
      {#if !cfg.enabled}<div class="note info small">Правила сетей выключены.</div>{/if}
      {#if view.current.error}
        <div class="note warn small">
          Не удалось определить сеть полностью: {hide(view.current.error)}. Правила с условиями, которые не удалось проверить, не сработают — действует
          «Неизвестная сеть».
        </div>
      {/if}
      {#if active?.ssidDenied && view.usesSSID}
        <div class="note warn small">
          Windows не даёт HyRoute имя Wi-Fi. В Windows 11 24H2 и новее включите «Параметры → Конфиденциальность и защита → Расположение → Разрешить
          классическим приложениям доступ к расположению». Пока HyRoute сравнивает имя Wi-Fi с именем сети в Windows.
        </div>
      {/if}
      <div class="row btns">
        <button onclick={forThisNetwork} disabled={broken || !active || !!forThisBlock} title={forThisBlock}>Создать правило для этой сети</button>
        <button class="primary" onclick={apply} disabled={broken || !cfg.enabled || !active || applying}>{applying ? 'Применяю…' : 'Применить сейчас'}</button>
        <button onclick={() => refresh(true)} disabled={refreshing}>Обновить</button>
      </div>
      {#if view.current.others?.length}
        <p class="faint small">
          Также подключено: {view.current.others.map((n) => `${hideNet(n.adapterName)}${n.name ? ' — «' + hideNet(n.name) + '»' : ''}`).join(', ')}
        </p>
      {/if}
    </section>

    <section class="card">
      <div class="row">
        <h2 class="grow">Правила сетей</h2>
        <button onclick={() => (editing = newRule())} disabled={broken}><Icon name="plus" size={16} />Добавить правило</button>
      </div>
      {#if cfg.rules.length === 0}
        <p class="muted small">Правил нет. Нажмите «Создать правило для этой сети», когда будете дома или в офисе.</p>
      {/if}
      <div class="rules">
        {#each cfg.rules as r, i (r.id)}
          <div class="rule" class:off={r.enabled === false}>
            <label class="switch" title={r.enabled === false ? 'Включить' : 'Выключить'}>
              <input type="checkbox" checked={r.enabled !== false} disabled={broken} onchange={(e) => settle(e, (el) => toggleRule(r, el.checked), () => view?.config.rules.find((x) => x.id === r.id)?.enabled !== false)} /><span></span>
            </label>
            <div class="grow">
              <div class="name">
                <b>{hideNet(r.name)}</b>
                {#if view.match && view.match.ruleId === r.id}<span class="badge now">сейчас</span>{/if}
                <span class="muted small">→ {hide(netActionText(r, view.rulesets))}</span>
              </div>
              <div class="muted small cond">{conditions(r)}</div>
              {#if view.ruleErrors?.[r.id]}<div class="err small">{hide(view.ruleErrors[r.id])}</div>{/if}
            </div>
            <button class="icon" onclick={() => move(i, -1)} disabled={broken || i === 0} title="Выше" aria-label="Выше"><Icon name="up" size={15} /></button>
            <button class="icon" onclick={() => move(i, 1)} disabled={broken || i === cfg.rules.length - 1} title="Ниже" aria-label="Ниже"><Icon name="down" size={15} /></button>
            <button class="icon" onclick={() => (editing = JSON.parse(JSON.stringify(r)))} disabled={broken} title="Изменить" aria-label="Изменить"><Icon name="edit" size={15} /></button>
            <button class="icon danger" onclick={() => remove(r)} disabled={broken} title="Удалить" aria-label="Удалить"><Icon name="trash" size={15} /></button>
          </div>
        {/each}
      </div>
    </section>

    <section class="card">
      <h2>Неизвестная сеть</h2>
      <p class="small">Если не подошло ни одно правило:</p>
      <div class="acts">
        <label for="nu-conn">Подключение</label>
        <select id="nu-conn" value={cfg.unknown.connect ?? ''} disabled={broken} onchange={(e) => settle(e, (el) => setUnknown('connect', el.value), () => view?.config.unknown.connect ?? '')}>
          {#each connects as c (c)}<option value={c}>{netConnectLabel[c]}</option>{/each}
        </select>
        {#if view.rulesets !== null}
          <label for="nu-rs">Профиль правил</label>
          <select id="nu-rs" value={cfg.unknown.ruleset ?? ''} disabled={broken} onchange={(e) => settle(e, (el) => setUnknown('ruleset', el.value), () => view?.config.unknown.ruleset ?? '')}>
            <option value="">Не менять</option>
            {#each view.rulesets as rs (rs.id)}<option value={rs.id}>{hide(rs.name)}</option>{/each}
            {#if unknownDeleted}<option value={cfg.unknown.ruleset} disabled>(удалён)</option>{/if}
          </select>
        {/if}
      </div>
      {#if view.ruleErrors?.unknown}<div class="err small">{hide(view.ruleErrors.unknown)}</div>{/if}
      {#if view.rulesets !== null && view.rulesets.length === 0 && view.rulesetsNote}
        <p class="muted small">
          {hide(view.rulesetsNote)}
          {#if !view.rulesetsNote.startsWith('Профили')}<button class="link" onclick={() => go('rules')}>Открыть «Правила»</button>{/if}
        </p>
      {/if}
      <p class="muted small">Сюда попадает и сеть, которую HyRoute не смог определить.</p>
      {#if unknownWarn}<div class="note warn small">{unknownWarn}</div>{/if}
      {#if unknownRsNote}<p class="muted small">{unknownRsNote}</p>{/if}
    </section>
  {/if}
</div>

{#if editing && view}
  <NetRuleEditor rule={editing} {view} onsave={saveRule} onclose={() => (editing = null)} />
{/if}

<style>
  .layout { display: grid; gap: 14px; max-width: 1000px; }
  .sub { margin: 4px 0 0; }
  header { align-items: flex-start; gap: 16px; }
  .big { font-weight: 600; white-space: nowrap; margin-top: 4px; }
  .netname { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; overflow-wrap: anywhere; }
  .netname :global(svg) { color: var(--accent); flex: none; }
  .kv { display: grid; grid-template-columns: 190px minmax(0, 1fr); gap: 4px 12px; }
  .kv > span { overflow-wrap: anywhere; }
  .k { color: var(--muted); }
  .err { display: block; color: var(--block); }
  .btns { margin-top: 12px; }
  .rules { display: grid; gap: 6px; }
  .rule { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: var(--radius-sm); background: var(--surface-2); }
  .rule.off { opacity: 0.65; }
  .name { display: flex; align-items: baseline; flex-wrap: wrap; gap: 4px 8px; overflow-wrap: anywhere; }
  .cond { overflow-wrap: anywhere; }
  .now { background: var(--accent-soft); color: var(--accent); }
  .danger { color: var(--block); }
  .acts { display: grid; grid-template-columns: 130px minmax(0, 1fr); gap: 8px 12px; align-items: center; max-width: 560px; }
  .acts select { width: 100%; }
  .switch { position: relative; width: 34px; height: 20px; flex: none; cursor: pointer; }
  .switch input { opacity: 0; width: 0; height: 0; position: absolute; }
  .switch span { position: absolute; inset: 0; border-radius: 10px; background: var(--surface-3); transition: background 0.15s; }
  .switch span::after { content: ''; position: absolute; top: 3px; left: 3px; width: 14px; height: 14px; border-radius: 50%; background: #fff; transition: transform 0.15s; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25); }
  .switch input:checked + span { background: var(--accent); }
  .switch input:checked + span::after { transform: translateX(14px); }
  .switch input:focus-visible + span { outline: 2px solid var(--accent); outline-offset: 2px; }
  @media (max-width: 720px) {
    header { flex-direction: column; }
    .kv, .acts { grid-template-columns: 1fr; }
    .k { margin-top: 4px; }
  }
</style>
