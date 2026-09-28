<script lang="ts">
  // The «Группы» tab of «Серверы»: server groups, the state of their
  // members and the latency probe.
  import { onMount } from 'svelte';
  import { api, errText, strategyLabel, type Group, type GroupMember, type GroupView, type GroupsInfo } from '../api';
  import { ui, hide, profileName } from '../state.svelte';
  import Icon from './Icon.svelte';
  import GroupEditor from './GroupEditor.svelte';

  let { onchange }: { onchange: () => void } = $props();

  let info = $state<GroupsInfo | null>(null);
  let error = $state('');
  let ok = $state('');
  let editing = $state<Group | null>(null);
  let probing = $state<Record<string, boolean>>({});
  // The probe settings as edited (loaded once, then the user's).
  let probeURL = $state('');
  let probeEvery = $state(60);
  let probeLoaded = false;
  let probeSaving = $state(false);

  async function load() {
    try {
      const v = await api.Groups();
      info = v;
      ui.groups = v.groups;
      if (!probeLoaded) {
        probeLoaded = true;
        probeURL = v.probe.url ?? '';
        probeEvery = v.probe.intervalSec || 60;
      }
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(() => {
    load();
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  });

  const online = $derived(ui.status != null && ui.status.state !== 'disconnected' && !(ui.status.state === 'error' && !ui.status.stats));
  // Edits are refused while groups.json or profiles.json did not load.
  const locked = $derived(!!info?.loadError || !!info?.serversBroken);

  async function run(f: () => Promise<unknown>, done = '') {
    error = '';
    ok = '';
    try {
      await f();
      ok = done;
    } catch (e) {
      error = errText(e);
    }
    await load();
    onchange();
  }

  function create() {
    editing = { id: '', name: '', strategy: 'latency', members: [] };
  }

  function edit(g: GroupView) {
    editing = { id: g.id, name: g.name, strategy: g.strategy, members: [...g.members], revert: g.revert, toleranceMs: g.toleranceMs, switchAfterErrors: g.switchAfterErrors };
  }

  function remove(g: GroupView) {
    let q = `Удалить группу «${hide(g.name)}»?`;
    if (g.main) q += info?.activeServer ? ` Основным снова станет сервер «${profileName(info.activeServer)}».` : ' Основного сервера не будет.';
    if (confirm(q)) run(() => api.DeleteGroup(g.id));
  }

  async function probe(g: GroupView) {
    probing[g.id] = true;
    error = '';
    try {
      const v = await api.ProbeGroup(g.id);
      if (info) info.groups = info.groups.map((x) => (x.id === v.id ? v : x));
    } catch (e) {
      error = errText(e);
    }
    probing[g.id] = false;
  }

  function saveProbe() {
    probeSaving = true;
    run(() => api.SetProbe({ url: probeURL.trim(), intervalSec: +probeEvery }), 'Настройки проверки сохранены').finally(() => (probeSaving = false));
  }

  const count = (g: GroupView) => g.members.length - g.missing;
  const current = (g: GroupView) => g.strategy === 'failover' || g.strategy === 'latency';

  function stateLine(g: GroupView): string {
    let s: string;
    if (!online) s = 'Не подключено';
    else if (!g.running) s = 'Не используется правилами';
    else if (current(g)) s = g.active ? `Сейчас: ${profileName(g.active)}` : 'Сейчас: нет доступных серверов';
    else s = `Доступно ${g.up} из ${count(g)}`;
    if (g.rejected > 0) s += ` · отклонено соединений: ${g.rejected}`;
    return s;
  }

  function dot(m: GroupMember): string {
    return m.state === 'connected' ? 'ok' : m.state === 'connecting' ? 'wait' : m.state === 'failed' ? 'bad' : '';
  }

  const at = (ms: number) => new Date(ms).toLocaleTimeString('ru-RU', { hour12: false });

  // What a member's chip says after its name, with its tooltip.
  function detail(m: GroupMember): { text: string; tip: string; bad?: boolean } {
    if (m.missing) return { text: 'удалён', tip: 'Сервера больше нет: он уберётся из группы при сохранении', bad: true };
    if (m.reason === 'trial') return { text: 'пробное соединение', tip: 'После ошибок группа пробует через сервер одно соединение' };
    if (m.reason === 'errors') return { text: `ошибки подряд: ${m.errors}`, tip: 'Новые соединения через сервер не открывались: группа обходит его стороной', bad: true };
    if (m.probeError) return { text: 'нет ответа', tip: hide(m.probeError), bad: m.reason === 'probe' };
    if (m.latencyMs > 0) return { text: `${m.latencyMs} мс`, tip: m.probeAt ? `последняя проверка: ${m.lastMs} мс, ${at(m.probeAt)}` : '' };
    if (m.state === 'stopped') return { text: 'не запущен', tip: '' };
    return { text: '', tip: '' };
  }

  const intervals = [
    { v: 30, l: 'каждые 30 с' },
    { v: 60, l: 'каждую минуту' },
    { v: 120, l: 'каждые 2 мин' },
    { v: 300, l: 'каждые 5 мин' },
    { v: 600, l: 'каждые 10 мин' },
  ];
</script>

<div class="groups">
  <div class="row top">
    <p class="muted grow sub">
      Группа сама выбирает сервер: самый быстрый, первый работающий, по кругу. Её можно указать в правилах, прокси и как основной сервер (★). Пока
      группа используется, работают все её серверы.
    </p>
    <button class="primary" onclick={create} disabled={ui.profiles.length === 0 || locked} title={ui.profiles.length === 0 ? 'Сначала добавьте сервер' : ''}
      ><Icon name="plus" size={16} />Создать группу</button
    >
  </div>

  {#if info?.loadError}
    <div class="note error">
      Группы не загружены: {hide(info.loadError)}. Файл не изменяется, пока вы его не исправите или не удалите. Пока он не загружен, серверы нельзя
      удалять, а подписки не удаляют пропавшие серверы.
    </div>
  {:else if info?.serversBroken}
    <div class="note warn">Серверы не загружены — группы не изменяются.</div>
  {/if}
  {#if error}<div class="note error">{hide(error)}</div>{/if}
  {#if ok}<div class="note ok">{ok}</div>{/if}

  {#if !info && !error}
    <p class="muted">Загрузка…</p>
  {:else if info && info.groups.length === 0 && !info.loadError}
    <div class="card empty">
      <Icon name="server" size={28} />
      <div>
        <b>Групп пока нет.</b>
        <p class="muted">Например, «Авто»: DE1, DE2 и NL1 — HyRoute будет отправлять новые соединения через самый быстрый из них.</p>
      </div>
    </div>
  {/if}

  {#each info?.groups ?? [] as g (g.id)}
    <section class="card grp" class:main={g.main}>
      <div class="row head">
        <button class="icon star" class:on={g.main} disabled={locked || g.main} onclick={() => run(() => api.SetMain(g.id))} title={g.main ? 'Основная группа' : 'Сделать основной'}>
          <Icon name="star" size={18} />
        </button>
        <div class="grow info">
          <div class="name-line">
            <span class="name ellipsis">{hide(g.name)}</span>
            <span class="badge">{strategyLabel[g.strategy]}</span>
            {#if g.switchAfterErrors}<span class="badge">после {g.switchAfterErrors} ошибок</span>{/if}
          </div>
          <div class="muted small">{hide(stateLine(g))}</div>
        </div>
        <button onclick={() => probe(g)} disabled={probing[g.id] || count(g) === 0} title="Измерить задержку через каждый сервер группы сейчас">
          <Icon name="zap" size={15} />{probing[g.id] ? 'Проверяю…' : 'Проверить'}
        </button>
        <div class="acts">
          <button class="icon" onclick={() => edit(g)} disabled={locked} title="Изменить"><Icon name="edit" size={16} /></button>
          <button class="icon danger" onclick={() => remove(g)} disabled={locked} title="Удалить"><Icon name="trash" size={16} /></button>
        </div>
      </div>
      {#if g.probeBroken}
        <div class="note warn small">
          Адрес проверки не отвечает ни через один сервер группы — задержка не измеряется, серверы из-за проверки не пропускаются. Проверьте адрес в
          «Проверка задержки».
        </div>
      {/if}
      <div class="members">
        {#each g.memberViews as m, i (m.id)}
          {@const d = detail(m)}
          <span class="chip" class:cur={current(g) && g.active === m.id} title={d.tip}>
            <span class="n">{i + 1}</span>
            <span class="dot {dot(m)}"></span>
            <span class="ellipsis">{m.missing ? 'удалённый сервер' : profileName(m.id)}</span>
            {#if d.text}<span class="d" class:bad={d.bad}>{d.text}</span>{/if}
            {#if m.state === 'connected' && !m.udp}<span class="d">без UDP</span>{/if}
          </span>
          {#if m.notInSub}
            <span class="chip warn-c" title="Сервер пропал из подписки и оставлен, чтобы группа не опустела. Он может не работать.">нет в подписке</span>
          {/if}
        {/each}
      </div>
      <div class="muted small ellipsis">
        {#if g.usedBy.length}Используют: {g.usedBy.map((u) => hide(u)).join(', ')}{:else}Не используется{/if}
      </div>
      {#if g.missing > 0}
        <div class="note info small">Серверов, которых больше нет: {g.missing}. Они уберутся из группы при сохранении.</div>
      {/if}
    </section>
  {/each}

  {#if info}
    <section class="card probe">
      <h2>Проверка задержки</h2>
      <div class="form">
        <label for="gp-url">Адрес</label>
        {#if ui.privacy && probeURL}
          <input id="gp-url" value={hide(probeURL)} disabled title="Скрыто: включено «Скрыть данные»" />
        {:else}
          <input id="gp-url" bind:value={probeURL} placeholder={info.defaultProbeURL} disabled={locked} />
        {/if}
        <label for="gp-every">Как часто</label>
        <select id="gp-every" bind:value={probeEvery} disabled={locked}>
          {#each intervals as it (it.v)}<option value={it.v}>{it.l}</option>{/each}
        </select>
      </div>
      <p class="muted small">
        Запрос идёт через каждый сервер используемых групп. Нужен адрес, который отвечает быстро и без содержимого, например …/generate_204.
      </p>
      <div class="row"><button onclick={saveProbe} disabled={locked || probeSaving || (ui.privacy && !!probeURL)}>Сохранить</button></div>
    </section>
  {/if}
</div>

{#if editing}
  <GroupEditor
    group={editing}
    onclose={() => (editing = null)}
    onsaved={() => {
      editing = null;
      run(async () => {});
    }}
  />
{/if}

<style>
  .groups { display: grid; gap: 12px; }
  .top { align-items: flex-start; gap: 12px; }
  .sub { margin: 0; }
  .grp { display: grid; gap: 8px; padding: 12px 14px; }
  .grp.main { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); }
  .head { gap: 12px; align-items: center; flex-wrap: wrap; }
  .info { display: grid; gap: 3px; min-width: 0; }
  .name-line { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; min-width: 0; }
  .name { font-weight: 650; font-size: 14.5px; }
  .star { color: var(--faint); }
  .star.on { color: var(--warn); }
  .star.on :global(svg) { fill: currentColor; }
  .acts { display: flex; }
  .danger { color: var(--block); }
  .members { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip { display: inline-flex; align-items: center; gap: 6px; max-width: 320px; padding: 3px 10px 3px 4px; border-radius: 999px; background: var(--surface-2); border: 1px solid var(--border); font-size: 13px; }
  .chip.cur { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
  .chip .n { width: 18px; height: 18px; border-radius: 50%; display: grid; place-items: center; font-size: 11px; background: var(--accent-soft); color: var(--accent); flex: none; }
  .chip .d { color: var(--muted); font-size: 12px; white-space: nowrap; }
  .chip .d.bad { color: var(--block); }
  .warn-c { color: var(--warn); padding-left: 10px; }
  .empty { display: flex; gap: 16px; align-items: center; color: var(--muted); }
  .empty b { color: var(--text); }
  .empty p { margin: 4px 0 0; }
  .probe h2 { margin-top: 0; }
  .form { display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 10px 12px; align-items: center; max-width: 640px; }
  .form > * { min-width: 0; }
  @media (max-width: 640px) {
    .form { grid-template-columns: 1fr; }
  }
</style>
