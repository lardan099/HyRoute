<script lang="ts">
  // A server group: its name, how it picks the server of a new connection
  // and its servers in order.
  import { api, errText, strategyLabel, type Group, type Strategy, type ProfileSummary } from '../api';
  import { ui, hide, serverLabel } from '../state.svelte';
  import Icon from './Icon.svelte';

  let { group, onclose, onsaved }: { group: Group; onclose: () => void; onsaved: () => void } = $props();

  // svelte-ignore state_referenced_locally
  let g = $state<Group>(JSON.parse(JSON.stringify(group)));
  // svelte-ignore state_referenced_locally
  let errorsOn = $state((group.switchAfterErrors ?? 0) > 0);
  // svelte-ignore state_referenced_locally
  let errorsN = $state(group.switchAfterErrors || 3);
  // svelte-ignore state_referenced_locally
  let tolerance = $state(group.toleranceMs || 50);
  let error = $state('');
  let saving = $state(false);
  let subSearch = $state<Record<string, string>>({});

  const strategies: { v: Strategy; d: string }[] = [
    { v: 'failover', d: 'Первый работающий сервер списка, остальные — запасные.' },
    { v: 'latency', d: 'Сервер с наименьшей задержкой.' },
    { v: 'roundrobin', d: 'Каждое новое соединение — через следующий сервер.' },
    { v: 'random', d: 'Каждое новое соединение — через случайный сервер.' },
    { v: 'sticky', d: 'Программа и сайт идут через один и тот же сервер, пока он работает. Для сайтов, которые не любят смену IP.' },
  ];

  const server = (id: string) => ui.profiles.find((p) => p.id === id);
  // svelte-ignore state_referenced_locally
  g.subs ??= [];
  const followed = (p: ProfileSummary) => !!p.source && g.subs!.includes(p.source.replace(/^sub:/, ''));
  // Servers not yet in the group, by subscription (manual ones last).
  const sources = $derived.by(() => {
    const out = new Map<string, { name: string; list: ProfileSummary[] }>();
    for (const p of ui.profiles) {
      if (g.members.includes(p.id) || followed(p)) continue;
      const key = p.source || '';
      if (!out.has(key)) out.set(key, { name: p.source ? hide(p.sourceName) : 'Добавленные вручную', list: [] });
      out.get(key)!.list.push(p);
    }
    return [...out.entries()].sort(([a], [b]) => (a === '' ? 1 : b === '' ? -1 : 0));
  });
  const subs = $derived(sources.filter(([k]) => k !== ''));

  function add(id: string) {
    if (id && !g.members.includes(id)) g.members.push(id);
  }

  // A subscription joins whole: its servers now and those it gets later.
  function addSub(source: string) {
    const id = source.replace(/^sub:/, '');
    if (!g.subs!.includes(id)) g.subs!.push(id);
    g.members = g.members.filter((m) => server(m)?.source !== source);
  }
  const subName = (id: string) => hide(ui.profiles.find((p) => p.source === 'sub:' + id)?.sourceName ?? 'подписка');
  const excluded = $derived(new Set(g.excluded));
  const subMembers = $derived.by(() => {
    const out = new Map<string, ProfileSummary[]>();
    const manual = new Set(g.members);
    for (const id of g.subs ?? []) out.set('sub:' + id, []);
    for (const p of ui.profiles) {
      if (!manual.has(p.id)) out.get(p.source)?.push(p);
    }
    return out;
  });
  const included = $derived([...subMembers.values()].flat().filter((p) => !excluded.has(p.id)));
  const total = $derived(g.members.length + included.length);
  const fastOpen = $derived([...g.members.map(server), ...included].filter((p): p is ProfileSummary => p?.fastOpen === true));

  function setIncluded(id: string, included: boolean) {
    if (included) g.excluded = (g.excluded ?? []).filter((x) => x !== id);
    else if (!excluded.has(id)) g.excluded = [...(g.excluded ?? []), id];
  }

  function move(i: number, by: -1 | 1) {
    const j = i + by;
    if (j < 0 || j >= g.members.length) return;
    [g.members[i], g.members[j]] = [g.members[j], g.members[i]];
  }

  async function save() {
    error = '';
    saving = true;
    const out: Group = { id: g.id, name: g.name.trim(), strategy: g.strategy, members: g.members, subs: g.subs ?? [], excluded: g.excluded };
    if (g.strategy === 'failover' && g.revert) out.revert = true;
    if (g.strategy === 'latency') out.toleranceMs = +tolerance;
    if (errorsOn) out.switchAfterErrors = +errorsN;
    try {
      await api.SaveGroup(out);
      onsaved();
    } catch (e) {
      error = errText(e);
    }
    saving = false;
  }

  // Only a click that starts on the backdrop closes the editor (see
  // RuleEditor).
  let downOnBackdrop = false;
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && !e.defaultPrevented && onclose()} />

<div
  class="backdrop"
  role="presentation"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && onclose()}
>
  <div class="dialog ed" role="dialog" aria-modal="true" aria-labelledby="ge-title">
    <div class="row">
      <h2 class="grow" id="ge-title">{group.id ? `Группа «${hide(group.name)}»` : 'Новая группа'}</h2>
      <button class="icon" onclick={onclose} title="Закрыть"><Icon name="x" /></button>
    </div>

    <label class="lbl" for="ge-name">Название</label>
    <!-- svelte-ignore a11y_autofocus -->
    <input id="ge-name" bind:value={g.name} placeholder="например, «Авто»" autofocus />

    <div class="lbl">Как выбирать сервер</div>
    <div class="strats" role="radiogroup">
      {#each strategies as s (s.v)}
        <div class="strat" class:on={g.strategy === s.v}>
          <input type="radio" id="ge-s-{s.v}" name="ge-strategy" value={s.v} bind:group={g.strategy} />
          <div class="grow">
            <label class="opt" for="ge-s-{s.v}"><b>{strategyLabel[s.v]}</b> — <span class="muted">{s.d}</span></label>
            {#if s.v === 'failover' && g.strategy === 'failover'}
              <label class="check sub"><input type="checkbox" bind:checked={g.revert} /> Возвращаться на первый, когда он снова работает (через 30 с)</label>
            {/if}
            {#if s.v === 'latency' && g.strategy === 'latency'}
              <label class="sub inline">Переключать, только если другой быстрее на <input type="number" min="10" max="1000" bind:value={tolerance} class="num" /> мс</label>
            {/if}
          </div>
        </div>
      {/each}
    </div>

    <label class="check">
      <input type="checkbox" bind:checked={errorsOn} /> Переключать после
      <input type="number" min="2" max="20" bind:value={errorsN} class="num" disabled={!errorsOn} /> ошибок подряд
    </label>
    <div class="hint">
      Если столько новых соединений подряд не открылись через сервер, группа минуту обходит его стороной, потом пробует одно соединение.
      {#if errorsOn && fastOpen.length}
        <div class="warn-t">
          У серверов с быстрым открытием (fastOpen) ошибки соединений не видны.
          {fastOpen.slice(0, 3).map((p) => `«${serverLabel(p)}»`).join(', ')}{fastOpen.length > 3 ? ` и ещё ${fastOpen.length - 3}` : ''}.
        </div>
      {/if}
    </div>

    <div class="lbl">Серверы группы</div>
    <div class="members">
      {#each g.members as id, i (id)}
        {@const p = server(id)}
        <div class="member">
          <span class="n">{i + 1}</span>
          <span class="grow ellipsis">{p ? serverLabel(p) : 'удалённый сервер'}</span>
          {#if p?.source}<span class="badge"><Icon name="rss" size={11} />{hide(p.sourceName)}</span>{/if}
          <button class="icon" onclick={() => move(i, -1)} disabled={i === 0} title="Выше"><Icon name="up" size={15} /></button>
          <button class="icon" onclick={() => move(i, 1)} disabled={i === g.members.length - 1} title="Ниже"><Icon name="down" size={15} /></button>
          <button class="icon danger" onclick={() => g.members.splice(i, 1)} title="Убрать из группы"><Icon name="x" size={15} /></button>
        </div>
      {/each}
      {#each g.subs ?? [] as id, i (id)}
        {@const members = subMembers.get('sub:' + id) ?? []}
        {@const skipped = members.filter((p) => excluded.has(p.id)).length}
        <div class="member sub">
          <span class="n"><Icon name="rss" size={11} /></span>
          <span class="grow ellipsis">«{subName(id)}» · {members.length - skipped} в группе</span>
          <button class="icon danger" onclick={() => g.subs!.splice(i, 1)} title="Убрать подписку из группы"><Icon name="x" size={15} /></button>
        </div>
        {#if members.length}
          <details class="subscription-members">
            <summary>Серверы подписки{skipped ? ` · исключено ${skipped}` : ''}</summary>
            {#if members.length > 10}
              <input type="search" bind:value={subSearch[id]} aria-label="Поиск по серверам подписки" placeholder="Поиск по серверам" />
            {/if}
            <div class="subscription-list">
              {#each members.filter((p) => hide(p.name).toLocaleLowerCase().includes((subSearch[id] ?? '').trim().toLocaleLowerCase())) as p (p.id)}
                <label class="check">
                  <input type="checkbox" checked={!excluded.has(p.id)} onchange={(e) => setIncluded(p.id, e.currentTarget.checked)} />
                  <span class="ellipsis" title={hide(p.name)}>{hide(p.name)}</span>
                </label>
              {:else}
                <span class="muted small">Совпадений нет</span>
              {/each}
            </div>
          </details>
        {/if}
      {/each}
      {#if g.members.length === 0 && !g.subs?.length}<p class="muted small">Серверов пока нет: добавьте хотя бы один или подписку.</p>{/if}
      <div class="row adds">
        {#if sources.length}
          <select
            value="__add"
            aria-label="Добавить сервер"
            onchange={(e) => {
              const el = e.currentTarget as HTMLSelectElement;
              add(el.value === '__add' ? '' : el.value);
              el.value = '__add';
            }}
          >
            <option value="__add" disabled>+ сервер</option>
            {#each sources as [key, src] (key)}
              <optgroup label={src.name}>
                {#each src.list as p (p.id)}<option value={p.id}>{hide(p.name)}{p.missing ? ' — нет в подписке' : ''}</option>{/each}
              </optgroup>
            {/each}
          </select>
        {/if}
        {#if subs.length}
          <select
            value="__add"
            aria-label="Добавить все серверы подписки"
            onchange={(e) => {
              const el = e.currentTarget as HTMLSelectElement;
              if (el.value !== '__add') addSub(el.value);
              el.value = '__add';
            }}
          >
            <option value="__add" disabled>+ подписка целиком…</option>
            {#each subs as [key, src] (key)}<option value={key}>{src.name}</option>{/each}
          </select>
        {/if}
      </div>
    </div>
    {#if total === 0 && g.subs?.length}
      <div class="hint">Сейчас в группе нет серверов. Новые серверы подписок добавятся автоматически.</div>
    {/if}
    <div class="hint">{g.strategy === 'failover' ? 'Порядок важен: сверху — первый.' : 'Порядок нужен только при равенстве.'}</div>
    {#if total > 10}
      <div class="note info small">
        Одновременно работают не больше 10 серверов группы — самые быстрые. Остальные HyRoute проверяет по очереди (по 4 за раз) и подменяет, если
        найдёт быстрее.
      </div>
    {/if}

    {#if error}<div class="note error">{hide(error)}</div>{/if}
    <div class="actions">
      <button onclick={onclose}>Отмена</button>
      <button class="primary" onclick={save} disabled={saving || !g.name.trim() || (g.members.length === 0 && !g.subs?.length)}>Сохранить</button>
    </div>
  </div>
</div>

<style>
  /* minmax(0, 1fr): a long server name must not widen the dialog past its
     width (a grid track grows to the longest unbreakable row otherwise). */
  .ed { width: min(680px, 94vw); display: grid; grid-template-columns: minmax(0, 1fr); gap: 8px; max-height: 92vh; overflow-y: auto; overflow-x: hidden; }
  .ed h2 { margin: 0; }
  .lbl { color: var(--muted); font-weight: 500; margin-top: 6px; }
  .strats { display: grid; gap: 4px; }
  .strat { display: flex; gap: 10px; align-items: flex-start; padding: 8px 10px; border-radius: var(--radius-sm); border: 1px solid var(--border); }
  .strat .opt { display: block; cursor: pointer; }
  .strat.on { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); background: var(--accent-soft); }
  .strat input[type='radio'] { margin-top: 3px; }
  .sub { display: flex; align-items: center; gap: 6px; margin-top: 6px; font-size: 13px; }
  .inline { flex-wrap: wrap; }
  .num { width: 72px; padding: 3px 6px; }
  .hint { font-size: 12px; color: var(--muted); }
  .warn-t { color: var(--warn); margin-top: 4px; }
  .members { display: grid; grid-template-columns: minmax(0, 1fr); gap: 4px; padding: 6px; border-radius: var(--radius-sm); background: var(--surface-2); }
  .member { display: flex; align-items: center; gap: 8px; min-width: 0; padding: 2px 4px 2px 8px; border-radius: var(--radius-sm); background: var(--surface); }
  .member .grow { min-width: 0; }
  .member .badge { flex: 0 1 auto; min-width: 0; max-width: 35%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .member button { flex: none; }
  .subscription-members { padding: 2px 8px 6px; }
  .subscription-members summary { cursor: pointer; color: var(--muted); font-size: 13px; }
  .subscription-members input[type='search'] { width: 100%; margin: 6px 0; }
  .subscription-list { display: grid; gap: 2px; max-height: 220px; overflow: auto; padding: 4px 0; }
  .subscription-list label { margin: 0; padding: 3px; min-width: 0; }
  .n { min-width: 20px; height: 20px; padding: 0 5px; box-sizing: border-box; border-radius: 10px; display: grid; place-items: center; font-size: 11px; background: var(--accent-soft); color: var(--accent); flex: none; }
  .adds { gap: 8px; flex-wrap: wrap; }
  .adds select { width: auto; max-width: 300px; }
  .danger { color: var(--block); }
  .muted.small { margin: 4px; }
</style>
