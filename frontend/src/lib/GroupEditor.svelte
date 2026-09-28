<script lang="ts">
  // A server group: its name, how it picks the server of a new connection
  // and its servers in order.
  import { api, errText, strategyLabel, type Group, type Strategy, type ProfileSummary } from '../api';
  import { ui, hide } from '../state.svelte';
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

  const strategies: { v: Strategy; d: string }[] = [
    { v: 'failover', d: 'Первый работающий сервер списка, остальные — запасные.' },
    { v: 'latency', d: 'Сервер с наименьшей задержкой.' },
    { v: 'roundrobin', d: 'Каждое новое соединение — через следующий сервер.' },
    { v: 'random', d: 'Каждое новое соединение — через случайный сервер.' },
    { v: 'sticky', d: 'Программа и сайт идут через один и тот же сервер, пока он работает. Для сайтов, которые не любят смену IP.' },
  ];

  const server = (id: string) => ui.profiles.find((p) => p.id === id);
  // Servers not yet in the group, by subscription (manual ones last).
  const sources = $derived.by(() => {
    const out = new Map<string, { name: string; list: ProfileSummary[] }>();
    for (const p of ui.profiles) {
      if (g.members.includes(p.id)) continue;
      const key = p.source || '';
      if (!out.has(key)) out.set(key, { name: p.source ? hide(p.sourceName) : 'Добавленные вручную', list: [] });
      out.get(key)!.list.push(p);
    }
    return [...out.entries()].sort(([a], [b]) => (a === '' ? 1 : b === '' ? -1 : 0));
  });
  const subs = $derived(sources.filter(([k]) => k !== ''));
  const fastOpen = $derived(g.members.map(server).filter((p) => p?.fastOpen) as ProfileSummary[]);

  function add(id: string) {
    if (id && !g.members.includes(id)) g.members.push(id);
  }

  function addSub(source: string) {
    for (const p of ui.profiles) if (p.source === source) add(p.id);
  }

  function move(i: number, by: -1 | 1) {
    const j = i + by;
    if (j < 0 || j >= g.members.length) return;
    [g.members[i], g.members[j]] = [g.members[j], g.members[i]];
  }

  async function save() {
    error = '';
    saving = true;
    const out: Group = { id: g.id, name: g.name.trim(), strategy: g.strategy, members: g.members };
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
          У серверов с быстрым открытием (fastOpen) — {fastOpen.map((p) => `«${hide(p.name)}»`).join(', ')} — ошибки соединений не видны, для них это не
          сработает.
        </div>
      {/if}
    </div>

    <div class="lbl">Серверы группы</div>
    <div class="members">
      {#each g.members as id, i (id)}
        {@const p = server(id)}
        <div class="member">
          <span class="n">{i + 1}</span>
          <span class="grow ellipsis">{p ? hide(p.name) : 'удалённый сервер'}</span>
          {#if p?.source}<span class="badge"><Icon name="rss" size={11} />{hide(p.sourceName)}</span>{/if}
          <button class="icon" onclick={() => move(i, -1)} disabled={i === 0} title="Выше"><Icon name="up" size={15} /></button>
          <button class="icon" onclick={() => move(i, 1)} disabled={i === g.members.length - 1} title="Ниже"><Icon name="down" size={15} /></button>
          <button class="icon danger" onclick={() => g.members.splice(i, 1)} title="Убрать из группы"><Icon name="x" size={15} /></button>
        </div>
      {/each}
      {#if g.members.length === 0}<p class="muted small">Серверов пока нет: добавьте хотя бы один.</p>{/if}
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
            <option value="__add" disabled>+ все серверы подписки…</option>
            {#each subs as [key, src] (key)}<option value={key}>{src.name}</option>{/each}
          </select>
        {/if}
      </div>
    </div>
    <div class="hint">{g.strategy === 'failover' ? 'Порядок важен: сверху — первый.' : 'Порядок нужен только при равенстве.'}</div>
    {#if g.members.length > 10}
      <div class="note warn small">Каждый сервер группы — отдельный процесс Hysteria, пока группа используется.</div>
    {/if}

    {#if error}<div class="note error">{hide(error)}</div>{/if}
    <div class="actions">
      <button onclick={onclose}>Отмена</button>
      <button class="primary" onclick={save} disabled={saving || !g.name.trim() || g.members.length === 0}>Сохранить</button>
    </div>
  </div>
</div>

<style>
  .ed { width: min(680px, 94vw); display: grid; gap: 8px; max-height: 92vh; overflow: auto; }
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
  .members { display: grid; gap: 4px; padding: 6px; border-radius: var(--radius-sm); background: var(--surface-2); }
  .member { display: flex; align-items: center; gap: 8px; padding: 2px 4px 2px 8px; border-radius: var(--radius-sm); background: var(--surface); }
  .n { width: 20px; height: 20px; border-radius: 50%; display: grid; place-items: center; font-size: 11px; background: var(--accent-soft); color: var(--accent); flex: none; }
  .adds { gap: 8px; flex-wrap: wrap; }
  .adds select { width: auto; max-width: 300px; }
  .danger { color: var(--block); }
  .muted.small { margin: 4px; }
</style>
