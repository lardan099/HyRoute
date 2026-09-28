<script lang="ts">
  // A network rule («Сети»): the conditions on the network and what HyRoute
  // does there. In Privacy mode it opens read-only with the names masked.
  import { api, errText, netAdapterLabel, netCategoryLabel, netConnectLabel, type NetAdapter, type NetCategory, type NetConnect, type NetModesView, type NetRule } from '../api';
  import { ui, hide, hideNet } from '../state.svelte';
  import Icon from './Icon.svelte';

  let {
    rule,
    view,
    onsave,
    onclose,
  }: {
    rule: NetRule;
    view: NetModesView;
    // unknownConnect: the user chose to connect in other networks too (one
    // save with «Неизвестная сеть: подключить»).
    onsave: (r: NetRule, unknownConnect?: boolean) => Promise<void>;
    onclose: () => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  const start: NetRule = JSON.parse(JSON.stringify(rule));
  start.match.networks ??= [];
  start.match.ssids ??= [];
  start.match.names ??= [];
  start.match.categories ??= [];
  start.match.adapters ??= [];
  start.connect ??= '';
  start.ruleset ??= '';
  let r = $state<NetRule>(start);
  const m = $derived(r.match);

  let error = $state('');
  let saving = $state(false);
  let ssidInput = $state('');
  let nameInput = $state('');
  let ssidNote = $state('');
  let asking = $state(false);
  // The question before the first disconnect rule while «Неизвестная сеть»
  // does not change the connection.
  let prompt = $state(false);

  // Privacy mode: read-only until «Показать и редактировать», again once
  // Privacy mode is turned off and on.
  let revealed = $state(false);
  $effect(() => {
    if (!ui.privacy) revealed = false;
  });
  const ro = $derived(ui.privacy && !revealed);
  // What the dialog shows of a name: revealed → as is, else through hideNet.
  const shown = (s: string | undefined | null) => (revealed ? (s ?? '') : hideNet(s));

  const active = $derived(view.current.active);
  const hasCurrent = $derived(!!active?.id && (m.networks ?? []).some((k) => k.id.toUpperCase() === active!.id.toUpperCase()));
  const currentBlock = $derived.by(() => {
    if (!active) return 'Нет подключения к сети';
    if (!active.id || !active.identified) return 'Windows ещё не опознала эту сеть — подождите или нажмите «Обновить»';
    if (hasCurrent) return 'Эта сеть уже в списке';
    return '';
  });

  const categories: NetCategory[] = ['public', 'private', 'domain'];
  const adapters: NetAdapter[] = ['wifi', 'ethernet', 'mobile', 'other'];
  const connects: NetConnect[] = ['', 'connect', 'disconnect'];

  const deleted = $derived(!!r.ruleset && view.rulesets !== null && !view.rulesets.some((x) => x.id === r.ruleset));
  const empty = $derived(!m.networks?.length && !m.ssids?.length && !m.names?.length && !m.categories?.length && !m.adapters?.length);
  const nameOnly = $derived(r.connect === 'disconnect' && !m.networks?.length && !m.categories?.includes('domain'));
  const unknownKeeps = $derived(!view.config.unknown.connect);

  function addCurrent() {
    if (!active || currentBlock) return;
    r.match.networks = [...(m.networks ?? []), { id: active.id, name: active.name }];
  }

  function addTag(kind: 'ssids' | 'names', v: string) {
    if (kind === 'names') v = v.trim();
    if (!v) return;
    const list = r.match[kind] ?? [];
    const has = kind === 'names' ? list.some((x) => x.toLowerCase() === v.toLowerCase()) : list.includes(v);
    if (!has) r.match[kind] = [...list, v];
  }

  function removeAt<T>(list: T[] | undefined, i: number): T[] {
    const out = [...(list ?? [])];
    out.splice(i, 1);
    return out;
  }

  function toggleIn<T extends string>(list: T[] | undefined, v: T, on: boolean): T[] {
    const out = (list ?? []).filter((x) => x !== v);
    if (on) out.push(v);
    return out;
  }

  async function currentSSID() {
    asking = true;
    ssidNote = '';
    try {
      const s = await api.CurrentSSID();
      if (s) addTag('ssids', s);
      else ssidNote = 'Сейчас подключение не по Wi-Fi.';
    } catch (e) {
      ssidNote = errText(e);
    }
    asking = false;
  }

  function currentName() {
    if (active?.name) addTag('names', active.name);
  }

  async function save(unknownConnect?: boolean) {
    const firstDisconnect =
      r.connect === 'disconnect' &&
      unknownKeeps &&
      !view.config.rules.some((x) => x.id !== r.id && x.id !== '' && x.enabled !== false && x.connect === 'disconnect');
    if (unknownConnect === undefined && firstDisconnect) {
      prompt = true;
      return;
    }
    prompt = false;
    saving = true;
    error = '';
    try {
      await onsave($state.snapshot(r), unknownConnect);
    } catch (e) {
      error = errText(e);
    }
    saving = false;
  }

  function onKey(e: KeyboardEvent) {
    if (e.key !== 'Escape' || e.defaultPrevented) return;
    if (prompt) prompt = false;
    else onclose();
  }

  // Only a click that starts on the backdrop closes the editor.
  let downOnBackdrop = false;
</script>

<svelte:window onkeydown={onKey} />

<div
  class="backdrop"
  role="presentation"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && onclose()}
>
  <div class="dialog ed" role="dialog" aria-modal="true" aria-labelledby="nr-title">
    <div class="row">
      <h2 class="grow" id="nr-title">{rule.id ? 'Правило сети' : 'Новое правило сети'}</h2>
      <button class="icon" onclick={onclose} title="Закрыть"><Icon name="x" /></button>
    </div>

    {#if ro}
      <div class="note info row">
        <span class="grow">Включено «Скрыть данные»: имена сетей и Wi-Fi скрыты, правило открыто для просмотра.</span>
        <button onclick={() => (revealed = true)}>Показать и редактировать</button>
      </div>
    {/if}

    <label class="lbl" for="nr-name">Название</label>
    {#if ro}
      <div class="ro">{shown(r.name) || '—'}</div>
    {:else}
      <!-- svelte-ignore a11y_autofocus -->
      <input id="nr-name" bind:value={r.name} placeholder="Дом" autofocus />
    {/if}

    <div class="lbl">Условия</div>
    <p class="hint">Должны выполняться все заполненные условия; внутри одного условия подходит любое из значений.</p>

    <div class="cond">
      <div class="ch">Именно эта сеть</div>
      <div class="chips">
        {#each m.networks ?? [] as k, i (k.id)}
          <span class="chip">
            <Icon name="wifi" size={12} />{shown(k.name) || 'сеть без имени'}
            {#if !ro}<button class="x" onclick={() => (r.match.networks = removeAt(m.networks, i))} title="Убрать" aria-label="Убрать сеть"><Icon name="x" size={12} /></button>{/if}
          </span>
        {/each}
        <button class="mini" onclick={addCurrent} disabled={ro || !!currentBlock} title={currentBlock}>Добавить текущую</button>
      </div>
      <p class="hint">Windows узнаёт сеть по роутеру — так же, как решает, общедоступная она или частная. Надёжнее имени Wi-Fi.</p>
    </div>

    <div class="cond">
      <div class="ch">Имя Wi-Fi</div>
      <div class="chips">
        {#each m.ssids ?? [] as s, i (s)}
          <span class="chip"
            >{shown(s)}{#if !ro}<button class="x" onclick={() => (r.match.ssids = removeAt(m.ssids, i))} title="Убрать" aria-label="Убрать имя Wi-Fi"
                ><Icon name="x" size={12} /></button
              >{/if}</span
          >
        {/each}
        {#if !ro}
          <input
            class="tag"
            bind:value={ssidInput}
            placeholder="имя и Enter"
            aria-label="Имя Wi-Fi"
            onkeydown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                addTag('ssids', ssidInput);
                ssidInput = '';
              }
            }}
            onblur={() => {
              addTag('ssids', ssidInput);
              ssidInput = '';
            }}
          />
        {/if}
        <button class="mini" onclick={currentSSID} disabled={ro || asking}>{asking ? 'Спрашиваю…' : 'Текущее'}</button>
      </div>
      {#if ssidNote}<p class="hint warn-t">{hide(ssidNote)}</p>{/if}
      <p class="hint">
        Точное совпадение, с учётом регистра. Имя Wi-Fi может взять любая точка доступа. В Windows 11 запрос имени Wi-Fi считается доступом к
        расположению: HyRoute появится в «Недавней активности» расположения.
      </p>
    </div>

    <div class="cond">
      <div class="ch">Имя сети Windows</div>
      <div class="chips">
        {#each m.names ?? [] as s, i (s)}
          <span class="chip"
            >{shown(s)}{#if !ro}<button class="x" onclick={() => (r.match.names = removeAt(m.names, i))} title="Убрать" aria-label="Убрать имя сети"
                ><Icon name="x" size={12} /></button
              >{/if}</span
          >
        {/each}
        {#if !ro}
          <input
            class="tag"
            bind:value={nameInput}
            placeholder="имя и Enter"
            aria-label="Имя сети Windows"
            onkeydown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                addTag('names', nameInput);
                nameInput = '';
              }
            }}
            onblur={() => {
              addTag('names', nameInput);
              nameInput = '';
            }}
          />
        {/if}
        <button class="mini" onclick={currentName} disabled={ro || !active?.name}>Текущее</button>
      </div>
    </div>

    <div class="cond">
      <div class="ch">Тип сети</div>
      <div class="checks">
        {#each categories as c (c)}
          <label class="check"
            ><input
              type="checkbox"
              disabled={ro}
              checked={m.categories?.includes(c) ?? false}
              onchange={(e) => (r.match.categories = toggleIn(m.categories, c, e.currentTarget.checked))}
            />
            {netCategoryLabel[c]}</label
          >
        {/each}
      </div>
    </div>

    <div class="cond">
      <div class="ch">Подключение</div>
      <div class="checks">
        {#each adapters as a (a)}
          <label class="check"
            ><input
              type="checkbox"
              disabled={ro}
              checked={m.adapters?.includes(a) ?? false}
              onchange={(e) => (r.match.adapters = toggleIn(m.adapters, a, e.currentTarget.checked))}
            />
            {netAdapterLabel[a]}</label
          >
        {/each}
      </div>
    </div>
    {#if empty}<p class="hint">Укажите хотя бы одно условие.</p>{/if}

    <div class="lbl">Действие</div>
    <div class="acts">
      <label for="nr-conn">Подключение</label>
      <select id="nr-conn" bind:value={r.connect} disabled={ro}>
        {#each connects as c (c)}<option value={c}>{netConnectLabel[c]}</option>{/each}
      </select>
      {#if view.rulesets !== null}
        <label for="nr-rs">Профиль правил</label>
        <div>
          <select id="nr-rs" bind:value={r.ruleset} disabled={ro}>
            <option value="">Не менять</option>
            {#each view.rulesets as rs (rs.id)}<option value={rs.id}>{hide(rs.name)}</option>{/each}
            {#if deleted}<option value={r.ruleset} disabled>(удалён)</option>{/if}
          </select>
          {#if view.rulesets.length === 0 && view.rulesetsNote}<p class="hint">{hide(view.rulesetsNote)}</p>{/if}
        </div>
      {/if}
    </div>

    {#if r.connect === 'disconnect'}
      <div class="note warn small">
        Отключение по правилу сети — то же, что кнопка «Отключить»: весь трафик идёт напрямую, локальные прокси останавливаются, kill switch снимает
        блокировку.
      </div>
      {#if nameOnly}
        <div class="note warn small">
          Условие только по имени, типу или подключению может выполниться в чужой сети с тем же именем. Для отключения выберите «Именно эта сеть».
        </div>
      {/if}
      {#if unknownKeeps}
        <div class="note warn small">В других сетях HyRoute останется отключённым — весь трафик напрямую, пока «Неизвестная сеть» не меняет подключение.</div>
      {/if}
    {/if}
    {#if !r.connect && !r.ruleset}
      <p class="hint">Правило ничего не делает, но останавливает проверку правил ниже.</p>
    {/if}

    {#if prompt}
      <div class="note info ask" role="alertdialog" aria-labelledby="nr-ask">
        <b id="nr-ask">Подключать HyRoute в других сетях?</b>
        <p class="small">
          Сейчас «Неизвестная сеть» не меняет подключение: после этой сети HyRoute останется отключённым в кафе, гостинице и любой другой сети.
        </p>
        <div class="row">
          <!-- svelte-ignore a11y_autofocus -->
          <button class="primary" onclick={() => save(true)} disabled={saving} autofocus>Подключать</button>
          <button onclick={() => save(false)} disabled={saving}>Оставить как есть</button>
        </div>
      </div>
    {/if}

    {#if error}<div class="note error">{hide(error)}</div>{/if}
    <div class="actions">
      <button onclick={onclose}>Отмена</button>
      <button class="primary" onclick={() => save()} disabled={ro || saving || empty}>Сохранить</button>
    </div>
  </div>
</div>

<style>
  .ed { width: min(680px, 94vw); display: grid; gap: 8px; max-height: 92vh; overflow: auto; }
  .ed h2 { margin: 0; }
  .lbl { color: var(--muted); font-weight: 500; margin-top: 6px; }
  .ro { padding: 6px 0; }
  .hint { font-size: 12px; color: var(--muted); margin: 0; }
  .warn-t { color: var(--warn); }
  .cond { display: grid; gap: 6px; padding: 10px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border); }
  .ch { font-weight: 600; }
  .chips { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
  .chip { display: inline-flex; align-items: center; gap: 4px; padding: 2px 4px 2px 10px; border-radius: 999px; background: var(--surface-2); font-size: 13px; max-width: 100%; overflow-wrap: anywhere; }
  .chip .x { padding: 2px; min-width: 0; min-height: 0; background: transparent; border-radius: 50%; }
  .tag { width: 160px; padding: 4px 8px; }
  .mini { padding: 4px 10px; font-size: 12.5px; }
  .checks { display: flex; flex-wrap: wrap; gap: 6px 18px; }
  .acts { display: grid; grid-template-columns: 130px minmax(0, 1fr); gap: 8px 12px; align-items: center; }
  .acts select { width: 100%; }
  .ask { display: grid; gap: 6px; }
  .ask p { margin: 0; }
  .note { margin: 0; }
  @media (max-width: 640px) {
    .acts { grid-template-columns: 1fr; }
  }
</style>
