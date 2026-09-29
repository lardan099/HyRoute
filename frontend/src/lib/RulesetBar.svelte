<script module lang="ts">
  import { api, errText, type SwitchResult } from '../api';
  import { hide } from '../state.svelte';
  import { toast } from '../toast.svelte';

  // switchDetail is the second line of a switch's toast, each name through
  // hide() (Go's note carries them unmasked).
  function switchDetail(res: SwitchResult): string {
    let s: string;
    if (!res.connected) s = 'Он начнёт действовать при подключении.';
    else if (!res.stopped.length) s = 'Новые соединения идут по его правилам, уже открытые — по прежнему профилю.';
    else {
      const shown = res.stopped.slice(0, 3).map((n) => `«${hide(n)}»`);
      const more = res.stopped.length - shown.length;
      s =
        `Новые соединения идут по его правилам, уже открытые — по прежнему профилю, кроме шедших через ${shown.join(', ')}${more > 0 ? ` и ещё ${more}` : ''}: ` +
        'этим серверам новый профиль не нужен, такие соединения закроются, и программы откроют их заново уже по нему.';
    }
    if (res.warnings.length) s += ' В нём есть правила с удалёнными или пропавшими серверами: такие соединения будут отклоняться.';
    if (res.connected) s += ' «Переподключить» откроет заново большинство открытых соединений уже по новому профилю.';
    return s;
  }

  // showSwitchResult tells what a switch did (the Rules page, Home).
  export function showSwitchResult(res: SwitchResult) {
    toast({
      tone: 'ok',
      text: () => `Включён профиль правил «${hide(res.ruleset.name)}»`,
      detail: () => switchDetail(res),
      actions: res.connected
        ? [
            {
              label: () => 'Переподключить',
              run: async () => {
                try {
                  await api.Reconnect();
                } catch (e) {
                  toast({ tone: 'error', text: () => hide(errText(e)) });
                }
              },
            },
          ]
        : [],
    });
  }

  // showRulesetError shows a refused switch or create.
  export function showRulesetError(e: unknown) {
    toast({ tone: 'error', text: () => hide(errText(e)) });
  }
</script>

<script lang="ts">
  // «Профиль: X ▾» on the Rules page: the rule profiles, switching, and
  // opening an inactive one for editing (edit mode is the page's).
  import { onMount, tick } from 'svelte';
  import { defaultLabel, plural, type CreateResult, type RulesetsView, type RulesetView } from '../api';
  import { ui, hideNet } from '../state.svelte';
  import Icon from './Icon.svelte';
  import RulesetDialog from './RulesetDialog.svelte';

  let {
    editing,
    beforeSwitch,
    onedit,
    onchanged,
    onerror,
    onview,
  }: {
    editing: string | null; // the profile the page edits without switching
    beforeSwitch: () => Promise<void>; // the page's queued saves
    onedit: (id: string | null) => void;
    onchanged: () => void;
    onerror: (msg: string) => void; // shown in the page's .note.error
    onview?: (v: RulesetsView) => void;
  } = $props();

  let view = $state<RulesetsView | null>(null);
  let open = $state(false);
  let busy = $state(false);
  let dialog = $state<{ mode: 'create' | 'duplicate' | 'rename'; source?: string } | null>(null);
  let root = $state<HTMLElement>();
  let toggleBtn = $state<HTMLButtonElement>();

  // One request at a time is enough: the latest answer wins.
  let seq = 0;
  async function load() {
    const my = ++seq;
    try {
      const v = await api.Rulesets();
      if (my !== seq) return;
      view = v;
      onview?.(v);
    } catch (e) {
      if (my === seq) onerror(errText(e));
    }
  }

  onMount(load);

  // Reload when the list changes elsewhere (its revision or the active
  // one), and when the rules change (the active row's counts).
  let seenRev = -1;
  let seenToken = '';
  let seenSettings = 0;
  $effect(() => {
    const r = ui.status?.ruleset;
    const s = ui.settingsRev;
    if (!r || (r.rev === seenRev && r.token === seenToken && s <= seenSettings)) return;
    const first = seenRev < 0;
    seenRev = r.rev;
    seenToken = r.token;
    seenSettings = s;
    if (!first) load();
  });

  const current = $derived(view?.list.find((r) => (editing ? r.id === editing : r.active)));

  function rowText(r: RulesetView): string {
    if (r.error) return `Не загружается: ${hide(r.error)}`;
    return `${r.rules} ${plural(r.rules, 'правило', 'правила', 'правил')} · остальное ${defaultLabel[r.defaultAction] ?? r.defaultAction}`;
  }

  async function toggleMenu() {
    open = !open;
    if (!open) return;
    load();
    await tick();
    (root?.querySelector('[role="menuitemradio"][aria-checked="true"]') as HTMLElement | null)?.focus();
  }

  function close(focusToggle = false) {
    open = false;
    if (focusToggle) toggleBtn?.focus();
  }

  // Esc closes; ↑/↓ move between the rows (Tab reaches the row buttons).
  function onMenuKey(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      close(true);
      return;
    }
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const rows = [...(root?.querySelectorAll<HTMLElement>('[role="menuitemradio"], [role="menuitem"]') ?? [])];
    if (!rows.length) return;
    const i = rows.indexOf(document.activeElement as HTMLElement);
    const next = e.key === 'ArrowDown' ? (i + 1) % rows.length : (i <= 0 ? rows.length : i) - 1;
    rows[next].focus();
  }

  function onWindowClick(e: MouseEvent) {
    if (open && root && !root.contains(e.target as Node)) close();
  }

  async function pick(r: RulesetView) {
    if (r.error) {
      onerror(r.newer ? `Профиль правил «${r.name}» создан более новой версией HyRoute: обновите HyRoute` : `Профиль правил «${r.name}» не загружается: ${r.error}`);
      close(true);
      return;
    }
    if (r.active) {
      close(true);
      if (editing) onedit(null);
      return;
    }
    close(true);
    busy = true;
    try {
      await beforeSwitch();
      showSwitchResult(await api.SwitchRuleset(r.id));
      onchanged();
    } catch (e) {
      showRulesetError(e);
    } finally {
      busy = false;
      load();
    }
  }

  async function run(what: () => Promise<void>) {
    try {
      await what();
      onchanged();
    } catch (e) {
      onerror(errText(e));
    }
    load();
  }

  function move(r: RulesetView, to: number) {
    run(() => api.MoveRuleset(r.id, to));
  }

  function remove(r: RulesetView) {
    let q = `Удалить профиль правил «${hide(r.name)}» и его правила (${r.rules})? Это не отменить.`;
    if (r.usedBy?.length) {
      // Network rule names are free text (often a Wi-Fi name): hideNet,
      // which hide()'s patterns do not cover.
      q += `\n\nИспользуется правилами сетей: ${r.usedBy.map((n) => `«${hideNet(n)}»`).join(', ')}. После удаления они не будут переключать профиль, пока вы не выберете другой.`;
    }
    if (!confirm(q)) return;
    close(true);
    run(() => api.DeleteRuleset(r.id));
  }

  function openDialog(mode: 'create' | 'duplicate' | 'rename', source?: string) {
    close();
    dialog = { mode, source };
  }

  function done(res: CreateResult | null) {
    dialog = null;
    if (res?.switch) showSwitchResult(res.switch);
    else if (res) {
      const name = res.view.name;
      const id = res.view.id;
      toast({ tone: 'ok', text: () => `Создан профиль правил «${hide(name)}»`, actions: [{ label: () => 'Открыть', run: () => onedit(id) }] });
    }
    onchanged();
    load();
  }
</script>

<svelte:window onclick={onWindowClick} />

<div class="rsbar" bind:this={root}>
  <button
    bind:this={toggleBtn}
    onclick={toggleMenu}
    aria-haspopup="menu"
    aria-expanded={open}
    title="Сохранённые наборы правил. Переключение действует сразу"
    disabled={busy}
  >
    {#if busy}
      <span class="spin"><Icon name="refresh" size={16} /></span>
    {:else}
      <Icon name={view?.error ? 'alert' : 'rules'} size={16} />
    {/if}
    {#if view?.error}
      Профиль: —
    {:else}
      Профиль: <b class="ellipsis">{hide(current?.name ?? ui.status?.ruleset?.name ?? 'Основной')}</b>{#if editing}&nbsp;(правка){/if}
    {/if}
    <Icon name="down" size={14} />
  </button>

  {#if open && view}
    <div class="menu" role="menu" tabindex="-1" onkeydown={onMenuKey}>
      {#if view.error}
        <div class="menu-error">{hide(view.error)}</div>
      {:else}
        {#each view.list as r, i (r.id || 'implicit')}
          <div class="item" class:current={editing ? r.id === editing : r.active} title={r.active && view.saved ? 'Активный профиль удалить нельзя' : ''}>
            <button
              class="main"
              role="menuitemradio"
              aria-checked={r.active}
              aria-disabled={!!r.error}
              onclick={() => pick(r)}
            >
              <span class="mark">{#if r.active}<Icon name="check" size={15} />{/if}</span>
              <span class="grow text">
                <span class="name ellipsis">{hide(r.name)}</span>
                <span class="sub ellipsis" class:bad={!!r.error}>{rowText(r)}</span>
              </span>
              {#if r.error}
                <span class="err" title={hide(r.error)}><Icon name="alert" size={15} /></span>
              {:else if r.warnings > 0}
                <span class="warn" title="Есть правила с удалёнными или пропавшими серверами: такие соединения будут отклоняться"><Icon name="alert" size={15} /></span>
              {/if}
            </button>
            <!-- Editing profiles is for the full interface; switching is for both. -->
            {#if ui.expert}<span class="acts">
              {#if view.saved}
                <button class="icon" title="Выше" disabled={i === 0} onclick={() => move(r, i - 1)}><Icon name="up" size={15} /></button>
                <button class="icon" title="Ниже" disabled={i === view.list.length - 1} onclick={() => move(r, i + 1)}><Icon name="down" size={15} /></button>
                {#if !r.active && !r.newer}
                  <button
                    class="icon"
                    title="Открыть без включения"
                    onclick={() => {
                      close();
                      onedit(r.id);
                    }}><Icon name="eye" size={15} /></button
                  >
                {/if}
                <button class="icon" title="Переименовать" onclick={() => openDialog('rename', r.id)}><Icon name="edit" size={15} /></button>
              {/if}
              {#if !r.newer}
                <button class="icon" title="Дублировать" onclick={() => openDialog('duplicate', r.id)}><Icon name="copy" size={15} /></button>
              {/if}
              {#if view.saved && !r.active}
                <button class="icon danger" title="Удалить" onclick={() => remove(r)}><Icon name="trash" size={15} /></button>
              {/if}
            </span>{/if}
          </div>
        {/each}
        {#if ui.expert}
          <div class="sep"></div>
          <button class="item new" role="menuitem" onclick={() => openDialog('create')}><Icon name="plus" size={15} />Новый профиль правил…</button>
        {/if}
      {/if}
    </div>
  {:else if open}
    <!-- The first list has not arrived yet. -->
    <div class="menu" role="menu" tabindex="-1" onkeydown={onMenuKey}>
      <div class="menu-loading muted"><span class="spin"><Icon name="refresh" size={15} /></span>Загрузка…</div>
    </div>
  {/if}
</div>

{#if dialog && view}
  <RulesetDialog mode={dialog.mode} source={dialog.source} {view} {beforeSwitch} onclose={() => (dialog = null)} ondone={done} />
{/if}

<style>
  .rsbar { position: relative; }
  .rsbar > button { max-width: 320px; }
  .rsbar > button b { max-width: 180px; display: inline-block; vertical-align: bottom; }
  .spin { display: inline-flex; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    z-index: 30;
    width: min(440px, 92vw);
    max-height: 70vh;
    overflow: auto;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow-lg);
    padding: 4px;
  }
  .item { display: flex; align-items: center; gap: 2px; border-radius: 6px; }
  .item:hover, .item:focus-within { background: var(--surface-2); }
  .item.current .name { font-weight: 650; }
  .main { flex: 1; min-width: 0; justify-content: flex-start; text-align: left; background: none; padding: 6px 8px; gap: 8px; }
  .main:hover:not(:disabled) { background: none; }
  .main[aria-disabled='true'] { cursor: default; }
  .mark { width: 15px; flex: none; display: inline-flex; color: var(--accent); }
  .text { display: grid; gap: 1px; }
  .name { max-width: 100%; }
  .sub { font-size: 12px; color: var(--muted); max-width: 100%; }
  .sub.bad { color: var(--block); }
  .warn { color: var(--warn); display: inline-flex; }
  .err { color: var(--block); display: inline-flex; }
  .acts { display: flex; opacity: 0; transition: opacity 0.1s; }
  .item:hover .acts, .item:focus-within .acts { opacity: 1; }
  .acts button { min-width: 28px; min-height: 28px; padding: 4px; }
  .sep { height: 1px; background: var(--border); margin: 4px 2px; }
  .new { width: 100%; justify-content: flex-start; background: none; padding: 8px 10px; }
  .new:hover:not(:disabled) { background: var(--surface-2); }
  .menu-error { color: var(--block); padding: 10px 12px; font-size: 13px; user-select: text; }
  .menu-loading { display: flex; align-items: center; gap: 8px; padding: 10px 12px; font-size: 13px; }
  @media (max-width: 700px) {
    .acts { opacity: 1; }
    .menu { right: auto; left: 0; }
  }
</style>
