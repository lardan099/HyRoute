<script lang="ts">
  // The panel by the tray icon (cmd/hyroute/panel_windows.go): what is
  // changed most often, without the main window. A page of its own, in a
  // window process of its own: main.ts mounts it instead of App when the
  // window says it is the panel. It has no native <select> and no context
  // menu: their pop-ups belong to WebView2's process, and the panel closes
  // when another process takes the foreground.
  import { onMount } from 'svelte';
  import { api, errText, onEvent, isGroupId, type RulesetsView, type ZapretBrief } from '../api';
  import { ui, hide, applyTheme, serverLabel, serverSections } from '../state.svelte';
  import Icon from './Icon.svelte';

  const w = window as any;

  let rulesets = $state<RulesetsView | null>(null);
  let bypass = $state<ZapretBrief | null>(null);
  let open = $state<'' | 'server' | 'ruleset'>('');
  let busy = $state(false);
  let error = $state('');
  let loaded = $state(false);
  let root = $state<HTMLElement | null>(null);

  // The window is as tall as what is in it: the page tells it once there
  // is something to show, and again whenever that grows or shrinks (a
  // list opened, an error). The first call also shows the window.
  $effect(() => {
    const el = root;
    if (!el || !(loaded || error)) return;
    const fit = () => w.go?.main?.Bridge?.PanelFit?.(Math.ceil(el.getBoundingClientRect().height));
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  });

  const st = $derived(ui.status);
  const online = $derived(st != null && st.state !== 'disconnected' && !(st.state === 'error' && !st.stats));
  const tone = $derived.by(() => {
    if (!st || st.state === 'disconnected') return '';
    if (st.state === 'error' || st.state === 'tunnel-down' || st.killSwitch === 'blocking') return 'bad';
    if (st.state === 'starting' || st.state === 'connecting' || st.noTunnel) return 'wait';
    return 'ok';
  });
  const title = $derived.by(() => {
    if (!st) return 'Загрузка…';
    if (st.killSwitch === 'blocking') return 'Интернет закрыт kill switch';
    switch (st.state) {
      case 'disconnected':
        return 'Отключено';
      case 'starting':
        return 'Запуск…';
      case 'connecting':
        return 'Подключение…';
      case 'tunnel-down':
        return 'Сервер недоступен';
      case 'error':
        return 'Ошибка';
    }
    return st.noTunnel ? 'Включено, VPN не используется' : 'Подключено';
  });

  const mainId = $derived(st?.mainId ?? '');
  const mainName = $derived.by(() => {
    if (!mainId) return 'не выбран';
    if (isGroupId(mainId)) return 'Группа «' + hide(ui.groups.find((g) => g.id === mainId)?.name ?? '…') + '»';
    const p = ui.profiles.find((x) => x.id === mainId);
    return p ? serverLabel(p) : '…';
  });
  const servers = $derived(ui.profiles.length + ui.groups.length);
  const activeRuleset = $derived(rulesets?.list.find((r) => r.active)?.name ?? st?.ruleset?.name ?? '');
  const manyRulesets = $derived((rulesets?.list.length ?? 0) > 1 && !!rulesets?.saved);

  async function load() {
    try {
      const [status, profiles, groups, rs, z] = await Promise.all([api.Status(), api.Profiles(), api.Groups(), api.Rulesets(), api.ZapretBrief()]);
      ui.status = status;
      ui.profiles = profiles ?? [];
      ui.groups = groups?.groups ?? [];
      rulesets = rs;
      bypass = z;
      loaded = true;
    } catch (e) {
      error = errText(e);
    }
  }

  // run does what a click asked and reads everything anew; an error stays
  // in sight until the next click.
  async function run(f: () => Promise<unknown>) {
    if (busy) return;
    busy = true;
    error = '';
    try {
      await f();
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
      await load();
    }
  }

  function pick(kind: 'server' | 'ruleset') {
    open = open === kind ? '' : kind;
  }

  function close() {
    w.go?.main?.Bridge?.ClosePanel?.();
  }

  onMount(() => {
    applyTheme();
    load();
    const off = onEvent('status', load);
    // The bypass and the profiles change without a status event of their
    // own reaching a panel just opened: read again now and then.
    const t = setInterval(load, 4000);
    const key = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (open) open = '';
      else close();
    };
    const menu = (e: Event) => e.preventDefault();
    window.addEventListener('keydown', key);
    window.addEventListener('contextmenu', menu);
    return () => {
      off();
      clearInterval(t);
      window.removeEventListener('keydown', key);
      window.removeEventListener('contextmenu', menu);
    };
  });
</script>

<div class="tp" bind:this={root}>
  <div class="head">
    <span class="dot {tone}"></span>
    <b class="grow ellipsis">{title}</b>
    <button class="icon" onclick={close} title="Закрыть (Esc)"><Icon name="x" size={16} /></button>
  </div>
  {#if st?.message && st.state !== 'connected'}<div class="muted small msg">{hide(st.message)}</div>{/if}

  <button class="big" class:primary={!online} disabled={busy || !loaded} onclick={() => run(() => (online ? api.Disconnect() : api.Connect()))}>
    <Icon name="power" size={16} />{online ? 'Отключить' : 'Подключить'}
  </button>

  <div class="rows">
    <button class="line" onclick={() => pick('server')} disabled={servers < 2} aria-expanded={open === 'server'}>
      <span class="muted">Сервер</span>
      <span class="val ellipsis">{mainName}</span>
      {#if servers > 1}<Icon name={open === 'server' ? 'up' : 'down'} size={14} />{/if}
    </button>
    {#if open === 'server'}
      <div class="choices">
        {#each serverSections() as sec (sec.key)}
          {#if sec.title}<div class="sec muted small">{sec.title}</div>{/if}
          {#each sec.list as p (p.id)}
            <button class="choice" class:on={p.id === mainId} disabled={busy || (p.missing && p.id !== mainId)} onclick={() => run(() => api.SetMain(p.id)).then(() => (open = ''))}>
              <span class="ellipsis">{hide(p.name)}</span>{#if p.id === mainId}<Icon name="check" size={14} />{/if}
            </button>
          {/each}
        {/each}
        {#if ui.groups.length}
          <div class="sec muted small">Группы</div>
          {#each ui.groups as g (g.id)}
            <button class="choice" class:on={g.id === mainId} disabled={busy} onclick={() => run(() => api.SetMain(g.id)).then(() => (open = ''))}>
              <span class="ellipsis">{hide(g.name)}</span>{#if g.id === mainId}<Icon name="check" size={14} />{/if}
            </button>
          {/each}
        {/if}
      </div>
    {/if}

    {#if manyRulesets && rulesets}
      <button class="line" onclick={() => pick('ruleset')} aria-expanded={open === 'ruleset'}>
        <span class="muted">Профиль правил</span>
        <span class="val ellipsis">{hide(activeRuleset)}</span>
        <Icon name={open === 'ruleset' ? 'up' : 'down'} size={14} />
      </button>
      {#if open === 'ruleset'}
        <div class="choices">
          {#each rulesets.list as r (r.id)}
            <button class="choice" class:on={r.active} disabled={busy || !!r.error} title={r.error ? hide(r.error) : ''} onclick={() => run(() => api.SwitchRuleset(r.id)).then(() => (open = ''))}>
              <span class="ellipsis">{hide(r.name)}</span>{#if r.active}<Icon name="check" size={14} />{/if}
            </button>
          {/each}
        </div>
      {/if}
    {/if}

    {#if bypass?.Shown}
      <label class="line">
        <span class="muted">Обход DPI</span>
        <span class="val ellipsis" class:off={!bypass.Enabled}>{bypass.Enabled ? bypass.Targets.join(', ') : 'выключен'}</span>
        <span class="switch" title={bypass.Enabled ? 'Выключить обход' : 'Включить обход'}>
          <input type="checkbox" checked={bypass.Enabled} disabled={busy} onchange={() => run(() => api.SetZapretEnabled(!bypass!.Enabled))} />
          <span></span>
        </span>
      </label>
    {/if}
  </div>

  {#if error}<div class="note error small">{hide(error)}</div>{/if}

  <div class="foot">
    <button class="grow" onclick={() => api.PanelOpenWindow()}><Icon name="home" size={15} />Открыть HyRoute</button>
    <button class="icon" onclick={() => confirm('Выйти из HyRoute? Маршрутизация остановится.') && api.PanelQuit()} title="Выход"><Icon name="power" size={16} /></button>
  </div>
</div>

<style>
  :global(html), :global(body) { overflow: hidden; }
  .tp { display: flex; flex-direction: column; gap: 10px; padding: 12px; border: 1px solid var(--border); }
  .head { display: flex; align-items: center; gap: 8px; font-size: 15px; }
  .msg { margin-top: -4px; overflow-wrap: anywhere; }
  .big { justify-content: center; padding: 9px 12px; font-weight: 600; }
  .rows { display: grid; grid-template-columns: minmax(0, 1fr); gap: 2px; }
  .line { display: flex; align-items: center; gap: 8px; width: 100%; padding: 8px 8px; background: none; border-radius: var(--radius-sm); text-align: left; }
  button.line:hover:not(:disabled) { background: var(--surface-2); }
  .line:disabled { opacity: 1; cursor: default; }
  .line .val { flex: 1; min-width: 0; text-align: right; font-weight: 600; }
  .line .val.off { color: var(--muted); font-weight: 400; }
  label.line { cursor: pointer; }
  .choices { display: grid; gap: 1px; max-height: 240px; overflow-y: auto; margin: 0 0 4px; padding: 4px; background: var(--surface-2); border-radius: var(--radius-sm); }
  .choice { display: flex; align-items: center; justify-content: space-between; gap: 8px; width: 100%; padding: 6px 8px; background: none; border-radius: 6px; text-align: left; font-size: 13px; }
  .choice:hover:not(:disabled) { background: var(--surface-3); }
  .choice.on { color: var(--accent); font-weight: 600; }
  .sec { padding: 6px 8px 2px; }
  .foot { display: flex; gap: 6px; }
  .foot .grow { justify-content: center; }

  .switch { position: relative; width: 34px; height: 20px; flex: none; }
  .switch input { opacity: 0; width: 0; height: 0; position: absolute; }
  .switch span { position: absolute; inset: 0; border-radius: 10px; background: var(--surface-3); transition: background 0.15s; }
  .switch span::after { content: ''; position: absolute; top: 3px; left: 3px; width: 14px; height: 14px; border-radius: 50%; background: #fff; transition: transform 0.15s; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25); }
  .switch input:checked + span { background: var(--accent); }
  .switch input:checked + span::after { transform: translateX(14px); }
</style>
