<script lang="ts">
  import { plural, type Flow } from '../api';
  import { hide } from '../state.svelte';
  import { flowFailed, flowState, overviewGroups } from './flowOverview';
  import Icon from './Icon.svelte';

  let { flows, selected, routeLabel, inspect, filtered }: {
    flows: Flow[]; selected: Flow | null; routeLabel: (f: Flow) => string;
    inspect: (f: Flow) => void; filtered: boolean;
  } = $props();

  function appKey(f: Flow) {
    return (f.path || f.process || `pid:${f.pid}`).toLowerCase();
  }
  const names: Record<string, string> = { chrome: 'Google Chrome', msedge: 'Microsoft Edge', msedgewebview2: 'Microsoft Edge WebView2', telegram: 'Telegram', discord: 'Discord', chatgpt: 'ChatGPT', codex: 'Codex', firefox: 'Firefox' };
  const tints: Record<string, string> = { Telegram: '#319acb', Discord: '#8585ec', 'Google Chrome': '#49a97b', Firefox: '#df915a' };
  function appName(f: Flow) {
    const base = hide(f.process.replace(/\.exe$/i, ''));
    return names[base.toLowerCase()] || base || `Процесс ${f.pid}`;
  }
  const conns = (n: number) => n + ' ' + plural(n, 'соединение', 'соединения', 'соединений');
  const apps = $derived.by(() => {
    const groups = new Map<string, { key: string; name: string; flows: Flow[]; errors: number }>();
    for (const f of flows) {
      const key = appKey(f);
      let app = groups.get(key);
      if (!app) { app = { key, name: appName(f), flows: [], errors: 0 }; groups.set(key, app); }
      app.flows.push(f);
      if (flowFailed(f)) app.errors++;
    }
    return [...groups.values()].sort((a,b) => a.name.localeCompare(b.name, 'ru') || a.key.localeCompare(b.key));
  });
  let picked = $state('');
  const current = $derived(apps.find(a => a.key === picked) ?? apps.find(a => selected && a.key === appKey(selected)) ?? apps[0]);
  let limit = $state(12);
  const entries = $derived(current ? [...overviewGroups(current.flows).values()] : []);
  const routes = $derived.by(() => {
    const counts = new Map<string, number>();
    for (const f of current?.flows ?? []) {
      const label = routeLabel(f);
      counts.set(label, (counts.get(label) ?? 0) + 1);
    }
    return [...counts].sort((a,b) => b[1] - a[1]);
  });
</script>

{#if current}
  <div class="workspace">
    <section class="apps" aria-label="Приложения">
      <h2>Приложения <small>{apps.length}</small></h2>
      <div class="applist">
        {#each apps as app (app.key)}
          <button class="app" class:chosen={current.key === app.key} aria-pressed={current.key === app.key}
            onclick={() => { picked = app.key; limit = 12; }}>
            <span class="glyph" style:--tint={tints[app.name] ?? 'var(--accent)'} aria-hidden="true">{app.name.slice(0, 1).toUpperCase()}</span>
            <span class="apptext"><strong>{app.name}</strong><small>{conns(app.flows.length)}</small></span>
            {#if app.errors}<span class="warning" title="Ошибок подключения: {app.errors}"><Icon name="alert" size={14}/>{app.errors}</span>{/if}
          </button>
        {/each}
      </div>
    </section>
    <section class="inspector" aria-label="Соединения приложения">
      <div class="intro"><h2>{current.name}</h2><span class="muted">{conns(current.flows.length)}</span></div>
      <h3>Маршруты</h3>
      <div class="routes">
        {#each routes as [label, count] (label)}
          <span class="route"><span>{label}</span><b>{count}</b></span>
        {/each}
      </div>
      <h3>Адреса и попытки</h3>
      <div class="endpoints">
        {#each entries.slice(0,limit) as entry}
          {@const f = entry.flow}
          <button class="endpoint" onclick={() => inspect(f)}>
            <span class="indicator" class:warning={flowFailed(f)}><Icon name={flowFailed(f) ? 'alert' : f.route === 'block' ? 'ban' : 'globe'} size={17}/></span>
            <span class="address"><strong>{hide(f.domain || f.dst) || 'Адрес неизвестен'}</strong><small>{flowState(f)} · {routeLabel(f)}</small></span>
            {#if entry.count > 1}<span class="repeat">×{entry.count}</span>{/if}
            <span class="open"><Icon name="arrow" size={15}/></span>
          </button>
        {/each}
      </div>
      {#if entries.length > limit}<button class="more" onclick={() => limit += 12}>Показать ещё {Math.min(12, entries.length - limit)}</button>{/if}
    </section>
  </div>
{:else}
  <p class="muted blank">{filtered ? 'По этому фильтру соединений нет.' : 'Здесь появятся приложения, когда они начнут подключаться.'}</p>
{/if}

<style>
  .workspace { flex:0 1 auto; min-height:0; display:grid; grid-template-columns:minmax(195px, 30%) minmax(0, 1fr); border:1px solid var(--border); border-radius:14px; overflow:hidden; background:var(--surface); }
  .apps, .inspector { overflow:auto; min-height:0; }
  .apps { padding:20px 10px; border-right:1px solid var(--border); }
  .apps h2 { display:flex; align-items:center; gap:9px; font-size:16px; margin:0 10px 16px; }
  .apps h2 small { font-size:12px; font-weight:500; color:var(--muted); }
  .applist { display:grid; gap:3px; }
  .app, .endpoint { width:100%; border:none; box-shadow:none; color:var(--text); background:transparent; text-align:left; display:flex; justify-content:flex-start; align-items:center; }
  .app { gap:11px; padding:11px 10px; border-radius:9px; }
  .app.chosen { background:var(--accent-soft); box-shadow:inset 3px 0 var(--accent); }
  .glyph { width:36px; height:36px; display:grid; place-items:center; flex:none; background:color-mix(in srgb, var(--tint) 18%, var(--surface)); color:color-mix(in srgb, var(--tint) 55%, var(--text)); border-radius:10px; font-size:16px; font-weight:650; }
  .apptext, .address { min-width:0; flex:1; display:grid; gap:3px; }
  strong { font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  small, .repeat, .open { color:var(--muted); font-size:12px; font-weight:400; }
  .warning { display:inline-flex; gap:4px; align-items:center; color:var(--warn); }
  .inspector { padding:24px clamp(16px, 2.5vw, 34px); }
  .intro { display:flex; align-items:baseline; gap:12px; flex-wrap:wrap; }
  .intro h2 { margin:0; font-size:24px; overflow-wrap:anywhere; }
  h3 { margin:22px 0 10px; font-size:14px; }
  .routes { display:flex; flex-wrap:wrap; gap:6px; }
  .route { display:inline-flex; align-items:center; gap:12px; padding:5px 9px; border:1px solid var(--border); border-radius:7px; font-size:12px; }
  .route b { color:var(--muted); font-variant-numeric:tabular-nums; }
  .endpoints { border-top:1px solid var(--border); }
  .endpoint { gap:12px; padding:12px 4px; border-radius:0; border-bottom:1px solid var(--border); }
  .indicator, .open { display:flex; }
  .indicator:not(.warning) { color:var(--muted); }
  .address small { overflow-wrap:anywhere; }
  .more { margin-top:12px; }
  .blank { padding:22px; }
  @media(max-width:780px) {
    .workspace { flex:1; display:flex; flex-direction:column; }
    .apps { flex:none; padding:12px; border-right:0; border-bottom:1px solid var(--border); }
    .apps h2 { margin:0 4px 8px; }
    .applist { display:flex; overflow-x:auto; }
    .app { width:auto; flex:none; max-width:230px; padding:7px; }
    .inspector { flex:1; padding:16px; }
  }
</style>
