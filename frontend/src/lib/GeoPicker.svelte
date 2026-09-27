<script lang="ts">
  // Pick geosite:/geoip: categories: popular ones with descriptions, and a
  // search over every category of the downloaded databases.
  import { onMount } from 'svelte';
  import { api, type GeoCategory, type GeoInfo } from '../api';
  import { geo, loadGeo, missingText } from '../geo.svelte';
  import Icon from './Icon.svelte';

  let { chosen, onpick, onclose }: { chosen: string[]; onpick: (item: string) => void; onclose: () => void } = $props();

  let q = $state('');
  let info = $state<GeoInfo | null>(null);
  let found = $state<{ site: string[]; ip: string[] }>({ site: [], ip: [] });
  let seq = 0;

  onMount(async () => {
    await loadGeo();
    try {
      info = await api.GeoInfo();
    } catch {}
  });

  $effect(() => {
    const query = q.trim().toLowerCase().replace(/^geo(site|ip):/, '');
    const my = ++seq;
    if (!query) {
      found = { site: [], ip: [] };
      return;
    }
    Promise.all([api.GeoCategories('site', query), api.GeoCategories('ip', query)])
      .then(([site, ip]) => {
        if (my === seq) found = { site, ip };
      })
      .catch(() => {});
  });

  const item = (c: { kind: string; name: string }) => (c.kind === 'ip' ? 'geoip:' : 'geosite:') + c.name;
  const has = (s: string) => chosen.some((x) => x.toLowerCase() === s);

  const groups = $derived.by(() => {
    const query = q.trim().toLowerCase();
    const list = geo.popular.filter(
      (c) => !query || c.name.includes(query) || c.title.toLowerCase().includes(query) || c.hint.toLowerCase().includes(query),
    );
    const out: { name: string; items: GeoCategory[] }[] = [];
    for (const c of list) {
      let g = out.find((x) => x.name === c.group);
      if (!g) out.push((g = { name: c.group, items: [] }));
      g.items.push(c);
    }
    return out;
  });

  const extra = $derived.by(() => {
    const known = new Set(geo.popular.map((c) => item(c)));
    return [
      ...found.site.map((n) => ({ kind: 'site', name: n })),
      ...found.ip.map((n) => ({ kind: 'ip', name: n })),
    ].filter((c) => !known.has(item(c)));
  });

  const noData = $derived(info && !info.site && !info.ip);
</script>

<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="dialog picker">
    <div class="row">
      <h2 class="grow">Готовые списки сайтов и адресов</h2>
      <button class="icon" onclick={onclose}><Icon name="x" /></button>
    </div>
    <p class="muted small">
      Не нужно вспоминать все домены сервиса: список «YouTube» уже включает видео, превью и приложение. Списки обновляются сами.
    </p>
    {#if info}
      {@const src = info.sources.find((s) => s.id === info?.source)}
      <div class="base">
        <Icon name="database" size={16} />
        <div class="grow">
          Списки берутся из базы <b>{info.sourceName}</b>{src && src.name !== info.sourceName ? ` (${src.name})` : ''}. Одно и то же имя, например <code>geosite:youtube</code>, в разных
          базах может немного отличаться, а некоторых списков в базе может не быть: такие отмечены ниже.
          <span class="muted">Сменить базу: «Настройки → Базы правил».</span>
        </div>
      </div>
    {/if}
    {#if noData}
      <div class="note info small">
        Базы ещё не скачаны: HyRoute скачает их сам, как только вы сохраните правило со списком ({info?.sources.find((s) => s.id === info?.source)?.size ?? '≈ 30–90 МБ'}).
        Пока они качаются, правило не срабатывает. Локальная сеть работает без баз.
      </div>
    {/if}
    <input bind:value={q} placeholder="Поиск: youtube, telegram, реклама, ru-blocked…" />

    <div class="scroll">
      {#each groups as g (g.name)}
        <div class="group">{g.name}</div>
        <div class="grid">
          {#each g.items as c (item(c))}
            {@const id = item(c)}
            {@const miss = missingText(c)}
            <button class="cat" class:on={has(id)} class:miss={!!miss} onclick={() => !has(id) && onpick(id)} title={id}>
              <span class="top">
                <b>{c.title}</b>
                <span class="badge">{c.kind === 'ip' ? 'IP' : 'сайты'}</span>
                {#if has(id)}<Icon name="check" size={14} />{/if}
              </span>
              {#if c.hint}<span class="muted small">{c.hint}</span>{/if}
              {#if miss}<span class="warn-t small"><Icon name="alert" size={12} /> {miss}</span>{/if}
              <code>{id}</code>
            </button>
          {/each}
        </div>
      {/each}

      {#if extra.length}
        <div class="group">Все категории базы</div>
        <div class="list">
          {#each extra as c (item(c))}
            {@const id = item(c)}
            <button class="line" class:on={has(id)} onclick={() => !has(id) && onpick(id)}>
              <code>{id}</code>
              <span class="badge">{c.kind === 'ip' ? 'IP' : 'сайты'}</span>
              {#if has(id)}<Icon name="check" size={14} />{/if}
            </button>
          {/each}
        </div>
      {:else if q.trim() && groups.length === 0}
        <p class="muted small">Ничего не найдено{noData ? ': полный список категорий появится после скачивания баз' : ''}.</p>
      {/if}
    </div>

    <div class="actions"><button class="primary" onclick={onclose}>Готово</button></div>
  </div>
</div>

<style>
  .picker { width: min(760px, 94vw); display: flex; flex-direction: column; gap: 10px; max-height: 88vh; }
  .scroll { flex: 1; }
  .picker h2 { margin: 0; }
  .picker p { margin: 0; }
  .scroll { overflow: auto; min-height: 0; padding-right: 4px; }
  .group { font-size: 12px; font-weight: 650; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin: 12px 0 6px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 6px; }
  .cat { flex-direction: column; align-items: flex-start; gap: 3px; padding: 10px 12px; background: var(--surface-2); text-align: left; white-space: normal; border: 1.5px solid transparent; }
  .cat.on { border-color: var(--accent); background: var(--accent-soft); cursor: default; }
  .cat.miss { opacity: 0.75; }
  .warn-t { color: var(--warn); display: inline-flex; gap: 4px; align-items: center; }
  .base { display: flex; gap: 10px; align-items: flex-start; padding: 10px 12px; border-radius: var(--radius-sm); background: var(--accent-soft); font-size: 12.5px; }
  .base > :global(svg) { color: var(--accent); flex: none; margin-top: 1px; }
  .base code { font-family: var(--mono); font-size: 11.5px; }
  .top { display: flex; align-items: center; gap: 6px; width: 100%; }
  .top :global(svg) { margin-left: auto; color: var(--accent); }
  .cat code { font-family: var(--mono); font-size: 11px; color: var(--faint); }
  .list { display: grid; gap: 2px; }
  .line { justify-content: flex-start; gap: 8px; background: none; padding: 5px 8px; }
  .line:hover { background: var(--surface-2); }
  .line.on { color: var(--accent); }
  .line code { font-family: var(--mono); font-size: 12.5px; }
  .badge { font-size: 10.5px; padding: 0 6px; border-radius: 999px; background: var(--surface-3); color: var(--muted); font-weight: 500; }
</style>
