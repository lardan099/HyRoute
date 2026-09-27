<script lang="ts">
  // Everything inside one geosite:/geoip: list, with a filter and paging.
  import { onMount } from 'svelte';
  import { api, errText, type GeoListing } from '../api';
  import { category } from '../geo.svelte';
  import Icon from './Icon.svelte';

  let { tag, onclose }: { tag: string; onclose: () => void } = $props();

  const kind = $derived<'site' | 'ip'>(tag.startsWith('geoip:') ? 'ip' : 'site');
  const name = $derived(tag.replace(/^geo(site|ip):/, ''));
  let filter = $state('');
  let data = $state<GeoListing | null>(null);
  let error = $state('');
  let copied = $state('');
  const page = 500;
  let seq = 0;

  async function load(more = false) {
    const my = ++seq;
    try {
      const l = await api.GeoList(kind, name, filter, more && data ? data.entries.length : 0, page);
      if (my !== seq) return;
      data = more && data ? { ...l, entries: [...data.entries, ...l.entries] } : l;
      error = '';
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(() => load());
  let timer: ReturnType<typeof setTimeout> | undefined;
  function onFilter() {
    clearTimeout(timer);
    timer = setTimeout(() => load(), 200);
  }

  async function copyAll() {
    try {
      const l = await api.GeoList(kind, name, filter, 0, 5000);
      await api.CopyText(l.entries.join('\n'));
      copied = l.matched > 5000 ? `Скопированы первые 5000 из ${l.matched}` : `Скопировано: ${l.entries.length}`;
    } catch (e) {
      error = errText(e);
    }
  }

  const title = $derived(category(kind, name)?.title);
</script>

<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="dialog viewer">
    <div class="row">
      <h2 class="grow"><code>{tag}</code>{#if title}<span class="muted">&nbsp;· {title}</span>{/if}</h2>
      <button class="icon" onclick={onclose}><Icon name="x" /></button>
    </div>
    <div class="row">
      <input class="grow" bind:value={filter} oninput={onFilter} placeholder={kind === 'ip' ? 'Фильтр: 149.154' : 'Фильтр: часть домена'} />
      <button onclick={copyAll}><Icon name="copy" size={15} />Копировать</button>
    </div>
    {#if data}
      <div class="muted small">
        {#if filter.trim()}Найдено {data.matched} из {data.total}{:else}Всего записей: {data.total}{/if}
        {#if kind === 'site'}· <code>domain:</code> — сайт и поддомены, <code>full:</code> — только этот адрес, <code>keyword:</code> — слово в имени{/if}
      </div>
      <div class="entries">
        {#each data.entries as e, i (i)}<div>{e}</div>{/each}
        {#if data.entries.length < data.matched}
          <button class="more" onclick={() => load(true)}>Показать ещё ({data.matched - data.entries.length})</button>
        {/if}
      </div>
    {/if}
    {#if error}<div class="note error">{error}</div>{/if}
    {#if copied}<div class="note ok small">{copied}</div>{/if}
  </div>
</div>

<style>
  .viewer { width: min(720px, 94vw); display: flex; flex-direction: column; gap: 10px; height: 82vh; }
  h2 { margin: 0; font-size: 16px; }
  h2 code, .small code { font-family: var(--mono); }
  .entries { flex: 1; overflow: auto; font-family: var(--mono); font-size: 12.5px; line-height: 1.6; background: var(--surface-2); border-radius: var(--radius-sm); padding: 8px 12px; user-select: text; }
  .more { margin: 8px 0; }
</style>
