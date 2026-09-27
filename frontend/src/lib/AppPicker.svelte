<script lang="ts">
  // Pick programs from the running ones: search by file name, description
  // or folder; programs with a window first.
  import { onMount } from 'svelte';
  import { api, type RunningApp } from '../api';
  import Icon from './Icon.svelte';

  let { chosen, onpick, onclose }: { chosen: string[]; onpick: (a: RunningApp) => void; onclose: () => void } = $props();

  let q = $state('');
  let all = $state(false);
  let list = $state<RunningApp[] | null>(null);
  let seq = 0;

  async function load() {
    const my = ++seq;
    try {
      const r = await api.RunningApps(q, all, 0);
      if (my === seq) list = r;
    } catch {
      if (my === seq) list = [];
    }
  }

  onMount(load);
  $effect(() => {
    q;
    all;
    load();
  });

  const has = (a: RunningApp) => chosen.some((x) => x.toLowerCase() === a.name.toLowerCase() || x.toLowerCase() === a.path.toLowerCase());
  const dir = (p: string) => p.slice(0, p.lastIndexOf('\\'));
</script>

<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="dialog picker">
    <div class="row">
      <h2 class="grow">Запущенные программы</h2>
      <button class="icon" onclick={load} title="Обновить список"><Icon name="refresh" /></button>
      <button class="icon" onclick={onclose}><Icon name="x" /></button>
    </div>
    <p class="muted small">
      Нажмите на программу, чтобы добавить её в правило. Она добавится по имени файла, поэтому правило переживёт обновления, которые меняют папку.
      Нужной программы нет — запустите её и обновите список, или выберите файл кнопкой «Обзор…».
    </p>
    <!-- svelte-ignore a11y_autofocus -->
    <input bind:value={q} autofocus placeholder="Поиск: telegram, discord, steam, chrome…" />
    <label class="check small"><input type="checkbox" bind:checked={all} /> Показывать фоновые программы Windows</label>

    <div class="scroll">
      {#if list === null}
        <p class="muted small">Загрузка…</p>
      {:else if list.length === 0}
        <p class="muted small">{q.trim() ? 'Ничего не найдено среди запущенных.' : 'Список пуст.'}</p>
      {:else}
        <div class="list">
          {#each list as a (a.path)}
            {@const on = has(a)}
            <button class="app" class:on onclick={() => !on && onpick(a)} title={a.path}>
              <span class="top">
                <b>{a.description || a.name.replace(/\.exe$/i, '')}</b>
                {#if a.windowed}<span class="badge">окно</span>{/if}
                {#if a.system}<span class="badge">Windows</span>{/if}
                {#if a.count > 1}<span class="badge">{a.count} процессов</span>{/if}
                {#if on}<Icon name="check" size={14} />{/if}
              </span>
              <span class="sub"><code>{a.name}</code> <span class="faint ellipsis">{dir(a.path)}</span></span>
            </button>
          {/each}
        </div>
      {/if}
    </div>

    <div class="actions"><button class="primary" onclick={onclose}>Готово</button></div>
  </div>
</div>

<style>
  .picker { width: min(700px, 94vw); display: flex; flex-direction: column; gap: 10px; max-height: 88vh; }
  .picker h2,
  .picker p { margin: 0; }
  .scroll { flex: 1; overflow: auto; min-height: 0; padding-right: 4px; }
  .list { display: grid; gap: 4px; }
  .app { flex-direction: column; align-items: stretch; gap: 3px; padding: 8px 12px; background: var(--surface-2); text-align: left; border: 1.5px solid transparent; }
  .app:hover { border-color: var(--border); }
  .app.on { border-color: var(--accent); background: var(--accent-soft); cursor: default; }
  .top { display: flex; align-items: center; gap: 6px; }
  .top :global(svg) { margin-left: auto; color: var(--accent); }
  .sub { display: flex; gap: 8px; min-width: 0; font-size: 12px; align-items: baseline; }
  .sub code { font-family: var(--mono); font-size: 12px; flex: none; }
  .badge { font-size: 10.5px; padding: 0 6px; border-radius: 999px; background: var(--surface-3); color: var(--muted); font-weight: 500; }
</style>
