<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, errText, fmtTime, type LogEntry } from '../api';
  import { ui, hide } from '../state.svelte';

  // engine | hysteria (every server) | hysteria:<profile id>
  let source = $state('engine');
  const journal = $derived(source);
  $effect(() => {
    journal;
    gen++;
    lines = [];
    last = 0;
    poll();
  });

  const MAX = 10000;
  let lines = $state<LogEntry[]>([]);
  let last = 0;
  let level = $state('info');
  let query = $state('');
  let follow = $state(true);
  let error = $state('');
  let info = $state('');
  let box: HTMLDivElement | undefined = $state();

  const rank: Record<string, number> = { debug: 0, info: 1, warn: 2, warning: 2, error: 3, fatal: 4 };

  let polling = false;
  // gen counts source switches. An answer asked for before a switch is
  // dropped even if the source is back (A→B→A): it continues the old last,
  // and taking it would skip everything the new view has not loaded yet.
  let gen = 0;
  async function poll() {
    if (polling) return;
    polling = true;
    try {
      const g = gen;
      const add = (await api.Logs(journal, last)) ?? [];
      if (g !== gen) return;
      if (add.length) {
        last = add[add.length - 1].seq;
        const next = lines.concat(add);
        lines = next.length > MAX ? next.slice(next.length - MAX) : next;
        if (follow) {
          await tick();
          box?.scrollTo({ top: box.scrollHeight });
        }
      }
      error = '';
    } catch (e) {
      error = errText(e);
    } finally {
      polling = false;
    }
  }

  onMount(() => {
    const t = setInterval(poll, 1000);
    return () => clearInterval(t);
  });

  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const min = rank[level] ?? 0;
    return lines.filter((l) => (rank[l.level] ?? 1) >= min && (!q || l.msg.toLowerCase().includes(q)));
  });

  function lineText(l: LogEntry): string {
    return `${fmtTime(l.time)} ${l.level.toUpperCase().padEnd(5)} ${hide(l.msg)}`;
  }

  // Ctrl+A inside the log selects the log only, not the whole window.
  function onKey(e: KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && (e.code === 'KeyA' || e.key.toLowerCase() === 'a') && box) {
      e.preventDefault();
      e.stopPropagation();
      const r = document.createRange();
      r.selectNodeContents(box);
      const sel = window.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(r);
    }
  }

  async function copyAll() {
    info = '';
    try {
      await api.CopyText(shown.map(lineText).join('\r\n'));
      info = `Скопировано строк: ${shown.length}`;
    } catch (e) {
      error = errText(e);
    }
  }

  let choosing = $state(false);

  async function save(sanitized: boolean) {
    info = '';
    choosing = false;
    try {
      const p = await api.SaveLog(journal, sanitized);
      if (p) info = 'Сохранено: ' + p;
    } catch (e) {
      error = errText(e);
    }
  }
</script>

<div class="wrap">
  <header>
    <h1>Журнал</h1>
    <p class="muted sub">Что делают HyRoute и серверы Hysteria. Пригодится, если что-то не работает.</p>
  </header>
  <div class="row">
    <select bind:value={source} title="Чей журнал">
      <option value="engine">HyRoute</option>
      <option value="hysteria">Hysteria — все серверы</option>
      {#each ui.profiles as p (p.id)}<option value={'hysteria:' + p.id}>Hysteria — {hide(p.name)}</option>{/each}
    </select>
    <select bind:value={level}>
      <option value="debug">Все уровни</option>
      <option value="info">Info и выше</option>
      <option value="warn">Предупреждения и ошибки</option>
      <option value="error">Только ошибки</option>
    </select>
    <input class="grow" placeholder="Поиск" bind:value={query} />
    <label class="check"><input type="checkbox" bind:checked={follow} /> автопрокрутка</label>
    <button onclick={copyAll} disabled={shown.length === 0} title="Скопировать показанные строки (с учётом фильтра)">Копировать</button>
    <button onclick={() => (lines = [])}>Очистить</button>
    <button onclick={() => (choosing = !choosing)}>Сохранить в файл…</button>
  </div>
  {#if choosing}
    <div class="note choose">
      <span>Какую версию сохранить? Пароли, ключи подписок и SOCKS-данные вырезаны в обеих.</span>
      <button onclick={() => save(false)}>Оригинал</button>
      <button class:primary={ui.privacy} onclick={() => save(true)}>Очищенную (без IP и адресов серверов)</button>
      <button class="icon" onclick={() => (choosing = false)}>×</button>
    </div>
  {/if}
  {#if error}<div class="note error">{hide(error)}</div>{/if}
  {#if info}<div class="note ok">{info}</div>{/if}
  <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
  <div class="log panel mono" bind:this={box} tabindex="0" role="log" onkeydown={onKey} data-selectall>
    {#each shown as l (l.seq)}
      <div class="line lvl-{l.level}"><span class="t">{fmtTime(l.time)}{' '}</span><span class="l">{l.level.toUpperCase().padEnd(5)}{' '}</span>{hide(l.msg)}</div>
    {/each}
    {#if shown.length === 0}<p class="muted">Пусто.{source !== 'engine' ? ' Журнал Hysteria появляется, когда сервер запущен.' : ''}</p>{/if}
  </div>
</div>

<style>
  .wrap { display: flex; flex-direction: column; height: 100%; gap: 12px; }
  .sub { margin: 4px 0 0; }
  .log { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); }
  .wrap > .row input { max-width: 420px; }
  .log { flex: 1; min-height: 0; overflow: auto; user-select: text; padding: 8px 10px; }
  .log:focus { outline: none; }
  .choose { display: flex; gap: 8px; align-items: center; margin: 0; }
  .choose span { flex: 1; }
  .line { white-space: pre-wrap; word-break: break-all; padding: 1px 0; }
  .t { color: var(--muted); margin-right: 8px; }
  .l { color: var(--muted); white-space: pre; }
  .lvl-warn .l, .lvl-warning .l { color: var(--warn); }
  .lvl-error, .lvl-fatal { color: var(--block); }
  .lvl-error .l, .lvl-fatal .l { color: var(--block); }
  .lvl-debug { color: var(--muted); }
</style>
