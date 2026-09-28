<script lang="ts">
  // «Восстановление из копии» (global, App.svelte): open a file → password →
  // choose the sections and modes with a live plan → restore → result. What
  // is applied is the plan shown: its digest goes with «Восстановить».
  import { onMount, onDestroy, tick } from 'svelte';
  import { api, errText, fmtDateTime, planChangedText, type BackupPreview, type BackupPlan, type BackupApplyResult } from '../api';
  import { ui, hide, hideMsg, hideFile, hidePaths, appearance, confirmUnsaved, afterRestore } from '../state.svelte';
  import Icon from './Icon.svelte';

  let { onclose }: { onclose: () => void } = $props();

  type Step = 'opening' | 'error' | 'password' | 'choose' | 'done';
  let step = $state<Step>('opening');
  let token = '';
  let fileName = $state('');
  let error = $state('');
  let password = $state('');
  let pwInput = $state<HTMLInputElement>();
  let preview = $state<BackupPreview | null>(null);
  let choice = $state<Record<string, '' | 'replace' | 'add'>>({});
  let open = $state<Record<string, boolean>>({});
  let plan = $state<BackupPlan | null>(null);
  let planError = $state(''); // the plan request failed (e.g. the file was closed)
  let busy = $state(false);
  let result = $state<BackupApplyResult | null>(null);
  let undone = $state(false);

  const connected = $derived(!!ui.status && ui.status.state !== 'disconnected' && !(ui.status.state === 'error' && !ui.status.stats));

  async function pick() {
    const was = step;
    step = 'opening';
    error = '';
    try {
      const o = await api.OpenBackup();
      if (!o.token) {
        if (was === 'error') step = 'error';
        else onclose();
        return;
      }
      if (token && token !== o.token) api.CloseBackup(token);
      token = o.token;
      fileName = o.fileName;
      if (o.preview) show(o.preview);
      else {
        step = 'password';
        await tick();
        pwInput?.focus();
      }
    } catch (e) {
      error = errText(e);
      step = 'error';
    }
  }
  onMount(pick);

  onDestroy(() => {
    password = '';
    if (token) api.CloseBackup(token);
  });

  function show(p: BackupPreview) {
    preview = p;
    const c: Record<string, '' | 'replace' | 'add'> = {};
    for (const s of p.sections) c[s.key] = !s.error && s.modes.length && s.default ? s.modes[0] : '';
    choice = c;
    step = 'choose';
  }

  async function unlock() {
    busy = true;
    error = '';
    try {
      show(await api.UnlockBackup(token, password));
    } catch (e) {
      error = errText(e);
      await tick();
      pwInput?.focus();
    } finally {
      password = '';
      busy = false;
    }
  }

  const sections = $derived(Object.fromEntries(Object.entries(choice).filter(([, m]) => m)) as Record<string, 'replace' | 'add'>);

  // The plan follows every change of the choice (debounced).
  let seq = 0;
  async function requestPlan(s: Record<string, 'replace' | 'add'>) {
    const n = ++seq;
    try {
      const p = await api.PlanBackup(token, { sections: s });
      if (n === seq) {
        plan = p;
        planError = '';
      }
    } catch (e) {
      if (n === seq) {
        plan = null;
        planError = errText(e);
      }
    }
  }
  $effect(() => {
    if (step !== 'choose') return;
    const s = JSON.stringify(sections);
    plan = null;
    const t = setTimeout(() => requestPlan(JSON.parse(s)), 150);
    return () => clearTimeout(t);
  });

  async function apply() {
    if (!plan || plan.error || !confirmUnsaved()) return;
    busy = true;
    error = '';
    try {
      result = await api.ApplyBackup(token, { sections }, appearance(), plan.digest);
      token = ''; // Go closed it
      step = 'done';
      await afterRestore(result.appearance);
    } catch (e) {
      error = errText(e);
      if (error === planChangedText) {
        plan = null;
        requestPlan(sections);
      }
    } finally {
      busy = false;
    }
  }

  async function undo() {
    if (!confirmUnsaved()) return;
    busy = true;
    error = '';
    try {
      const r = await api.UndoRestore();
      undone = true;
      await afterRestore(r.appearance);
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
  }

  async function reconnect() {
    try {
      await api.Reconnect();
      onclose();
    } catch (e) {
      error = errText(e);
    }
  }

  function modeTitle(m: string): string {
    return m === 'add' ? 'Добавить к текущим' : 'Заменить';
  }
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && !e.defaultPrevented && !busy && onclose()} />

<div class="backdrop" role="presentation">
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="bk-title">
    <div class="row">
      <h2 class="grow" id="bk-title">{step === 'choose' || step === 'done' ? 'Восстановление из копии' : 'Открыть резервную копию'}</h2>
      <button class="icon" aria-label="Закрыть" onclick={onclose} disabled={busy}><Icon name="x" /></button>
    </div>

    {#if step === 'opening'}
      <p class="muted">Выберите файл резервной копии…</p>
    {:else if step === 'error'}
      <div class="note error">{hidePaths(error)}</div>
      <div class="actions">
        <button onclick={onclose}>Отмена</button>
        <button class="primary" onclick={pick}>Выбрать другой файл…</button>
      </div>
    {:else if step === 'password'}
      <p class="file">{hideFile(fileName)}</p>
      <form
        class="row"
        onsubmit={(e) => {
          e.preventDefault();
          if (password && !busy) unlock();
        }}
      >
        <input bind:this={pwInput} class="grow" type="password" placeholder="Пароль" bind:value={password} autocomplete="off" spellcheck="false" disabled={busy} />
      </form>
      {#if error}<div class="note error">{hidePaths(error)}</div>{/if}
      <div class="actions">
        <button onclick={onclose} disabled={busy}>Отмена</button>
        <button class="primary" onclick={unlock} disabled={busy || !password}>{busy ? 'Проверка пароля…' : 'Открыть'}</button>
      </div>
    {:else if step === 'choose' && preview}
      <p class="muted small">
        {hideFile(preview.fileName)}{preview.created ? ` · создана ${fmtDateTime(preview.created)}` : ''}{preview.app ? ` · HyRoute ${preview.app}` : ''}
      </p>
      {#if preview.legacy}
        <div class="note info small">Копия HyRoute 1.2 (.hyroute): её разделы восстанавливаются так же. «Только правила» из такой копии не меняет kill switch и другие настройки.</div>
      {/if}
      {#if !preview.secrets}
        <div class="note warn small">Копия без паролей: серверы придут без паролей — впишите их в редакторе сервера, иначе они не подключатся. Подписок в такой копии нет.</div>
      {/if}
      {#if preview.newer}
        <div class="note warn small">
          Копия сделана более новой версией HyRoute{preview.app ? ` (${preview.app})` : ''}. Разделы, которые эта версия не понимает, отмечены ниже.
        </div>
      {/if}
      {#if preview.unknown.length}
        <div class="note warn small">Часть данных этой версией не читается и будет пропущена.</div>
      {/if}

      <div class="sections">
        {#each preview.sections as s (s.key)}
          <div class="sec">
            <label class="check">
              <input
                type="checkbox"
                checked={!!choice[s.key]}
                disabled={!!s.error || s.modes.length === 0 || busy}
                onchange={(e) => (choice[s.key] = e.currentTarget.checked ? s.modes[0] : '')}
              />
              <b class:bad={!!s.error}>{s.title}</b>
            </label>
            <span class="muted small grow">
              {hide(s.detail)}
              {#if s.items.length}
                <button class="link small" onclick={() => (open[s.key] = !open[s.key])}>{open[s.key] ? 'Скрыть ▴' : 'Показать ▾'}</button>
              {/if}
            </span>
            {#if s.modes.length > 1 || (s.broken && s.modes.length === 1 && s.key !== 'settings')}
              <div class="seg small">
                {#each ['replace', 'add'] as m}
                  <button
                    class:on={choice[s.key] === m}
                    disabled={!s.modes.includes(m as 'replace' | 'add') || !choice[s.key] || busy}
                    onclick={() => (choice[s.key] = m as 'replace' | 'add')}>{modeTitle(m)}</button
                  >
                {/each}
              </div>
            {/if}
            {#if s.error}<div class="bad small full">{hide(s.error)}</div>{/if}
            {#if s.broken}<div class="note warn small full">{hidePaths(hide(s.broken))}</div>{/if}
            {#if open[s.key]}
              <ul class="items full">
                {#each s.items as it}<li>{it.sensitive && ui.privacy ? '***' : hide(it.text)}</li>{/each}
                {#if s.more}<li class="muted">и ещё {s.more}</li>{/if}
              </ul>
            {/if}
          </div>
        {/each}
      </div>

      <h3>Что изменится</h3>
      {#if !plan && planError}
        <div class="note error">{hidePaths(hide(planError))}</div>
        <div class="actions"><button onclick={pick} disabled={busy}>Выбрать другой файл…</button></div>
      {:else if !plan}
        <p class="muted small">Считаем…</p>
      {:else}
        {#if plan.error}<div class="note error">{hidePaths(hide(plan.error))}</div>{/if}
        <ul class="plan">
          {#each plan.lines as m}<li>{hideMsg(m)}</li>{/each}
        </ul>
        {#if plan.warnings.length}
          <div class="note warn">
            <b>Предупреждения:</b>
            <ul class="plan">
              {#each plan.warnings as m}<li>{hideMsg(m)}</li>{/each}
            </ul>
          </div>
        {/if}
      {/if}
      <p class="muted small">Перед восстановлением HyRoute запомнит текущие настройки: вернуть их можно кнопкой «Вернуть как было» в «Настройках».</p>
      {#if connected}
        <p class="muted small">Правила и серверы применятся к новым соединениям сразу, параметры движка — после переподключения.</p>
      {/if}
      {#if error}<div class="note error">{hidePaths(hide(error))}</div>{/if}
      <div class="actions">
        <button onclick={onclose} disabled={busy}>Отмена</button>
        <button class="primary" onclick={apply} disabled={busy || !plan || !!plan.error}>{busy ? 'Восстановление…' : 'Восстановить'}</button>
      </div>
    {:else if step === 'done' && result}
      {#if undone}
        <div class="note ok">Настройки возвращены.</div>
      {:else}
        <div class="note ok">Восстановлено: {result.restored.join(', ')}.</div>
        {#if result.warnings.length}
          <div class="note warn">
            <ul class="plan">
              {#each result.warnings as m}<li>{hideMsg(m)}</li>{/each}
            </ul>
          </div>
        {/if}
      {/if}
      {#if error}<div class="note error">{hidePaths(hide(error))}</div>{/if}
      <div class="actions">
        {#if !undone && result.undo}<button onclick={undo} disabled={busy}>Вернуть как было</button>{/if}
        {#if !undone && result.needsReconnect && connected}<button onclick={reconnect} disabled={busy}>Переподключить</button>{/if}
        <button class="primary" onclick={onclose} disabled={busy}>Готово</button>
      </div>
    {/if}
  </div>
</div>

<style>
  .dialog { width: min(720px, 94vw); }
  .file { font-weight: 600; margin: 4px 0 10px; }
  .sections { display: grid; gap: 6px; margin: 10px 0 14px; }
  .sec { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 12px; padding: 6px 0; border-bottom: 1px solid var(--border); }
  .sec .check { min-width: 170px; }
  .full { flex-basis: 100%; }
  .bad { color: var(--block); }
  .seg.small button { padding: 4px 10px; font-size: 12.5px; }
  .items { margin: 0; padding-left: 20px; font-size: 12.5px; max-height: 160px; overflow: auto; }
  h3 { font-size: 14px; margin: 12px 0 6px; }
  .plan { margin: 4px 0; padding-left: 20px; }
  .plan li { margin: 2px 0; user-select: text; }
</style>
