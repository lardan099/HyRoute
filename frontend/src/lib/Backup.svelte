<script lang="ts">
  // «Резервная копия» in Settings: save a .hyroute-backup file
  // (BackupSave), restore one (the global BackupRestore dialog) and take the
  // last restore back («Вернуть как было»). undoOnly (the simple interface):
  // only the last restore's note, and only while there is one — the restore
  // dialog is reachable from Home there, and its texts point here.
  import { onMount } from 'svelte';
  import { api, errText, fmtDateTime, type BackupMsg, type BackupUndoInfo } from '../api';
  import { ui, hideFile, hidePath, hidePaths, hideMsg, startRestore, confirmUnsaved, afterRestore } from '../state.svelte';
  import Icon from './Icon.svelte';
  import BackupSave from './BackupSave.svelte';

  let { undoOnly = false }: { undoOnly?: boolean } = $props();

  let saving = $state(false);
  let undo = $state<BackupUndoInfo | null>(null);
  let error = $state('');
  let busy = $state(false);

  // Not on every status event: it hashes the data files.
  async function loadUndo() {
    try {
      undo = await api.RestoreUndoInfo();
    } catch (e) {
      error = errText(e);
    }
  }
  onMount(loadUndo);

  // The restore dialog closed without a restore (a restore re-mounts us).
  let wasRestoring = ui.restore;
  $effect(() => {
    const r = ui.restore;
    if (wasRestoring && !r) loadUndo();
    wasRestoring = r;
  });

  const connected = $derived(!!ui.status && ui.status.state !== 'disconnected' && !(ui.status.state === 'error' && !ui.status.stats));

  function note(text: string, path = '', warnings: BackupMsg[] = []) {
    ui.backupNote = text;
    ui.backupPath = path;
    ui.backupWarnings = warnings;
  }

  async function undoRestore() {
    if (!undo) return;
    const titles = undo.sections.map((s) => `«${s}»`).join(', ');
    const what = undo.sections.length === 1 ? `раздел ${titles} таким, каким он был` : `разделы ${titles} такими, какими они были`;
    const tail = undo.changedSince.length
      ? `После восстановления вы меняли: ${undo.changedSince.join(', ')} — эти изменения пропадут.`
      : 'Изменения в этих разделах, сделанные после восстановления, пропадут.';
    if (!confirm(`Вернуть ${what} до восстановления ${fmtDateTime(undo.created)}? ${tail}`)) return;
    if (!confirmUnsaved()) return;
    busy = true;
    error = '';
    try {
      const res = await api.UndoRestore();
      note(res.needsReconnect && connected ? 'Настройки возвращены. Изменения вступят в силу после переподключения.' : 'Настройки возвращены.', '', res.warnings);
      await afterRestore(res.appearance);
    } catch (e) {
      error = errText(e);
    }
    busy = false;
  }

  async function forget() {
    error = '';
    try {
      await api.ForgetRestoreUndo();
    } catch (e) {
      error = errText(e);
    }
    loadUndo();
  }

  function saved(path: string) {
    saving = false;
    if (path) note('Резервная копия сохранена:', path);
  }
</script>

{#if !undoOnly || undo?.available || ui.backupNote || error}
<section class="card">
  <h2><Icon name="database" size={17} /> Резервная копия</h2>
  {#if !undoOnly}
  <p class="muted small">
    Серверы, подписки, правила, прокси и настройки в одном файле <code>.hyroute-backup</code> — для переноса на другой компьютер или на случай переустановки
    Windows.
  </p>
  <div class="row">
    <button class="primary" onclick={() => ((saving = true), note(''))}><Icon name="download" size={15} />Сохранить копию…</button>
    <button onclick={() => (note(''), startRestore())}><Icon name="folder" size={15} />Восстановить из копии…</button>
  </div>
  {/if}
  {#if undo?.available}
    <div class="note info row">
      <span class="grow">
        Последнее восстановление: {fmtDateTime(undo.created)} из «{hideFile(undo.fileName)}» ({undo.sections.join(', ')}).
      </span>
      <button onclick={undoRestore} disabled={busy}>Вернуть как было</button>
      <button class="icon" title="Удалить сохранённое состояние до восстановления" aria-label="Удалить сохранённое состояние до восстановления" onclick={forget} disabled={busy}>
        <Icon name="x" size={16} />
      </button>
    </div>
  {/if}
  {#if ui.backupNote}
    <div class="note ok row">
      <span class="grow">{ui.backupNote}{#if ui.backupPath}{' '}{hidePath(ui.backupPath)}{/if}</span>
      <button class="icon" aria-label="Скрыть" onclick={() => note('')}><Icon name="x" size={16} /></button>
    </div>
    {#if ui.backupWarnings.length}
      <div class="note warn">
        <ul class="warns">
          {#each ui.backupWarnings as m}<li>{hideMsg(m)}</li>{/each}
        </ul>
      </div>
    {/if}
  {/if}
  {#if error}<div class="note error">{hidePaths(error)}</div>{/if}
</section>
{/if}

{#if saving}
  <BackupSave onclose={saved} />
{/if}

<style>
  h2 { display: flex; align-items: center; gap: 8px; }
  p { margin: 0 0 10px; }
  code { font-family: var(--mono); font-size: 12px; }
  .warns { margin: 0; padding-left: 20px; }
  .warns li { margin: 2px 0; user-select: text; }
</style>
