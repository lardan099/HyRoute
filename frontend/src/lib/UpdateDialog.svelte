<script lang="ts">
  // Offered HyRoute update: versions, changelog, "Обновить / Позже".
  import { onDestroy } from 'svelte';
  import { api, errText, fmtBytes, type Updates } from '../api';

  let { updates, onclose, onchange }: { updates: Updates; onclose: () => void; onchange: () => void } = $props();

  let error = $state('');
  let applying = $state(false);
  // busy is set at once: updates.appStage reaches "downloading" only with
  // the next poll, and until then «Позже» and «Обновить» must be off.
  let busy = $state(false);
  let closed = false;
  onDestroy(() => (closed = true));

  async function start() {
    busy = true;
    error = '';
    try {
      if (updates.appStage !== 'ready') await api.DownloadAppUpdate();
      // Install only from an open dialog, never behind the user's back:
      // the downloaded update stays ready for «Установить…» in Settings.
      if (!closed) {
        applying = true;
        await api.ApplyAppUpdate(); // HyRoute exits; the updater takes over
      }
    } catch (e) {
      error = errText(e);
      applying = false;
    }
    busy = false;
    onchange();
  }

  async function later() {
    try {
      await api.SkipAppVersion(updates.app!.version);
    } catch {}
    onclose();
  }
</script>

{#if updates.app}
  <div class="backdrop">
    <div class="dialog panel">
      <h2>Доступно обновление HyRoute</h2>
      <p>Сейчас <b>{updates.current}</b> → новая версия <b>{updates.app.version}</b> <span class="muted">({fmtBytes(updates.app.size)})</span></p>
      <div class="notes">{updates.app.notes || 'Описание изменений не приложено.'}</div>
      {#if updates.appStage === 'downloading' || (busy && !applying)}
        <div class="bar"><div style="width: {Math.round(updates.appProgress * 100)}%"></div></div>
        <p class="muted">Загрузка и проверка SHA256…</p>
      {:else if applying}
        <p class="muted">Установка: HyRoute отключит маршрутизацию, закроется и запустится заново.</p>
      {:else}
        <p class="muted small">
          Перед установкой HyRoute снимет фильтры и остановит Hysteria. Если новая версия не запустится, вернётся текущая.
        </p>
      {/if}
      {#if error}<div class="note error">{error}</div>{/if}
      <div class="row end">
        <button onclick={later} disabled={busy || applying || updates.appStage === 'downloading'}>Позже</button>
        <button class="primary" onclick={start} disabled={busy || applying || updates.appStage === 'downloading'}>Обновить</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .backdrop { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.45); display: grid; place-items: center; z-index: 30; }
  .dialog { width: min(640px, 92vw); max-height: 88vh; overflow: auto; }
  .notes { white-space: pre-wrap; background: var(--panel-2); border-radius: 6px; padding: 10px 12px; max-height: 280px; overflow: auto; font-size: 13px; user-select: text; margin-bottom: 10px; }
  .bar { height: 6px; background: var(--panel-2); border-radius: 3px; overflow: hidden; }
  .bar div { height: 100%; background: var(--accent); }
  .small { font-size: 12px; }
  .end { justify-content: flex-end; }
</style>
