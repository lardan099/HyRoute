<script lang="ts">
  // «Резервная копия» in Settings: save everything to a .hyroute file (with
  // a password) or only the rules; restore from such a file.
  import { api, errText, fmtDateTime, type BackupChoice } from '../api';
  import { ui } from '../state.svelte';
  import Icon from './Icon.svelte';

  let full = $state(true);
  let pass = $state('');
  let pass2 = $state('');
  let saving = $state(false);
  let error = $state('');
  let ok = $state('');

  let chosen = $state<BackupChoice | null>(null);
  let restorePass = $state('');
  let restoring = $state(false);

  const connected = $derived(!!ui.status && ui.status.state !== 'disconnected' && !(ui.status.state === 'error' && !ui.status.stats));
  const passProblem = $derived(!full ? '' : pass.length < 8 ? 'Пароль — не короче 8 символов.' : pass !== pass2 ? 'Пароли не совпадают.' : '');

  async function save() {
    error = ok = '';
    saving = true;
    try {
      const path = await api.SaveBackup(full, full ? pass : '');
      if (path) {
        ok = `Копия сохранена: ${path}`;
        pass = pass2 = '';
      }
    } catch (e) {
      error = errText(e);
    }
    saving = false;
  }

  async function choose() {
    error = ok = '';
    try {
      const c = await api.ChooseBackup();
      if (c.name) {
        chosen = c;
        restorePass = '';
      }
    } catch (e) {
      error = errText(e);
    }
  }

  async function restore() {
    if (!chosen) return;
    const what = chosen.kind === 'full' ? 'серверы, подписки, правила, прокси и настройки' : 'правила и настройки маршрутизации';
    if (!confirm(`Заменить ${what} содержимым копии? Текущие будут удалены.`)) return;
    error = ok = '';
    restoring = true;
    try {
      const r = await api.RestoreBackup(restorePass);
      const parts = [`правил: ${r.rules}`];
      if (r.kind === 'full') parts.push(`серверов: ${r.profiles}`, `подписок: ${r.subscriptions}`, `прокси: ${r.proxies}`);
      ok = `Восстановлено (${parts.join(', ')}).`;
      if (r.remapped) ok += ` Серверов из копии здесь нет, поэтому ${r.remapped} ${r.remapped === 1 ? 'правило теперь идёт' : 'правил теперь идут'} через основной сервер.`;
      chosen = null;
      restorePass = '';
    } catch (e) {
      error = errText(e);
    }
    restoring = false;
  }
</script>

<section class="card">
  <h2><Icon name="download" size={17} /> Резервная копия</h2>
  <p class="muted small">
    Файл <code>.hyroute</code>, из которого HyRoute можно восстановить на этом или другом компьютере. Просто скопировать папку с настройками не получится:
    пароли в ней зашифрованы под вашу учётную запись Windows.
  </p>
  <div class="seg mode">
    <button class:on={full} onclick={() => (full = true)}>Всё</button>
    <button class:on={!full} onclick={() => (full = false)}>Только правила</button>
  </div>
  {#if full}
    <p class="small">
      Серверы с паролями, подписки со ссылками, правила, прокси и настройки. Копия шифруется паролем: без него её не открыть, и восстановить забытый пароль
      нельзя.
    </p>
    <div class="row">
      <input type="password" placeholder="Пароль копии" bind:value={pass} autocomplete="new-password" />
      <input type="password" placeholder="Ещё раз" bind:value={pass2} autocomplete="new-password" />
    </div>
    {#if pass && passProblem}<div class="muted small">{passProblem}</div>{/if}
  {:else}
    <p class="small">
      Правила и настройки маршрутизации, без серверов и паролей: копию можно отправить другому человеку. Правила на серверы, которых у него нет, пойдут через
      его основной сервер.
    </p>
  {/if}
  <div class="row">
    <button class="primary" onclick={save} disabled={saving || !!passProblem}><Icon name="download" size={15} />Сохранить копию…</button>
    <button onclick={choose}><Icon name="folder" size={15} />Восстановить из копии…</button>
  </div>

  {#if chosen}
    <div class="restore">
      <b>{chosen.name}</b>
      <span class="muted small">
        {chosen.kind === 'full' ? 'Полная копия' : 'Только правила'}{chosen.created ? `, от ${fmtDateTime(chosen.created)}` : ''}{chosen.app ? `, HyRoute ${chosen.app}` : ''}{chosen.rules >= 0
          ? `, правил: ${chosen.rules}`
          : ''}
      </span>
      {#if chosen.encrypted}
        <input type="password" placeholder="Пароль копии" bind:value={restorePass} onkeydown={(e) => e.key === 'Enter' && restorePass && !connected && restore()} />
      {/if}
      {#if connected}<div class="note warn small">Сначала отключите VPN: восстановление заменит серверы и правила, которыми он сейчас пользуется.</div>{/if}
      <div class="row">
        <button class="primary" onclick={restore} disabled={restoring || connected || (chosen.encrypted && !restorePass)}>Восстановить</button>
        <button class="ghost" onclick={() => (chosen = null)}>Отмена</button>
      </div>
    </div>
  {/if}
  {#if error}<div class="note error">{error}</div>{/if}
  {#if ok}<div class="note ok">{ok}</div>{/if}
</section>

<style>
  h2 { display: flex; align-items: center; gap: 8px; }
  p { margin: 0 0 10px; }
  .small { font-size: 12.5px; }
  .mode { margin: 4px 0 10px; }
  .row { margin-bottom: 8px; }
  .restore { display: grid; gap: 8px; margin-top: 8px; padding: 12px; border-radius: var(--radius-sm); background: var(--surface-2); }
  .restore input { max-width: 320px; }
  code { font-family: var(--mono); font-size: 12px; }
</style>
