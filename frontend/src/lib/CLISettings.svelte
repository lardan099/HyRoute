<script lang="ts">
  // «Настройки» → «Командная строка»: hyroutectl.exe's access and where it is.
  import { onMount } from 'svelte';
  import { api, errText, onEvent, type CLIInfo, type CLIMode } from '../api';
  import { ui, hide, settle, hideUserPath } from '../state.svelte';
  import Icon from './Icon.svelte';

  let info = $state<CLIInfo | null>(null);
  let error = $state('');
  let ok = $state('');

  async function load() {
    try {
      info = await api.CLIInfo();
    } catch (e) {
      error = errText(e);
    }
  }

  // Re-read on the status event (a retry that succeeded, a mode changed by
  // a restore) and when the window comes back to the front.
  onMount(() => {
    load();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const soon = () => {
      clearTimeout(timer);
      timer = setTimeout(load, 300);
    };
    const off = onEvent('status', soon);
    window.addEventListener('focus', soon);
    return () => {
      off();
      window.removeEventListener('focus', soon);
      clearTimeout(timer);
    };
  });

  async function setMode(mode: CLIMode) {
    error = '';
    ok = '';
    try {
      await api.SetCLIMode(mode);
      ok = 'Сохранено';
    } catch (e) {
      error = errText(e);
    }
    await load();
  }

  // Paths and the account name may carry the user's name: masked in
  // Privacy mode (the SID too).
  const hidePath = hideUserPath;
  function hideUser(u: string): string {
    return ui.privacy ? '***' : u;
  }

  const copyLine = $derived(info?.exe ? `& "${info.exe}" status` : '');

  async function copy() {
    error = '';
    ok = '';
    try {
      await api.CopyText(copyLine);
      ok = 'Скопировано';
    } catch (e) {
      error = errText(e);
    }
  }
</script>

<section class="card">
  <h2><Icon name="terminal" size={17} /> Командная строка</h2>
  <div class="row">
    <label for="climode" class="grow">Управление из командной строки (hyroutectl.exe)</label>
    <select id="climode" value={info?.mode ?? 'read'} disabled={!info || !!info.prefsError}
      onchange={(e) => settle(e, (el) => setMode(el.value as CLIMode), () => info?.mode ?? 'read')}>
      <option value="full">Полный доступ</option>
      <option value="read">Только просмотр</option>
      <option value="off">Выключено</option>
    </select>
  </div>
  <p class="muted small">
    hyroutectl.exe лежит рядом с HyRoute.exe и управляет запущенным HyRoute без прав администратора: подключение, основной сервер, профиль
    правил, «Проверить адрес», импорт и экспорт правил, правила сетей, статистика, журнал. Команды принимаются только от программ вашей учётной записи Windows на этом
    компьютере и от администраторов. «Только просмотр» (по умолчанию) разрешает состояние, списки, «Проверить адрес», экспорт правил, статистику и
    журнал; подключать, отключать и менять правила можно только с «Полным доступом». Команды записываются в журнал HyRoute.
  </p>
  {#if !info && !error}
    <p class="muted small">Загрузка…</p>
  {/if}
  {#if info}
    {#if info.userDiffers}
      <p class="muted small">Команды принимаются от: {hideUser(info.user)}</p>
    {/if}
    {#if info.exe}
      <div class="row">
        <code class="grow cmd">{hidePath(copyLine)}</code>
        <button onclick={copy}><Icon name="copy" size={15} /> Копировать</button>
      </div>
      <p class="muted small">В PowerShell — как показано; в cmd — без «&amp; ». Папка программы: {hidePath(info.dir)}</p>
    {:else}
      <div class="note warn small">hyroutectl.exe нет рядом с HyRoute.exe: он есть в архиве с программой.</div>
    {/if}
    {#if info.prefsError}
      <div class="note warn small">prefs.json не загружен: командная строка выключена, пока файл не исправлен.</div>
    {:else if info.error && info.mode !== 'off'}
      <div class="note error small">Командная строка недоступна: {hide(info.error)}</div>
    {/if}
  {/if}
  {#if error}<div class="note error small">{hide(error)}</div>{/if}
  {#if ok}<p class="muted small">{ok}</p>{/if}
</section>

<style>
  .cmd {
    overflow-wrap: anywhere;
    user-select: all;
  }
</style>
