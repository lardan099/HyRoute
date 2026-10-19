<script lang="ts">
  // «Сохранить резервную копию»: which sections, with or without a password.
  // The file is built (and encrypted) first; then Windows asks where to put
  // it. The password lives only in this dialog and is cleared after every
  // attempt.
  import { onDestroy, untrack } from 'svelte';
  import { api, errText, type BackupMsg, type BackupSectionInfo } from '../api';
  import { appearance, hide, hidePaths } from '../state.svelte';
  import Icon from './Icon.svelte';

  let { onclose }: { onclose: (path: string, warnings?: BackupMsg[]) => void } = $props();

  let withPass = $state(true);
  let password = $state('');
  let repeat = $state('');
  let rows = $state<BackupSectionInfo[]>([]);
  let chosen = $state<Record<string, boolean>>({});
  let error = $state('');
  let busy = $state(false);

  async function load(secrets: boolean) {
    try {
      const r = await api.BackupContents(secrets);
      const next: Record<string, boolean> = {};
      for (const s of r) {
        const can = s.available && !s.empty;
        next[s.key] = can && (s.key in chosen ? chosen[s.key] : s.default);
      }
      rows = r;
      chosen = next;
    } catch (e) {
      error = errText(e);
    }
  }
  $effect(() => {
    const w = withPass;
    untrack(() => load(w));
  });

  onDestroy(() => {
    password = repeat = '';
  });

  const keys = $derived(rows.filter((s) => chosen[s.key] && s.available && !s.empty).map((s) => s.key));
  const problem = $derived(
    keys.length === 0
      ? 'Ничего не выбрано'
      : withPass && [...password].length < 8
        ? 'Пароль — не меньше 8 символов'
        : withPass && password !== repeat
          ? 'Пароли не совпадают'
          : '',
  );

  async function save() {
    if (problem) {
      error = problem;
      return;
    }
    busy = true;
    error = '';
    try {
      const res = await api.ExportBackup({ sections: keys, password: withPass ? password : '', appearance: appearance() });
      if (res.path) onclose(res.path, res.warnings); // cancelled in Windows' dialog: this one stays
    } catch (e) {
      error = errText(e);
    } finally {
      password = repeat = '';
      busy = false;
    }
  }
  // A press that started in a field and ended on the backdrop is not a
  // click on the backdrop.
  let downOnBackdrop = false;
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && !e.defaultPrevented && !busy && onclose('')} />

<div
  class="backdrop"
  role="presentation"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && !busy && onclose('')}
>
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="bk-save-title">
    <div class="row">
      <h2 class="grow" id="bk-save-title">Сохранить резервную копию</h2>
      <button class="icon" aria-label="Закрыть" onclick={() => onclose('')} disabled={busy}><Icon name="x" /></button>
    </div>
    <p class="muted small">Отметьте, что сохранить. Копию можно восстановить на этом или другом компьютере.</p>

    <div class="sections">
      {#each rows as s (s.key)}
        <label class="check sec" class:off={!s.available || s.empty}>
          <input type="checkbox" bind:checked={chosen[s.key]} disabled={!s.available || s.empty || busy} />
          <span class="title">{s.title}</span>
          <span class="muted small">{s.available ? hide(s.detail) : s.reason}</span>
        </label>
      {/each}
    </div>

    <div class="modes">
      <label class="check">
        <input type="radio" name="bk-pass" checked={withPass} onchange={() => (withPass = true)} disabled={busy} />
        <span><b>С паролем</b> — сохраняются и пароли серверов, прокси, ссылки подписок и статистика</span>
      </label>
      {#if withPass}
        <div class="pass">
          <input type="password" placeholder="Пароль" bind:value={password} autocomplete="new-password" spellcheck="false" disabled={busy} />
          <input type="password" placeholder="Повторите" bind:value={repeat} autocomplete="new-password" spellcheck="false" disabled={busy} />
          <span class="muted small">Не меньше 8 символов. Без пароля копию не открыть, восстановить забытый пароль нельзя.</span>
        </div>
      {/if}
      <label class="check">
        <input type="radio" name="bk-pass" checked={!withPass} onchange={() => (withPass = false)} disabled={busy} />
        <span><b>Без пароля</b> — без паролей, ссылок подписок и статистики</span>
      </label>
      {#if !withPass}
        <div class="note warn small">
          Пароли серверов, прокси с паролем, подписки, статистика, свой DNS-сервер и свои ссылки на базы правил с ключами в файл не попадут. Остальное
          (адреса серверов, правила, названия сетей) может прочитать любой, у кого есть файл.
        </div>
      {/if}
    </div>

    {#if error}<div class="note error">{hidePaths(error)}</div>
    {:else if problem && (keys.length === 0 || password || repeat)}<p class="muted small">{problem}</p>{/if}

    <div class="actions">
      <button onclick={() => onclose('')} disabled={busy}>Отмена</button>
      <button class="primary" onclick={save} disabled={busy}>{busy ? 'Шифрование…' : 'Сохранить…'}</button>
    </div>
    <p class="muted small hint">
      Сетевые диски, подключённые буквой (Z:), в окне сохранения не видны: HyRoute работает с правами администратора. Укажите путь вида \\сервер\папка.
    </p>
  </div>
</div>

<style>
  .sections { display: grid; gap: 4px; margin: 10px 0 14px; }
  .sec { display: grid; grid-template-columns: auto 150px 1fr; gap: 10px; align-items: baseline; padding: 4px 0; }
  .sec.off .title { color: var(--muted); }
  .modes { display: grid; gap: 8px; }
  .pass { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-left: 26px; }
  .pass span { grid-column: 1 / -1; }
  .hint { margin-top: 12px; }
</style>
