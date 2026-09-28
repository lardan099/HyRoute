<script lang="ts">
  // Create, duplicate or rename a rule profile.
  import { api, errText, type CreateResult, type RulesetInput, type RulesetsView } from '../api';
  import { ui, hide, mainTarget } from '../state.svelte';
  import Icon from './Icon.svelte';
  import { schemes, schemeConfig, type Scheme } from './templates';

  let {
    mode,
    view,
    source = '',
    scheme,
    beforeSwitch,
    onclose,
    ondone,
  }: {
    mode: 'create' | 'duplicate' | 'rename';
    view: RulesetsView;
    source?: string; // duplicate, rename: the profile ('' = the implicit one)
    scheme?: Scheme; // «Новым профилем» from «Шаблоны»
    beforeSwitch: () => Promise<void>;
    onclose: () => void;
    ondone: (r: CreateResult | null) => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  const src = view.list.find((r) => r.id === source);
  // svelte-ignore state_referenced_locally
  const active = view.list.find((r) => r.active);
  const title = $derived(mode === 'rename' ? 'Переименовать профиль правил' : 'Новый профиль правил');
  // svelte-ignore state_referenced_locally
  let name = $state(mode === 'rename' ? (src?.name ?? '') : mode === 'duplicate' ? `${src?.name ?? ''} (копия)` : (scheme?.name ?? ''));
  // svelte-ignore state_referenced_locally
  let start = $state<'copy' | 'direct' | 'tunnel' | 'scheme'>(scheme ? 'scheme' : 'copy');
  // svelte-ignore state_referenced_locally
  let schemeId = $state(scheme?.id ?? schemes[0]?.id ?? '');
  // svelte-ignore state_referenced_locally
  let activate = $state(mode === 'create');
  let firstName = $state('Основной');
  let error = $state('');
  let busy = $state(false);

  // Privacy mode: a name taken from a profile starts masked and read-only;
  // «Показать и изменить» reveals it for this dialog. A masked value is
  // never sent back.
  // svelte-ignore state_referenced_locally
  const prefilled = mode !== 'create';
  let revealed = $state(false);
  const masked = $derived(ui.privacy && prefilled && !revealed);

  function check(n: string): string {
    const t = n.trim();
    if (!t) return 'Введите название';
    if ([...t].length > 40) return 'Не длиннее 40 символов';
    // While not saved, the only other name is the one the current rules get.
    const names = view.saved ? view.list.filter((r) => mode !== 'rename' || r.id !== source).map((r) => r.name) : [firstName.trim() || 'Основной'];
    if (names.some((x) => x.trim().toLowerCase() === t.toLowerCase())) return 'Профиль с таким названием уже есть';
    return '';
  }

  function input(): RulesetInput {
    const i: RulesetInput = { name: name.trim(), from: '', activate };
    if (!view.saved) i.firstName = firstName.trim();
    if (mode === 'duplicate') i.from = source || 'active';
    else if (start === 'copy') i.from = 'active';
    else if (start === 'scheme') {
      const sc = schemes.find((x) => x.id === schemeId);
      if (sc) i.config = schemeConfig(sc, mainTarget()?.id);
    } else i.config = { defaultAction: start, defaultProfile: '', rules: [] };
    return i;
  }

  async function submit() {
    if (masked || busy) return;
    error = check(name);
    if (error) return;
    busy = true;
    try {
      if (mode === 'rename') {
        await api.RenameRuleset(source, name.trim());
        ondone(null);
        return;
      }
      const i = input();
      // The page's own queued saves land in the profile they were made in.
      if (i.activate) await beforeSwitch();
      ondone(await api.CreateRuleset(i));
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
  }

  function focus(el: HTMLElement) {
    el.focus();
  }

  // Only a click that starts on the backdrop closes the dialog.
  let downOnBackdrop = false;
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && !busy && onclose()} />

<div
  class="backdrop"
  role="presentation"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && !busy && onclose()}
>
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="rs-dialog-title">
    <div class="row"><h2 class="grow" id="rs-dialog-title">{title}</h2><button class="icon" onclick={onclose} title="Закрыть"><Icon name="x" /></button></div>
    <form
      onsubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <label class="field">
        <span>Название</span>
        {#if masked}
          <input value={hide(name)} readonly />
          <button type="button" class="link small" onclick={() => (revealed = true)}>Показать и изменить</button>
        {:else}
          <input bind:value={name} placeholder="Например, Работа" maxlength="40" use:focus />
        {/if}
      </label>

      {#if mode === 'create'}
        <fieldset>
          <legend>Начать с</legend>
          <label class="check"><input type="radio" name="rs-start" value="copy" bind:group={start} />Копии профиля «{hide(active?.name ?? 'Основной')}»</label>
          <label class="check"><input type="radio" name="rs-start" value="direct" bind:group={start} />Пустого: всё остальное напрямую</label>
          <label class="check"><input type="radio" name="rs-start" value="tunnel" bind:group={start} />Пустого: всё остальное через VPN</label>
          <div class="row">
            <label class="check"><input type="radio" name="rs-start" value="scheme" bind:group={start} />Схемы</label>
            <select bind:value={schemeId} disabled={start !== 'scheme'} aria-label="Схема">
              {#each schemes as sc (sc.id)}<option value={sc.id}>{sc.name}</option>{/each}
            </select>
          </div>
        </fieldset>
      {:else if mode === 'duplicate'}
        <fieldset>
          <legend>Начать с</legend>
          <label class="check"><input type="radio" checked disabled />Копии профиля «{hide(src?.name ?? 'Основной')}»</label>
        </fieldset>
      {/if}

      {#if mode !== 'rename' && !view.saved}
        <label class="field">
          <span>Как назвать текущие правила</span>
          <input bind:value={firstName} maxlength="40" />
          <span class="muted small">Текущие правила станут профилем с этим названием. Переименовать можно потом.</span>
        </label>
      {/if}

      {#if mode !== 'rename'}
        <label class="check"><input type="checkbox" bind:checked={activate} />Сразу включить</label>
      {/if}

      {#if error}<div class="note error">{hide(error)}</div>{/if}

      <div class="actions">
        <button type="button" onclick={onclose} disabled={busy}>Отмена</button>
        <button type="submit" class="primary" disabled={busy || masked}>{mode === 'rename' ? 'Сохранить' : 'Создать'}</button>
      </div>
    </form>
  </div>
</div>

<style>
  .dialog { width: min(520px, 94vw); }
  form { display: grid; gap: 14px; }
  .field { display: grid; gap: 6px; }
  .field > span:first-child { font-weight: 600; font-size: 13px; }
  .field .link { justify-self: start; }
  fieldset { border: none; padding: 0; margin: 0; display: grid; gap: 8px; }
  legend { font-weight: 600; font-size: 13px; margin-bottom: 6px; padding: 0; }
  fieldset select { min-width: 0; max-width: 100%; flex: 1; }
  .actions { margin-top: 4px; }
</style>
