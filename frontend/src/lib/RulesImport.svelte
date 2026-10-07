<script lang="ts">
  // Rules of another program (SwitchyOmega, v2rayN, Throne, FoxyProxy,
  // Clash, PAC, AutoProxy, Hysteria ACL) into HyRoute: Go reads them, the
  // user picks where each place of the source goes, then the rules are
  // added to the profile the page shows or become a new rule profile.
  import { api, errText, tokenStale, type RulesImport, type RulesetsView } from '../api';
  import { ui, hide } from '../state.svelte';
  import { trackUnsaved } from '../state.svelte'; // backup
  import Icon from './Icon.svelte';
  import TargetOptions from './TargetOptions.svelte';

  let {
    target = '',
    rulesetName = '',
    list = null,
    onclose,
    onsaved,
    onprofile,
  }: {
    target?: string;
    rulesetName?: string;
    list?: RulesetsView | null;
    onclose: () => void;
    onsaved: (count: number) => void;
    onprofile: (id: string, name: string) => void;
  } = $props();

  let text = $state('');
  let fileName = $state('');
  let format = $state('');
  let to = $state<Record<string, string>>({});
  let res = $state<RulesImport | null>(null);
  let error = $state('');
  let busy = $state(false);
  let saved = $state(false);
  trackUnsaved(() => text.trim() !== '' && !saved); // backup

  // A new rule profile: its name and «Всё остальное» ('' = the source's
  // own, or directly when it does not say).
  let asProfile = $state(false);
  let profileName = $state('');
  let rest = $state('');

  // Privacy mode: the result is masked until «Показать».
  let revealed = $state(false);
  const masked = $derived(ui.privacy && !revealed);

  // Every change converts again; only the latest answer lands.
  let seq = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    const t = text;
    const f = format;
    const m = { ...to };
    clearTimeout(timer);
    if (!t.trim()) {
      res = null;
      error = '';
      return;
    }
    timer = setTimeout(async () => {
      const my = ++seq;
      try {
        const r = await api.ImportRules(t, f, m);
        if (my !== seq) return;
        res = r;
        error = '';
      } catch (e) {
        if (my !== seq) return;
        res = null;
        error = errText(e);
      }
    }, 250);
  });

  const MAX = 16 << 20;
  let fileInput = $state<HTMLInputElement>();
  async function openFile(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const f = input.files?.[0];
    input.value = '';
    if (!f) return;
    if (f.size > MAX) {
      error = `Файл больше ${MAX >> 20} МБ: это не файл правил`;
      return;
    }
    try {
      text = await f.text();
      fileName = f.name;
      format = '';
      to = {};
    } catch (err) {
      error = errText(err);
    }
  }

  function setTo(name: string, v: string) {
    to = { ...to, [name]: v };
  }

  const toOptions: { value: string; label: string }[] = [
    { value: 'vpn', label: 'VPN (основной)' },
    { value: 'direct', label: 'Напрямую' },
    { value: 'block', label: 'Блок' },
  ];
  function kindText(k: string): string {
    return k === 'direct' ? 'напрямую' : k === 'block' ? 'блок' : 'прокси';
  }
  // A select value for a target: vpn, direct, block or a server/group ID.
  function selValue(v: string): string {
    return v.startsWith('id:') ? v.slice(3) : v;
  }
  function fromSel(v: string): string {
    return v === 'vpn' || v === 'direct' || v === 'block' ? v : `id:${v}`;
  }

  const profileWord = $derived((ui.status?.ruleset?.count ?? 0) >= 2 && rulesetName ? `профиля «${hide(rulesetName)}»` : 'правил');

  async function addToRules() {
    if (!res || busy) return;
    busy = true;
    error = '';
    try {
      // Added after the current rules of the profile the page shows.
      await api.ApplyRulesText(res.text, false, { ruleset: target, rev: 0, editRev: 0 });
      saved = true;
      onsaved(res.count);
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
  }

  function restLine(): string {
    if (!rest) return res?.defaultLine || '* -> напрямую';
    if (rest === 'direct') return '* -> напрямую';
    if (rest === 'block') return '* -> блок';
    if (rest === 'vpn') return '* -> vpn';
    return `* -> id:${rest}`;
  }

  async function createProfile() {
    if (!res || busy) return;
    const name = profileName.trim();
    if (!name) {
      error = 'Введите название профиля';
      return;
    }
    if ([...name].length > 40) {
      error = 'Название не длиннее 40 символов';
      return;
    }
    busy = true;
    error = '';
    try {
      const p = await api.ParseRulesText(`${res.text}\n${restLine()}\n`);
      if (p.errors.length) {
        error = `Строка ${p.errors[0].line}: ${p.errors[0].text}`;
        return;
      }
      const r = await api.CreateRuleset({
        name,
        from: '',
        activate: false,
        config: { defaultAction: p.defaultAction, defaultProfile: p.defaultProfile, defaultFallback: p.defaultFallback, rules: p.rules },
      });
      saved = true;
      onprofile(r.view.id, r.view.name);
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
  }

  // The rule profile changed while the window was open: nothing is added.
  const stale = $derived(tokenStale(target, ui.status?.ruleset, list));

  // Only a click that starts on the backdrop closes the window.
  let downOnBackdrop = false;
  const example = `Например:
[SwitchyOmega Conditions]
@with result
*.example.com +proxy

или строки таблицы правил v2rayN, PAC-файл, JSON Throne / sing-box / FoxyProxy, правила Clash, список AutoProxy, ACL Hysteria, просто список сайтов`;
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && !busy && onclose()} />

<div
  class="backdrop"
  role="presentation"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && !busy && onclose()}
>
  <div class="dialog big" role="dialog" aria-modal="true" aria-labelledby="ri-title">
    <div class="row head">
      <h2 class="grow" id="ri-title">Импорт правил из другой программы</h2>
      <button class="icon" onclick={onclose} title="Закрыть"><Icon name="x" /></button>
    </div>
    <p class="muted small intro">
      Вставьте правила или откройте файл: SwitchyOmega и ZeroOmega (правила текстом или PAC), v2rayN (строки таблицы правил или JSON), Throne, Nekoray,
      sing-box, FoxyProxy, Clash, список AutoProxy / GFWList, ACL сервера Hysteria или просто список сайтов. Формат определяется сам. Потом выберите,
      куда в HyRoute идёт каждый выход той программы.
    </p>

    <div class="cols">
      <div class="left">
        <div class="row tools">
          <button onclick={() => fileInput?.click()}><Icon name="folder" size={15} />Открыть файл…</button>
          <input bind:this={fileInput} type="file" accept=".pac,.txt,.json,.yaml,.yml,.conf,.bak,.list,text/*,application/json" hidden onchange={openFile} />
          {#if fileName}<span class="muted small ellipsis">{fileName}</span>{/if}
          <span class="grow"></span>
          <label class="fmt">
            <span class="muted small">Формат</span>
            <select value={format} onchange={(e) => (format = (e.currentTarget as HTMLSelectElement).value)}>
              <option value="">Определить{res && !format ? `: ${res.title}` : ''}</option>
              {#each res?.formats ?? [] as f (f.id)}<option value={f.id}>{f.title}</option>{/each}
            </select>
          </label>
        </div>
        <textarea bind:value={text} spellcheck="false" wrap="off" placeholder={example} aria-label="Правила другой программы"></textarea>
      </div>

      <div class="right">
        {#if error}<div class="note error small">{masked ? hide(error) : error}</div>{/if}
        {#if res}
          {#if res.targets.length}
            <b class="small">Куда идёт каждый выход</b>
            <div class="targets">
              {#each res.targets as t (t.name)}
                <div class="t">
                  <div class="tn">
                    <span class="ellipsis" title={masked ? '' : t.detail || t.name}>{masked ? hide(t.name) : t.name}</span>
                    <span class="faint small"
                      >{kindText(t.kind)}{t.detail && t.detail !== t.name ? ` · ${masked ? hide(t.detail) : t.detail}` : ''} · {t.rules
                        ? `${t.rules} прав.`
                        : 'всё остальное'}</span
                    >
                  </div>
                  <select value={selValue(t.to)} onchange={(e) => setTo(t.name, fromSel((e.currentTarget as HTMLSelectElement).value))} aria-label="Куда: {t.name}">
                    {#each toOptions as o}<option value={o.value}>{o.label}</option>{/each}
                    <TargetOptions current={t.to.startsWith('id:') ? t.to.slice(3) : ''} />
                  </select>
                </div>
              {/each}
            </div>
          {/if}
          <div class="summary small">
            <Icon name="check" size={15} />
            Правил: {res.count}{res.defaultLine ? ` · всё остальное: ${res.defaultLine.replace('* -> ', '')}` : ''}
          </div>
          {#each res.notes as n}<div class="muted small">{n}</div>{/each}
          {#if res.warnings.length}
            <details class="warns" open={res.warnings.length <= 4}>
              <summary>Не перенесено или перенесено иначе: {res.warnings.length}</summary>
              {#each res.warnings.slice(0, 60) as w}<div>{masked ? hide(w) : w}</div>{/each}
              {#if res.warnings.length > 60}<div>…и ещё {res.warnings.length - 60}</div>{/if}
            </details>
          {/if}
        {:else if !error}
          <p class="muted small">Здесь появится, что получится.</p>
        {/if}
      </div>
    </div>

    {#if res}
      <div class="result">
        <div class="row">
          <b class="grow small">Правила HyRoute</b>
          {#if masked}<button class="link small" onclick={() => (revealed = true)}>Показать</button>{/if}
        </div>
        <pre class="ro">{masked ? hide(res.text) : res.text}</pre>
      </div>
    {/if}

    {#if asProfile && res}
      <div class="profile row">
        <label class="grow">
          <span class="muted small">Название профиля</span>
          <input bind:value={profileName} maxlength="40" placeholder="Например, Из Omega" />
        </label>
        <label>
          <span class="muted small">Всё остальное</span>
          <select bind:value={rest}>
            <option value="">{res.defaultLine ? `Как там: ${res.defaultLine.replace('* -> ', '')}` : 'Напрямую'}</option>
            {#each toOptions as o}<option value={o.value}>{o.label}</option>{/each}
            <TargetOptions current={['', 'vpn', 'direct', 'block'].includes(rest) ? '' : rest} />
          </select>
        </label>
      </div>
    {/if}

    {#if stale}<div class="note warn small">Профиль правил сменился, пока было открыто это окно: закройте его и откройте заново.</div>{/if}

    <div class="actions">
      <button onclick={onclose} disabled={busy}>Закрыть</button>
      {#if ui.expert}
        {#if asProfile}
          <button class="primary" onclick={createProfile} disabled={!res || !res.count || busy || stale}>Создать профиль</button>
        {:else}
          <button onclick={() => (asProfile = true)} disabled={!res || !res.count || busy}>Новым профилем…</button>
        {/if}
      {/if}
      {#if !asProfile}
        <button class="primary" onclick={addToRules} disabled={!res || !res.count || busy || stale} title="Правила добавятся в конец списка, «Всё остальное» не меняется"
          >Добавить в конец {profileWord}</button
        >
      {/if}
    </div>
  </div>
</div>

<style>
  .big { width: min(1080px, 96vw); max-height: 94vh; overflow: auto; }
  .head { gap: 12px; }
  .head h2 { margin: 0; }
  .intro { margin: 6px 0 12px; }
  .cols { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 16px; }
  .left { display: flex; flex-direction: column; gap: 8px; min-width: 0; }
  .tools { gap: 8px; align-items: center; }
  .fmt { display: flex; align-items: center; gap: 6px; }
  .fmt select { max-width: 300px; }
  textarea { width: 100%; height: 30vh; font-size: 12.5px; line-height: 1.5; resize: vertical; font-family: var(--mono); }
  .right { display: flex; flex-direction: column; gap: 8px; min-width: 0; }
  .targets { display: grid; gap: 6px; max-height: 30vh; overflow: auto; }
  .t { display: grid; grid-template-columns: minmax(0, 1fr) 170px; gap: 8px; align-items: center; }
  .tn { display: flex; flex-direction: column; min-width: 0; }
  .t select { width: 100%; }
  .summary { display: flex; align-items: center; gap: 6px; color: var(--direct); }
  .warns { font-size: 12.5px; color: var(--warn); }
  .warns summary { cursor: pointer; }
  .warns div { margin-top: 3px; }
  .result { margin-top: 12px; }
  .ro {
    margin: 6px 0 0;
    max-height: 26vh;
    overflow: auto;
    padding: 7px 10px;
    border-radius: var(--radius-sm);
    background: var(--surface-2);
    font-family: var(--mono);
    font-size: 12.5px;
    line-height: 1.5;
    user-select: text;
  }
  .profile { gap: 12px; margin-top: 12px; align-items: flex-end; }
  .profile label { display: flex; flex-direction: column; gap: 4px; }
  .faint { color: var(--faint); }
  @media (max-width: 760px) {
    .cols { grid-template-columns: 1fr; }
  }
</style>
