<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, fmtBytes, type ProfileSummary, type Profile, type ImportResult } from '../api';
  import { ui, hide } from '../state.svelte';
  import Icon from './Icon.svelte';
  import ProfileEditor from './ProfileEditor.svelte';
  import CheckProfile from './CheckProfile.svelte';

  let { onchange }: { onchange: () => void } = $props();

  let list = $state<ProfileSummary[]>([]);
  let adding = $state(false);
  let text = $state('');
  let result = $state<ImportResult | null>(null);
  let error = $state('');
  let info = $state('');
  let editing = $state<Profile | null>(null);
  let checking = $state<ProfileSummary | null>(null);

  async function load() {
    try {
      list = await api.Profiles();
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(load);

  async function after() {
    await load();
    onchange();
  }

  async function doImport(fromClipboard: boolean) {
    error = '';
    info = '';
    result = null;
    try {
      result = fromClipboard ? await api.ImportClipboard() : await api.ImportURIs(text);
      if (result.added.length > 0) text = '';
      await after();
      if (result.added.length && !result.errors.length && !result.warnings.length) adding = false;
      if (result.added.length) info = `Добавлено серверов: ${result.added.length} — ${result.added.map((p) => p.name).join(', ')}`;
    } catch (e) {
      error = errText(e);
    }
  }

  async function run(f: () => Promise<unknown>, ok = '') {
    error = '';
    info = '';
    try {
      await f();
      info = ok;
      await after();
    } catch (e) {
      error = errText(e);
    }
  }

  async function edit(id: string) {
    try {
      editing = await api.Profile(id);
    } catch (e) {
      error = errText(e);
    }
  }

  function create() {
    adding = false;
    editing = { id: '', name: '', host: '', ports: '443', auth: '', tls: {}, obfs: {}, hop: {}, bandwidth: {}, congestion: {}, quic: {}, pinServerIP: true };
  }

  function remove(p: ProfileSummary) {
    if (confirm(`Удалить сервер «${hide(p.name)}»?`)) run(() => api.DeleteProfile(p.id));
  }

  function tunnel(id: string) {
    return ui.status?.tunnels?.find((t) => t.id === id);
  }

  const stateText: Record<string, string> = { connected: 'работает', connecting: 'подключается', failed: 'ошибка', stopped: 'остановлен' };
  function tone(state: string): string {
    return state === 'connected' ? 'ok' : state === 'connecting' ? 'wait' : 'bad';
  }
</script>

<div class="page-wrap">
  <header class="row">
    <div class="grow">
      <h1>Серверы</h1>
      <p class="muted sub">
        Серверы Hysteria 2. Работает только тот, который нужен правилам, и несколько могут работать одновременно. ★ — основной сервер.
      </p>
    </div>
    <button class="primary" onclick={() => (adding = !adding)}><Icon name="plus" size={16} />Добавить сервер</button>
  </header>

  {#if adding}
    <section class="card">
      <h2>Добавить сервер</h2>
      <textarea rows="4" placeholder="Вставьте ссылки hysteria2://… или hy2://… (по одной на строку)" bind:value={text}></textarea>
      <div class="row" style="margin-top: 10px">
        <button class="primary" onclick={() => doImport(false)} disabled={!text.trim()}>Добавить</button>
        <button onclick={() => doImport(true)}><Icon name="clipboard" size={16} />Из буфера обмена</button>
        <div class="grow"></div>
        <button class="ghost" onclick={create}>Заполнить вручную</button>
      </div>
      <p class="muted small">Ссылка подписки (https://…) добавляется на странице «Подписки».</p>
    </section>
  {/if}

  {#if result}
    {#each result.warnings as w}<div class="note warn">{hide(w)}</div>{/each}
    {#each result.errors as w}<div class="note error">{hide(w)}</div>{/each}
  {/if}
  {#if error}<div class="note error">{hide(error)}</div>{/if}
  {#if info}<div class="note ok">{hide(info)}</div>{/if}

  {#if list.length === 0}
    <div class="card empty">
      <Icon name="server" size={28} />
      <div><b>Серверов пока нет.</b><p class="muted">Нажмите «Добавить сервер» и вставьте ссылку от вашего VPN.</p></div>
    </div>
  {/if}

  <div class="list">
    {#each list as p, i (p.id)}
      {@const t = tunnel(p.id)}
      <div class="srv card" class:main={p.main} class:missing={p.missing}>
        <button class="icon star" class:on={p.main} onclick={() => run(() => api.SetMain(p.id))} title={p.main ? 'Основной сервер' : 'Сделать основным'}>
          <Icon name="star" size={18} />
        </button>
        <div class="grow info">
          <div class="name ellipsis">{hide(p.name)}</div>
          <div class="meta">
            <span class="mono ellipsis">{hide(p.server)}</span>
            {#if p.source}<span class="badge"><Icon name="rss" size={11} />{hide(p.sourceName)}</span>{/if}
            {#if p.missing}<span class="badge warn-b" title="Сервер пропал из подписки, но его используют правила">нет в подписке</span>{/if}
            {#if p.obfs}<span class="badge">{p.obfs}</span>{/if}
            {#if p.pinned}<span class="badge" title="Сертификат проверяется по отпечатку">pin</span>{:else if p.insecure}<span class="badge warn-b" title="Сертификат не проверяется">insecure</span>{/if}
          </div>
          <div class="muted small ellipsis">
            {#if p.usedBy.length}Используют: {p.usedBy.join(', ')}{:else}Не используется правилами{/if}
          </div>
        </div>
        {#if t}
          <div class="state" title={hide(t.message)}>
            <span class="dot {tone(t.state)}"></span>{stateText[t.state] ?? t.state}
            <span class="faint small mono">↓ {fmtBytes(t.recv)}</span>
          </div>
        {/if}
        <button onclick={() => (checking = p)} title="Запустить и проверить: подключение, внешний IP, задержка, UDP"><Icon name="zap" size={15} />Проверить</button>
        <div class="acts">
          <button class="icon" onclick={() => edit(p.id)} title="Изменить"><Icon name="edit" size={16} /></button>
          <button class="icon" onclick={() => run(() => api.CopyURI(p.id), 'Ссылка скопирована (в ней пароль сервера)')} title="Копировать ссылку"><Icon name="copy" size={16} /></button>
          <button class="icon" onclick={() => run(() => api.MoveProfile(p.id, i - 1))} disabled={i === 0} title="Выше"><Icon name="up" size={16} /></button>
          <button class="icon" onclick={() => run(() => api.MoveProfile(p.id, i + 1))} disabled={i === list.length - 1} title="Ниже"><Icon name="down" size={16} /></button>
          <button class="icon danger" onclick={() => remove(p)} title="Удалить"><Icon name="trash" size={16} /></button>
        </div>
      </div>
    {/each}
  </div>
</div>

{#if checking}
  <CheckProfile id={checking.id} name={checking.name} onclose={() => (checking = null)} />
{/if}

{#if editing}
  <ProfileEditor
    profile={editing}
    onclose={() => (editing = null)}
    onsaved={() => {
      editing = null;
      after();
    }}
  />
{/if}

<style>
  .page-wrap { display: grid; gap: 16px; max-width: 1000px; }
  header { align-items: flex-start; }
  .sub { margin: 4px 0 0; }
  textarea { width: 100%; }
  .list { display: grid; gap: 8px; }
  .srv { display: flex; align-items: center; gap: 12px; padding: 12px 14px; }
  .srv.main { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); }
  .srv.missing { border-style: dashed; }
  .star { color: var(--faint); }
  .star.on { color: var(--warn); }
  .star.on :global(svg) { fill: currentColor; }
  .info { display: grid; gap: 3px; }
  .name { font-weight: 650; font-size: 14.5px; }
  .meta { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; font-size: 12px; color: var(--muted); }
  .warn-b { color: var(--warn); }
  .state { display: flex; align-items: center; gap: 6px; font-size: 13px; white-space: nowrap; }
  .acts { display: flex; }
  .empty { display: flex; gap: 16px; align-items: center; color: var(--muted); }
  .empty b { color: var(--text); }
  .empty p { margin: 4px 0 0; }
</style>
