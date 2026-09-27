<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, fmtDateTime, plural, type Subscription, type SubPreview, type MergeStats } from '../api';
  import { hide, settle, ui } from '../state.svelte';

  let { onchange }: { onchange: () => void } = $props();

  let list = $state<Subscription[]>([]);
  let url = $state('');
  let name = $state('');
  let interval = $state('24h');
  let preview = $state<SubPreview | null>(null);
  let checkedURL = $state(''); // the link preview was fetched for
  let autoName = ''; // the title check() put into name
  // The preview (and its token) belongs to the link it was fetched for: once
  // the field holds another link, «Добавить» must not add the old one.
  const shown = $derived(preview && url.trim() === checkedURL ? preview : null);
  let busy = $state('');
  let error = $state('');
  let info = $state('');
  let showNames = $state(false);

  const intervals = [
    { v: 'manual', l: 'Вручную' },
    { v: 'startup', l: 'При запуске' },
    { v: '6h', l: 'Каждые 6 часов' },
    { v: '12h', l: 'Каждые 12 часов' },
    { v: '24h', l: 'Раз в сутки' },
  ];

  async function load() {
    try {
      list = await api.Subscriptions();
    } catch (e) {
      error = errText(e);
    }
  }

  onMount(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  });

  async function step<T>(label: string, f: () => Promise<T>): Promise<T | undefined> {
    busy = label;
    error = '';
    info = '';
    try {
      return await f();
    } catch (e) {
      error = errText(e);
    } finally {
      busy = '';
    }
  }

  async function check() {
    const u = url.trim();
    preview = null;
    const pv = await step('check', () => api.PreviewSubscription(u));
    if (pv) {
      preview = pv;
      checkedURL = u;
      // Keep a name the user typed, not the title of a previous link.
      if (!name || name === autoName) name = autoName = pv.title;
    }
  }

  async function add() {
    const pv = shown;
    if (!pv) return;
    const v = await step('add', () => api.AddSubscription({ token: pv.token, name, enabled: true, interval }));
    if (v) {
      info = `Подписка «${v.name}» добавлена: ${v.profiles} ${plural(v.profiles, 'профиль', 'профиля', 'профилей')}.`;
      url = name = '';
      preview = null;
      await load();
      onchange();
    }
  }

  function statsText(s: MergeStats): string {
    const p = [`новых ${s.added}`, `обновлено ${s.updated}`];
    if (s.removed) p.push(`удалено ${s.removed}`);
    if (s.missingKept) p.push(`оставлено с пометкой «нет в подписке» ${s.missingKept} (их используют правила)`);
    return p.join(', ');
  }

  async function update(s: Subscription) {
    const st = await step('upd:' + s.id, () => api.UpdateSubscription(s.id));
    if (st) info = `«${s.name}» обновлена: ${statsText(st)}.`;
    await load();
    onchange();
  }

  async function rollback(s: Subscription) {
    if (!confirm(`Вернуть предыдущую версию подписки «${hide(s.name)}»?`)) return;
    const st = await step('rb:' + s.id, () => api.RollbackSubscription(s.id));
    if (st) info = `«${s.name}»: возвращена предыдущая версия (${statsText(st)}).`;
    await load();
    onchange();
  }

  // edit reports whether the change was saved. token (a preview's) also
  // changes the link and applies what the preview downloaded.
  async function edit(s: Subscription, patch: Partial<{ name: string; token: string; enabled: boolean; interval: string }>): Promise<boolean> {
    const ok = await step('edit', async () => {
      await api.EditSubscription({ id: s.id, name: patch.name ?? s.name, token: patch.token ?? '', enabled: patch.enabled ?? s.enabled, interval: patch.interval ?? s.interval });
      return true;
    });
    await load();
    return ok === true;
  }

  // changeURL checks the new link the way adding does before it replaces
  // the old one: the saved link is shown only masked, so a mistyped one
  // would lose it for good. The checked download is what gets applied: the
  // link is not downloaded a second time.
  async function changeURL(s: Subscription) {
    const u = prompt(`Новая ссылка подписки «${hide(s.name)}»:`)?.trim();
    if (!u) return;
    const pv = await step('upd:' + s.id, () => api.PreviewSubscription(u));
    if (!pv) return;
    const ok = await edit(s, { token: pv.token });
    onchange();
    if (ok) info = `«${s.name}»: ссылка изменена, профили обновлены.`;
  }

  function rename(s: Subscription) {
    const n = prompt('Название подписки:', s.name);
    if (n && n.trim()) edit(s, { name: n.trim() });
  }

  async function remove(s: Subscription) {
    if (!confirm(`Удалить подписку «${hide(s.name)}»? Профили, которые используют правила, останутся как ручные, остальные будут удалены.`)) return;
    await step('del', () => api.DeleteSubscription(s.id));
    await load();
    onchange();
  }

  function ignoredText(m: Record<string, number> | null): string {
    if (!m) return '';
    return Object.entries(m)
      .map(([k, v]) => `${k}: ${v}`)
      .join(', ');
  }

  function total(m: Record<string, number> | null): number {
    return m ? Object.values(m).reduce((a, b) => a + b, 0) : 0;
  }
</script>

<div class="layout">
  <header>
    <h1>Подписки</h1>
    <p class="muted sub">Ссылка от VPN-сервиса, по которой HyRoute сам получает и обновляет список серверов.</p>
  </header>
  <section class="card">
    <h2>Добавить подписку</h2>
    <p class="muted small">
      Ссылка подписки от вашего VPN-сервиса (вида <code>https://…/sub/…</code>). HyRoute сам заберёт из неё все профили
      <code>hysteria2://</code> и будет обновлять их. Ссылка хранится зашифрованной и в логах не показывается.
    </p>
    <div class="row">
      <input
        class="grow mono"
        type={ui.privacy ? 'password' : 'text'}
        placeholder="https://example.com/sub/…"
        bind:value={url}
        onkeydown={(e) => e.key === 'Enter' && url.trim() && check()}
      />
      <button class="primary" onclick={check} disabled={!url.trim() || busy !== ''}>{busy === 'check' ? 'Загрузка…' : 'Проверить'}</button>
    </div>
    {#if shown}
      <div class="preview">
        <div class="big">
          Найдено {shown.count} {plural(shown.count, 'Hysteria-профиль', 'Hysteria-профиля', 'Hysteria-профилей')}{#if shown.ignoredTotal},
            {shown.ignoredTotal} {plural(shown.ignoredTotal, 'запись', 'записи', 'записей')} других протоколов {plural(shown.ignoredTotal, 'проигнорирована', 'проигнорированы', 'проигнорированы')}
            <span class="muted">({ignoredText(shown.ignored)})</span>{/if}.
        </div>
        {#if shown.traffic}<div class="muted">Трафик: {shown.traffic}</div>{/if}
        {#if shown.base64}<div class="muted small">Формат: base64-список ссылок.</div>{/if}
        <button class="link" onclick={() => (showNames = !showNames)}>{showNames ? 'Скрыть список' : 'Показать профили'}</button>
        {#if showNames}<div class="names">{#each shown.names as n}<span>{hide(n)}</span>{/each}</div>{/if}
        {#each shown.warnings.slice(0, 8) as w}<div class="note warn small">{hide(w)}</div>{/each}
        {#each shown.errors.slice(0, 8) as w}<div class="note error small">{hide(w)}</div>{/each}
        <div class="row">
          <input class="grow" placeholder="Название" bind:value={name} />
          <select bind:value={interval} title="Автообновление">
            {#each intervals as i}<option value={i.v}>{i.l}</option>{/each}
          </select>
          <button class="primary" onclick={add} disabled={busy !== '' || shown.count === 0}>Добавить</button>
          <button onclick={() => (preview = null)}>Отмена</button>
        </div>
      </div>
    {/if}
    {#if error}<div class="note error">{hide(error)}</div>{/if}
    {#if info}<div class="note ok">{hide(info)}</div>{/if}
  </section>

  <section class="card">
    <h2>Мои подписки</h2>
    <p class="muted small">
      Правила ссылаются на профиль по внутреннему ID, поэтому переименование серверов и смена их порядка в подписке правила не ломают.
      Если сервер пропал из подписки, а правило его использует, профиль остаётся с пометкой «нет в подписке» — трафик не
      переводится молча на другой сервер. Неудачное обновление не трогает текущий список; предыдущую версию можно вернуть.
    </p>
    {#if list.length === 0}<p class="muted">Подписок нет.</p>{/if}
    {#each list as s (s.id)}
      <div class="sub-item" class:off={!s.enabled}>
        <div class="row">
          <label class="check" title="Автообновление включено"><input type="checkbox" checked={s.enabled} onchange={(e) => settle(e, (el) => edit(s, { enabled: el.checked }), () => s.enabled)} /></label>
          <div class="grow info">
            <div class="name">{hide(s.name)}</div>
            <div class="muted mono small">{hide(s.url)}</div>
          </div>
          <select value={s.interval} onchange={(e) => settle(e, (el) => edit(s, { interval: el.value }), () => s.interval)} title="Автообновление">
            {#each intervals as i}<option value={i.v}>{i.l}</option>{/each}
          </select>
        </div>
        <div class="actions">
          <button onclick={() => update(s)} disabled={busy !== ''}>{busy === 'upd:' + s.id ? 'Обновление…' : 'Обновить сейчас'}</button>
          {#if s.hasPrevious}<button onclick={() => rollback(s)} disabled={busy !== ''} title="Вернуть предыдущую успешную версию">Откатить</button>{/if}
          <button onclick={() => rename(s)}>Переименовать</button>
          <button onclick={() => changeURL(s)}>Сменить ссылку</button>
          <button class="danger" onclick={() => remove(s)}>Удалить</button>
        </div>
        <div class="meta small">
          <span>Обновлено: {fmtDateTime(s.lastUpdate)}</span>
          <span>Профилей: {s.profiles}{s.missing ? ` (нет в подписке: ${s.missing})` : ''}</span>
          {#if total(s.ignored)}<span class="muted">пропущено других протоколов: {total(s.ignored)}</span>{/if}
          {#if s.traffic}<span>{s.traffic}</span>{/if}
          {#if s.enabled && s.nextAt && !s.nextAt.startsWith('0001')}<span class="muted">следующее: {fmtDateTime(s.nextAt)}</span>{/if}
        </div>
        {#if s.lastError}<div class="note error small">Последняя ошибка ({fmtDateTime(s.lastAttempt)}): {hide(s.lastError)}. Профили не изменены.</div>{/if}
      </div>
    {/each}
  </section>
</div>

<style>
  .layout { display: grid; gap: 16px; max-width: 1000px; }
  .sub { margin: 4px 0 0; }
  .small { font-size: 12px; }
  p.small { margin: 0 0 10px; }
  code { font-family: var(--mono); font-size: 12px; }
  .preview { margin-top: 10px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 6px; display: grid; gap: 6px; }
  .big { font-weight: 600; }
  .names { display: flex; flex-wrap: wrap; gap: 4px 12px; font-size: 12.5px; max-height: 160px; overflow: auto; }
  .link { background: none; border: none; padding: 0; color: var(--accent); cursor: pointer; justify-self: start; }
  .sub-item { border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 10px 12px; margin-bottom: 8px; }
  .sub-item.off { opacity: 0.7; }
  .info { min-width: 0; }
  .actions { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0 0 30px; }
  .name { font-weight: 600; }
  .meta { display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 6px 0 0 30px; }
  .note.small { margin: 6px 0 0; }
</style>
