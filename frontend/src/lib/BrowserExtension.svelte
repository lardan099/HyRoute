<script lang="ts">
  // «Настройки» → «Расширение для браузера»: the extension's files, the
  // link to the browsers and the switch that lets it in.
  import { onMount } from 'svelte';
  import { api, errText, type BrowserExtView } from '../api';
  import { ui, hide, settle } from '../state.svelte';
  import Icon from './Icon.svelte';

  let view = $state<BrowserExtView | null>(null);
  let error = $state('');
  let ok = $state('');
  let busy = $state(false);

  async function load() {
    try {
      view = await api.BrowserExtInfo();
    } catch (e) {
      error = errText(e);
    }
  }

  // Re-read when the window comes back: the user was in the browser.
  onMount(() => {
    load();
    const soon = () => load();
    window.addEventListener('focus', soon);
    return () => window.removeEventListener('focus', soon);
  });

  async function run(f: () => Promise<BrowserExtView | void>, done: string) {
    error = '';
    ok = '';
    busy = true;
    try {
      const v = await f();
      if (v) view = v;
      ok = done;
    } catch (e) {
      error = errText(e);
      await load();
    } finally {
      busy = false;
    }
  }

  const install = () => run(() => api.InstallBrowserExt(), 'Готово. Осталось добавить расширение в браузер: шаги ниже.');
  const open = (id: string) => run(() => api.OpenBrowserExtensions(id), 'Путь к папке скопирован.');
  const remove = () =>
    confirm('Отвязать браузеры от HyRoute и удалить папку расширения? Само расширение уберите на странице расширений браузера.') &&
    run(() => api.RemoveBrowserExt(), 'Связь с браузерами удалена.');

  async function copyDir() {
    if (view) await run(() => api.CopyText(view!.dir), 'Скопировано');
  }

  function seenText(t: number): string {
    if (!t) return 'с запуска HyRoute расширение ещё не обращалось';
    const min = Math.round((Date.now() / 1000 - t) / 60);
    if (min < 1) return 'расширение обращалось только что';
    if (min < 60) return `расширение обращалось ${min} мин назад`;
    return `расширение обращалось ${Math.round(min / 60)} ч назад`;
  }

  // The folder may carry the user's name: masked in Privacy mode.
  function hidePath(p: string): string {
    if (!ui.privacy) return p;
    return hide(p.replace(/([\\/]Users[\\/])[^\\/]+/i, '$1***'));
  }
</script>

<section class="card">
  <h2><Icon name="globe" size={17} /> Расширение для браузера</h2>
  <p class="muted small">
    Кнопка HyRoute в Chrome, Edge, Яндекс Браузере, Brave, Opera и Vivaldi. Показывает адреса открытой страницы (и какие не загрузились) и как
    HyRoute их отправляет, а одним нажатием отправляет их через VPN, напрямую или в блок. Сайты попадают в правила «Из браузера: …» в начале
    {ui.expert ? 'активного профиля правил' : 'списка правил'}.{#if ui.expert}
      Связь с HyRoute — через hyroutectl.exe, без открытых портов; список адресов страницы хранится только в памяти браузера.{/if}
  </p>
  {#if !view && !error}<p class="muted small">Загрузка…</p>{/if}
  {#if view}
    {#if !view.host}
      <div class="note warn small">hyroutectl.exe нет рядом с HyRoute.exe: без него расширение не свяжется с HyRoute. Он есть в архиве с программой.</div>
    {/if}
    {#if !view.installed}
      <button class="primary" disabled={busy || !view.host} onclick={install}><Icon name="download" size={15} /> Установить в браузер</button>
    {:else}
      <label class="check">
        <input type="checkbox" checked={view.on} disabled={busy}
          onchange={(e) => settle(e, (el) => run(() => api.SetBrowserExtOn(el.checked), el.checked ? 'Расширение включено' : 'Расширение выключено'), () => view?.on ?? false)} />
        Расширение может смотреть и менять правила
      </label>
      <p class="muted small">{view.on ? seenText(view.seen) : 'Выключено: расширение покажет, что HyRoute его не пускает.'}</p>

      <h3>Как добавить в браузер</h3>
      <ol class="steps small">
        <li>Нажмите свой браузер ниже: откроется страница расширений и папка с расширением, а путь к ней скопируется.</li>
        <li>Включите «Режим разработчика» — переключатель вверху страницы расширений.</li>
        <li>Перетащите папку <b>browser-extension</b> на страницу. Или «Загрузить распакованное расширение» → вставьте путь (Ctrl+V) → «Выбор папки».</li>
        <li>Закрепите значок HyRoute: значок пазла справа от адресной строки → булавка.</li>
      </ol>
      {#if view.browsers.length}
        <div class="row wrap">
          {#each view.browsers as b (b.id)}
            <button disabled={busy || !b.exe} onclick={() => open(b.id)} title={b.linked ? 'Связан с HyRoute' : 'Не связан: нажмите «Установить заново»'}>
              {#if b.linked}<Icon name="check" size={14} />{/if}
              {b.name}
            </button>
          {/each}
        </div>
      {:else}
        <p class="muted small">Браузеры на Chromium не найдены. Откройте страницу расширений вручную (chrome://extensions) и загрузите папку ниже.</p>
      {/if}
      <div class="row">
        <code class="grow path">{hidePath(view.dir)}</code>
        <button onclick={copyDir} disabled={busy}><Icon name="copy" size={15} /> Копировать</button>
      </div>
      <p class="muted small">
        Браузер может напоминать, что расширение установлено в режиме разработчика: так бывает со всеми расширениями не из магазина. HyRoute
        обновляет файлы расширения сам; браузер подхватит их после перезапуска или кнопки «Обновить» на странице расширений. Если перенесли
        HyRoute в другую папку, установите расширение заново.
      </p>
      <div class="row wrap">
        <button disabled={busy || !view.host} onclick={install}><Icon name="refresh" size={15} /> Установить заново</button>
        <button class="danger" disabled={busy} onclick={remove}><Icon name="trash" size={15} /> Удалить связь с браузерами</button>
      </div>
    {/if}
  {/if}
  {#if error}<div class="note error small">{hide(error)}</div>{/if}
  {#if ok}<p class="muted small">{ok}</p>{/if}
</section>

<style>
  h3 {
    margin: 12px 0 4px;
    font-size: 13px;
  }
  .steps {
    margin: 0 0 8px;
    padding-left: 20px;
  }
  .steps li {
    margin: 2px 0;
  }
  .path {
    overflow-wrap: anywhere;
    user-select: all;
  }
  .wrap {
    flex-wrap: wrap;
  }
</style>
