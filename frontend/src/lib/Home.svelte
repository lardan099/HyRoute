<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errText, fmtBytes, fmtDuration, cleanSettings, type Settings, type SystemInfo, type TunnelStatus } from '../api';
  import { ui, hide, settle, mainProfile } from '../state.svelte';
  import Icon from './Icon.svelte';
  import CheckProfile from './CheckProfile.svelte';

  let { go }: { go: (page: string) => void } = $props();

  let settings = $state<Settings | null>(null);
  let busy = $state(false);
  let error = $state('');
  let checking = $state(false);

  async function loadSettings() {
    try {
      settings = await api.Settings();
    } catch (e) {
      error = errText(e);
    }
  }

  let sys = $state<SystemInfo | null>(null);
  let moving = $state(false);
  // Already where "Перенести" would copy it: only the folder's permissions are wrong.
  const inMoveTarget = $derived(sys != null && sys.programDir.toLowerCase() === sys.moveTarget.toLowerCase());

  onMount(() => {
    loadSettings();
    api.System().then((s) => (sys = s)).catch(() => {});
  });

  async function move() {
    moving = true;
    error = '';
    try {
      await api.MoveToProgramFiles(); // this copy exits, the new one starts
    } catch (e) {
      error = errText(e);
      moving = false;
    }
  }

  const st = $derived(ui.status);
  const online = $derived(st != null && st.state !== 'disconnected' && !(st.state === 'error' && !st.stats));
  const main = $derived(mainProfile());
  const everything = $derived(settings?.defaultAction === 'tunnel');
  const selected = $derived(settings?.defaultAction === 'direct');
  const ruleCount = $derived(settings?.rules?.filter((r) => r.enabled !== false).length ?? 0);

  const tone = $derived.by(() => {
    if (!st || st.state === 'disconnected') return 'off';
    if (st.state === 'error' || st.state === 'tunnel-down') return 'bad';
    if (st.state === 'starting' || st.state === 'connecting' || st.noTunnel) return 'wait';
    return 'ok';
  });

  const title = $derived.by(() => {
    if (!st) return '';
    switch (st.state) {
      case 'disconnected':
        return 'Отключено';
      case 'starting':
        return 'Запуск…';
      case 'connecting':
        return 'Подключение к серверу…';
      case 'tunnel-down':
        return 'Сервер недоступен';
      case 'error':
        return 'Ошибка';
    }
    return st.noTunnel ? 'Включено, но VPN не используется' : 'Подключено';
  });

  const subtitle = $derived.by(() => {
    if (!st) return '';
    if (st.state === 'disconnected') {
      if (st.message) return st.message;
      return ui.profiles.length ? 'Нажмите кнопку, чтобы включить маршрутизацию.' : 'Сначала добавьте сервер.';
    }
    if (st.noTunnel) return 'Правил «через VPN» нет, и всё остальное идёт напрямую. Выберите ниже «Весь трафик» или добавьте правила.';
    if (st.state === 'connected') {
      return everything ? 'Весь трафик идёт через VPN, кроме исключений в правилах.' : 'Через VPN идут только программы и сайты из правил.';
    }
    return st.message;
  });

  async function toggle() {
    busy = true;
    error = '';
    try {
      if (online) await api.Disconnect();
      else await api.Connect();
    } catch (e) {
      error = errText(e);
    }
    busy = false;
  }

  async function reconnect() {
    busy = true;
    error = '';
    try {
      if (online) await api.Reconnect();
      else await api.Connect();
    } catch (e) {
      error = errText(e);
    }
    busy = false;
  }

  async function unblock() {
    error = '';
    try {
      await api.ReleaseKillSwitch();
    } catch (e) {
      error = errText(e);
    }
  }

  // "Всё остальное" may also be "Блок" (set on the Rules page): then
  // neither button is on and either one switches.
  async function setEverything(on: boolean) {
    const want = on ? 'tunnel' : 'direct';
    if (!settings || settings.defaultAction === want) return;
    const next: Settings = JSON.parse(JSON.stringify(settings));
    next.defaultAction = want;
    try {
      await api.SaveSettings(cleanSettings(next, mainProfile()?.id));
      await loadSettings();
    } catch (e) {
      error = errText(e);
    }
  }

  async function pickMain(id: string) {
    try {
      await api.SetMain(id);
      ui.profiles = await api.Profiles();
    } catch (e) {
      error = errText(e);
    }
  }

  function tunnelTone(t: TunnelStatus): string {
    if (t.state === 'connected') return 'ok';
    if (t.state === 'connecting' && t.restarts === 0 && t.rejected === 0) return 'wait';
    return 'bad';
  }

  const tunnelText: Record<string, string> = { connected: 'работает', connecting: 'подключается', failed: 'ошибка', stopped: 'остановлен' };
  const since = $derived(st?.since && !st.since.startsWith('0001') ? Date.now() - new Date(st.since).getTime() : 0);
</script>

<div class="home">
  <section class="hero card tone-{tone}">
    <button class="power" onclick={toggle} disabled={busy || st?.state === 'starting' || (!online && ui.profiles.length === 0)} title={online ? 'Отключить' : 'Подключить'}>
      <Icon name="power" size={38} stroke={2.2} />
    </button>
    <div class="grow">
      <h1>{title}</h1>
      <p class="muted">{hide(subtitle)}</p>
      {#if online && since > 0}<p class="faint small">Работает {fmtDuration(since * 1e6)}{st?.killSwitch === 'armed' ? ' · kill switch включён' : ''}</p>{/if}
      {#if error}<div class="note error">{hide(error)}</div>{/if}
    </div>
  </section>

  {#if st?.killSwitch === 'blocking'}
    <section class="card unsafe">
      <Icon name="shield" size={22} />
      <div class="grow">
        <b>Kill switch закрыл интернет</b>
        <p class="muted small">
          HyRoute закрылся или перестал маршрутизировать трафик без команды «Отключить», поэтому соединения не выпускаются
          напрямую. Работают только локальная сеть и сам HyRoute. Подключитесь снова или откройте интернет.
        </p>
      </div>
      <!-- Off while a start is under way (autoconnect at logon): Reconnect
           would wait for it and then tear the new session down. -->
      <button class="primary" onclick={reconnect} disabled={busy || st.state === 'starting' || ui.profiles.length === 0}>Подключиться</button>
      <button onclick={unblock}>Открыть интернет</button>
    </section>
  {:else if st?.killSwitchError}
    <div class="note warn">Kill switch не включился: {hide(st.killSwitchError)}</div>
  {/if}

  {#if sys && !sys.protectedLocation && inMoveTarget}
    <section class="card unsafe">
      <Icon name="alert" size={22} />
      <div class="grow">
        <b>Папку HyRoute могут менять программы без прав администратора</b>
        <p class="muted small">
          {sys.programDir} — в Program Files, но права этой папки или файлов в ней разрешают менять их без запроса прав. HyRoute работает с правами
          администратора, поэтому оставьте запись и изменение только администраторам: свойства папки и HyRoute.exe, вкладка «Безопасность». До
          этого автозапуск с Windows недоступен.
        </p>
      </div>
    </section>
  {:else if sys && !sys.protectedLocation}
    <section class="card unsafe">
      <Icon name="alert" size={22} />
      <div class="grow">
        <b>HyRoute запущен из папки, в которую может писать любая программа</b>
        <p class="muted small">
          {sys.programDir}. HyRoute работает с правами администратора, поэтому его лучше держать в Program Files: туда без запроса прав ничего не
          записать. HyRoute скопирует себя в {sys.moveTarget}, добавит ярлык в меню «Пуск» и перезапустится оттуда. Настройки, серверы и правила
          останутся.
        </p>
      </div>
      <button class="primary" onclick={move} disabled={moving}>{moving ? 'Переношу…' : 'Перенести'}</button>
    </section>
  {/if}

  {#if ui.profiles.length === 0}
    <section class="card start">
      <h2>С чего начать</h2>
      <ol>
        <li>
          <b>Добавьте сервер.</b> Вставьте ссылку <code>hysteria2://…</code> от вашего VPN или ссылку подписки.
          <div class="row"><button class="primary" onclick={() => go('servers')}><Icon name="plus" size={16} />Добавить сервер</button><button onclick={() => go('subs')}><Icon name="rss" size={16} />Добавить подписку</button></div>
        </li>
        <li><b>Решите, что пускать через VPN:</b> весь трафик или только нужные программы и сайты.</li>
        <li><b>Нажмите кнопку включения.</b></li>
      </ol>
    </section>
  {:else}
    <div class="grid">
      <section class="card">
        <h2>Что идёт через VPN</h2>
        <div class="seg wide">
          <button class:on={everything} onclick={() => setEverything(true)}><Icon name="globe" size={16} />Весь трафик</button>
          <button class:on={selected} onclick={() => setEverything(false)}><Icon name="rules" size={16} />Только выбранное</button>
        </div>
        <p class="muted small explain">
          {#if everything}
            Всё идёт через основной сервер. В правилах можно указать исключения: что пускать напрямую или через другой сервер.
          {:else if selected}
            Через VPN идут только программы и сайты из правил, остальное — напрямую, как без VPN.
          {:else if settings}
            Через VPN идут только программы и сайты из правил, а всё остальное блокируется: так выбрано в «Правила → Всё остальное».
          {/if}
        </p>
        <button class="ghost" onclick={() => go('rules')}>
          <Icon name="rules" size={16} />{ruleCount ? `Правила: ${ruleCount}` : 'Добавить правила'}<Icon name="arrow" size={15} />
        </button>
      </section>

      <section class="card">
        <h2>Основной сервер</h2>
        <select class="main-select" value={main?.id ?? ''} onchange={(e) => settle(e, (el) => pickMain(el.value), () => main?.id ?? '')}>
          {#each ui.profiles as p (p.id)}<option value={p.id}>{hide(p.name)}{p.missing ? ' (нет в подписке)' : ''}</option>{/each}
        </select>
        <p class="muted small explain">Через него идёт «весь трафик» и правила, где сервер не выбран явно.</p>
        <div class="row">
          <button onclick={() => (checking = true)} disabled={!main}><Icon name="zap" size={16} />Проверить сервер</button>
          <button class="ghost" onclick={() => go('servers')}>Все серверы<Icon name="arrow" size={15} /></button>
        </div>
      </section>
    </div>

    {#if st?.tunnels?.length}
      <section class="card">
        <h2>Работающие серверы</h2>
        <div class="tunnels">
          {#each st.tunnels as t (t.id)}
            <div class="tunnel">
              <span class="dot {tunnelTone(t)}"></span>
              <div class="grow">
                <div class="ellipsis"><b>{hide(t.name)}</b> <span class="muted small">{tunnelText[t.state] ?? t.state}</span></div>
                {#if t.message && t.state !== 'connected'}<div class="small bad-text">{hide(t.message)}</div>{/if}
              </div>
              {#if t.rejected}<span class="badge" title="Соединений отклонено, пока сервер был недоступен">отклонено {t.rejected}</span>{/if}
              <span class="small muted mono">↑ {fmtBytes(t.sent)} ↓ {fmtBytes(t.recv)}</span>
            </div>
          {/each}
        </div>
      </section>
    {/if}

    {#if st?.warnings?.length}
      <section class="card">
        <h2>Требует внимания</h2>
        {#each st.warnings as w}<div class="note warn">Правило «{hide(w.rule)}»: {hide(w.text)}</div>{/each}
        <button onclick={() => go('rules')}>Открыть правила</button>
      </section>
    {/if}
  {/if}
</div>

{#if checking && main}
  <CheckProfile id={main.id} name={main.name} onclose={() => (checking = false)} />
{/if}

<style>
  .home { display: grid; gap: 16px; max-width: 980px; }

  .hero { display: flex; align-items: center; gap: 26px; padding: 26px 28px; }
  .hero h1 { margin-bottom: 4px; }
  .hero p { margin: 0; }
  .hero .note { margin-top: 10px; }

  .power {
    width: 92px;
    height: 92px;
    border-radius: 50%;
    flex: none;
    background: var(--surface-2);
    color: var(--muted);
    border: 2px solid var(--border);
    transition: transform 0.12s, background 0.2s, color 0.2s, box-shadow 0.2s;
  }
  .power:hover:not(:disabled) { transform: scale(1.03); }
  .tone-ok .power { background: var(--accent); color: #fff; border-color: transparent; box-shadow: 0 8px 28px color-mix(in srgb, var(--accent) 45%, transparent); }
  .tone-wait .power { color: var(--warn); border-color: var(--warn); }
  .tone-bad .power { color: var(--block); border-color: var(--block); }
  :global(:root[data-accent='rainbow']) .tone-ok .power {
    background: conic-gradient(from 0deg, #ff4d4d, #ffb84d, #f5f542, #4dd97a, #4db8ff, #a64dff, #ff4dd2, #ff4d4d);
    animation: spin 6s linear infinite;
  }
  :global(:root[data-accent='rainbow']) .tone-ok .power :global(svg) { animation: spin 6s linear infinite reverse; }
  @keyframes spin { to { transform: rotate(360deg); } }

  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .seg.wide { display: flex; }
  .seg.wide button { flex: 1; }
  .explain { margin: 10px 0 12px; min-height: 36px; }
  .main-select { width: 100%; font-size: 15px; padding: 9px 12px; }

  .start ol { margin: 0; padding-left: 20px; display: grid; gap: 12px; }
  .start .row { margin-top: 8px; }
  code { font-family: var(--mono); font-size: 12px; background: var(--surface-2); padding: 1px 5px; border-radius: 4px; }

  .tunnels { display: grid; gap: 4px; }
  .tunnel { display: flex; align-items: center; gap: 12px; padding: 8px 10px; border-radius: var(--radius-sm); }
  .tunnel:hover { background: var(--surface-2); }
  .bad-text { color: var(--block); }

  @media (max-width: 900px) {
    .grid { grid-template-columns: 1fr; }
  }
  .unsafe { display: flex; gap: 14px; align-items: center; border-color: color-mix(in srgb, var(--warn) 50%, var(--border)); }
  .unsafe > :global(svg) { color: var(--warn); flex: none; }
  .unsafe p { margin: 4px 0 0; }
</style>
