<script lang="ts">
  // «Настройки» → «DNS»: DNS by the rules, an encrypted server for direct
  // names, browser DoH blocking. Saves at once; applies at once.
  import { onMount } from 'svelte';
  import { api, errText, dnsErrorText, type DNSConfig, type DNSHealth, type DNSView } from '../api';
  import { ui, hide, settle, profileName, trackUnsaved } from '../state.svelte';
  import Icon from './Icon.svelte';
  import { canPause as portalPausable } from './HomeDNS.svelte';

  let view = $state<DNSView | null>(null);
  // The configuration as shown: the last saved one with the clicks queued
  // since applied in order.
  let cfg = $state<DNSConfig | null>(null);
  let loadError = $state('');
  let error = $state('');
  let ok = $state('');
  let busy = $state(false);
  let customTunnel = $state('');
  let customDirect = $state('');
  // «Свой…» chosen in a select but not saved yet (it needs an address).
  let pickTunnel = $state('');
  let pickDirect = $state('');
  let saving: Promise<unknown> = Promise.resolve();
  let pending = 0; // saves queued: a copy read meanwhile is older than the screen

  async function load() {
    try {
      const v = await api.DNS();
      view = v;
      if (pending === 0) {
        cfg = JSON.parse(JSON.stringify(v.config));
        customTunnel = v.config.tunnel.preset === 'custom' ? (v.config.tunnel.url ?? '') : customTunnel;
        customDirect = v.config.direct.preset === 'custom' ? (v.config.direct.url ?? '') : customDirect;
      }
      loadError = '';
    } catch (e) {
      loadError = errText(e);
    }
  }

  onMount(load);

  // Saves go one after another in click order, each built on the one
  // before (not on a copy read while it ran); the saved settings are read
  // back after the last.
  async function save(patch: Partial<DNSConfig>) {
    if (!cfg) return;
    const next: DNSConfig = { ...cfg, ...patch };
    cfg = next;
    error = ok = '';
    pending++;
    busy = true;
    const job = saving.then(() => api.SaveDNS(next));
    saving = job.catch(() => {});
    let failed = false;
    try {
      await job;
      ok = 'Сохранено';
    } catch (e) {
      error = errText(e);
      failed = true;
    }
    if (--pending === 0) {
      busy = false;
      // A refused address stays in its field to be corrected.
      if (!failed) pickTunnel = pickDirect = '';
      await load();
    }
  }

  const broken = $derived(!!view?.error);
  const off = $derived(!view || broken || busy);
  const tunnelPresets = $derived(view?.presets.filter((p) => p.tunnel) ?? []);
  const directPresets = $derived(view?.presets.filter((p) => p.direct) ?? []);
  const tunnelSel = $derived(pickTunnel || cfg?.tunnel.preset || 'cloudflare');
  const directSel = $derived(pickDirect || cfg?.direct.preset || 'cloudflare');
  // backup: a typed custom address not saved yet.
  const savedURL = (u: { preset: string; url?: string } | undefined) => (u?.preset === 'custom' ? (u.url ?? '').trim() : '');
  trackUnsaved(
    () =>
      !!view &&
      ((tunnelSel === 'custom' && customTunnel.trim() !== savedURL(view.config.tunnel)) ||
        (directSel === 'custom' && customDirect.trim() !== savedURL(view.config.direct))),
  );

  function chooseTunnel(id: string) {
    if (id === 'custom') {
      pickTunnel = 'custom';
      return customTunnel.trim() ? save({ tunnel: { preset: 'custom', url: customTunnel.trim() } }) : Promise.resolve();
    }
    pickTunnel = '';
    return save({ tunnel: { preset: id } });
  }

  function chooseDirect(id: string) {
    if (id === 'custom') {
      pickDirect = 'custom';
      return customDirect.trim() ? save({ direct: { preset: 'custom', url: customDirect.trim() } }) : Promise.resolve();
    }
    pickDirect = '';
    return save({ direct: { preset: id } });
  }

  const st = $derived(ui.status);
  const online = $derived(!!st && st.state !== 'disconnected' && !(st.state === 'error' && !st.stats));
  const anyOn = $derived(!!cfg && (cfg.byRules || cfg.blockBrowserDoH || cfg.direct.preset !== ''));

  // «За это подключение: …» (parts with 0 left out).
  const counters = $derived.by(() => {
    const s = st?.stats;
    if (!online || !anyOn || !s) return '';
    const parts: string[] = [];
    const add = (n: number | undefined, label: string) => {
      if (n) parts.push(`${label} — ${n}`);
    };
    add(s.dnsTunnel, 'через VPN');
    if (cfg?.direct.preset) add(s.dnsDirect, 'напрямую по DoH');
    add(s.dnsBlocked, 'заблокировано');
    add(s.dnsDoH, 'DoH браузеров');
    add(s.dnsFailed, 'не разрешено');
    return parts.length ? `За это подключение: ${parts.join(', ')}.` : '';
  });

  // A tunnel's resolver that is down while the tunnel works.
  function tunnelUp(h: DNSHealth): boolean {
    return !!st?.tunnels.some((t) => t.id === h.profile && t.state === 'connected');
  }
  const health = $derived(online ? (st?.dns?.health ?? []).filter((h) => h.via === 'direct' || tunnelUp(h)) : []);
  const retry = (h: DNSHealth) => (h.retryIn <= 0 ? 'Проверка сейчас.' : `Проверка повторится через ${h.retryIn} с.`);

  const systemDoH = $derived(online && !!cfg && (cfg.byRules || cfg.direct.preset !== '') && (st?.stats?.systemDoH ?? 0) > 0);
  // The captive-portal pause: DNS by the rules on and every tunnel the
  // rules use down (Home's predicate).
  const pauseLeft = $derived(st?.dns?.pauseLeft ?? 0);
  const canPause = $derived(portalPausable(st));
  let pausing = $state(false);

  async function pause(f: () => Promise<void>) {
    error = ok = '';
    pausing = true;
    try {
      await f();
      ui.status = await api.Status();
    } catch (e) {
      error = errText(e);
    }
    pausing = false;
  }
</script>

<section class="card" id="dns">
  <h2><Icon name="globe" size={17} /> DNS</h2>
  {#if loadError}
    <div class="note error">{hide(loadError)}</div>
  {:else if !view || !cfg}
    <p class="muted small">Загрузка…</p>
  {:else}
    {#if broken}
      <div class="note error">
        ⛔ dns.json не загружен: {hide(view.error)}. Настройки DNS выключены; файл не перезаписывается — исправьте или удалите его и перезапустите
        HyRoute.
      </div>
    {/if}
    {#if error}<div class="note error">{hide(error)}</div>{/if}
    {#if ok}<div class="note ok">{ok}</div>{/if}

    <div class="opt">
      <label class="check">
        <input type="checkbox" checked={cfg.byRules} disabled={off} onchange={(e) => settle(e, (el) => save({ byRules: el.checked }), () => cfg?.byRules ?? false)} />
        DNS по правилам
      </label>
      <p class="muted small">
        Имена сайтов, которые правила ведут через VPN, HyRoute разрешает через тот же сервер: провайдер не видит запрос и не может подменить
        ответ. Сайты из правил «блок» не разрешаются вовсе. Остальные имена — как раньше.
      </p>
      {#if cfg.byRules}
        <div class="sub">
          <div class="field">
            <label for="dns-tunnel">DNS-сервер для VPN</label>
            <select id="dns-tunnel" value={tunnelSel} disabled={off} onchange={(e) => settle(e, (el) => chooseTunnel(el.value), () => tunnelSel)}>
              {#each tunnelPresets as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
              <option value="custom">Свой…</option>
            </select>
          </div>
          {#if tunnelSel === 'custom'}
            <div class="row custom">
              <input
                class="grow"
                placeholder="https://…/dns-query или tls://…"
                aria-label="Адрес своего DNS-сервера для VPN"
                readonly={ui.privacy}
                disabled={off}
                value={ui.privacy ? hide(customTunnel) : customTunnel}
                oninput={(e) => (customTunnel = (e.currentTarget as HTMLInputElement).value)}
                onkeydown={(e) => e.key === 'Enter' && !ui.privacy && save({ tunnel: { preset: 'custom', url: customTunnel.trim() } })}
              />
              <button disabled={off || ui.privacy} onclick={() => save({ tunnel: { preset: 'custom', url: customTunnel.trim() } })}>Сохранить</button>
            </div>
            {#if ui.privacy}<p class="muted small">Адрес скрыт: выключите «Скрыть данные», чтобы изменить.</p>{/if}
            {#if !ui.privacy && customTunnel.trim().toLowerCase().startsWith('tcp://')}
              <p class="muted small">tcp:// не шифруется: запрос защищён только на пути до сервера VPN, а дальше его видно.</p>
            {/if}
          {/if}
          <p class="muted small">Запрос уходит через VPN к этому серверу (у своего сервера — по протоколу из адреса). Если VPN недоступен, имя не разрешается: напрямую запрос не уходит.</p>
          <label class="check">
            <input type="checkbox" checked={!cfg.ignoreAddrRules} disabled={off}
              onchange={(e) => settle(e, (el) => save({ ignoreAddrRules: !el.checked }), () => !(cfg?.ignoreAddrRules ?? false))} />
            Сверяться с правилами по IP и geoip
          </label>
          <p class="muted small">
            Если выше есть правило «Напрямую» по IP или geoip (например, geoip:ru), имя разрешается как раньше, через DNS-сервер сети. Иначе DNS
            через VPN может вернуть зарубежный адрес, и сайт пойдёт через VPN, а не напрямую. Выключите, чтобы и такие имена разрешались через VPN.
          </p>
        </div>
      {/if}
    </div>

    <div class="opt">
      <label class="check">
        <input type="checkbox" checked={cfg.direct.preset !== ''} disabled={off}
          onchange={(e) => settle(e, (el) => save({ direct: el.checked ? { preset: 'cloudflare' } : { preset: '' } }), () => cfg?.direct.preset !== '')} />
        Шифровать прямые DNS-запросы
      </label>
      <p class="muted small">
        Запросы, которые идут напрямую, HyRoute отправляет сам по DoH или DoT вместо DNS-сервера сети. Если сервер не отвечает, запрос уходит
        DNS-серверу сети, как без этой настройки.
      </p>
      {#if cfg.direct.preset !== ''}
        <div class="sub">
          <div class="field">
            <label for="dns-direct">DNS-сервер</label>
            <select id="dns-direct" value={directSel} disabled={off} onchange={(e) => settle(e, (el) => chooseDirect(el.value), () => directSel)}>
              {#each directPresets as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
              <option value="custom">Свой…</option>
            </select>
          </div>
          {#if directSel === 'custom'}
            <div class="row custom">
              <input
                class="grow"
                placeholder="https://…/dns-query или tls://…"
                aria-label="Адрес своего DNS-сервера"
                readonly={ui.privacy}
                disabled={off}
                value={ui.privacy ? hide(customDirect) : customDirect}
                oninput={(e) => (customDirect = (e.currentTarget as HTMLInputElement).value)}
                onkeydown={(e) => e.key === 'Enter' && !ui.privacy && save({ direct: { preset: 'custom', url: customDirect.trim() } })}
              />
              <button disabled={off || ui.privacy} onclick={() => save({ direct: { preset: 'custom', url: customDirect.trim() } })}>Сохранить</button>
            </div>
            {#if ui.privacy}<p class="muted small">Адрес скрыт: выключите «Скрыть данные», чтобы изменить.</p>{/if}
          {/if}
        </div>
      {/if}
    </div>

    <div class="opt">
      <label class="check">
        <input type="checkbox" checked={cfg.blockBrowserDoH} disabled={off}
          onchange={(e) => settle(e, (el) => save({ blockBrowserDoH: el.checked }), () => cfg?.blockBrowserDoH ?? false)} />
        Не давать браузерам обходить DNS
      </label>
      <p class="muted small">
        Chrome, Edge, Firefox, Яндекс Браузер и другие не смогут пользоваться встроенным «безопасным DNS» (DoH) и спросят Windows — так HyRoute
        узнаёт сайты. Если в браузере вручную выбран поставщик безопасного DNS, сайты в нём перестанут открываться: верните в браузере настройку
        по умолчанию.
      </p>
      <div class="sub">
        <label class="check" class:dim={!cfg.blockBrowserDoH}>
          <input type="checkbox" checked={cfg.stripECH} disabled={off || !cfg.blockBrowserDoH}
            onchange={(e) => settle(e, (el) => save({ stripECH: el.checked }), () => cfg?.stripECH ?? false)} />
          Отключать ECH
        </label>
        <p class="muted small">
          Браузер не получит ключи ECH и покажет имя сайта в соединении, поэтому правила для сайтов сработают. Имя сайта увидит и провайдер, если
          соединение идёт напрямую.
        </p>
      </div>
    </div>

    {#if counters}<p class="small">{counters}</p>{/if}
    {#if online && st?.dns?.notApplied}<div class="note warn">⚠ Настройки DNS не применены к подключению: имена сайтов спрашиваются у DNS-сервера сети, как без них. Переподключитесь.</div>{/if}
    {#each health as h}
      {#if h.via === 'tunnel'}
        <div class="note warn">
          ⚠ DNS-сервер для VPN ({h.upstream}) не отвечает через {profileName(h.profile ?? '')}: сайты через VPN не открываются.
          {dnsErrorText(h.kind, h.code)}. {retry(h)}
        </div>
      {:else}
        <div class="note warn">⚠ DNS-сервер ({h.upstream}) не отвечает: прямые запросы идут DNS-серверу сети. {dnsErrorText(h.kind, h.code)}.</div>
      {/if}
    {/each}
    {#if systemDoH}
      <div class="note warn">
        ⚠ Windows шифрует DNS-запросы (DoH/DoT). HyRoute их не видит, и настройки DNS на них не действуют. Выключите шифрование в «Параметры → Сеть
        и Интернет → свойства подключения → Назначение DNS-сервера».
      </div>
    {/if}
    {#if pauseLeft > 0}
      <div class="note info row">
        <span class="grow">Имена через VPN сейчас разрешаются напрямую, пока VPN недоступен — ещё {Math.ceil(pauseLeft / 60)} мин.</span>
        <button class="link" disabled={pausing} onclick={() => pause(() => api.CancelDNSPause())}>Отменить</button>
      </div>
    {:else if canPause}
      <div class="portal">
        <button class="small" disabled={pausing} onclick={() => pause(() => api.PauseDNSTunnel())}>Разрешить имена напрямую на 5 минут</button>
        <p class="muted small">
          Для входа в сеть с авторизацией (гостиница, аэропорт): пока VPN недоступен, имена сайтов через VPN будут спрашиваться у DNS-сервера сети —
          он их увидит.
        </p>
      </div>
    {/if}
    <p class="muted small foot">
      {#if online}
        Действует сразу. При изменениях и при отключении HyRoute очищает кэш DNS Windows, чтобы программы спросили имена заново.
      {:else}
        Включится при подключении. Сейчас DNS работает как без HyRoute.
      {/if}
    </p>
  {/if}
</section>

<style>
  h2 { display: flex; align-items: center; gap: 8px; }
  p { margin: 4px 0 10px; user-select: text; }
  .opt { margin-bottom: 8px; }
  .sub { margin: 0 0 8px 26px; }
  .field { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin: 4px 0 8px; }
  .field select { min-width: 220px; }
  .custom { margin: 0 0 6px; }
  .custom input { min-width: 240px; }
  .dim { opacity: 0.6; }
  .portal { margin: 8px 0; }
  .foot { margin-top: 12px; }
</style>
