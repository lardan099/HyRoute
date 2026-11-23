<script lang="ts">
  import { api, errText, type Profile } from '../api';
  import { ui, hide } from '../state.svelte';
  import { trackUnsaved } from '../state.svelte'; // backup

  // sourceName is the subscription the server comes from ('' for a server
  // added by hand).
  let {
    profile,
    sourceName = '',
    onclose,
    onsaved,
  }: { profile: Profile; sourceName?: string; onclose: () => void; onsaved: () => void } = $props();

  // Edit a deep copy of the initial value; untouched advanced fields
  // (quic, congestion, ...) are kept.
  // svelte-ignore state_referenced_locally
  let p = $state<Profile>(JSON.parse(JSON.stringify(profile)));
  trackUnsaved(() => JSON.stringify(p) !== JSON.stringify(profile)); // backup
  let showSecrets = $state(false);
  let error = $state('');
  let saving = $state(false);
  // Privacy mode: the name, address and SNI are shown masked and read-only
  // until «Показать и редактировать», again once the mode is turned off
  // and on (as NetRuleEditor).
  let revealed = $state(false);
  $effect(() => {
    if (!ui.privacy) revealed = false;
  });
  const ro = $derived(ui.privacy && !revealed);
  const ingressProfiles = $derived(ui.profiles.filter((server) => server.id !== p.id && !server.via));
  const ingressGroups = $derived.by(() => {
    const direct = new Set(ingressProfiles.map((server) => server.id));
    return ui.groups.filter((group) => group.memberViews.some((member) => direct.has(member.id)));
  });
  // A press that started in a field and ended on the backdrop is not a
  // click on the backdrop.
  let downOnBackdrop = false;

  // validPin mirrors hysteria.ValidPin: a hex SHA-256, with the ':' or '-'
  // separators Hysteria strips. Any other value never matches a
  // certificate, and the server would never connect.
  function validPin(s: string): boolean {
    return /^[0-9a-f]{64}$/i.test(s.replace(/[:-]/g, ''));
  }
  const pinBad = $derived(!!p.tls.pinSHA256?.trim() && !validPin(p.tls.pinSHA256.trim()));

  // VLESS (run by Xray): its settings live in p.vless; switching keeps
  // what was typed for the other protocol until the save, where the
  // backend drops it.
  const isVLESS = $derived(p.protocol === 'vless');
  // AmneziaWG: its settings live in p.awg, the endpoint in host and ports.
  const isAWG = $derived(p.protocol === 'awg');
  function setProtocol(proto: string) {
    p.protocol = proto;
    if (proto === 'vless') {
      p.vless ??= { id: '', security: 'reality' };
      if (/[,-]/.test(p.ports)) p.ports = '443';
    }
    if (proto === 'awg') {
      p.awg ??= { privateKey: '', publicKey: '', address: '' };
      if (/[,-]/.test(p.ports) || !p.id) p.ports = '51820';
    }
  }
  // v is p.vless for the VLESS fields (always set while isVLESS).
  const v = $derived(p.vless ?? { id: '' });
  // Xray's fingerprints a person picks from; the field takes any other.
  const fingerprints = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized'];
  const vPinBad = $derived(
    !!v.pinSHA256?.trim() &&
      v.pinSHA256
        .split(',')
        .map((x) => x.trim())
        .some((x) => x && !validPin(x)),
  );

  async function save() {
    error = '';
    // A pasted value often brings a space along: Hysteria compares the SNI
    // and the pin as they are, and the backend trims only the address.
    if (p.tls.sni) p.tls.sni = p.tls.sni.trim();
    if (p.tls.pinSHA256) p.tls.pinSHA256 = p.tls.pinSHA256.trim();
    if (!isVLESS && !isAWG && pinBad || isVLESS && vPinBad) {
      error = 'Отпечаток (pinSHA256) должен быть SHA-256 сертификата: 64 шестнадцатеричных символа (можно через «:»). С другим значением сервер не подключится.';
      return;
    }
    if (isVLESS && p.vless) {
      for (const k of ['id', 'sni', 'publicKey', 'shortId', 'host', 'path', 'serviceName', 'pinSHA256'] as const) {
        const x = p.vless[k];
        if (typeof x === 'string') p.vless[k] = x.trim();
      }
    }
    saving = true;
    try {
      if (!p.obfs.type) p.obfs = {};
      await api.SaveProfile(p);
      onsaved();
    } catch (e) {
      error = errText(e);
    }
    saving = false;
  }
</script>

{#snippet ingressPicker()}
  <label for="pe-via">Подключаться через</label>
  <select id="pe-via" value={p.via ?? ''} onchange={(e) => (p.via = e.currentTarget.value || undefined)}
    title="Первый VPN подключается к серверу этого профиля">
    <option value="">Напрямую</option>
    {#if p.via && !ingressProfiles.some((server) => server.id === p.via) && !ingressGroups.some((group) => group.id === p.via)}
      <option value={p.via}>Первый VPN недоступен</option>
    {/if}
    {#if ingressGroups.length}
      <optgroup label="Группы">
        {#each ingressGroups as group (group.id)}
          <option value={group.id}>{hide(group.name)}</option>
        {/each}
      </optgroup>
    {/if}
    {#if ingressProfiles.length}
      <optgroup label="Серверы">
        {#each ingressProfiles as server (server.id)}
          <option value={server.id}>{hide(server.name)} · {hide(server.server)}</option>
        {/each}
      </optgroup>
    {/if}
  </select>
{/snippet}

<div
  class="backdrop"
  role="presentation"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && onclose()}
>
  <div class="dialog" role="dialog" aria-modal="true">
    <h2>{p.balance ? hide(p.name) : p.id ? 'Сервер' : 'Новый сервер'}</h2>
    {#if sourceName && isVLESS && !p.balance}
      <div class="note warn">
        Сервер из подписки «{hide(sourceName)}». При обновлении сохраняются выбор первого VPN и настройка «Резолвить адрес».
        Остальные параметры снова берутся из подписки.
      </div>
    {:else if sourceName && !p.balance}
      <div class="note warn">
        Сервер из подписки «{hide(sourceName)}». При её обновлении название, адрес, пароль, обфускация, SNI, отпечаток и
        «insecure» снова возьмутся из ссылки подписки, так что их правки здесь временные. Сохраняются первый VPN, скорость,
        «Резолвить адрес» и интервал port hopping, если ссылка подписки не задаёт свой.
      </div>
    {/if}
    {#if ro && !p.balance}
      <div class="note info row">
        <span class="grow">Включено «Скрыть данные»: название, адрес и SNI скрыты.</span>
        <button onclick={() => (revealed = true)}>Показать и редактировать</button>
      </div>
    {/if}
    {#if p.balance}
      <div class="grid">{@render ingressPicker()}</div>
    {:else}
    <div class="grid">
      <label for="pe-proto">Протокол</label>
      <div class="row">
        <select id="pe-proto" value={p.protocol ?? ''} onchange={(e) => setProtocol((e.currentTarget as HTMLSelectElement).value)}>
          <option value="">Hysteria 2</option>
          <option value="vless">VLESS (Xray)</option>
          <option value="awg">AmneziaWG / WireGuard</option>
        </select>
      </div>

      <label for="pe-name">Название</label>
      {#if ro}
        <div class="ro" id="pe-name">{hide(p.name) || '—'}</div>
      {:else}
        <input id="pe-name" bind:value={p.name} placeholder="например, 🇳🇱 Нидерланды" />
      {/if}

      <label for="pe-host">Адрес и порт</label>
      <div class="row">
        {#if ro}
          <div class="ro grow" id="pe-host">{hide(p.host) || '—'}</div>
        {:else}
          <input id="pe-host" class="grow" bind:value={p.host} placeholder="example.com или IP" />
        {/if}
        {#if isVLESS}
          <input bind:value={p.ports} style="width: 170px" placeholder="443" title="Порт сервера" />
        {:else if isAWG}
          <input bind:value={p.ports} style="width: 170px" placeholder="51820" title="UDP-порт сервера" />
        {:else}
          <input bind:value={p.ports} style="width: 170px" placeholder="443 или 443,20000-50000" title="Порт или диапазоны для port hopping" />
        {/if}
      </div>
      {@render ingressPicker()}
    {#if isAWG && p.awg}
      <label for="pe-awg-key">Приватный ключ</label>
      <div class="row">
        <input id="pe-awg-key" class="grow mono" type={showSecrets ? 'text' : 'password'} bind:value={p.awg.privateKey} placeholder="PrivateKey из [Interface]" />
        <label class="check"><input type="checkbox" bind:checked={showSecrets} /> показать</label>
      </div>

      <label for="pe-awg-pub">Ключ сервера</label>
      <input id="pe-awg-pub" class="mono" bind:value={p.awg.publicKey} placeholder="PublicKey из [Peer]" />

      <label for="pe-awg-addr">Адрес в VPN</label>
      <div class="row">
        <input id="pe-awg-addr" class="grow" bind:value={p.awg.address} placeholder="Address, например 10.8.1.2/32" />
        <input class="grow" bind:value={p.awg.dns} placeholder="DNS, по умолчанию 1.1.1.1" title="DNS-серверы, которые спрашиваются через туннель" />
      </div>

      <label for="pe-awg-jc">Мусорные пакеты</label>
      <div class="row">
        <input id="pe-awg-jc" class="num" type="number" min="0" max="128" bind:value={p.awg.jc} placeholder="Jc" title="Jc: сколько мусорных пакетов перед рукопожатием" />
        <input class="num" type="number" min="0" bind:value={p.awg.jmin} placeholder="Jmin" title="Jmin: наименьший размер" />
        <input class="num" type="number" min="0" bind:value={p.awg.jmax} placeholder="Jmax" title="Jmax: наибольший размер" />
      </div>

      <label for="pe-awg-s1">Дополнение S1–S4</label>
      <div class="row">
        <input id="pe-awg-s1" class="num" type="number" min="0" bind:value={p.awg.s1} placeholder="S1" title="S1: к пакету начала рукопожатия" />
        <input class="num" type="number" min="0" bind:value={p.awg.s2} placeholder="S2" title="S2: к ответу на рукопожатие" />
        <input class="num" type="number" min="0" bind:value={p.awg.s3} placeholder="S3" title="S3: к пакету cookie" />
        <input class="num" type="number" min="0" bind:value={p.awg.s4} placeholder="S4" title="S4: к пакетам с данными" />
      </div>

      <label for="pe-awg-h1">Заголовки H1–H4</label>
      <div class="row">
        <input id="pe-awg-h1" class="grow mono" bind:value={p.awg.h1} placeholder="H1" title="Число или диапазон «от-до»" />
        <input class="grow mono" bind:value={p.awg.h2} placeholder="H2" title="Число или диапазон «от-до»" />
        <input class="grow mono" bind:value={p.awg.h3} placeholder="H3" title="Число или диапазон «от-до»" />
        <input class="grow mono" bind:value={p.awg.h4} placeholder="H4" title="Число или диапазон «от-до»" />
      </div>
      <span></span>
      <p class="muted small hint">Обфускация должна совпадать с сервером. Проще всего добавить сервер из конфига .conf или ключа vpn:// — тогда всё заполнится само. Без этих параметров это обычный WireGuard.</p>
    {:else if isVLESS && p.vless}
      <label for="pe-uuid">UUID</label>
      <div class="row">
        <input id="pe-uuid" class="grow mono" type={showSecrets ? 'text' : 'password'} bind:value={p.vless.id} placeholder="id пользователя" />
        <label class="check"><input type="checkbox" bind:checked={showSecrets} /> показать</label>
      </div>

      <label for="pe-sec">Защита</label>
      <div class="row">
        <select id="pe-sec" bind:value={p.vless.security} title="Без защиты Xray подключается только к адресам локальной сети или с шифрованием VLESS">
          <option value="reality">REALITY</option>
          <option value="tls">TLS</option>
          <option value="">нет</option>
        </select>
        <select bind:value={p.vless.flow} title="flow">
          <option value="">без flow</option>
          <option value="xtls-rprx-vision">xtls-rprx-vision</option>
          <option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option>
        </select>
      </div>

      <label for="pe-vsni">SNI</label>
      {#if ro}
        <div class="ro" id="pe-vsni">{hide(p.vless.sni ?? '') || '—'}</div>
      {:else}
        <input id="pe-vsni" bind:value={p.vless.sni} placeholder={p.vless.security === 'reality' ? 'сайт для маскировки, обязательно' : 'по умолчанию — адрес сервера'} />
      {/if}

      {#if p.vless.security === 'reality'}
        <label for="pe-pbk">Публичный ключ</label>
        <input id="pe-pbk" class="mono" bind:value={p.vless.publicKey} placeholder="pbk" />
        <label for="pe-sid">shortId</label>
        <div class="row">
          <input id="pe-sid" class="mono" bind:value={p.vless.shortId} placeholder="sid, можно пусто" style="width: 200px" />
          <input bind:value={p.vless.spiderX} placeholder="spiderX, например /" style="width: 170px" />
        </div>
      {/if}

      <label for="pe-net">Транспорт</label>
      <div class="row">
        <select id="pe-net" bind:value={p.vless.network}>
          <option value="">RAW (TCP)</option>
          <option value="xhttp">XHTTP</option>
          <option value="ws">WebSocket</option>
          <option value="grpc">gRPC</option>
          <option value="httpupgrade">HTTPUpgrade</option>
          <option value="kcp">mKCP</option>
        </select>
        {#if p.vless.network === 'grpc'}
          <input class="grow" bind:value={p.vless.serviceName} placeholder="serviceName" />
          <select bind:value={p.vless.mode} title="режим gRPC">
            <option value="">gun</option>
            <option value="multi">multi</option>
          </select>
        {:else if p.vless.network === 'xhttp'}
          <select bind:value={p.vless.mode} title="режим XHTTP">
            <option value="">auto</option>
            <option value="packet-up">packet-up</option>
            <option value="stream-up">stream-up</option>
            <option value="stream-one">stream-one</option>
          </select>
        {:else if p.vless.network === 'kcp'}
          <input class="grow" type={showSecrets ? 'text' : 'password'} bind:value={p.vless.seed} placeholder="seed, можно пусто" />
        {/if}
      </div>
      {#if p.vless.network === 'ws' || p.vless.network === 'httpupgrade' || p.vless.network === 'xhttp' || (!p.vless.network && p.vless.headerType === 'http')}
        <label for="pe-path">Путь и Host</label>
        <div class="row">
          <input id="pe-path" class="grow" type={ro ? 'password' : 'text'} bind:value={p.vless.path} placeholder="путь, например /ws" />
          <input class="grow" type={ro ? 'password' : 'text'} bind:value={p.vless.host} placeholder="Host, по умолчанию SNI" />
        </div>
      {/if}
    {:else}

      <label for="pe-auth">Пароль</label>
      <div class="row">
        <input id="pe-auth" class="grow" type={showSecrets ? 'text' : 'password'} bind:value={p.auth} />
        <label class="check"><input type="checkbox" bind:checked={showSecrets} /> показать</label>
      </div>

      <label for="pe-obfs">Обфускация</label>
      <div class="row">
        <select id="pe-obfs" bind:value={p.obfs.type}>
          <option value={undefined}>нет</option>
          <option value="salamander">salamander</option>
          <option value="gecko">gecko</option>
        </select>
        {#if p.obfs.type}
          <input class="grow" type={showSecrets ? 'text' : 'password'} bind:value={p.obfs.password} placeholder="пароль obfs" />
        {/if}
      </div>
    {/if}
    </div>

    {#if isAWG && p.awg}
    <details class="adv">
      <summary>Дополнительно: общий ключ, MTU, пакеты I1–I5, AmneziaWG 3</summary>
      <div class="grid">
        <label for="pe-awg-psk">Общий ключ</label>
        <input id="pe-awg-psk" class="mono" type={showSecrets ? 'text' : 'password'} bind:value={p.awg.presharedKey} placeholder="PresharedKey, если сервер его выдал" />

        <label for="pe-awg-mtu">MTU и keepalive</label>
        <div class="row">
          <input id="pe-awg-mtu" class="num" type="number" min="576" max="65535" bind:value={p.awg.mtu} placeholder="1420" title="MTU туннеля" />
          <input bind:value={p.awg.keepalive} style="width: 170px" placeholder="PersistentKeepalive, с" title="Раз в сколько секунд слать keepalive: число или диапазон «от-до»" />
        </div>

        <label for="pe-awg-i1">Пакеты I1–I5</label>
        <input id="pe-awg-i1" class="mono" bind:value={p.awg.i1} placeholder="I1, например <b 0x…><r 16><t>" />
        <span></span>
        <input class="mono" bind:value={p.awg.i2} placeholder="I2" />
        <span></span>
        <input class="mono" bind:value={p.awg.i3} placeholder="I3" />
        <span></span>
        <input class="mono" bind:value={p.awg.i4} placeholder="I4" />
        <span></span>
        <input class="mono" bind:value={p.awg.i5} placeholder="I5" />

        <label for="pe-awg-hpk">Защита заголовков</label>
        <input id="pe-awg-hpk" class="mono" type={showSecrets ? 'text' : 'password'} bind:value={p.awg.headerProtectionKey} placeholder="HeaderProtectionKey (AmneziaWG 3)" />

        <label for="pe-awg-pad">Дополнение данных</label>
        <input id="pe-awg-pad" bind:value={p.awg.contentPadding} style="width: 170px" placeholder="ContentPaddingAddition" title="Число или диапазон «от-до»" />

        <span></span>
        <div class="row">
          <label class="check"><input type="checkbox" bind:checked={p.awg.randomTrailers} /> Случайные хвосты пакетов (RandomTrailers)</label>
          <label class="check"><input type="checkbox" bind:checked={p.awg.disableCookies} /> Без cookie (DisableCookies)</label>
        </div>

        <label for="pe-awg-rekey">Таймеры, с</label>
        <div class="row">
          <input id="pe-awg-rekey" class="grow" bind:value={p.awg.rekeyAfterTime} placeholder="RekeyAfterTime" />
          <input class="grow" bind:value={p.awg.rekeyTimeout} placeholder="RekeyTimeout" />
          <input class="grow" bind:value={p.awg.rejectAfterTime} placeholder="RejectAfterTime" />
          <input class="grow" bind:value={p.awg.keepaliveTimeout} placeholder="KeepaliveTimeout" />
          <input class="grow" bind:value={p.awg.maxHandshakeAttempts} placeholder="MaxHandshakeAttempts" />
        </div>
      </div>
    </details>
    {:else if isVLESS && p.vless}
    <details class="adv">
      <summary>Дополнительно: TLS, шифрование VLESS, XHTTP</summary>
      <div class="grid">
        <label for="pe-fp">Отпечаток TLS (fp)</label>
        <div class="row">
          <input id="pe-fp" list="pe-fps" bind:value={p.vless.fingerprint} placeholder={p.vless.security === 'reality' ? 'chrome' : 'по умолчанию Xray'} style="width: 200px" />
          <datalist id="pe-fps">{#each fingerprints as f}<option value={f}></option>{/each}</datalist>
          <input class="grow" bind:value={p.vless.alpn} placeholder="ALPN, например h2,http/1.1" />
        </div>

        {#if p.vless.security === 'tls'}
          <label for="pe-vpin">Отпечаток (pinSHA256)</label>
          <input id="pe-vpin" class="mono" class:bad={vPinBad} aria-invalid={vPinBad} bind:value={p.vless.pinSHA256} placeholder="SHA-256 сертификата; через запятую — несколько" />
          <label for="pe-vcn">Имя в сертификате</label>
          <input id="pe-vcn" type={ro ? 'password' : 'text'} bind:value={p.vless.verifyName} placeholder="если сертификат выдан на другое имя, чем SNI" />
          <label for="pe-ech">ECH</label>
          <input id="pe-ech" class="mono" bind:value={p.vless.ech} placeholder="ECHConfigList в base64" />
        {/if}
        {#if p.vless.security === 'reality'}
          <label for="pe-pqv">mldsa65Verify</label>
          <input id="pe-pqv" class="mono" bind:value={p.vless.mldsa65Verify} placeholder="pqv, если сервер его выдал" />
        {/if}

        <label for="pe-enc">Шифрование VLESS</label>
        <input id="pe-enc" class="mono" bind:value={p.vless.encryption} placeholder="none или mlkem768x25519plus.…" />

        {#if p.vless.network === 'grpc'}
          <label for="pe-auth2">authority</label>
          <input id="pe-auth2" type={ro ? 'password' : 'text'} bind:value={p.vless.authority} placeholder="можно пусто" />
        {/if}
        {#if p.vless.network === 'xhttp'}
          <label for="pe-extra">extra (JSON)</label>
          <textarea id="pe-extra" class="mono" rows="3" bind:value={p.vless.extra} placeholder={'{"xPaddingBytes": "100-1000"}'}></textarea>
        {/if}
        {#if !p.vless.network && !p.vless.security}
          <span></span>
          <label class="check">
            <input type="checkbox" checked={p.vless.headerType === 'http'} onchange={(e) => p.vless && (p.vless.headerType = (e.currentTarget as HTMLInputElement).checked ? 'http' : '')} />
            Маскировка под HTTP (headerType http)
          </label>
        {/if}
        {#if p.vless.network === 'kcp'}
          <label for="pe-kh">Заголовок mKCP</label>
          <input id="pe-kh" bind:value={p.vless.headerType} placeholder="none, srtp, utp, wechat-video, dtls, wireguard, dns" />
        {/if}

        {#if !p.via}
          <span></span>
          <label class="check" title="HyRoute сам резолвит адрес и передаёт Xray IP: исключение из перехвата совпадает точно">
            <input type="checkbox" bind:checked={p.pinServerIP} /> Резолвить адрес в HyRoute и передавать IP
          </label>
        {/if}
      </div>
    </details>
    {:else}
    <details class="adv">
      <summary>Дополнительно: TLS, скорость, port hopping</summary>
      <div class="grid">
        <label for="pe-sni">SNI</label>
        {#if ro}
          <div class="ro" id="pe-sni">{hide(p.tls.sni) || 'по умолчанию — адрес сервера'}</div>
        {:else}
          <input id="pe-sni" bind:value={p.tls.sni} placeholder="по умолчанию — адрес сервера" />
        {/if}

        <label for="pe-pin">Отпечаток (pinSHA256)</label>
        <input id="pe-pin" bind:value={p.tls.pinSHA256} class="mono" class:bad={pinBad} aria-invalid={pinBad} placeholder="если задан, сертификат проверяется только по нему" />

        <span></span>
        <label class="check"><input type="checkbox" bind:checked={p.tls.insecure} /> Не проверять сертификат (insecure)</label>

        <label for="pe-up">Скорость</label>
        <div class="row">
          <input id="pe-up" bind:value={p.bandwidth.up} placeholder="up, напр. 50 mbps" style="width: 170px" />
          <input bind:value={p.bandwidth.down} placeholder="down, напр. 200 mbps" style="width: 170px" />
          <span class="muted small">пусто — BBR</span>
        </div>

        <label for="pe-hop">Port hopping</label>
        <input id="pe-hop" bind:value={p.hop.interval} placeholder="интервал, напр. 30s" style="width: 170px" />

        {#if !p.via}
          <span></span>
          <label class="check" title="HyRoute сам резолвит адрес и передаёт Hysteria IP: исключение из перехвата совпадает точно">
            <input type="checkbox" bind:checked={p.pinServerIP} /> Резолвить адрес в HyRoute и передавать IP
          </label>
        {/if}
      </div>
    </details>
    {/if}
    {/if}
    <!-- An error may quote the address or another server's name. -->
    {#if error}<div class="note error">{ro ? hide(error) : error}</div>{/if}
    <p class="muted small">Если сервер сейчас используется, он переподключится с новыми настройками.</p>
    <div class="actions">
      <button onclick={onclose}>Отмена</button>
      <button class="primary" onclick={save} disabled={saving || (!p.balance && !p.host.trim())}>Сохранить</button>
    </div>
  </div>
</div>

<style>
  .dialog { width: min(720px, 94vw); }
  .grid { display: grid; grid-template-columns: 150px 1fr; gap: 10px 14px; align-items: center; }
  .grid > label:not(.check) { color: var(--muted); }
  .adv { margin-top: 14px; }
  .adv summary { cursor: pointer; color: var(--muted); margin-bottom: 10px; }
  p.small { margin: 12px 0 0; }
  input.bad { border-color: var(--block); }
  .ro { padding: 6px 0; overflow-wrap: anywhere; }
  textarea.mono { width: 100%; }
  input.num { width: 90px; }
  p.hint { margin: 0; }
</style>
