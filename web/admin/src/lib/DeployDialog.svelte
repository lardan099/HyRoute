<script lang="ts">
  // Deploy Hysteria 2 on a server. The form starts from the server's
  // current config: the params of the deploy that made it, else what the
  // config says; a server without one gets the defaults. A redeploy keeps
  // the client passwords. A config no deploy made (edited, rolled back,
  // imported) is replaced only after the admin confirms that what the form
  // does not cover is lost. Every advanced setting left empty keeps
  // Hysteria's default; the controller checks the combinations again.
  import { onMount } from 'svelte';
  import {
    api,
    asApiError,
    defaultHysteria,
    dnsProviders,
    type ACMEChallenge,
    type ApiError,
    type ConfigFields,
    type ConfigMeta,
    type DeployParams,
    type DeploySecrets,
    type DeploySource,
    type Job,
    type MasqType,
    type OutboundType,
    type Server,
    type ServerConfig,
    type TLSMode,
    type Preset,
    type PresetSection,
    deploySections,
  } from '../api';
  import { t, type Key } from '../i18n';
  import Dialog from './Dialog.svelte';

  let { server, onclose, onstarted }: { server: Server; onclose: () => void; onstarted: (j: Job) => void } = $props();

  const defaultVersion = defaultHysteria;
  const defaultHop = '20000-50000';

  let tls = $state<TLSMode>('self-signed');
  let port = $state(443);
  let hopping = $state(false);
  let hopPorts = $state(defaultHop);
  let domain = $state('');
  let email = $state('');
  let challenge = $state<ACMEChallenge>('http');
  let dnsProvider = $state('cloudflare');
  let dnsValues = $state<Record<string, string>>({});
  let masqType = $state<MasqType>('');
  let masquerade = $state('');
  let masqDir = $state('');
  let masqText = $state('');
  let masqStatus = $state<number | null>(null);
  let masqTCP = $state(false);
  let obfs = $state(false);
  // authMode '' keeps the current config's auth (an external service).
  let authMode = $state<'' | 'password' | 'userpass'>('password');
  let usersText = $state('');
  let sni = $state('');
  let version = $state(defaultVersion);
  let source = $state<DeploySource>('auto');
  let keepFirewall = $state(false);
  let replace = $state(false);

  let up = $state<number | null>(null);
  let down = $state<number | null>(null);
  let ignoreClient = $state(false);
  let streamWin = $state<number | null>(null);
  let connWin = $state<number | null>(null);
  let quicIdle = $state<number | null>(null);
  let maxStreams = $state<number | null>(null);
  let noMTU = $state(false);
  let udpOff = $state(false);
  let udpIdle = $state<number | null>(null);
  let sniffOn = $state(false);
  let sniffTimeout = $state<number | null>(null);
  let sniffRewrite = $state(false);
  let sniffTCP = $state('');
  let sniffUDP = $state('');
  let outType = $state<OutboundType>('');
  let outMode = $state('');
  let outDevice = $state('');
  let outIPv4 = $state('');
  let outIPv6 = $state('');
  let outAddr = $state('');
  let outUser = $state('');
  let outPass = $state('');
  // A preset's sections laid over the config (not ports, obfuscation).
  let presets = $state<Preset[]>([]);
  let presetId = $state(0);
  let presetChosen = $state<Record<string, boolean>>({});
  let preset = $derived(presets.find((p) => p.id === presetId) ?? null);
  let presetOffer = $derived((preset?.sections ?? []).filter((s) => deploySections.includes(s)));
  let fromPreset = $derived((s: PresetSection) => !!preset && presetOffer.includes(s) && !!presetChosen[s]);

  let loading = $state(true);
  // cfg is the server's current config revision (null: none).
  let cfg = $state<ServerConfig | null>(null);
  // curAuth, curUsers: the client auth of the current config.
  let curAuth = $state('');
  let curUsers = $state<string[]>([]);
  // changed: the current config was not made by a deploy; the deploy
  // replaces it only with overwrite.
  let changed = $state(false);
  let overwrite = $state(false);
  let busy = $state(false);
  let error = $state<ApiError | null>(null);

  const changedKey: Record<string, Key> = {
    edit: 'deploy.changedEdit',
    rollback: 'deploy.changedRollback',
    import: 'deploy.changedImport',
    rotate: 'deploy.changedRotate',
  };
  const outModes: [string, Key][] = [
    ['', 'deploy.outModeDefault'],
    ['46', 'deploy.outMode46'],
    ['64', 'deploy.outMode64'],
    ['4', 'deploy.outMode4'],
    ['6', 'deploy.outMode6'],
  ];

  // A certificate name for the placeholder: the masquerade site's.
  let sniPh = $derived.by(() => {
    try {
      return masqType === 'proxy' && masquerade ? new URL(masquerade).hostname : '';
    } catch {
      return '';
    }
  });

  let users = $derived(usersText.split(/[\s,;]+/).filter(Boolean));
  let removedUsers = $derived(authMode === 'userpass' && curAuth === 'userpass' ? curUsers.filter((u) => !users.includes(u)) : []);
  let authChanges = $derived(!!cfg && !!curAuth && authMode !== '' && authMode !== curAuth);
  // TCP 80 and 443 are the ACME http and tls challenges' too.
  let tcpBlocked = $derived(tls === 'acme' && challenge !== 'dns');
  let winBad = $derived((streamWin || 8) > (connWin || 20));

  // The groups of the advanced settings that differ from the defaults.
  let setSpeed = $derived(!!up || !!down || ignoreClient);
  let setQUIC = $derived(!!streamWin || !!connWin || !!quicIdle || !!maxStreams || noMTU);
  let setUDP = $derived(udpOff || !!udpIdle);
  let setOut = $derived(outType !== '');

  // fromMeta fills what the summary of a config tells.
  function fromMeta(m: ConfigMeta) {
    version = m.version || defaultVersion;
    tls = m.tls === 'acme' ? 'acme' : 'self-signed';
    const ports = (m.ports ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    const first = Number(ports[0]);
    if (Number.isInteger(first) && first >= 1 && first <= 65535) {
      port = first;
      hopping = ports.length > 1;
      if (hopping) hopPorts = ports.slice(1).join(',');
    }
    if (tls === 'acme') domain = m.sni ?? '';
    else sni = m.sni ?? '';
    obfs = m.obfs === 'salamander';
  }

  // fromParams fills the form of the deploy that made the config.
  function fromParams(p: Partial<DeployParams>) {
    tls = p.tls ?? 'self-signed';
    port = p.port ?? 443;
    hopping = !!p.hopPorts;
    hopPorts = p.hopPorts || defaultHop;
    domain = p.domain ?? '';
    email = p.email ?? '';
    challenge = p.challenge ?? 'http';
    dnsProvider = p.dnsProvider || 'cloudflare';
    masquerade = p.masquerade ?? '';
    masqType = p.masq?.type ?? (masquerade ? 'proxy' : '');
    masqDir = p.masq?.dir ?? '';
    masqText = p.masq?.text ?? '';
    masqStatus = p.masq?.status ?? null;
    masqTCP = !!p.masq?.tcp;
    obfs = !!p.obfs;
    if (p.auth) authMode = p.auth;
    if (p.users?.length) usersText = p.users.join('\n');
    sni = p.sni ?? '';
    version = p.version || defaultVersion;
    source = p.source ?? 'auto';
    keepFirewall = !!p.keepFirewall;
    up = p.bandwidth?.upMbps ?? null;
    down = p.bandwidth?.downMbps ?? null;
    ignoreClient = !!p.bandwidth?.ignoreClient;
    streamWin = p.quic?.streamWindowMB ?? null;
    connWin = p.quic?.connWindowMB ?? null;
    quicIdle = p.quic?.idleTimeout ?? null;
    maxStreams = p.quic?.maxStreams ?? null;
    noMTU = !!p.quic?.disableMTUDiscovery;
    udpOff = !!p.udp?.disable;
    udpIdle = p.udp?.idleTimeout ?? null;
    sniffOn = !!p.sniff?.enable;
    sniffTimeout = p.sniff?.timeout ?? null;
    sniffRewrite = !!p.sniff?.rewriteDomain;
    sniffTCP = p.sniff?.tcpPorts ?? '';
    sniffUDP = p.sniff?.udpPorts ?? '';
    if (p.preset) {
      presetId = p.preset.id;
      presetChosen = Object.fromEntries(p.preset.sections.map((s) => [s, true]));
    }
    const o = p.outbound ?? {};
    outType = o.type ?? '';
    outMode = o.mode ?? '';
    outDevice = o.bindDevice ?? '';
    outIPv4 = o.bindIPv4 ?? '';
    outIPv6 = o.bindIPv6 ?? '';
    outAddr = o.addr ?? '';
    outUser = o.user ?? '';
  }

  // seconds reads "60s" (and a bare number) of a config.
  function seconds(v: string): number | null {
    const m = /^(\d+)s?$/.exec(v.trim());
    return m ? Number(m[1]) : null;
  }

  // mbps reads "100 mbps" of a config; other units stay out of the form.
  function mbps(v: string): number | null {
    const m = /^(\d+)\s*(m|mb|mbps)$/i.exec(v.trim());
    return m ? Number(m[1]) : null;
  }

  // fromFields adds what the summary lacks from the config itself.
  function fromFields(f: ConfigFields) {
    if (f.masquerade === 'proxy' && f.masqueradeUrl) {
      masqType = 'proxy';
      masquerade = f.masqueradeUrl;
    }
    if (f.tls === 'acme') {
      tls = 'acme';
      domain = f.acmeDomains[0] ?? domain;
      email = f.acmeEmail ?? '';
    }
    up = mbps(f.bandwidthUp);
    down = mbps(f.bandwidthDown);
    ignoreClient = f.ignoreClientBandwidth;
    udpOff = f.disableUDP;
    udpIdle = seconds(f.udpIdleTimeout);
  }

  onMount(async () => {
    try {
      presets = await api.presets();
    } catch {}
    try {
      cfg = await api.serverConfig(server.id);
    } catch {
      // No config yet (or no answer): the defaults; the controller still
      // keeps the passwords and asks before replacing an edited config.
    }
    if (cfg) {
      fromMeta(cfg.meta);
      try {
        const s = await api.clientSummary(server.id);
        curAuth = s.auth;
        curUsers = s.users ?? [];
      } catch {
        curAuth = cfg.meta.auth ?? '';
      }
      // The current auth unless the deploy said otherwise.
      authMode = curAuth === 'password' || curAuth === 'userpass' ? curAuth : '';
      usersText = curUsers.join('\n');
      if (cfg.source === 'deploy') {
        try {
          if (cfg.jobId) fromParams((await api.job(cfg.jobId)).params as Partial<DeployParams>);
        } catch {}
      } else {
        changed = true;
        try {
          fromFields((await api.configEdit(server.id)).fields);
        } catch {}
      }
    }
    loading = false;
  });

  // num is a number input's value for the params (empty: the default).
  function num(v: number | null | undefined): number | undefined {
    return v == null || Number.isNaN(Number(v)) || Number(v) === 0 ? undefined : Number(v);
  }

  // compact drops the empty values of a group; an empty group is left out.
  function compact<T extends object>(o: T): T | undefined {
    const out = Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== '' && v !== false)) as T;
    return Object.keys(out).length ? out : undefined;
  }

  function setIgnore(on: boolean) {
    ignoreClient = on;
    if (on) up = down = null;
  }

  function setUDPOff(on: boolean) {
    udpOff = on;
    if (on) {
      udpIdle = null;
      sniffUDP = '';
    }
  }

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = null;
    const p: DeployParams = {
      tls,
      version: version.trim(),
      port: Number(port) || 443,
      hopPorts: hopping ? hopPorts.trim() : undefined,
      obfs,
      source,
      keepFirewall,
      // An imported installation is replaced together with its config.
      replace: replace || (changed && overwrite && cfg?.source === 'import'),
      overwrite: changed && overwrite ? true : undefined,
      auth: authMode || undefined,
      users: authMode === 'userpass' ? users : undefined,
      bandwidth: compact({ upMbps: num(up), downMbps: num(down), ignoreClient }),
      quic: compact({ streamWindowMB: num(streamWin), connWindowMB: num(connWin), idleTimeout: num(quicIdle), maxStreams: num(maxStreams), disableMTUDiscovery: noMTU }),
      udp: compact({ disable: udpOff, idleTimeout: num(udpIdle) }),
      sniff: sniffOn
        ? compact({ enable: true, timeout: num(sniffTimeout), rewriteDomain: sniffRewrite, tcpPorts: sniffTCP.trim(), udpPorts: sniffUDP.trim() })
        : undefined,
    };
    switch (masqType) {
      case 'proxy':
        p.masquerade = masquerade.trim();
        break;
      case 'file':
        p.masq = { type: 'file', dir: masqDir.trim() };
        break;
      case 'string':
        p.masq = { type: 'string', text: masqText, status: num(masqStatus) };
        break;
    }
    if (masqType && masqTCP) p.masq = { ...p.masq, tcp: true };
    const secrets: DeploySecrets = {};
    if (tls === 'acme') {
      p.domain = domain.trim();
      p.email = email.trim() || undefined;
      p.challenge = challenge;
      if (challenge === 'dns') {
        p.dnsProvider = dnsProvider;
        const dns = Object.fromEntries(
          dnsProviders[dnsProvider].map((f) => [f.key, (dnsValues[f.key] ?? '').trim()]).filter(([, v]) => v),
        );
        if (Object.keys(dns).length) secrets.dns = dns;
      }
    } else {
      p.sni = sni.trim() || undefined;
    }
    if (outType === 'direct') {
      p.outbound = compact({ type: outType, mode: outMode, bindDevice: outDevice.trim(), bindIPv4: outIPv4.trim(), bindIPv6: outIPv6.trim() });
    } else if (outType) {
      p.outbound = compact({ type: outType, addr: outAddr.trim(), user: outUser.trim() });
      if (outPass) secrets.outPassword = outPass;
    }
    const taken = presetOffer.filter((s) => presetChosen[s]);
    if (preset && taken.length) {
      p.preset = { id: preset.id, sections: taken };
      // A section comes from the preset or from the form, not both.
      if (taken.includes('masquerade')) {
        p.masquerade = undefined;
        p.masq = undefined;
      }
      if (taken.includes('speed')) p.bandwidth = undefined;
      if (taken.includes('quic')) p.quic = undefined;
      if (taken.includes('udp')) p.udp = undefined;
      if (taken.includes('sniff')) p.sniff = undefined;
      if (taken.includes('outbounds')) {
        p.outbound = undefined;
        delete secrets.outPassword;
      }
    }
    try {
      onstarted(await api.startDeploy(server.id, p, Object.keys(secrets).length ? secrets : undefined));
    } catch (err) {
      error = asApiError(err);
      // The config changed since the form opened (or was not known):
      // the same question as above.
      if (error.code === 'config_changed') {
        changed = true;
        overwrite = false;
      }
      busy = false;
    }
  }

  // A DNS setting that is a key or a token is typed like a password.
  function secretKey(k: string): boolean {
    return /token|key/.test(k);
  }
</script>

<Dialog title={t('deploy.title', { name: server.name })} {onclose}>
  {#if loading}
    <p class="muted">{t('deploy.loading')}</p>
  {:else}
    <form id="deploy-form" class="form" onsubmit={submit}>
      {#if changed}
        <div class="note warn small changed" role="alert">
          <div>
            {cfg && changedKey[cfg.source] ? t(changedKey[cfg.source], { rev: cfg.revision }) : t('deploy.changedOther')}
            {t('deploy.changedText')}
          </div>
          <label class="check"><input type="checkbox" bind:checked={overwrite} /> {cfg?.source === 'import' ? t('deploy.overwriteImport') : t('deploy.overwrite')}</label>
        </div>
      {:else if cfg}
        <div class="note info small">{t('deploy.redeploy')}</div>
      {/if}

      <div class="field">
        <span class="lbl">{t('deploy.tls')}</span>
        <div class="seg" role="radiogroup" aria-label={t('deploy.tls')}>
          <button type="button" class:on={tls === 'self-signed'} onclick={() => (tls = 'self-signed')}>{t('deploy.tlsSelf')}</button>
          <button type="button" class:on={tls === 'acme'} onclick={() => (tls = 'acme')}>{t('deploy.tlsACME')}</button>
        </div>
        <span class="hint">{tls === 'acme' ? t('deploy.tlsACMEHint') : t('deploy.tlsSelfHint')}</span>
      </div>

      {#if tls === 'acme'}
        <div class="two">
          <label class="grow">
            <span>{t('deploy.domain')}</span>
            <input type="text" required bind:value={domain} placeholder="vpn.example.com" autocomplete="off" spellcheck="false" />
          </label>
          <label class="grow">
            <span>{t('deploy.email')}</span>
            <input type="text" bind:value={email} placeholder={t('deploy.emailPh')} autocomplete="off" spellcheck="false" />
          </label>
        </div>
        <label>
          <span>{t('deploy.challenge')}</span>
          <select bind:value={challenge}>
            <option value="http">{t('deploy.challengeHTTP')}</option>
            <option value="tls">{t('deploy.challengeTLS')}</option>
            <option value="dns">{t('deploy.challengeDNS')}</option>
          </select>
        </label>
        {#if challenge === 'dns'}
          <div class="sub">
            <label>
              <span>{t('deploy.dnsProvider')}</span>
              <select bind:value={dnsProvider}>
                {#each Object.keys(dnsProviders) as name (name)}
                  <option value={name}>{name}</option>
                {/each}
              </select>
            </label>
            {#each dnsProviders[dnsProvider] as f (f.key)}
              <label>
                <span class="mono">{f.key}</span>
                <input
                  type={secretKey(f.key) ? 'password' : 'text'}
                  bind:value={dnsValues[f.key]}
                  required={f.required && !cfg}
                  placeholder={cfg ? t('deploy.keepCurrent') : f.required ? '' : t('deploy.optional')}
                  autocomplete="off"
                  spellcheck="false"
                />
              </label>
            {/each}
            <span class="hint">{t('deploy.dnsHint')}</span>
          </div>
        {/if}
      {/if}

      <div class="two">
        <label class="port">
          <span>{t('deploy.port')}</span>
          <input type="number" min="1" max="65535" required bind:value={port} />
        </label>
        <div class="grow field">
          <label class="check top"><input type="checkbox" bind:checked={hopping} /> {t('deploy.hopping')}</label>
          {#if hopping}
            <input type="text" required bind:value={hopPorts} placeholder={defaultHop} aria-label={t('deploy.hopRange')} spellcheck="false" />
          {/if}
          <span class="hint">{t('deploy.hoppingHint')}</span>
        </div>
      </div>

      {#if presets.length}
        <div class="field">
          <label>
            <span>{t('deploy.preset')}</span>
            <select bind:value={presetId}>
              <option value={0}>{t('deploy.presetNone')}</option>
              {#each presets as pr (pr.id)}<option value={pr.id}>{pr.name}</option>{/each}
            </select>
          </label>
          {#if preset}
            {#if presetOffer.length}
              <div class="secs">
                {#each presetOffer as sec (sec)}
                  <label class="check"><input type="checkbox" bind:checked={presetChosen[sec]} /> {t(`psec.${sec}` as Key)}</label>
                {/each}
              </div>
              <span class="hint">{t('deploy.presetHint')}</span>
            {:else}
              <span class="hint">{t('deploy.presetNothing')}</span>
            {/if}
          {/if}
        </div>
      {/if}

      {#if fromPreset('masquerade')}
        <p class="hint">{t('deploy.masqFromPreset')}</p>
      {:else}
      <div class="field">
        <label>
          <span>{t('deploy.masquerade')}</span>
          <select bind:value={masqType}>
            <option value="">{t('deploy.masqNone')}</option>
            <option value="proxy">{t('deploy.masqProxy')}</option>
            <option value="file">{t('deploy.masqFile')}</option>
            <option value="string">{t('deploy.masqString')}</option>
          </select>
        </label>
        <span class="hint">{t('deploy.masqHint')}</span>
      </div>
      {#if masqType}
        <div class="sub">
          {#if masqType === 'proxy'}
            <label>
              <span>{t('deploy.masqURL')}</span>
              <input type="text" required bind:value={masquerade} placeholder="https://www.example.com" autocomplete="off" spellcheck="false" />
              <span class="hint">{t('deploy.masqueradeHint')}</span>
            </label>
          {:else if masqType === 'file'}
            <label>
              <span>{t('deploy.masqDir')}</span>
              <input type="text" required bind:value={masqDir} placeholder="/var/www/site" autocomplete="off" spellcheck="false" />
              <span class="hint">{t('deploy.masqDirHint')}</span>
            </label>
          {:else}
            <label>
              <span>{t('deploy.masqText')}</span>
              <textarea rows="3" required bind:value={masqText} spellcheck="false"></textarea>
            </label>
            <label class="port">
              <span>{t('deploy.masqStatus')}</span>
              <input type="number" min="200" max="599" bind:value={masqStatus} placeholder="200" />
            </label>
            <span class="hint">{t('deploy.masqTextHint')}</span>
          {/if}
          <div class="field">
            <label class="check"><input type="checkbox" bind:checked={masqTCP} disabled={tcpBlocked} /> {t('deploy.masqTCP')}</label>
            <span class="hint">{tcpBlocked ? t('deploy.masqTCPAcme') : t('deploy.masqTCPHint')}</span>
            {#if masqTCP && tls === 'self-signed'}<span class="hint">{t('deploy.masqTCPSelf')}</span>{/if}
          </div>
        </div>
      {/if}

      {/if}

      <div class="field">
        <label class="check"><input type="checkbox" bind:checked={obfs} /> {t('deploy.obfs')}</label>
        <span class="hint">{t('deploy.obfsHint')}</span>
      </div>

      <div class="field">
        <span class="lbl">{t('deploy.auth')}</span>
        <div class="seg" role="radiogroup" aria-label={t('deploy.auth')}>
          <button type="button" class:on={authMode === 'password'} onclick={() => (authMode = 'password')}>{t('deploy.authPassword')}</button>
          <button type="button" class:on={authMode === 'userpass'} onclick={() => (authMode = 'userpass')}>{t('deploy.authUsers')}</button>
        </div>
        {#if authMode === ''}
          <span class="hint">{t('deploy.authKeep', { type: curAuth })}</span>
        {:else}
          <span class="hint">{authMode === 'userpass' ? t('deploy.authUsersHint') : t('deploy.authPasswordHint')}</span>
        {/if}
      </div>
      {#if authMode === 'userpass'}
        <label class="sub">
          <span>{t('deploy.users')}</span>
          <textarea rows="3" required bind:value={usersText} placeholder={'alice\nbob'} spellcheck="false"></textarea>
          <span class="hint">{t('deploy.usersHint')}</span>
        </label>
      {/if}
      {#if authChanges}
        <div class="note warn small">{t('deploy.authChanged')}</div>
      {:else if removedUsers.length}
        <div class="note warn small">{t('deploy.usersRemoved', { users: removedUsers.join(', ') })}</div>
      {/if}

      <details>
        <summary>{t('deploy.advanced')}</summary>
        <div class="form inner">
          <p class="hint">{t('deploy.advancedHint')}</p>

          <details class="grp">
            <summary>{t('deploy.grpSpeed')}{#if setSpeed}<span class="set">{t('deploy.set')}</span>{/if}{#if fromPreset('speed')}<span class="set">{t('deploy.fromPreset')}</span>{/if}</summary>
            <fieldset class="form inner" disabled={fromPreset('speed')}>
              <div class="two">
                <label class="grow">
                  <span>{t('deploy.up')}</span>
                  <input type="number" min="1" max="100000" bind:value={up} disabled={ignoreClient} placeholder={t('deploy.unlimited')} />
                </label>
                <label class="grow">
                  <span>{t('deploy.down')}</span>
                  <input type="number" min="1" max="100000" bind:value={down} disabled={ignoreClient} placeholder={t('deploy.unlimited')} />
                </label>
              </div>
              <span class="hint">{t('deploy.speedHint')}</span>
              <div class="field">
                <label class="check"><input type="checkbox" checked={ignoreClient} onchange={(e) => setIgnore(e.currentTarget.checked)} /> {t('deploy.ignoreClient')}</label>
                <span class="hint">{t('deploy.ignoreClientHint')}</span>
              </div>
            </fieldset>
          </details>

          <details class="grp">
            <summary>{t('deploy.grpQUIC')}{#if setQUIC}<span class="set">{t('deploy.set')}</span>{/if}{#if fromPreset('quic')}<span class="set">{t('deploy.fromPreset')}</span>{/if}</summary>
            <fieldset class="form inner" disabled={fromPreset('quic')}>
              <div class="two">
                <label class="grow">
                  <span>{t('deploy.streamWin')}</span>
                  <input type="number" min="1" max="256" bind:value={streamWin} placeholder="8" />
                </label>
                <label class="grow">
                  <span>{t('deploy.connWin')}</span>
                  <input type="number" min="1" max="1024" bind:value={connWin} placeholder="20" />
                </label>
              </div>
              <span class="hint">{t('deploy.winHint')}</span>
              {#if winBad}<span class="bad small">{t('deploy.winBad')}</span>{/if}
              <div class="two">
                <label class="grow">
                  <span>{t('deploy.quicIdle')}</span>
                  <input type="number" min="4" max="120" bind:value={quicIdle} placeholder="30" />
                </label>
                <label class="grow">
                  <span>{t('deploy.maxStreams')}</span>
                  <input type="number" min="8" max="65535" bind:value={maxStreams} placeholder="1024" />
                </label>
              </div>
              <span class="hint">{t('deploy.quicIdleHint')}</span>
              <div class="field">
                <label class="check"><input type="checkbox" bind:checked={noMTU} /> {t('deploy.noMTU')}</label>
                <span class="hint">{t('deploy.noMTUHint')}</span>
              </div>
            </fieldset>
          </details>

          <details class="grp">
            <summary>{t('deploy.grpUDP')}{#if setUDP}<span class="set">{t('deploy.set')}</span>{/if}{#if fromPreset('udp')}<span class="set">{t('deploy.fromPreset')}</span>{/if}</summary>
            <fieldset class="form inner" disabled={fromPreset('udp')}>
              <div class="field">
                <label class="check"><input type="checkbox" checked={udpOff} onchange={(e) => setUDPOff(e.currentTarget.checked)} /> {t('deploy.udpOff')}</label>
                <span class="hint">{t('deploy.udpOffHint')}</span>
              </div>
              <label class="port">
                <span>{t('deploy.udpIdle')}</span>
                <input type="number" min="2" max="600" bind:value={udpIdle} disabled={udpOff} placeholder="60" />
              </label>
              <span class="hint">{t('deploy.udpIdleHint')}</span>
            </fieldset>
          </details>

          <details class="grp">
            <summary>{t('deploy.grpSniff')}{#if sniffOn}<span class="set">{t('deploy.set')}</span>{/if}{#if fromPreset('sniff')}<span class="set">{t('deploy.fromPreset')}</span>{/if}</summary>
            <fieldset class="form inner" disabled={fromPreset('sniff')}>
              <div class="field">
                <label class="check"><input type="checkbox" bind:checked={sniffOn} /> {t('deploy.sniff')}</label>
                <span class="hint">{t('deploy.sniffHint')}</span>
              </div>
              {#if sniffOn}
                <div class="two">
                  <label class="port">
                    <span>{t('deploy.sniffTimeout')}</span>
                    <input type="number" min="1" max="60" bind:value={sniffTimeout} placeholder="2" />
                  </label>
                  <label class="grow">
                    <span>{t('deploy.sniffTCP')}</span>
                    <input type="text" bind:value={sniffTCP} placeholder={t('deploy.allPorts')} spellcheck="false" />
                  </label>
                  <label class="grow">
                    <span>{t('deploy.sniffUDP')}</span>
                    <input type="text" bind:value={sniffUDP} disabled={udpOff} placeholder={t('deploy.allPorts')} spellcheck="false" />
                  </label>
                </div>
                <span class="hint">{t('deploy.sniffPortsHint')}</span>
                <label class="check"><input type="checkbox" bind:checked={sniffRewrite} /> {t('deploy.sniffRewrite')}</label>
              {/if}
            </fieldset>
          </details>

          <details class="grp">
            <summary>{t('deploy.grpOut')}{#if setOut}<span class="set">{t('deploy.set')}</span>{/if}{#if fromPreset('outbounds')}<span class="set">{t('deploy.fromPreset')}</span>{/if}</summary>
            <fieldset class="form inner" disabled={fromPreset('outbounds')}>
              <label>
                <span>{t('deploy.outType')}</span>
                <select bind:value={outType}>
                  <option value="">{t('deploy.outDefault')}</option>
                  <option value="direct">{t('deploy.outDirect')}</option>
                  <option value="socks5">{t('deploy.outSOCKS5')}</option>
                  <option value="http">{t('deploy.outHTTP')}</option>
                </select>
                <span class="hint">{t('deploy.outHint')}</span>
              </label>
              {#if outType === 'direct'}
                <label>
                  <span>{t('deploy.outMode')}</span>
                  <select bind:value={outMode}>
                    {#each outModes as [v, k] (v)}<option value={v}>{t(k)}</option>{/each}
                  </select>
                  <span class="hint">{t('deploy.outModeHint')}</span>
                </label>
                <div class="two">
                  <label class="grow">
                    <span>{t('deploy.outDevice')}</span>
                    <input type="text" bind:value={outDevice} disabled={!!outIPv4 || !!outIPv6} placeholder="eth1" spellcheck="false" />
                  </label>
                  <label class="grow">
                    <span>{t('deploy.outIPv4')}</span>
                    <input type="text" bind:value={outIPv4} disabled={!!outDevice || outMode === '6'} placeholder="192.0.2.10" spellcheck="false" />
                  </label>
                  <label class="grow">
                    <span>{t('deploy.outIPv6')}</span>
                    <input type="text" bind:value={outIPv6} disabled={!!outDevice || outMode === '4'} placeholder="2001:db8::10" spellcheck="false" />
                  </label>
                </div>
                <span class="hint">{t('deploy.outBindHint')}</span>
              {:else if outType}
                <label>
                  <span>{t('deploy.outAddr')}</span>
                  <input
                    type="text"
                    required
                    bind:value={outAddr}
                    placeholder={outType === 'socks5' ? '127.0.0.1:40000' : 'http://127.0.0.1:8080'}
                    autocomplete="off"
                    spellcheck="false"
                  />
                </label>
                <div class="two">
                  <label class="grow">
                    <span>{t('deploy.outUser')}</span>
                    <input type="text" bind:value={outUser} placeholder={t('deploy.optional')} autocomplete="off" spellcheck="false" />
                  </label>
                  <label class="grow">
                    <span>{t('deploy.outPass')}</span>
                    <input type="password" bind:value={outPass} disabled={!outUser} placeholder={cfg ? t('deploy.keepCurrent') : ''} autocomplete="new-password" />
                  </label>
                </div>
                <span class="hint">{t('deploy.outPassHint')}</span>
              {/if}
            </fieldset>
          </details>

          <details class="grp">
            <summary>{t('deploy.grpInstall')}</summary>
            <div class="form inner">
              {#if tls === 'self-signed'}
                <label>
                  <span>{t('deploy.sni')}</span>
                  <input type="text" bind:value={sni} placeholder={sniPh || t('deploy.sniNone')} autocomplete="off" spellcheck="false" />
                  <span class="hint">{t('deploy.sniHint')}</span>
                </label>
              {/if}
              <div class="two">
                <label class="ver">
                  <span>{t('deploy.version')}</span>
                  <input type="text" required bind:value={version} spellcheck="false" />
                </label>
                <label class="grow">
                  <span>{t('deploy.source')}</span>
                  <select bind:value={source}>
                    <option value="auto">{t('deploy.sourceAuto')}</option>
                    <option value="direct">{t('deploy.sourceDirect')}</option>
                    <option value="relay">{t('deploy.sourceRelay')}</option>
                  </select>
                </label>
              </div>
              <label class="check"><input type="checkbox" bind:checked={keepFirewall} /> {t('deploy.keepFirewall')}</label>
              <div class="field">
                <label class="check"><input type="checkbox" bind:checked={replace} /> {t('deploy.replace')}</label>
                <span class="hint">{t('deploy.replaceHint')}</span>
              </div>
            </div>
          </details>
        </div>
      </details>

      {#if error}
        <div class="note error" role="alert">
          {error.message}
          {#if error.details && error.code !== 'invalid'}<div class="small mono">{error.details}</div>{/if}
        </div>
      {/if}
    </form>
  {/if}
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button class="primary" type="submit" form="deploy-form" disabled={busy || loading || (changed && !overwrite) || winBad}>{t('deploy.submit')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 14px; }
  .inner { margin-top: 12px; }
  label:not(.check), .field { display: flex; flex-direction: column; gap: 5px; }
  label span, .lbl { color: var(--muted); font-size: 12.5px; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; margin: 0; }
  .two { display: flex; gap: 12px; align-items: flex-start; }
  .grow { flex: 1; min-width: 0; }
  .port { width: 110px; flex: none; }
  .ver { width: 130px; flex: none; }
  .check.top { min-height: 20px; margin-bottom: 2px; }
  .seg { align-self: flex-start; }
  .sub { display: flex; flex-direction: column; gap: 10px; padding-left: 12px; border-left: 2px solid var(--border); }
  summary { cursor: pointer; color: var(--muted); font-size: 13px; }
  .grp { border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 10px 12px; }
  .grp summary { color: var(--text); font-weight: 600; }
  .grp .inner { gap: 10px; }
  .set { margin-left: 8px; font-weight: 400; font-size: 12px; color: var(--accent); }
  .bad { color: var(--block); }
  fieldset { border: 0; padding: 0; margin: 12px 0 0; min-width: 0; }
  fieldset:disabled { opacity: 0.55; }
  .secs { display: flex; flex-wrap: wrap; gap: 6px 16px; }
  textarea { resize: vertical; font-family: var(--mono, monospace); font-size: 12.5px; }
  .note { margin: 0; }
  .changed { display: flex; flex-direction: column; gap: 10px; }
  .changed .check { color: var(--text); font-weight: 600; }
  @media (max-width: 560px) {
    .two { flex-direction: column; }
    .port, .ver, .two > * { width: 100%; }
  }
</style>
