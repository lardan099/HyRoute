<script lang="ts">
  // Deploy Hysteria 2 on a server. The form starts from the server's
  // current config: the params of the deploy that made it, else what the
  // config says; a server without one gets the defaults. A redeploy keeps
  // the client passwords. A config no deploy made (edited, rolled back,
  // imported) is replaced only after the admin confirms that what the form
  // does not cover is lost.
  import { onMount } from 'svelte';
  import {
    api,
    asApiError,
    type ApiError,
    type ConfigFields,
    type ConfigMeta,
    type DeployParams,
    type DeploySource,
    type Job,
    type Server,
    type ServerConfig,
    type TLSMode,
  } from '../api';
  import { t, type Key } from '../i18n';
  import Dialog from './Dialog.svelte';

  let { server, onclose, onstarted }: { server: Server; onclose: () => void; onstarted: (j: Job) => void } = $props();

  const defaultVersion = 'v2.12.3';
  const defaultHop = '20000-50000';

  let tls = $state<TLSMode>('self-signed');
  let port = $state(443);
  let hopping = $state(false);
  let hopPorts = $state(defaultHop);
  let domain = $state('');
  let email = $state('');
  let challenge = $state<'http' | 'tls'>('http');
  let masquerade = $state('');
  let obfs = $state(false);
  let sni = $state('');
  let version = $state(defaultVersion);
  let source = $state<DeploySource>('auto');
  let keepFirewall = $state(false);
  let replace = $state(false);

  let loading = $state(true);
  // cfg is the server's current config revision (null: none).
  let cfg = $state<ServerConfig | null>(null);
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
  };

  // A certificate name for the placeholder: the masquerade site's.
  let sniPh = $derived.by(() => {
    try {
      return masquerade ? new URL(masquerade).hostname : '';
    } catch {
      return '';
    }
  });

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
    masquerade = p.masquerade ?? '';
    obfs = !!p.obfs;
    sni = p.sni ?? '';
    version = p.version || defaultVersion;
    source = p.source ?? 'auto';
    keepFirewall = !!p.keepFirewall;
  }

  // fromFields adds what the summary lacks from the config itself.
  function fromFields(f: ConfigFields) {
    if (f.masquerade === 'proxy' && f.masqueradeUrl) masquerade = f.masqueradeUrl;
    if (f.tls === 'acme') {
      tls = 'acme';
      domain = f.acmeDomains[0] ?? domain;
      email = f.acmeEmail ?? '';
    }
  }

  onMount(async () => {
    try {
      cfg = await api.serverConfig(server.id);
    } catch {
      // No config yet (or no answer): the defaults; the controller still
      // keeps the passwords and asks before replacing an edited config.
    }
    if (cfg) {
      fromMeta(cfg.meta);
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

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = null;
    const p: DeployParams = {
      tls,
      version: version.trim(),
      port: Number(port) || 443,
      hopPorts: hopping ? hopPorts.trim() : undefined,
      masquerade: masquerade.trim() || undefined,
      obfs,
      source,
      keepFirewall,
      // An imported installation is replaced together with its config.
      replace: replace || (changed && overwrite && cfg?.source === 'import'),
      overwrite: changed && overwrite ? true : undefined,
    };
    if (tls === 'acme') {
      p.domain = domain.trim();
      p.email = email.trim() || undefined;
      p.challenge = challenge;
    } else {
      p.sni = sni.trim() || undefined;
    }
    try {
      onstarted(await api.startDeploy(server.id, p));
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
          </select>
        </label>
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

      <label>
        <span>{t('deploy.masquerade')}</span>
        <input type="text" bind:value={masquerade} placeholder="https://www.example.com" autocomplete="off" spellcheck="false" />
        <span class="hint">{t('deploy.masqueradeHint')}</span>
      </label>

      <div class="field">
        <label class="check"><input type="checkbox" bind:checked={obfs} /> {t('deploy.obfs')}</label>
        <span class="hint">{t('deploy.obfsHint')}</span>
      </div>

      <details>
        <summary>{t('deploy.advanced')}</summary>
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
    <button class="primary" type="submit" form="deploy-form" disabled={busy || loading || (changed && !overwrite)}>{t('deploy.submit')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 14px; }
  .inner { margin-top: 12px; }
  label:not(.check), .field { display: flex; flex-direction: column; gap: 5px; }
  label span, .lbl { color: var(--muted); font-size: 12.5px; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; }
  .two { display: flex; gap: 12px; align-items: flex-start; }
  .port { width: 110px; flex: none; }
  .ver { width: 130px; flex: none; }
  .check.top { min-height: 20px; margin-bottom: 2px; }
  .seg { align-self: flex-start; }
  summary { cursor: pointer; color: var(--muted); font-size: 13px; }
  .note { margin: 0; }
  .changed { display: flex; flex-direction: column; gap: 10px; }
  .changed .check { color: var(--text); font-weight: 600; }
</style>
