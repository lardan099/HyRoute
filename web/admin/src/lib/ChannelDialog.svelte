<script lang="ts">
  // Add or edit a notification channel. A stored secret is never shown:
  // on edit the field is empty and an empty field keeps it.
  import { untrack } from 'svelte';
  import { api, asApiError, type AlertChannel, type ApiError, type ChannelKind, type EventKind } from '../api';
  import { t, type Key } from '../i18n';
  import Dialog from './Dialog.svelte';

  let { channel, onclose, onsaved }: { channel: AlertChannel | null; onclose: () => void; onsaved: () => void } = $props();

  const eventKinds: EventKind[] = ['server', 'link', 'job', 'attention', 'host_key', 'ssh_auth', 'disk', 'geo', 'network', 'drift'];

  const c = untrack(() => channel);
  const set = (c?.settings ?? {}) as Record<string, unknown>;
  const str = (k: string) => (typeof set[k] === 'string' ? (set[k] as string) : '');
  // The browser's time zone: quiet hours are the admin's hours.
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';

  let kind = $state<ChannelKind>(c?.kind ?? 'telegram');
  let name = $state(c?.name ?? '');
  let enabled = $state(c?.enabled ?? true);
  let secret = $state('');
  let clearSecret = $state(false);
  let chatId = $state(str('chatId'));
  let apiBase = $state(str('apiBase'));
  let url = $state(str('url'));
  let host = $state(str('host'));
  let port = $state(typeof set.port === 'number' ? String(set.port) : '');
  let security = $state(str('security') || 'starttls');
  let username = $state(str('username'));
  let from = $state(str('from'));
  let to = $state(Array.isArray(set.to) ? (set.to as string[]).join(', ') : '');
  let all = $state(!c || c.events.length === 0);
  let picked = $state<Record<string, boolean>>(Object.fromEntries((c?.events ?? []).map((k) => [k, true])));
  let quietOn = $state(!!c?.quiet.from);
  let quietFrom = $state(c?.quiet.from || '23:00');
  let quietTo = $state(c?.quiet.to || '08:00');
  let quietZone = $state(c?.quiet.zone || zone);

  let busy = $state(false);
  let error = $state<ApiError | null>(null);
  let errField = $derived(error?.code === 'invalid' ? error.details : '');

  function settings(): Record<string, unknown> {
    switch (kind) {
      case 'telegram':
        return apiBase.trim() ? { chatId, apiBase } : { chatId };
      case 'webhook':
        return { url };
      default:
        return {
          host,
          port: Number(port) || 0,
          security,
          ...(username.trim() ? { username } : {}),
          from,
          to: to.split(',').map((x) => x.trim()).filter(Boolean),
        };
    }
  }

  // generate fills in a random signing key (24 bytes, base64url): it is
  // shown here once, to copy to the receiver.
  function generate() {
    const b = crypto.getRandomValues(new Uint8Array(24));
    secret = btoa(String.fromCharCode(...b)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = null;
    const input = {
      name,
      kind,
      enabled,
      settings: settings(),
      events: all ? [] : eventKinds.filter((k) => picked[k]),
      quiet: quietOn ? { from: quietFrom, to: quietTo, zone: quietZone } : { from: '', to: '', zone: '' },
      secret: secret !== '' ? secret : undefined,
      clearSecret: kind === 'smtp' && clearSecret ? true : undefined,
    };
    try {
      if (c) await api.updateAlertChannel(c.id, input);
      else await api.createAlertChannel(input);
      onsaved();
    } catch (err) {
      error = asApiError(err);
    } finally {
      busy = false;
    }
  }

  let keep = $derived(c?.hasSecret ? t('alerts.keepSecret') : '');
</script>

<Dialog title={c ? t('alerts.editTitle') : t('alerts.addTitle')} {onclose}>
  <form id="channel-form" class="form" onsubmit={save}>
    {#if !c}
      <div class="seg" role="radiogroup" aria-label={t('alerts.kind')}>
        {#each ['telegram', 'webhook', 'smtp'] as ChannelKind[] as k (k)}
          <button type="button" class:on={kind === k} onclick={() => (kind = k)}>{t(`alerts.via.${k}` as Key)}</button>
        {/each}
      </div>
    {/if}
    <label class:bad={errField === 'name'}>
      <span>{t('alerts.name')}</span>
      <input type="text" required maxlength="64" bind:value={name} placeholder={t('alerts.namePh')} />
    </label>

    {#if kind === 'telegram'}
      <label class:bad={errField === 'secret'}>
        <span>{t('alerts.botToken')}</span>
        <input type="password" bind:value={secret} autocomplete="off" spellcheck="false" placeholder={keep || '123456789:AA…'} required={!c?.hasSecret} />
      </label>
      <label class:bad={errField === 'chatId'}>
        <span>{t('alerts.chatId')}</span>
        <input type="text" required bind:value={chatId} spellcheck="false" placeholder="-1001234567890" />
      </label>
      <label class:bad={errField === 'apiBase'}>
        <span>{t('alerts.apiBase')}</span>
        <input type="url" bind:value={apiBase} spellcheck="false" placeholder="https://api.telegram.org" />
      </label>
      <p class="small muted">{t('alerts.telegramHint')}</p>
    {:else if kind === 'webhook'}
      <label class:bad={errField === 'url'}>
        <span>{t('alerts.url')}</span>
        <input type="url" required bind:value={url} spellcheck="false" placeholder="https://hooks.example.com/hyroute" />
      </label>
      <div class="two">
        <label class="grow" class:bad={errField === 'secret'}>
          <span>{t('alerts.hookKey')}</span>
          <input type="text" class="mono" bind:value={secret} autocomplete="off" spellcheck="false" placeholder={keep || t('alerts.hookKeyPh')} required={!c?.hasSecret} />
        </label>
        <button type="button" class="gen" onclick={generate}>{t('alerts.generate')}</button>
      </div>
      <p class="small muted">{t('alerts.webhookHint')}</p>
    {:else}
      <div class="two">
        <label class="grow" class:bad={errField === 'host'}>
          <span>{t('alerts.smtpHost')}</span>
          <input type="text" required bind:value={host} spellcheck="false" placeholder="smtp.example.com" />
        </label>
        <label class="port" class:bad={errField === 'port'}>
          <span>{t('alerts.port')}</span>
          <input type="number" min="1" max="65535" bind:value={port} placeholder={security === 'tls' ? '465' : security === 'none' ? '25' : '587'} />
        </label>
      </div>
      <label class:bad={errField === 'security'}>
        <span>{t('alerts.security')}</span>
        <select bind:value={security}>
          <option value="starttls">{t('alerts.sec.starttls')}</option>
          <option value="tls">{t('alerts.sec.tls')}</option>
          <option value="none">{t('alerts.sec.none')}</option>
        </select>
      </label>
      <div class="two">
        <label class="grow" class:bad={errField === 'username'}>
          <span>{t('alerts.smtpUser')}</span>
          <input type="text" bind:value={username} autocomplete="off" spellcheck="false" placeholder={t('servers.optional')} />
        </label>
        <label class="grow" class:bad={errField === 'secret'}>
          <span>{t('alerts.smtpPass')}</span>
          <input type="password" bind:value={secret} autocomplete="new-password" placeholder={keep} disabled={clearSecret} />
        </label>
      </div>
      {#if c?.hasSecret}
        <label class="check"><input type="checkbox" bind:checked={clearSecret} /> {t('alerts.clearPass')}</label>
      {/if}
      <label class:bad={errField === 'from'}>
        <span>{t('alerts.from')}</span>
        <input type="text" required bind:value={from} spellcheck="false" placeholder="HyRoute <bot@example.com>" />
      </label>
      <label class:bad={errField === 'to'}>
        <span>{t('alerts.to')}</span>
        <input type="text" required bind:value={to} spellcheck="false" placeholder="admin@example.com, ops@example.com" />
      </label>
    {/if}

    <fieldset class:bad={errField === 'events'}>
      <legend>{t('alerts.events')}</legend>
      <label class="check"><input type="checkbox" bind:checked={all} /> {t('alerts.allEvents')}</label>
      {#if !all}
        <div class="kinds">
          {#each eventKinds as k (k)}
            <label class="check"><input type="checkbox" bind:checked={picked[k]} /> {t(`alerts.ev.${k}` as Key)}</label>
          {/each}
        </div>
      {/if}
    </fieldset>

    <fieldset class:bad={errField === 'quiet'}>
      <legend>{t('alerts.quiet')}</legend>
      <label class="check"><input type="checkbox" bind:checked={quietOn} /> {t('alerts.quietOn')}</label>
      {#if quietOn}
        <div class="row">
          <input type="time" required bind:value={quietFrom} aria-label={t('alerts.quietFrom')} />
          <span>—</span>
          <input type="time" required bind:value={quietTo} aria-label={t('alerts.quietTo')} />
          <span class="small muted">{t('alerts.quietZone', { zone: quietZone || '—' })}</span>
        </div>
        <p class="small muted">{t('alerts.quietHint')}</p>
      {/if}
    </fieldset>

    <label class="check"><input type="checkbox" bind:checked={enabled} /> {t('alerts.enabled')}</label>
    {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
  </form>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button class="primary" type="submit" form="channel-form" disabled={busy}>{t('common.save')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 12px; }
  label:not(.check) { display: flex; flex-direction: column; gap: 5px; }
  label span { color: var(--muted); font-size: 12.5px; }
  label.bad input, label.bad select, fieldset.bad { border-color: var(--block); }
  .two { display: flex; gap: 10px; align-items: flex-end; }
  .port { width: 110px; }
  .gen { white-space: nowrap; }
  fieldset { border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 8px 12px 10px; margin: 0; display: flex; flex-direction: column; gap: 8px; }
  legend { color: var(--muted); font-size: 12.5px; padding: 0 4px; }
  .kinds { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 6px 12px; }
  p { margin: 0; }
  .note { margin: 0; }
  .seg { align-self: flex-start; }
</style>
