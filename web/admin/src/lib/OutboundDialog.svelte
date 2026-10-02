<script lang="ts">
  // An outbound of the server: direct (mode, bind), SOCKS5 or HTTP proxy.
  // Passwords come hidden: kept unless the admin types a new one. The
  // current name stays in `from`, so the controller renames the outbound
  // in the rules too.
  import { untrack } from 'svelte';
  import { HIDDEN, type RoutingOutbound } from '../api';
  import { t } from '../i18n';
  import { outboundOK } from './acl';
  import Dialog from './Dialog.svelte';

  let {
    outbound,
    taken,
    fixedName = false,
    onsave,
    onclose,
  }: { outbound: RoutingOutbound | null; taken: string[]; fixedName?: boolean; onsave: (o: RoutingOutbound) => void; onclose: () => void } = $props();

  // The form starts from the outbound as it was when the dialog opened.
  const o = untrack(() => outbound);
  let name = $state(o?.name ?? '');
  let type = $state(o?.type ?? 'socks5');
  let mode = $state(o?.direct?.mode ?? '');
  let bind4 = $state(o?.direct?.bindIPv4 ?? '');
  let bind6 = $state(o?.direct?.bindIPv6 ?? '');
  let device = $state(o?.direct?.bindDevice ?? '');
  let fastOpen = $state(o?.direct?.fastOpen ?? false);
  let addr = $state(o?.socks5?.addr ?? '');
  let user = $state(o?.socks5?.username ?? '');
  let socksPass = $state(o?.socks5?.password ?? '');
  let url = $state(o?.http?.url ?? '');
  let httpPass = $state(o?.http?.password ?? '');
  let insecure = $state(o?.http?.insecure ?? false);

  let nameError = $derived(
    !outboundOK(name.trim())
      ? 'ob.errName'
      : taken.some((n) => n.toLowerCase() === name.trim().toLowerCase())
        ? 'ob.errTaken'
        : name.trim().toLowerCase() === 'cascade' && o?.from?.toLowerCase() !== 'cascade'
          ? 'ob.errCascade'
          : null,
  );
  let fieldError = $derived(
    type === 'socks5' && !/^[^\s/]+:\d{1,5}$/.test(addr.trim())
      ? 'ob.errAddr'
      : type === 'http' && !/^https?:\/\/[^\s]+$/.test(url.trim())
        ? 'ob.errURL'
        : null,
  );

  function save(e: SubmitEvent) {
    e.preventDefault();
    if (nameError || fieldError) return;
    const out: RoutingOutbound = { name: name.trim(), type, from: o?.from };
    if (type === 'direct') out.direct = { mode: mode || undefined, bindIPv4: bind4.trim() || undefined, bindIPv6: bind6.trim() || undefined, bindDevice: device.trim() || undefined, fastOpen: fastOpen || undefined };
    if (type === 'socks5') out.socks5 = { addr: addr.trim(), username: user.trim() || undefined, password: socksPass || undefined };
    if (type === 'http') out.http = { url: url.trim(), password: httpPass || undefined, insecure: insecure || undefined };
    onsave(out);
  }
</script>

<Dialog title={o ? t('ob.edit', { name: o.name }) : t('ob.new')} {onclose}>
  <form id="ob-form" class="form" onsubmit={save}>
    <div class="two">
      <label class="grow">
        <span>{t('ob.name')}</span>
        <input type="text" bind:value={name} spellcheck="false" autocomplete="off" readonly={fixedName} />
        {#if nameError && name}<span class="err">{t(nameError as 'ob.errName')}</span>{/if}
      </label>
      <label>
        <span>{t('ob.type')}</span>
        <select bind:value={type}>
          <option value="direct">{t('ob.direct')}</option>
          <option value="socks5">SOCKS5</option>
          <option value="http">HTTP / HTTPS</option>
        </select>
      </label>
    </div>
    {#if o?.from && name.trim() && name.trim() !== o.from}<p class="hint">{t('ob.renameNote', { from: o.from })}</p>{/if}

    {#if type === 'direct'}
      <label>
        <span>{t('ob.mode')}</span>
        <select bind:value={mode}>
          <option value="">{t('ob.modeAuto')}</option>
          <option value="46">{t('ob.mode46')}</option>
          <option value="64">{t('ob.mode64')}</option>
          <option value="4">{t('ob.mode4')}</option>
          <option value="6">{t('ob.mode6')}</option>
        </select>
      </label>
      <div class="two">
        <label class="grow"><span>{t('ob.bind4')}</span><input type="text" bind:value={bind4} spellcheck="false" /></label>
        <label class="grow"><span>{t('ob.bind6')}</span><input type="text" bind:value={bind6} spellcheck="false" /></label>
      </div>
      <label><span>{t('ob.device')}</span><input type="text" bind:value={device} placeholder="eth1" spellcheck="false" /></label>
      <p class="hint">{t('ob.bindHint')}</p>
      <label class="check"><input type="checkbox" bind:checked={fastOpen} /> {t('ob.fastOpen')}</label>
    {:else if type === 'socks5'}
      <label>
        <span>{t('ob.addr')}</span>
        <input type="text" bind:value={addr} placeholder="203.0.113.5:1080" spellcheck="false" />
      </label>
      <div class="two">
        <label class="grow"><span>{t('ob.user')}</span><input type="text" bind:value={user} spellcheck="false" autocomplete="off" /></label>
        <div class="grow field">
          <span class="lbl">{t('ob.password')}</span>
          {#if socksPass === HIDDEN}
            <div class="row"><span class="muted small">{t('cfg.hidden')}</span><button type="button" class="ghost" onclick={() => (socksPass = '')}>{t('cfg.setNew')}</button></div>
          {:else}
            <input class="mono" type="text" bind:value={socksPass} spellcheck="false" autocomplete="off" />
          {/if}
        </div>
      </div>
    {:else}
      <label>
        <span>{t('ob.url')}</span>
        <input type="text" bind:value={url} placeholder="https://user@proxy.example.com:8443" spellcheck="false" />
      </label>
      <div class="field">
        <span class="lbl">{t('ob.password')}</span>
        {#if httpPass === HIDDEN}
          <div class="row"><span class="muted small">{t('cfg.hidden')}</span><button type="button" class="ghost" onclick={() => (httpPass = '')}>{t('cfg.setNew')}</button></div>
        {:else}
          <input class="mono" type="text" bind:value={httpPass} spellcheck="false" autocomplete="off" />
        {/if}
      </div>
      <label class="check"><input type="checkbox" bind:checked={insecure} /> {t('ob.insecure')}</label>
    {/if}
    {#if fieldError}<span class="err">{t(fieldError as 'ob.errAddr')}</span>{/if}
  </form>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button type="submit" form="ob-form" class="primary" disabled={!!nameError || !!fieldError}>{t('common.save')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 12px; min-width: min(520px, 82vw); }
  .form label:not(.check), .field { display: flex; flex-direction: column; gap: 5px; }
  .form label span, .lbl { color: var(--muted); font-size: 12.5px; }
  .err { color: var(--block); font-size: 12px; }
  .two { display: flex; gap: 12px; align-items: flex-start; }
  .grow { flex: 1; min-width: 0; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; margin: -4px 0 0; }
  @media (max-width: 640px) { .two { flex-direction: column; } }
</style>
