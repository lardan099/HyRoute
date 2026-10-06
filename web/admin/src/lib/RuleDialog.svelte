<script lang="ts">
  // A routing rule: the kind of address and its value (geo categories
  // searched in the controller's databases), protocol and port, outbound,
  // hijack, comment, group, off. Fields are checked here; the controller
  // checks the rule again with Hysteria's compiler.
  import { untrack } from 'svelte';
  import { api, asApiError, type AclRule } from '../api';
  import { t, type Key } from '../i18n';
  import { addressOf, bad, badChars, isIP, kindOf, kinds, outboundOK, portOK, valueOf, type AddrKind } from './acl';
  import Dialog from './Dialog.svelte';

  let {
    rule,
    outbounds,
    groups,
    onsave,
    onclose,
  }: { rule: AclRule | null; outbounds: string[]; groups: string[]; onsave: (r: AclRule) => void; onclose: () => void } = $props();

  // The form starts from the rule as it was when the dialog opened.
  const start = untrack(() => (rule && !bad(rule) ? rule : null));
  let kind = $state<AddrKind>(start ? kindOf(start.address) : 'domain');
  let value = $state(start ? valueOf(start.address) : '');
  let proto = $state(start?.proto ?? '');
  let port = $state(start?.port ?? '');
  let outbound = $state(start?.outbound ?? untrack(() => outbounds[0]) ?? 'direct');
  let hijack = $state(start?.hijack ?? '');
  let comment = $state(start?.comment ?? '');
  // A line Hysteria cannot read keeps its group when it is fixed here.
  let group = $state(untrack(() => rule?.group) ?? '');
  let off = $state(start?.off ?? false);
  let names = $state<string[]>([]);
  let noGeo = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  let choices = $derived(outbounds.includes(outbound) ? outbounds : [...outbounds, outbound]);
  let problems = $derived.by(() => {
    const p: Partial<Record<'value' | 'port' | 'outbound' | 'hijack' | 'text', Key>> = {};
    const v = value.trim();
    if (kind !== 'all' && !v) p.value = 'rt.errValue';
    else if (kind === 'ip' && !isIP(v)) p.value = 'rt.errIP';
    else if (kind === 'cidr' && !/^[0-9a-f:.]+\/\d{1,3}$/i.test(v)) p.value = 'rt.errCIDR';
    else if ((kind === 'domain' || kind === 'suffix') && v.includes('*')) p.value = 'rt.errStar';
    if (!portOK(port)) p.port = 'rt.errPort';
    if (!outboundOK(outbound)) p.outbound = 'rt.errOutbound';
    if (hijack.trim() && !isIP(hijack.trim())) p.hijack = 'rt.errHijack';
    // Hysteria cuts the line at the first #: a comment or group may hold
    // commas and brackets, only no line break. The value of "all" is not
    // shown and not saved.
    if ([kind === 'all' ? '' : value, port, hijack].some((s) => badChars.test(s)) || /[\r\n]/.test(comment + group)) p.text = 'rt.errChars';
    return p;
  });
  let valid = $derived(Object.keys(problems).length === 0);

  // search looks up geo categories as the admin types.
  function search() {
    clearTimeout(timer);
    if (kind !== 'geoip' && kind !== 'geosite') return;
    const k = kind;
    timer = setTimeout(async () => {
      try {
        names = (await api.geoCategories(k, value.split('@')[0].trim())).names;
        noGeo = false;
      } catch (e) {
        names = [];
        noGeo = asApiError(e).code === 'no_geo';
      }
    }, 250);
  }

  function setKind(k: AddrKind) {
    kind = k;
    names = [];
    search();
  }

  function save(e: SubmitEvent) {
    e.preventDefault();
    if (!valid) return;
    const r: AclRule = { ...(rule && !bad(rule) ? rule : {}), outbound: outbound.trim(), address: addressOf(kind, value) };
    if (rule && bad(rule)) r.before = rule.before;
    r.proto = proto || undefined;
    r.port = port.trim() || undefined;
    r.hijack = hijack.trim() || undefined;
    r.comment = comment.trim() || undefined;
    r.group = group.trim() || undefined;
    r.off = off || undefined;
    onsave(r);
  }
</script>

<Dialog title={rule && !bad(rule) ? t('rt.editRule') : t('rt.newRule')} {onclose}>
  <form id="rule-form" class="form" onsubmit={save}>
    {#if rule && bad(rule)}
      <div class="note error small">{t('rt.badLine')} <span class="mono">{rule.text}</span></div>
    {/if}
    <div class="two">
      <label class="kind">
        <span>{t('rt.kind')}</span>
        <select value={kind} onchange={(e) => setKind(e.currentTarget.value as AddrKind)}>
          {#each kinds as k (k)}<option value={k}>{t(`rt.kind.${k}` as Key)}</option>{/each}
        </select>
      </label>
      {#if kind !== 'all'}
        <label class="grow">
          <span>{t(`rt.value.${kind}` as Key)}</span>
          <input type="text" bind:value oninput={search} list="geo-names" spellcheck="false" autocomplete="off" placeholder={t(`rt.ph.${kind}` as Key)} />
          {#if problems.value}<span class="err">{t(problems.value)}</span>{/if}
        </label>
      {/if}
    </div>
    <datalist id="geo-names">{#each names as n (n)}<option value={n}></option>{/each}</datalist>
    <p class="hint">{t(`rt.hint.${kind}` as Key)}</p>
    {#if noGeo && (kind === 'geoip' || kind === 'geosite')}<p class="hint">{t('rt.noGeo')}</p>{/if}

    <div class="two">
      <label>
        <span>{t('rt.proto')}</span>
        <select bind:value={proto}>
          <option value="">{t('rt.protoAny')}</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
      </label>
      <label class="grow">
        <span>{t('rt.port')}</span>
        <input type="text" bind:value={port} placeholder={t('rt.portPh')} spellcheck="false" />
        {#if problems.port}<span class="err">{t(problems.port)}</span>{/if}
      </label>
    </div>

    <div class="two">
      <label class="grow">
        <span>{t('rt.outbound')}</span>
        <select bind:value={outbound}>
          {#each choices as o (o)}<option value={o}>{o}</option>{/each}
        </select>
        {#if problems.outbound}<span class="err">{t(problems.outbound)}</span>{/if}
      </label>
      <label class="grow">
        <span>{t('rt.hijack')}</span>
        <input type="text" bind:value={hijack} placeholder={t('rt.hijackPh')} spellcheck="false" />
        {#if problems.hijack}<span class="err">{t(problems.hijack)}</span>{/if}
      </label>
    </div>
    <p class="hint">{t('rt.outboundHint')}</p>

    <div class="two">
      <label class="grow">
        <span>{t('rt.comment')}</span>
        <input type="text" bind:value={comment} />
      </label>
      <label class="grow">
        <span>{t('rt.group')}</span>
        <input type="text" bind:value={group} list="rule-groups" />
      </label>
    </div>
    <datalist id="rule-groups">{#each groups as g (g)}<option value={g}></option>{/each}</datalist>
    <label class="check"><input type="checkbox" bind:checked={off} /> {t('rt.off')}</label>
    {#if problems.text}<span class="err">{t(problems.text)}</span>{/if}
  </form>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button type="submit" form="rule-form" class="primary" disabled={!valid}>{t('common.save')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 12px; min-width: min(560px, 82vw); }
  .form label:not(.check) { display: flex; flex-direction: column; gap: 5px; }
  .form label span { color: var(--muted); font-size: 12.5px; }
  .form label span.err, .err { color: var(--block); font-size: 12px; }
  .two { display: flex; gap: 12px; align-items: flex-start; }
  .grow { flex: 1; min-width: 0; }
  .kind { width: 230px; flex: none; }
  .hint { color: var(--faint); font-size: 12px; line-height: 1.4; margin: -4px 0 0; }
  @media (max-width: 640px) {
    .two { flex-direction: column; }
    .kind { width: 100%; }
  }
</style>
