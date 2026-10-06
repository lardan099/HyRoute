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

  async function save() {
    error = '';
    // A pasted value often brings a space along: Hysteria compares the SNI
    // and the pin as they are, and the backend trims only the address.
    if (p.tls.sni) p.tls.sni = p.tls.sni.trim();
    if (p.tls.pinSHA256) p.tls.pinSHA256 = p.tls.pinSHA256.trim();
    if (pinBad) {
      error = 'Отпечаток (pinSHA256) должен быть SHA-256 сертификата: 64 шестнадцатеричных символа (можно через «:»). С другим значением сервер не подключится.';
      return;
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

<div
  class="backdrop"
  role="presentation"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && onclose()}
>
  <div class="dialog" role="dialog" aria-modal="true">
    <h2>{p.id ? 'Сервер' : 'Новый сервер'}</h2>
    {#if sourceName}
      <div class="note warn">
        Сервер из подписки «{hide(sourceName)}». При её обновлении название, адрес, пароль, обфускация, SNI, отпечаток и
        «insecure» снова возьмутся из ссылки подписки, так что их правки здесь временные. Сохраняются только скорость, port
        hopping и «Резолвить адрес». Чтобы изменить их насовсем, скопируйте ссылку сервера и добавьте его как отдельный.
      </div>
    {/if}
    {#if ro}
      <div class="note info row">
        <span class="grow">Включено «Скрыть данные»: название, адрес и SNI скрыты.</span>
        <button onclick={() => (revealed = true)}>Показать и редактировать</button>
      </div>
    {/if}
    <div class="grid">
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
        <input bind:value={p.ports} style="width: 170px" placeholder="443 или 443,20000-50000" title="Порт или диапазоны для port hopping" />
      </div>

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
    </div>

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

        <span></span>
        <label class="check" title="HyRoute сам резолвит адрес и передаёт Hysteria IP: исключение из перехвата совпадает точно">
          <input type="checkbox" bind:checked={p.pinServerIP} /> Резолвить адрес в HyRoute и передавать IP
        </label>
      </div>
    </details>
    <!-- An error may quote the address or another server's name. -->
    {#if error}<div class="note error">{ro ? hide(error) : error}</div>{/if}
    <p class="muted small">Если сервер сейчас используется, он переподключится с новыми настройками.</p>
    <div class="actions">
      <button onclick={onclose}>Отмена</button>
      <button class="primary" onclick={save} disabled={saving || !p.host.trim()}>Сохранить</button>
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
</style>
