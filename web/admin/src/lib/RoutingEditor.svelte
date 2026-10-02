<script lang="ts">
  // The routing editor of a server: its ACL rules as a table (groups,
  // drag and drop or arrows, selection and bulk actions, search and
  // filters), the checks of the controller over it, and the apply job. The
  // controller checks every draft (Hysteria's compiler and lint) and keeps
  // the text of untouched rules as it was.
  import { onMount } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import {
    api,
    asApiError,
    type AclProblem,
    type AclRequest,
    type AclRule,
    type ApiError,
    type RoutingOutbound,
    type RoutingPreview,
    type RoutingResolver,
    type RoutingTemplate,
    type RoutingView,
    type Server,
  } from '../api';
  import { t, type Key } from '../i18n';
  import { go } from '../router.svelte';
  import { bad, builtIn, kindOf, kinds, merge, protoPort, valueOf, type AddrKind, type TemplateMode } from './acl';
  import ChainNote from './ChainNote.svelte';
  import Dialog from './Dialog.svelte';
  import DiffView from './DiffView.svelte';
  import GeoCard from './GeoCard.svelte';
  import OutboundDialog from './OutboundDialog.svelte';
  import RoutingCheck from './RoutingCheck.svelte';
  import RuleDialog from './RuleDialog.svelte';
  import TemplateDialog from './TemplateDialog.svelte';

  let { server, onclose }: { server: Server; onclose: () => void } = $props();

  type Row = { key: number; rule: AclRule };
  let nextKey = 1;
  const rowsOf = (rules: AclRule[] | null) => (rules ?? []).map((rule) => ({ key: nextKey++, rule }));

  let view = $state<RoutingView | null>(null);
  let rows = $state<Row[]>([]);
  let obs = $state<RoutingOutbound[]>([]);
  let resolver = $state<RoutingResolver>({ type: 'system' });
  let extra = $state('');
  let highlight = $state<number | null>(null);
  let obEditing = $state<{ index: number | null; o: RoutingOutbound | null } | null>(null);
  let tplOpen = $state<{ list: RoutingTemplate[]; title: string } | null>(null);
  let fileInput = $state<HTMLInputElement | null>(null);
  let tail = $state<string[] | undefined>(undefined);
  let keepFile = $state(false);
  let fileRows = $state<Row[] | null>(null);
  let fileProblems = $state<AclProblem[]>([]);
  let preview = $state<RoutingPreview | null>(null);
  let error = $state<ApiError | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let confirming = $state(false);
  let editing = $state<{ key: number | null; rule: AclRule | null } | null>(null);
  let bulk = $state<'group' | 'outbound' | 'delete' | null>(null);
  let bulkValue = $state('');
  let q = $state('');
  let fOutbound = $state('');
  let fKind = $state<AddrKind | ''>('');
  let collapsed = new SvelteSet<string>();
  let selected = new SvelteSet<number>();
  let dragKey = $state<number | null>(null);
  let overKey = $state<number | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let seq = 0;

  // outbounds a rule can name: the config's, then the built-in ones it
  // does not override.
  let outbounds = $derived.by(() => {
    const names = obs.map((o) => o.name);
    return [...names, ...builtIn.filter((b) => !names.some((n) => n.toLowerCase() === b))];
  });
  let groups = $derived([...new Set(rows.map((r) => r.rule.group ?? '').filter(Boolean))]);
  let problems = $derived(preview?.rules ?? view?.problems ?? []);
  let byRule = $derived.by(() => {
    const m = new Map<number, AclProblem[]>();
    for (const p of problems) if (p.rule >= 0) m.set(p.rule, [...(m.get(p.rule) ?? []), p]);
    return m;
  });
  let whole = $derived(problems.filter((p) => p.rule < 0));
  let filtering = $derived(!!(q.trim() || fOutbound || fKind));
  let shown = $derived(
    rows
      .map((r, i) => ({ ...r, i }))
      .filter(({ rule }) => {
        if (fOutbound && rule.outbound.toLowerCase() !== fOutbound.toLowerCase()) return false;
        if (fKind && (bad(rule) || kindOf(rule.address) !== fKind)) return false;
        const s = q.trim().toLowerCase();
        return !s || [rule.address, rule.outbound, rule.comment, rule.group, rule.text].some((f) => (f ?? '').toLowerCase().includes(s));
      }),
  );
  let configErrors = $derived(preview?.problems.filter((p) => !p.warning) ?? []);
  let configWarnings = $derived(preview?.problems.filter((p) => p.warning) ?? []);
  let ruleErrors = $derived(problems.filter((p) => p.level === 'error'));
  let changed = $derived(!!preview && !preview.same);

  onMount(async () => {
    try {
      view = await api.routing(server.id);
      rows = rowsOf(view.acl.rules);
      tail = view.acl.tail;
      obs = view.outbounds.map((o) => ({ ...o }));
      resolver = { ...view.resolver };
      keepFile = !!view.file;
      await check();
    } catch (e) {
      error = asApiError(e);
    } finally {
      loading = false;
    }
  });

  function input() {
    return {
      base: view!.revision,
      acl: { rules: rows.map((r) => r.rule), tail },
      keepFile,
      outbounds: obs,
      resolver,
      requests: requests(),
    };
  }

  // requests are the admin's addresses for the dry run: host, host:port,
  // [IPv6]:port (TCP 443 when no port).
  function requests(): AclRequest[] {
    const out: AclRequest[] = [];
    for (const tok of extra.split(/[\s,]+/).filter(Boolean)) {
      let host = tok;
      let port = 443;
      const v6 = tok.match(/^\[([^\]]+)\](?::(\d+))?$/);
      if (v6) [host, port] = [v6[1], Number(v6[2] ?? 443)];
      else if ((tok.match(/:/g) ?? []).length === 1) [host, port] = [tok.split(':')[0], Number(tok.split(':')[1]) || 443];
      out.push({ host, port });
    }
    return out;
  }

  // Outbounds: the cascade's stays first; a rename follows in the rules.
  function saveOutbound(o: RoutingOutbound) {
    if (!obEditing) return;
    if (obEditing.index === null) obs.push(o);
    else {
      const old = obs[obEditing.index].name;
      obs[obEditing.index] = o;
      if (old !== o.name) for (const r of rows) if (r.rule.outbound.toLowerCase() === old.toLowerCase()) r.rule = { ...r.rule, outbound: o.name };
    }
    obEditing = null;
    changedRules();
  }

  function moveOutbound(i: number, to: number) {
    if (to < 0 || to >= obs.length || obs[i].locked || obs[to].locked) return;
    const [o] = obs.splice(i, 1);
    obs.splice(to, 0, o);
    changedRules();
  }

  function removeOutbound(i: number) {
    if (obs[i].locked) return;
    obs.splice(i, 1);
    changedRules();
  }

  // check asks the controller about the draft.
  async function check() {
    if (!view) return;
    const my = ++seq;
    busy = true;
    try {
      const p = await api.routingPreview(server.id, input());
      if (my !== seq) return;
      preview = p;
      error = null;
    } catch (e) {
      if (my !== seq) return;
      error = asApiError(e);
    } finally {
      if (my === seq) busy = false;
    }
  }

  function changedRules() {
    busy = true;
    seq++; // a preview on its way is of an older draft
    clearTimeout(timer);
    timer = setTimeout(check, 400);
  }

  function save(r: AclRule) {
    if (!editing) return;
    if (editing.key === null) rows.push({ key: nextKey++, rule: r });
    else {
      const i = rows.findIndex((x) => x.key === editing!.key);
      if (i >= 0) rows[i] = { key: rows[i].key, rule: r };
    }
    editing = null;
    changedRules();
  }

  function move(from: number, to: number) {
    if (to < 0 || to >= rows.length || from === to) return;
    const [r] = rows.splice(from, 1);
    rows.splice(to, 0, r);
    changedRules();
  }

  function drop(target: number) {
    if (dragKey === null) return;
    const from = rows.findIndex((r) => r.key === dragKey);
    const to = rows.findIndex((r) => r.key === target);
    dragKey = overKey = null;
    if (from >= 0 && to >= 0) move(from, to);
  }

  function remove(key: number) {
    rows = rows.filter((r) => r.key !== key);
    selected.delete(key);
    changedRules();
  }

  function toggle(i: number) {
    const r = rows[i];
    if (bad(r.rule)) return;
    r.rule = { ...r.rule, off: !r.rule.off || undefined };
    changedRules();
  }

  // addFix puts a problem's rules at the top.
  function addFix(p: AclProblem) {
    rows = [...rowsOf(p.fix ?? []), ...rows];
    changedRules();
  }

  let selectedRows = $derived(rows.filter((r) => selected.has(r.key)));
  let allShown = $derived(shown.length > 0 && shown.every((r) => selected.has(r.key)));

  function selectShown(on: boolean) {
    for (const r of shown) {
      if (on) selected.add(r.key);
      else selected.delete(r.key);
    }
  }

  function setOff(off: boolean) {
    for (const r of selectedRows) if (!bad(r.rule)) r.rule = { ...r.rule, off: off || undefined };
    changedRules();
  }

  function duplicate() {
    const out: Row[] = [];
    for (const r of rows) {
      out.push(r);
      if (selected.has(r.key)) out.push({ key: nextKey++, rule: { ...r.rule, text: undefined, before: undefined } });
    }
    rows = out;
    changedRules();
  }

  function doBulk() {
    const v = bulkValue.trim();
    if (bulk === 'delete') {
      rows = rows.filter((r) => !selected.has(r.key));
      selected.clear();
    } else {
      for (const r of selectedRows) {
        if (bad(r.rule)) continue;
        if (bulk === 'group') r.rule = { ...r.rule, group: v || undefined };
        if (bulk === 'outbound' && v) r.rule = { ...r.rule, outbound: v };
      }
    }
    bulk = null;
    changedRules();
  }

  async function openTemplates() {
    try {
      tplOpen = { list: await api.routingTemplates(), title: t('tpl.title') };
    } catch (e) {
      error = asApiError(e);
    }
  }

  // importFile reads a routing export or a Hysteria ACL as a template.
  async function importFile(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const f = input.files?.[0];
    input.value = '';
    if (!f) return;
    try {
      const x = await api.routingImport(await f.text());
      tplOpen = { list: [{ id: 'import', name: f.name, acl: x.acl, outbounds: x.outbounds, resolver: x.resolver }], title: t('tpl.importTitle', { name: f.name }) };
    } catch (err) {
      error = asApiError(err);
    }
  }

  function applyTemplate(tpl: RoutingTemplate, mode: TemplateMode, withOutbounds: boolean) {
    const m = merge(
      rows.map((r) => r.rule),
      obs,
      tpl,
      mode,
      withOutbounds,
    );
    rows = rowsOf(m.rules);
    obs = m.outbounds;
    if (m.resolver) resolver = m.resolver;
    selected.clear();
    tplOpen = null;
    changedRules();
  }

  // exportAs saves what the server has now (not the draft).
  async function exportAs(format: 'json' | 'text') {
    try {
      const text = await api.routingExport(server.id, format);
      const url = URL.createObjectURL(new Blob([text], { type: format === 'json' ? 'application/json' : 'text/plain' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `routing-${server.name.replace(/[^\p{L}\p{N}._-]+/gu, '-')}.${format === 'json' ? 'json' : 'acl'}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      error = asApiError(e);
    }
  }

  async function openFile() {
    try {
      const f = await api.routingFile(server.id);
      fileRows = rowsOf(f.acl.rules);
      fileProblems = f.problems;
      tail = f.acl.tail;
    } catch (e) {
      error = asApiError(e);
    }
  }

  function moveIntoInline() {
    if (!fileRows) return;
    rows = fileRows;
    fileRows = null;
    keepFile = false;
    changedRules();
  }

  async function apply() {
    confirming = false;
    busy = true;
    try {
      const j = await api.routingApply(server.id, input());
      go('deployments', j.id);
    } catch (e) {
      error = asApiError(e);
      busy = false;
    }
  }

  // headed: a group header goes above the shown row at index n.
  const headed = (n: number) => !!shown[n].rule.group && (n === 0 || shown[n - 1].rule.group !== shown[n].rule.group);
  const hidden = (r: Row) => !!r.rule.group && collapsed.has(r.rule.group);
  const count = (g: string) => rows.filter((r) => r.rule.group === g).length;
  const kindName = (r: AclRule) => (bad(r) ? t('rt.badShort') : t(`rt.kind.${kindOf(r.address)}` as Key));
</script>

<section class="card editor">
  <div class="row head">
    <h2 class="grow">{t('rt.title', { name: server.name })} {#if view}<span class="faint small">{t('cfg.revision', { n: view.revision })}</span>{/if}</h2>
    {#if busy}<span class="faint small">{t('cfg.checking')}</span>{/if}
  </div>

  {#if loading}
    <p class="muted">{t('cfg.loading')}</p>
  {:else if view}
    {#if view.cascade}<div class="note info small">{t('rt.cascadeNote', { name: view.cascade.name })}</div>{/if}

    {#if keepFile}
      <div class="note info">
        {t('rt.fileNote', { path: view.file ?? '' })}
        {#if !fileRows}<button class="link" onclick={openFile}>{t('rt.fileOpen')}</button>{/if}
      </div>
      {#if fileRows}
        <div class="filebar row">
          <span class="grow small muted">{t('rt.fileRules', { n: fileRows.length })}</span>
          <button class="primary" onclick={moveIntoInline}>{t('rt.fileMove')}</button>
        </div>
        <ol class="file mono small">
          {#each fileRows as r, i (r.key)}
            <li class:off={r.rule.off}>
              {bad(r.rule) ? r.rule.text : `${r.rule.outbound}(${r.rule.address}${protoPort(r.rule) ? ', ' + protoPort(r.rule) : ''}${r.rule.hijack ? ', ' + r.rule.hijack : ''})`}
              {#each fileProblems.filter((p) => p.rule === i) as p, j (j)}<div class="prob {p.level}">{p.message}</div>{/each}
            </li>
          {/each}
        </ol>
      {/if}
    {:else}
      {#each whole as p, i (i)}
        <div class="note {p.level === 'error' ? 'error' : 'warn'} small lint">
          <span class="grow">{p.message}</span>
          {#if p.fix?.length}<button class="ghost" onclick={() => addFix(p)}>{t('rt.addFix')}</button>{/if}
        </div>
      {/each}

      <div class="row tools">
        <input class="search" type="search" bind:value={q} placeholder={t('rt.search')} />
        <select bind:value={fOutbound} aria-label={t('rt.outbound')}>
          <option value="">{t('rt.allOutbounds')}</option>
          {#each outbounds as o (o)}<option value={o}>{o}</option>{/each}
        </select>
        <select bind:value={fKind} aria-label={t('rt.kind')}>
          <option value="">{t('rt.allKinds')}</option>
          {#each kinds as k (k)}<option value={k}>{t(`rt.kind.${k}` as Key)}</option>{/each}
        </select>
        <span class="grow"></span>
        <button class="ghost" onclick={openTemplates}>{t('tpl.open')}</button>
        <button class="ghost" onclick={() => fileInput?.click()}>{t('tpl.import')}</button>
        <button class="ghost" onclick={() => exportAs('json')} title={t('tpl.exportHint')}>{t('tpl.exportJSON')}</button>
        <button class="ghost" onclick={() => exportAs('text')} title={t('tpl.exportHint')}>{t('tpl.exportText')}</button>
        <input type="file" accept=".json,.acl,.txt,text/plain,application/json" class="hidden" bind:this={fileInput} onchange={importFile} />
        <button class="primary" onclick={() => (editing = { key: null, rule: null })}>{t('rt.add')}</button>
      </div>

      {#if selected.size}
        <div class="row bulk small">
          <span class="grow">{t('rt.selected', { n: selected.size })}</span>
          <button class="ghost" onclick={() => setOff(false)}>{t('rt.on')}</button>
          <button class="ghost" onclick={() => setOff(true)}>{t('rt.offMany')}</button>
          <button class="ghost" onclick={duplicate}>{t('rt.duplicate')}</button>
          <button class="ghost" onclick={() => ((bulk = 'group'), (bulkValue = ''))}>{t('rt.toGroup')}</button>
          <button class="ghost" onclick={() => ((bulk = 'outbound'), (bulkValue = outbounds[0] ?? ''))}>{t('rt.setOutbound')}</button>
          <button class="ghost danger" onclick={() => (bulk = 'delete')}>{t('rt.delete')}</button>
          <button class="ghost" onclick={() => selected.clear()}>{t('rt.unselect')}</button>
        </div>
      {/if}

      {#if rows.length === 0}
        <p class="muted small empty">{t('rt.empty')}</p>
      {:else}
        <div class="table">
          <table>
            <thead>
              <tr>
                <th class="sel"><input type="checkbox" checked={allShown} onchange={(e) => selectShown(e.currentTarget.checked)} aria-label={t('rt.selectAll')} /></th>
                <th class="num">№</th>
                <th>{t('rt.onCol')}</th>
                <th>{t('rt.address')}</th>
                <th>{t('rt.protoPort')}</th>
                <th>{t('rt.outbound')}</th>
                <th>{t('rt.comment')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each shown as r, n (r.key)}
                {#if headed(n)}
                  <tr class="group">
                    <td colspan="8">
                      <button class="link-btn" onclick={() => (collapsed.has(r.rule.group!) ? collapsed.delete(r.rule.group!) : collapsed.add(r.rule.group!))}>
                        {collapsed.has(r.rule.group!) ? '▸' : '▾'} {r.rule.group} <span class="faint">({count(r.rule.group!)})</span>
                      </button>
                    </td>
                  </tr>
                {/if}
                {#if !hidden(r)}
                  <tr
                    class:off={r.rule.off}
                    class:grouped={!!r.rule.group}
                    class:over={overKey === r.key && dragKey !== r.key}
                    class:hl={highlight === r.i}
                    draggable={!filtering}
                    ondragstart={(e) => {
                      dragKey = r.key;
                      e.dataTransfer?.setData('text/plain', String(r.key));
                    }}
                    ondragover={(e) => {
                      if (dragKey === null) return;
                      e.preventDefault();
                      overKey = r.key;
                    }}
                    ondrop={(e) => {
                      e.preventDefault();
                      drop(r.key);
                    }}
                    ondragend={() => (dragKey = overKey = null)}
                  >
                    <td class="sel"><input type="checkbox" checked={selected.has(r.key)} onchange={(e) => (e.currentTarget.checked ? selected.add(r.key) : selected.delete(r.key))} aria-label={t('rt.select', { n: r.i + 1 })} /></td>
                    <td class="num faint">{#if !filtering}<span class="grip" aria-hidden="true">⋮⋮</span>{/if}{r.i + 1}</td>
                    <td><input type="checkbox" checked={!r.rule.off} disabled={bad(r.rule)} onchange={() => toggle(r.i)} aria-label={t('rt.onCol')} /></td>
                    <td class="addr">
                      {#if bad(r.rule)}
                        <span class="mono">{r.rule.text}</span>
                      {:else}
                        <span class="kind small">{kindName(r.rule)}</span>
                        <span class="mono">{valueOf(r.rule.address) || '*'}</span>
                        {#if r.rule.hijack}<span class="small muted"> → {r.rule.hijack}</span>{/if}
                      {/if}
                      {#each byRule.get(r.i) ?? [] as p, j (j)}<div class="prob {p.level}">{p.message}</div>{/each}
                    </td>
                    <td class="mono small">{bad(r.rule) ? '' : protoPort(r.rule) || t('rt.any')}</td>
                    <td>{#if !bad(r.rule)}<span class="pill {r.rule.outbound.toLowerCase() === 'reject' ? 'block' : 'direct'}">{r.rule.outbound}</span>{/if}</td>
                    <td class="small muted">{r.rule.comment ?? ''}</td>
                    <td class="acts">
                      <button class="ghost" disabled={filtering || r.i === 0} onclick={() => move(r.i, r.i - 1)} aria-label={t('rt.up')}>↑</button>
                      <button class="ghost" disabled={filtering || r.i === rows.length - 1} onclick={() => move(r.i, r.i + 1)} aria-label={t('rt.down')}>↓</button>
                      <button class="ghost" onclick={() => (editing = { key: r.key, rule: r.rule })}>{t('rt.edit')}</button>
                      <button class="ghost danger" onclick={() => remove(r.key)} aria-label={t('rt.delete')}>✕</button>
                    </td>
                  </tr>
                {/if}
              {/each}
            </tbody>
          </table>
        </div>
        {#if filtering}<p class="faint small">{t('rt.filterNote')}</p>{/if}
      {/if}
    {/if}

  {/if}
  {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
  {#if !preview}<div class="row actions"><span class="grow"></span><button onclick={onclose}>{t('cfg.cancel')}</button></div>{/if}
</section>

{#if view}
  <div class="side">
    <section class="card">
      <div class="row">
        <h2 class="grow">{t('ob.title')}</h2>
        <button class="ghost" onclick={() => (obEditing = { index: null, o: null })}>{t('ob.add')}</button>
      </div>
      {#if obs.length === 0}
        <p class="muted small">{t('ob.none')}</p>
      {:else}
        <ol class="obs">
          {#each obs as o, i (i)}
            <li>
              <span class="grow">
                {#if o.locked}<span aria-label={t('ob.locked')} title={t('ob.locked')}>🔒</span>{/if}
                <b>{o.name}</b>
                <span class="small muted">{o.type}{o.socks5 ? ' · ' + o.socks5.addr : o.http ? ' · ' + o.http.url : o.direct?.bindDevice ? ' · ' + o.direct.bindDevice : ''}</span>
                {#if i === 0}<span class="pill direct small">{t('ob.default')}</span>{/if}
                {#if o.locked && view.cascade}<span class="small muted">{t('ob.chain', { name: view.cascade.name })}</span>{/if}
              </span>
              {#if !o.locked}
                <span class="acts">
                  <button class="ghost" disabled={i === 0 || obs[i - 1].locked} onclick={() => moveOutbound(i, i - 1)} aria-label={t('rt.up')}>↑</button>
                  <button class="ghost" disabled={i === obs.length - 1} onclick={() => moveOutbound(i, i + 1)} aria-label={t('rt.down')}>↓</button>
                  <button class="ghost" onclick={() => (obEditing = { index: i, o })}>{t('rt.edit')}</button>
                  {#if !(keepFile && o.from)}<button class="ghost danger" onclick={() => removeOutbound(i)} aria-label={t('rt.delete')}>✕</button>{/if}
                </span>
              {/if}
            </li>
          {/each}
        </ol>
      {/if}
      <p class="small faint">{t('ob.hint')}</p>
      {#if keepFile}<p class="small faint">{t('ob.fileNote')}</p>{/if}

      <div class="rform">
        <h3>{t('rs.title')}</h3>
        <label>
          <span>{t('rs.type')}</span>
          <select bind:value={resolver.type} onchange={changedRules}>
            <option value="system">{t('rs.system')}</option>
            <option value="https">{t('rs.https')}</option>
            <option value="tls">{t('rs.tls')}</option>
            <option value="udp">{t('rs.udp')}</option>
            <option value="tcp">{t('rs.tcp')}</option>
          </select>
        </label>
        {#if resolver.type !== 'system'}
          <label>
            <span>{t('rs.addr')}</span>
            <input type="text" bind:value={resolver.addr} oninput={changedRules} placeholder={resolver.type === 'https' ? 'https://1.1.1.1/dns-query' : resolver.type === 'tls' ? '1.1.1.1:853' : '1.1.1.1:53'} spellcheck="false" />
          </label>
          <label><span>{t('rs.timeout')}</span><input type="text" bind:value={resolver.timeout} oninput={changedRules} placeholder="10s" /></label>
          {#if resolver.type === 'tls' || resolver.type === 'https'}
            <label><span>{t('rs.sni')}</span><input type="text" bind:value={resolver.sni} oninput={changedRules} spellcheck="false" /></label>
            <label class="check"><input type="checkbox" bind:checked={resolver.insecure} onchange={changedRules} /> {t('rs.insecure')}</label>
          {/if}
        {/if}
        <p class="small faint">{t('rs.hint')}</p>
      </div>
    </section>

    <div class="col">
      {#if !keepFile}<section class="card">
        <h2>{t('rc.title')}</h2>
        <RoutingCheck serverId={server.id} acl={() => ({ rules: rows.map((r) => r.rule), tail })} outbounds={obs.map((o) => o.name)} onrule={(i) => (highlight = i)} />
      </section>{/if}
      <section class="card"><GeoCard serverId={server.id} writable={true} /></section>
    </div>
  </div>
{/if}

{#if preview && view}
  <section class="card">
    <h2>{t('cfg.problems')}</h2>
    {#each configErrors as p, i (i)}<div class="prob error"><span class="mono">{p.field}</span> {p.message}</div>{/each}
    {#each configWarnings as p, i (i)}<div class="prob warn"><span class="mono">{p.field}</span> {p.message}</div>{/each}
    {#if ruleErrors.length}<div class="prob error">{t('rt.ruleErrors', { n: ruleErrors.length })}</div>{/if}
    {#if !configErrors.length && !configWarnings.length && !ruleErrors.length}<p class="muted small">{t('cfg.noProblems')}</p>{/if}
    {#if !changed}<p class="muted small">{t('rt.same')}</p>{/if}

    {#if !keepFile}
      <div class="dry">
        <h3>{t('dry.title')}</h3>
        <label class="field">
          <span>{t('dry.requests')}</span>
          <input type="text" bind:value={extra} oninput={changedRules} placeholder="youtube.com, ya.ru:443, [2001:db8::1]:53" spellcheck="false" />
        </label>
        {#if preview.changes.length}
          <ul class="changes small">
            {#each preview.changes as c, i (i)}
              <li>
                <span class="mono">{c.request.host}{c.request.proto && c.request.proto !== 'tcp' ? ' ' + c.request.proto : ''}:{c.request.port}</span>
                — {c.before.outbound}{c.before.hijack ? ' → ' + c.before.hijack : ''} ⟶ <b>{c.after.outbound}{c.after.hijack ? ' → ' + c.after.hijack : ''}</b>
              </li>
            {/each}
          </ul>
        {:else}
          <p class="muted small">{t('dry.none')}</p>
        {/if}
      </div>
    {/if}
    <div class="row actions">
      <span class="grow"></span>
      <button onclick={onclose}>{t('cfg.cancel')}</button>
      <button class="primary" disabled={busy || !changed || !preview.ok || !!error} onclick={() => (confirming = true)}>{t('cfg.apply')}</button>
    </div>
  </section>
{/if}

{#if tplOpen}
  <TemplateDialog templates={tplOpen.list} title={tplOpen.title} onapply={applyTemplate} onclose={() => (tplOpen = null)} />
{/if}

{#if obEditing}
  <OutboundDialog
    outbound={obEditing.o}
    taken={obs.filter((_, i) => i !== obEditing!.index).map((o) => o.name)}
    fixedName={keepFile && !!obEditing.o?.from}
    onsave={saveOutbound}
    onclose={() => (obEditing = null)}
  />
{/if}

{#if editing}
  <RuleDialog rule={editing.rule} {outbounds} {groups} onsave={save} onclose={() => (editing = null)} />
{/if}

{#if bulk}
  <Dialog title={t(bulk === 'group' ? 'rt.toGroup' : bulk === 'outbound' ? 'rt.setOutbound' : 'rt.deleteTitle')} onclose={() => (bulk = null)}>
    {#if bulk === 'group'}
      <label class="field"><span>{t('rt.group')}</span><input type="text" bind:value={bulkValue} list="bulk-groups" placeholder={t('rt.noGroup')} /></label>
      <datalist id="bulk-groups">{#each groups as g (g)}<option value={g}></option>{/each}</datalist>
    {:else if bulk === 'outbound'}
      <label class="field">
        <span>{t('rt.outbound')}</span>
        <select bind:value={bulkValue}>{#each outbounds as o (o)}<option value={o}>{o}</option>{/each}</select>
      </label>
    {:else}
      <p>{t('rt.deleteText', { n: selected.size })}</p>
    {/if}
    {#snippet actions()}
      <button onclick={() => (bulk = null)}>{t('common.cancel')}</button>
      <button class="primary {bulk === 'delete' ? 'danger-bg' : ''}" onclick={doBulk}>{bulk === 'delete' ? t('rt.delete') : t('common.save')}</button>
    {/snippet}
  </Dialog>
{/if}

{#if confirming && preview}
  <Dialog title={t('cfg.applyTitle')} onclose={() => (confirming = false)}>
    <ChainNote {server} />
    <p>{t('rt.applyText')}</p>
    {#if preview.secrets.length}<div class="note info small">{t('cfg.secrets', { list: preview.secrets.join(', ') })}</div>{/if}
    <div class="diff"><DiffView lines={preview.diff} /></div>
    {#snippet actions()}
      <button onclick={() => (confirming = false)}>{t('common.cancel')}</button>
      <button class="primary" onclick={apply}>{t('cfg.apply')}</button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .editor { margin-bottom: 16px; }
  .head h2 { margin: 0; }
  .note { margin: 10px 0 0; }
  .lint { display: flex; align-items: center; gap: 10px; }
  .tools { margin: 14px 0 8px; gap: 8px; flex-wrap: wrap; }
  .search { min-width: 220px; }
  .hidden { display: none; }
  .bulk { gap: 6px; padding: 6px 8px; background: var(--surface-2); border-radius: var(--radius-sm); margin-bottom: 8px; flex-wrap: wrap; }
  .table { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 6px 8px; white-space: nowrap; }
  td { padding: 6px 8px; border-top: 1px solid var(--border); vertical-align: top; }
  tr.off td:not(.sel):not(.acts) { opacity: 0.55; }
  tr.grouped td:first-child { box-shadow: inset 3px 0 0 var(--accent); }
  tr.over td { border-top: 2px solid var(--accent); }
  tr.group td { background: var(--surface-2); padding: 4px 8px; }
  tr.hl td { background: color-mix(in srgb, var(--accent) 12%, transparent); }
  .side { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; margin-bottom: 16px; }
  @media (max-width: 900px) { .side { grid-template-columns: 1fr; } }
  .side h2 { margin-bottom: 10px; }
  .col { display: flex; flex-direction: column; gap: 16px; }
  .obs { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
  .obs li { display: flex; align-items: center; gap: 8px; padding: 6px 8px; border: 1px solid var(--border); border-radius: var(--radius-sm); }
  .obs .acts button { padding: 2px 6px; }
  .rform { display: flex; flex-direction: column; gap: 10px; margin-top: 14px; }
  .rform label:not(.check) { display: flex; flex-direction: column; gap: 5px; }
  .rform label span { color: var(--muted); font-size: 12.5px; }
  .changes { margin: 8px 0 0; padding-left: 18px; }
  .changes li { padding: 2px 0; }
  .dry { margin-top: 14px; display: flex; flex-direction: column; gap: 6px; }
  .link-btn { background: none; border: 0; padding: 0; font: inherit; font-weight: 600; color: inherit; cursor: pointer; }
  .sel, .num { width: 1%; white-space: nowrap; }
  .grip { cursor: grab; margin-right: 4px; color: var(--faint); }
  .kind { color: var(--muted); margin-right: 6px; }
  .addr { min-width: 220px; }
  .acts { white-space: nowrap; text-align: right; }
  .acts button { padding: 2px 6px; }
  .prob { font-size: 12.5px; padding: 2px 0; }
  .prob.error { color: var(--block); }
  .prob.warn { color: var(--warn); }
  .empty { margin: 12px 0; }
  .filebar { margin: 10px 0 6px; }
  .file { margin: 0; padding-left: 28px; max-height: 360px; overflow: auto; }
  .file li.off { opacity: 0.55; }
  .field { display: flex; flex-direction: column; gap: 5px; min-width: min(420px, 80vw); }
  .field span { color: var(--muted); font-size: 12.5px; }
  .diff { max-height: 50vh; overflow: auto; margin-top: 10px; min-width: min(640px, 82vw); }
  .actions { margin-top: 16px; }
  .card + .card { margin-bottom: 16px; }
  p { margin: 0; }
</style>
