<script lang="ts">
  // «Создать правило» for a connection: pick what the rule takes (the whole
  // program, the site, its list, the address, the port), then the rule
  // editor opens with it filled in. The rule goes to the top of the list:
  // below the rule that took the connection it would never be reached.
  import { api, cleanSettings, toLists, type Flow, type InspectHit, type Rule } from '../api';
  import { hide, mainProfile } from '../state.svelte';
  import { toast } from '../toast.svelte';
  import Icon from './Icon.svelte';
  import RuleEditor from './RuleEditor.svelte';

  let { flow, onclose }: { flow: Flow; onclose: () => void } = $props();

  // svelte-ignore state_referenced_locally
  const f = flow;
  const app = f.process && f.pid ? f.process : '';
  // A name from the DNS cache may be several ("a.com,b.com"): the first.
  const domain = (f.domain || '').split(',')[0].trim().toLowerCase();
  const m = /^\[?(.*?)\]?:(\d+)$/.exec(f.dst);
  const ip = m ? m[1] : f.dst;
  const port = m ? m[2] : '';
  const proto = f.proto.toLowerCase() === 'udp' ? 'udp' : 'tcp';

  // Second-level labels of country domains (co.uk), as Go rootDomain.
  const countrySecond = new Set(['ac', 'co', 'com', 'edu', 'gov', 'mil', 'net', 'ne', 'nom', 'or', 'org']);
  function rootDomain(d: string): string {
    const l = d.replace(/^\*\./, '').split('.').filter(Boolean);
    const n = l.length;
    if (n < 2) return '';
    if (n >= 3 && l[n - 1].length === 2 && countrySecond.has(l[n - 2])) return l.slice(n - 3).join('.');
    return l.slice(n - 2).join('.');
  }
  const base = domain ? rootDomain(domain) : '';

  type Choice = { id: string; title: string; note?: string; warn?: string };
  let lists = $state<InspectHit[]>([]);
  const choices = $derived.by(() => {
    const c: Choice[] = [];
    if (app) c.push({ id: 'app', title: `Всю программу ${app}`, note: 'все её соединения, куда бы она ни подключалась' });
    if (domain) {
      c.push({ id: 'site', title: `Сайт ${hide(domain)}`, note: 'и все его поддомены' });
      if (base && base !== domain) c.push({ id: 'base', title: `Весь ${hide(base)}`, note: `${hide(domain)} — его поддомен; правило возьмёт и остальные` });
    }
    for (const h of lists.filter((h) => !h.broad).slice(0, 3))
      c.push({ id: 'list:' + h.tag, title: `Список «${h.title || h.tag.replace(/^geosite:/, '')}»`, note: `${h.tag}: ${h.size} записей, весь сервис целиком` });
    c.push({
      id: 'ip',
      title: `Адрес ${hide(ip)}`,
      warn: domain ? 'На одном адресе часто много сайтов (CDN): правило возьмёт и их. Надёжнее выбрать сайт.' : undefined,
    });
    if (port) c.push({ id: 'port', title: `Порт ${port} (${proto.toUpperCase()})`, note: 'любой сайт и адрес на этом порту' });
    return c;
  });

  let choice = $state(app ? 'app' : domain ? 'site' : 'ip');
  let onlyApp = $state(false);
  let onlyPort = $state(false);
  let editing = $state<Rule | null>(null);

  $effect(() => {
    if (!domain) return;
    api
      .SiteLists(domain)
      .then((l) => (lists = l))
      .catch(() => {});
  });

  function build(): Rule {
    const r: Rule = { name: '', apps: [], domains: [], action: f.route === 'tunnel' ? 'direct' : 'tunnel', profile: '', protocol: '' };
    const appItem = () => ({ pattern: app, inheritChildren: true });
    switch (true) {
      case choice === 'app':
        r.apps = [appItem()];
        r.name = app.replace(/\.exe$/i, '');
        break;
      case choice === 'site':
        r.domains = ['.' + domain.replace(/^www\./, '')];
        r.name = domain.replace(/^www\./, '');
        break;
      case choice === 'base':
        r.domains = ['.' + base];
        r.name = base;
        break;
      case choice.startsWith('list:'): {
        const tag = choice.slice(5);
        const h = lists.find((x) => x.tag === tag);
        r.domains = [tag];
        r.name = h?.title || tag.replace(/^geosite:/, '');
        break;
      }
      case choice === 'ip':
        r.domains = [ip];
        r.name = ip;
        break;
      case choice === 'port':
        r.ports = port;
        r.protocol = proto;
        r.name = `Порт ${port}`;
        break;
    }
    if (choice !== 'app' && onlyApp && app) {
      r.apps = [appItem()];
      r.name = `${r.name} в ${app.replace(/\.exe$/i, '')}`;
    }
    if ((choice === 'ip' || choice === 'app') && onlyPort && port) {
      r.ports = port;
      r.protocol = proto;
      r.name = `${r.name}, порт ${port}`;
    }
    return r;
  }

  async function save(r: Rule) {
    const s = await api.Settings();
    s.rules = (s.rules ?? []).map(toLists);
    s.rules.unshift(r);
    // With the revision of the copy just read (only a true race refuses it).
    await api.SaveSettings({ ...cleanSettings(s, mainProfile()?.id), rev: s.rev ?? 0 });
    const name = r.name;
    toast({ tone: 'ok', text: () => `Правило «${hide(name)}» добавлено в начало списка`, detail: () => 'Действует на новые соединения.' });
    onclose();
  }

  let downOnBackdrop = false;
</script>

{#if editing}
  <RuleEditor rule={editing} title="Новое правило из соединения" onsave={save} onclose={() => (editing = null)} />
{:else}
  <div
    class="backdrop"
    role="presentation"
    onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
    onclick={(e) => downOnBackdrop && e.target === e.currentTarget && onclose()}
  >
    <div class="dialog pick">
      <div class="row head">
        <h2 class="grow">Создать правило</h2>
        <button class="icon" onclick={onclose}><Icon name="x" /></button>
      </div>
      <p class="muted small">
        {app || `PID ${f.pid}`} → {hide(domain) || hide(f.dst)}. Что должно попадать под правило? Куда направить, выберете на следующем шаге.
      </p>
      <div class="opts">
        {#each choices as c (c.id)}
          <label class="opt" class:on={choice === c.id}>
            <input type="radio" bind:group={choice} value={c.id} />
            <span>
              <b>{c.title}</b>
              {#if c.note}<span class="muted small"> — {c.note}</span>{/if}
              {#if c.warn && choice === c.id}<span class="note warn small">{c.warn}</span>{/if}
            </span>
          </label>
        {/each}
      </div>
      {#if app && choice !== 'app'}
        <label class="check"><input type="checkbox" bind:checked={onlyApp} /> Только когда это открывает {app}</label>
      {/if}
      {#if port && (choice === 'ip' || choice === 'app')}
        <label class="check"><input type="checkbox" bind:checked={onlyPort} /> Только порт {port} ({proto.toUpperCase()})</label>
      {/if}
      <div class="note info small">
        Правило встанет первым в списке, иначе его перехватит правило, которое сработало сейчас{f.rule && f.rule !== 'default' ? ` («${f.rule}»)` : ''}.
      </div>
      <div class="actions">
        <button onclick={onclose}>Отмена</button>
        <button class="primary" onclick={() => (editing = build())}>Дальше</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .pick { width: min(600px, 94vw); display: grid; gap: 10px; }
  .head h2 { margin: 0; }
  .opts { display: grid; gap: 6px; }
  .opt { display: flex; gap: 10px; align-items: flex-start; padding: 9px 12px; border-radius: var(--radius-sm); border: 1.5px solid var(--border); cursor: pointer; }
  .opt.on { border-color: var(--accent); background: var(--accent-soft); }
  .opt input { margin-top: 3px; }
  .opt .note { display: block; margin-top: 6px; }
  .check { display: flex; gap: 8px; align-items: center; }
</style>
