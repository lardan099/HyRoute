<script lang="ts">
  // Live explanation of one rule: what the patterns mean and what the rule
  // will match.
  import { isGroupId, type Rule } from '../api';
  import { profileName, targetText, mainTarget } from '../state.svelte';

  let { rule, onexample }: { rule: Rule; onexample: (field: 'app' | 'domain', v: string) => void } = $props();

  function appKind(p: string): string {
    if (/[*?]/.test(p)) return 'glob';
    if (/[\\/]/.test(p)) return 'path';
    return 'name';
  }

  function domKind(p: string): { kind: 'exact' | 'sub' | 'suffix'; base: string } {
    if (p.startsWith('*.')) return { kind: 'sub', base: p.slice(2) };
    if (p.startsWith('.')) return { kind: 'suffix', base: p.slice(1) };
    return { kind: 'exact', base: p };
  }

  function domMatch(k: { kind: string; base: string }, d: string): boolean {
    const b = k.base.toLowerCase();
    if (k.kind === 'exact') return d === b;
    if (k.kind === 'sub') return d.endsWith('.' + b);
    return d === b || d.endsWith('.' + b);
  }

  const app = $derived(rule.app?.pattern?.trim() ?? '');
  const dom = $derived(rule.domain?.pattern?.trim() ?? '');
  const dk = $derived(domKind(dom));
  const samples = $derived(dk.base ? [dk.base, 'www.' + dk.base, 'api.cdn.' + dk.base] : []);

  const target = $derived.by(() => {
    if (rule.action === 'direct') return 'напрямую, мимо туннеля';
    if (rule.action === 'block') return 'будет сброшено (Блок)';
    const main = mainTarget();
    // groups: a group is named as one («группа «Авто»»).
    if (rule.profile) return `через туннель: ${isGroupId(rule.profile) ? targetText(rule.profile) : '«' + profileName(rule.profile) + '»'}`;
    if (!main) return 'через туннель: основной профиль (не выбран!)';
    if (main.unloaded) return `через туннель: ${main.name}`;
    return `через туннель: ${main.group ? `основная группа «${main.name}»` : `основной профиль «${main.name}»`}`;
  });

  const preview = $derived.by(() => {
    const who = app
      ? `приложения ${appKind(app) === 'name' ? app : '«' + app + '»'}${rule.app?.inheritChildren ? ' и запущенных им процессов' : ''}`
      : 'любого приложения';
    let where = 'к любому адресу';
    if (dom) {
      if (dk.kind === 'exact') where = `только к ${dk.base}`;
      else if (dk.kind === 'sub') where = `к поддоменам ${dk.base} (но не к самому ${dk.base})`;
      else where = `к ${dk.base} и всем его поддоменам`;
    }
    const proto = rule.protocol === 'tcp' ? 'по TCP' : rule.protocol === 'udp' ? 'по UDP' : 'по TCP и UDP';
    return `Соединения ${who} ${where} ${proto} пойдут ${target}.`;
  });
</script>

<div class="hints">
  <div class="preview">Это правило совпадёт с: {preview}</div>
  <div class="grid">
    <div>
      <div class="h">Приложение</div>
      {#if !app}
        <div>Пусто — любое приложение.</div>
      {:else if appKind(app) === 'name'}
        <div>По имени файла: <code>{app}</code> из любой папки.</div>
      {:else if appKind(app) === 'path'}
        <div>Только этот файл: <code>{app}</code>.</div>
      {:else}
        <div>По маске пути: <code>*</code> — любые символы, включая вложенные папки, <code>?</code> — один символ.</div>
      {/if}
      <div class="ex">
        Примеры:
        <button class="link" onclick={() => onexample('app', 'discord.exe')}><code>discord.exe</code></button>
        <button class="link" onclick={() => onexample('app', 'C:\\Program Files\\Discord\\Discord.exe')}><code>C:\Program Files\Discord\Discord.exe</code></button>
        <button class="link" onclick={() => onexample('app', 'C:\\Games\\*')}><code>C:\Games\*</code></button>
      </div>
      <div class="muted">«и дочерние» — правило действует и на процессы, которые запустило это приложение (лаунчер → игра, браузер → его служебные процессы).</div>
    </div>
    <div>
      <div class="h">Домен</div>
      <div><code>example.com</code> — только этот домен.</div>
      <div><code>*.example.com</code> — только поддомены: www.example.com, api.example.com, но не сам example.com.</div>
      <div><code>.example.com</code> — сам example.com и все его поддомены.</div>
      {#if dk.base}
        <div class="ex">
          {#each samples as d}<span class:yes={domMatch(dk, d)} class:no={!domMatch(dk, d)}>{domMatch(dk, d) ? '✓' : '✗'} {d}</span>{/each}
        </div>
      {/if}
    </div>
    <div>
      <div class="h">Протокол</div>
      <div>TCP — веб и большинство программ. UDP — игры, голос (Discord), QUIC, DNS. Не уверены — оставьте «TCP и UDP».</div>
    </div>
    <div>
      <div class="h">Действие</div>
      <div><b class="route-tunnel">Туннель</b> — через Hysteria выбранного профиля. Если профиль недоступен, соединение отклоняется, а не уходит напрямую.</div>
      <div><b class="route-direct">Напрямую</b> — мимо туннеля. <b class="route-block">Блок</b> — соединение сбрасывается.</div>
    </div>
  </div>
</div>

<style>
  .hints { font-size: 12.5px; display: grid; gap: 8px; margin-top: 4px; }
  .preview { padding: 6px 10px; border-left: 3px solid var(--accent); background: var(--panel-2); border-radius: 4px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 18px; }
  .h { font-weight: 600; margin-bottom: 2px; }
  code { font-family: var(--mono); font-size: 12px; background: var(--panel-2); padding: 0 4px; border-radius: 3px; }
  .ex { display: flex; flex-wrap: wrap; gap: 4px 10px; margin: 3px 0; align-items: center; }
  .link { background: none; border: none; padding: 0; cursor: pointer; color: var(--accent); }
  .yes { color: var(--direct); }
  .no { color: var(--muted); }
</style>
