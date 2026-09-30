<script lang="ts">
  import { t, type Key } from './i18n';
  import { route, go, pages, type Page } from './router.svelte';
  import Overview from './pages/Overview.svelte';
  import Soon from './pages/Soon.svelte';

  const title = (p: Page) => t(`nav.${p}` as Key);
</script>

<div class="app">
  <aside>
    <div class="brand">
      <span class="logo" aria-hidden="true">H</span>
      <span>{t('app.name')}</span>
    </div>
    <nav>
      {#each pages as p (p)}
        <a
          class="nav"
          class:active={route.page === p}
          href={p === 'overview' ? '/' : '/' + p}
          aria-current={route.page === p ? 'page' : undefined}
          onclick={(e) => {
            if (e.ctrlKey || e.metaKey || e.shiftKey || e.button !== 0) return;
            e.preventDefault();
            go(p);
          }}>{title(p)}</a
        >
      {/each}
    </nav>
  </aside>
  <main>
    <div class="page">
      {#if route.page === 'overview'}
        <Overview />
      {:else}
        <Soon title={title(route.page)} text={t(`soon.${route.page}` as Key)} />
      {/if}
    </div>
  </main>
</div>

<style>
  .app { display: flex; height: 100%; }

  aside {
    width: 212px;
    flex: none;
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 16px 12px;
    background: var(--surface);
    border-right: 1px solid var(--border);
  }

  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 16px; padding: 4px 8px 16px; letter-spacing: 0.2px; }
  .logo {
    width: 30px;
    height: 30px;
    border-radius: 9px;
    display: grid;
    place-items: center;
    color: #fff;
    background: linear-gradient(135deg, var(--accent), color-mix(in srgb, var(--accent) 55%, #b06cff));
  }

  nav { display: flex; flex-direction: column; gap: 2px; }

  .nav {
    display: flex;
    align-items: center;
    border-radius: var(--radius-sm);
    padding: 9px 12px;
    color: var(--muted);
    font-weight: 500;
    text-decoration: none;
  }
  .nav:hover { background: var(--surface-2); color: var(--text); }
  .nav.active { background: var(--accent-soft); color: var(--accent); font-weight: 600; }

  main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .page { flex: 1; min-height: 0; overflow: auto; padding: 24px 28px 28px; }

  @media (max-width: 720px) {
    .app { flex-direction: column; }
    aside { width: auto; border-right: none; border-bottom: 1px solid var(--border); }
    nav { flex-direction: row; flex-wrap: wrap; }
  }
</style>
