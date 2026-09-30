<script lang="ts">
  // A button that opens a list of actions; a click anywhere closes it.
  import type { Snippet } from 'svelte';

  let { label, children }: { label: string; children: Snippet } = $props();
  let open = $state(false);
  let root = $state<HTMLElement | null>(null);

  function outside(e: MouseEvent) {
    if (open && root && !root.contains(e.target as Node)) open = false;
  }
</script>

<svelte:window onclick={outside} onkeydown={(e) => e.key === 'Escape' && (open = false)} />

<div class="menu" bind:this={root}>
  <button class="ghost" aria-haspopup="menu" aria-expanded={open} onclick={() => (open = !open)}>{label} ▾</button>
  {#if open}
    <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
    <div class="pop" onclick={() => (open = false)}>{@render children()}</div>
  {/if}
</div>

<style>
  .menu { position: relative; display: inline-block; }
  .pop {
    position: absolute;
    right: 0;
    top: calc(100% + 4px);
    z-index: 30;
    min-width: 190px;
    display: flex;
    flex-direction: column;
    padding: 4px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow-lg);
  }
  .pop :global(button) { justify-content: flex-start; background: transparent; text-align: left; }
  .pop :global(button:hover:not(:disabled)) { background: var(--surface-2); }
</style>
