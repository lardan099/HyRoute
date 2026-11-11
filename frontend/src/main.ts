import { mount } from 'svelte';
import './style.css';
import App from './App.svelte';
import Panel from './lib/Panel.svelte';

// Ctrl+A outside text fields and logs would select the whole window.
// e.code is the physical key: with the Russian layout e.key is 'ф', and the
// browser still selects everything.
document.addEventListener('keydown', (e) => {
  if (!(e.ctrlKey || e.metaKey) || (e.code !== 'KeyA' && e.key.toLowerCase() !== 'a')) return;
  const t = e.target as HTMLElement | null;
  if (t?.closest('input, textarea, [contenteditable], [data-selectall]')) return;
  e.preventDefault();
});

// The same bundle is the main window's page and the panel's by the tray
// icon: the window says which it is (Bridge.Mode; «?panel» in a browser).
(async () => {
  let panel = new URLSearchParams(location.search).has('panel');
  try {
    panel ||= (await (window as any).go?.main?.Bridge?.Mode?.()) === 'panel';
  } catch {}
  mount(panel ? Panel : App, { target: document.getElementById('app')! });
})();
