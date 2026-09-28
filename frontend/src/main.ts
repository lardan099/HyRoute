import { mount } from 'svelte';
import './style.css';
import App from './App.svelte';

// Ctrl+A outside text fields and logs would select the whole window.
// e.code is the physical key: with the Russian layout e.key is 'ф', and the
// browser still selects everything.
document.addEventListener('keydown', (e) => {
  if (!(e.ctrlKey || e.metaKey) || (e.code !== 'KeyA' && e.key.toLowerCase() !== 'a')) return;
  const t = e.target as HTMLElement | null;
  if (t?.closest('input, textarea, [contenteditable], [data-selectall]')) return;
  e.preventDefault();
});

mount(App, { target: document.getElementById('app')! });
