import { mount } from 'svelte';
import './style.css';
import App from './App.svelte';

// Ctrl+A outside text fields and logs would select the whole window.
document.addEventListener('keydown', (e) => {
  if (!(e.ctrlKey || e.metaKey) || e.key.toLowerCase() !== 'a') return;
  const t = e.target as HTMLElement | null;
  if (t?.closest('input, textarea, [contenteditable], [data-selectall]')) return;
  e.preventDefault();
});

mount(App, { target: document.getElementById('app')! });
