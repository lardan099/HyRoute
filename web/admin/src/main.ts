import { mount } from 'svelte';
import App from './App.svelte';
import './style.css';
import '../../shared/support-link.css';

mount(App, { target: document.getElementById('app')! });
