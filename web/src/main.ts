import { mount } from 'svelte';
import './app.css';
import App from './App.svelte';
import { app } from './lib/state.svelte.ts';

// Before App mounts and adds its own hashchange router, so neither ever sees the token.
app.takeSetupToken();
window.addEventListener('hashchange', () => app.takeSetupToken());

mount(App, { target: document.getElementById('app')! });
