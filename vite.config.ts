import { defineConfig } from 'vite';
import { nip5aManifest } from '@napplet/vite-plugin';

export default defineConfig({
  build: {
    // Vite's module-preload polyfill calls `fetch`; one inlined entry needs no
    // preload graph, and NIP-5D napplet code has no ambient network authority.
    modulePreload: { polyfill: false },
  },
  plugins: [
    // Produce one self-contained `/index.html` for NIP-5D `srcdoc` loading,
    // then content-address it with the NIP-5A tag/hash schema.
    //
    // requires: only `storage` — the verdict is local computation, and every
    // other domain (identity, theme) is optional and feature-detected.
    nip5aManifest({
      nappletType: 'trust-check',
      artifactMode: 'single-file',
      requires: ['storage', 'wallet'],
    }),
  ],
});
