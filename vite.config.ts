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
    // requires: `storage` always; `wallet` (the invented predicate) and `cvm`
    // (Sandwich's sanctioned route) are declared too. Both are feature-detected
    // and degrade cleanly, so declaring them states intent rather than a hard
    // dependency — the manifest has no way to say "sensitive but optional".
    nip5aManifest({
      nappletType: 'trust-check',
      artifactMode: 'single-file',
      requires: ['storage', 'wallet', 'cvm'],
    }),
  ],
});
