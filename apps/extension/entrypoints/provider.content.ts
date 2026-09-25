import { defineContentScript } from "#imports";
import {
  createPageProvider,
  createSep43Provider,
  createWindowTransport,
} from "@vellar/provider-sdk";

// MAIN-world script: exposes the wallet provider to dApps as window.vela
// (technical-doc.md §5.3) and SEP-43 standard interface as window.stellar / window.vela.sep43.
// Runs in page context — it holds no state and no privileges; everything round-trips through
// the isolated bridge + background.

declare global {
  interface Window {
    vela?: unknown;
    stellar?: unknown;
  }
}

export default defineContentScript({
  matches: ["<all_urls>"],
  world: "MAIN",
  runAt: "document_start",
  main() {
    const transport = createWindowTransport(window);
    const pageProvider = createPageProvider({ transport });
    const sep43Provider = createSep43Provider({ transport });

    if (!window.vela) {
      window.vela = Object.assign(pageProvider, { sep43: sep43Provider });
    }
    if (!window.stellar) {
      window.stellar = sep43Provider;
    }
  },
});
