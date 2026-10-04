// End session (src/js/end-session.js). The residue audit found that closing
// the tab is the only step that removes every copy of a secret, so End session
// wipes what the page can and then asks the browser to close the tab.
//
// Contract: End session runs, in this order, every wipe the page runs when it
// is left (a pagehide that is not a bfcache entry), the modules' retirement
// (their whole linear memory overwritten with patterns, then zeroed), the clipboard clear, the page's
// replacement by the ended screen (nothing of the old DOM left), and
// window.close(). A clipboard the browser refuses to clear does not stop the
// rest. The live page (the header control, the dialog, a real tab) is covered
// in the browser suite; the modules' retirement in wasm-retire.test.mjs.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MiniDocument } from "./mini-dom.mjs";
import { endSession, renderSessionEnded } from "../src/js/end-session.js";

const SECRET = "legal winner thank year wave sausage worth useful legal winner thank yellow";

const fakePage = () => {
  const log = [];
  const doc = new MiniDocument();
  doc.body.innerHTML = `<div id="btc-calc"><textarea id="seed"></textarea><p id="out">${SECRET}</p></div>`;
  doc.getElementById("seed").value = SECRET;
  const win = {
    PageTransitionEvent: class {
      constructor(type, init) { this.type = type; this.persisted = init?.persisted; }
    },
    dispatchEvent: (event) => { log.push(`${event.type}:${event.persisted === false ? "left" : "restored"}`); return true; },
    close: () => { log.push(`close:${doc.querySelector("[data-session-ended]") ? "after the ended screen" : "before it"}`); },
  };
  return { log, doc, win };
};

test("End session wipes, retires, clears, replaces the page and closes, in that order", async () => {
  const { log, doc, win } = fakePage();
  await endSession({
    win,
    doc,
    retireModules: [() => log.push("retire crypto"), () => log.push("retire psbt")],
    clearClipboard: async () => { log.push("clear clipboard"); return true; },
  });
  assert.deepEqual(log, ["pagehide:left", "retire crypto", "retire psbt", "clear clipboard", "close:after the ended screen"]);
  assert.equal(doc.getElementById("btc-calc"), null, "the app's DOM must be gone");
  assert.equal(doc.getElementById("seed"), null);
  assert.ok(!doc.body.textContent.includes("legal winner"), "the ended screen must hold nothing of the session");
  assert.ok(doc.querySelector("[data-session-ended]"), "the ended screen is missing");
});

test("a clipboard the browser refuses to clear does not stop the session ending", async () => {
  const { log, doc, win } = fakePage();
  await endSession({
    win,
    doc,
    retireModules: [() => log.push("retire")],
    clearClipboard: async () => { throw new Error("NotAllowedError"); },
  });
  assert.deepEqual(log, ["pagehide:left", "retire", "close:after the ended screen"]);
  assert.ok(doc.querySelector("[data-session-ended]"));
});

test("the ended screen mentions the clipboard only when it was cleared", () => {
  const paragraphs = (cleared) => {
    const doc = new MiniDocument();
    renderSessionEnded(doc, { clipboardCleared: cleared });
    return doc.querySelectorAll("[data-session-ended] p").length;
  };
  assert.equal(paragraphs(true), paragraphs(false) + 1);
});
