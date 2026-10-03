// End session: one control that ends everything this page holds and then
// asks the browser to close the tab.
//
// The residue audit (2026-10-03) found that closing the tab is the only step
// that removes every copy of a secret in Chrome and Edge: the page's process
// exits, and the operating system reclaims its memory. Wiping inside the
// page cannot reach strings, DOM text or the browser's own copies. So this
// does what the page can, in order, and then hands over to the browser:
//
//   1. every wipe the page runs when it is left (the `pagehide` listeners:
//      each station, the Journal, Vanity's workers, the two dialogs);
//   2. the WebAssembly modules' whole linear memory, zeroed, and the modules
//      retired so nothing can run on them again;
//   3. the clipboard, emptied if this page wrote it;
//   4. the page replaced by a short screen, which drops the old DOM;
//   5. window.close(). A browser closes a tab by script only when it allows
//      it (typically a tab opened straight to this file, with no history to
//      go back to), so the screen says to close the tab when it is still
//      showing.
//
// Steps 2 and 3 come from the caller, so the suite can drive the sequence.

import { t } from "./i18n.js";
import { createModal } from "./modal.js";

// Static card skeleton; its words are set through textContent at init, so no
// translated text lands in a template attribute.
export const endSessionCardHtml = () => `
  <div class="modal-card is-warning end-session-card" id="end-session-dialog" role="dialog" aria-modal="true" aria-labelledby="end-session-title" aria-describedby="end-session-message">
    <svg class="modal-warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v9"/><path d="M6.3 6.3a8 8 0 1 0 11.4 0"/></svg>
    <p class="modal-warning-title" id="end-session-title"></p>
    <p id="end-session-message"></p>
    <div class="row tool-actions">
      <button class="btn red" id="end-session-confirm" type="button"></button>
      <button class="btn secondary" id="end-session-cancel" type="button"></button>
    </div>
  </div>`;

// The screen left behind. Built from elements and textContent: nothing of the
// session, and no catalog markup, reaches it.
export const renderSessionEnded = (doc, { clipboardCleared = false } = {}) => {
  const main = doc.createElement("main");
  main.className = "sanity-failure";
  main.dataset.sessionEnded = "";
  const card = doc.createElement("div");
  card.className = "sanity-failure-card";
  card.setAttribute("role", "status");
  const line = (tag, className, text) => {
    const element = doc.createElement(tag);
    element.className = className;
    element.textContent = text;
    card.append(element);
  };
  line("h1", "sanity-failure-title", t("Session ended"));
  line("p", "sanity-failure-message", t("EntropyLab wiped every key, seed and field this page held."));
  line("p", "sanity-failure-advice", t("Close this tab now, or quit the browser: that is what erases the copies the browser keeps for itself. Reloading starts a new session but does not erase them."));
  if (clipboardCleared) line("p", "sanity-failure-advice", t("The clipboard was emptied. Clipboard history and cloud clipboard sync keep their own copies of what was copied."));
  line("p", "sanity-failure-advice", t("Chrome and Edge keep running after the last window closes unless “Continue running background apps” is off in their System settings."));
  main.append(card);
  doc.body.replaceChildren(main);
};

export const endSession = async ({ win = window, doc = document, retireModules = [], clearClipboard = async () => false } = {}) => {
  win.dispatchEvent(new win.PageTransitionEvent("pagehide", { persisted: false }));
  for (const retire of retireModules) retire();
  // Started inside the confirm click, while the browser still counts it as
  // the user's action; some browsers refuse a clipboard write without one.
  const clipboardCleared = await clearClipboard().catch(() => false);
  renderSessionEnded(doc, { clipboardCleared });
  win.close();
};

// The confirm dialog. `open()` shows it with Cancel focused (the safe
// choice); Cancel, Escape or a click on the dimmed page closes it and
// nothing happens; End Session runs `onEnd`.
export const initEndSessionConfirm = (onEnd) => {
  if (document.getElementById("end-session-overlay")) return null;
  const modal = createModal({
    id: "end-session-overlay",
    className: "end-session-overlay",
    card: endSessionCardHtml(),
    focusables: () => focusables,
    onDismiss: () => modal.hide(),
  });
  const overlay = modal.overlay;
  const confirmButton = overlay.querySelector("#end-session-confirm"),
    cancelButton = overlay.querySelector("#end-session-cancel");
  overlay.querySelector("#end-session-title").textContent = t("End this session?");
  overlay.querySelector("#end-session-message").textContent = t("EntropyLab wipes every key, seed and field on this page, empties the clipboard if it copied something, and asks the browser to close this tab. Anything you have not written down or saved is lost.");
  confirmButton.textContent = t("End Session");
  cancelButton.textContent = t("Cancel");
  const focusables = [confirmButton, cancelButton];
  cancelButton.addEventListener("click", () => modal.hide());
  confirmButton.addEventListener("click", () => {
    modal.hide({ restoreFocus: false });
    onEnd();
  });
  return { open: (opener) => modal.show(cancelButton, opener), isOpen: modal.isOpen };
};
