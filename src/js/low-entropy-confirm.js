// Low-entropy confirmation (issue #416).
//
// The Key Station's Derive Key button enables as soon as ANY entropy is
// supplied, while the per-source warnings about staying under the recommended
// amount are easy to miss. This module adds a second step for exactly those
// sources: when the user asks to derive from less entropy than recommended, a
// modal states the estimate, and the user either goes back to add more or
// explicitly proceeds.
//
// "Don't show again this session" is kept in memory only — deliberately no
// Web Storage: the bypass for a security warning never outlives the page
// session, and the default direction is always to show the warning. The
// dismissal store is injectable so it stays unit-testable under Node.
//
// The pattern mirrors address-qr.js: the card markup is a pure function
// unit-tested under Node, and initLowEntropyConfirm is the only DOM entry
// point, keeping one shared overlay for the whole page. Unlike the
// informational QR overlays, this dialog gates key creation, so it also
// contains keyboard focus: Tab and Shift+Tab cycle through the dialog's
// controls and the background is unreachable by keyboard while it is open
// (the backdrop click and Escape remain the pointer/keyboard dismissal).

import { t } from "./i18n.js";

// Session-scoped dismissal: in-memory only, defaulting to "always show".
// A fresh page session starts un-dismissed; nothing can persist or corrupt
// the choice, so there is no failure direction to defend against beyond that.
export const createLowEntropyDismissal = () => {
  let dismissed = false;
  return {
    isDismissed: () => dismissed,
    dismiss: () => {
      dismissed = true;
    },
  };
};

// Focus containment for the modal: the next control to focus when Tab (or
// Shift+Tab) is pressed, cycling through the dialog's focusable elements.
// Pure and unit-tested under Node; the DOM handler supplies the live list.
export const nextDialogFocus = (focusables, active, shiftKey) => {
  if (!focusables.length) return null;
  const index = focusables.indexOf(active);
  if (index === -1) return focusables[0];
  return focusables[(index + (shiftKey ? -1 : 1) + focusables.length) % focusables.length];
};

// Static card skeleton. Every user-facing string is set through textContent
// at init/open time, so no translated text ever lands in a template attribute
// (see test/i18n-attribute-guard.test.mjs).
export const lowEntropyConfirmCardHtml = () => `
  <div class="low-entropy-card" id="low-entropy-dialog" role="dialog" aria-modal="true" aria-labelledby="low-entropy-title">
    <p class="low-entropy-title" id="low-entropy-title"></p>
    <p class="low-entropy-message" id="low-entropy-message"></p>
    <p class="low-entropy-detail muted" id="low-entropy-detail"></p>
    <p class="low-entropy-advice muted" id="low-entropy-advice"></p>
    <label class="choice low-entropy-dismiss-row"><input type="checkbox" id="low-entropy-dismiss" /><span id="low-entropy-dismiss-label"></span></label>
    <div class="row low-entropy-actions">
      <button class="btn secondary" id="low-entropy-more" type="button"></button>
      <button class="btn primary" id="low-entropy-proceed" type="button"></button>
    </div>
  </div>`;

// Builds the one shared overlay and returns its controls. `open(warning,
// onProceed)` shows the modal for a warning shaped { bits, recommended, words,
// detail }; "Add More Entropy" (or Escape / a backdrop click) cancels and
// returns focus to the Derive Key button, "I Understand, Proceed" optionally
// remembers the dismissal for the session and then runs onProceed.
export const initLowEntropyConfirm = () => {
  if (document.getElementById("low-entropy-overlay")) return null;
  const overlay = document.createElement("div");
  overlay.className = "low-entropy-overlay no-print";
  overlay.id = "low-entropy-overlay";
  overlay.hidden = true;
  overlay.innerHTML = lowEntropyConfirmCardHtml();
  document.body.append(overlay);
  const title = overlay.querySelector("#low-entropy-title"),
    message = overlay.querySelector("#low-entropy-message"),
    detail = overlay.querySelector("#low-entropy-detail"),
    advice = overlay.querySelector("#low-entropy-advice"),
    dismiss = overlay.querySelector("#low-entropy-dismiss"),
    dismissLabel = overlay.querySelector("#low-entropy-dismiss-label"),
    moreButton = overlay.querySelector("#low-entropy-more"),
    proceedButton = overlay.querySelector("#low-entropy-proceed");
  title.textContent = t("Low entropy");
  advice.textContent = t("A key derived from less entropy than recommended can be guessed. Add more entropy unless you are only testing.");
  dismissLabel.textContent = t("Don't show again this session");
  moreButton.textContent = t("Add More Entropy");
  proceedButton.textContent = t("I Understand, Proceed");
  const dismissal = createLowEntropyDismissal();
  const focusables = [dismiss, moreButton, proceedButton];
  let lastFocused = null;
  let proceed = null;

  const close = () => {
    overlay.hidden = true;
    proceed = null;
    lastFocused?.focus?.({ preventScroll: true });
    lastFocused = null;
  };
  const open = (warning, onProceed) => {
    if (typeof onProceed !== "function") return;
    message.textContent = t("You have provided only about {bits} bits of entropy (recommended: {recommended} bits for a {words}-word seed).", {
      bits: warning?.bits ?? "",
      recommended: warning?.recommended ?? "",
      words: warning?.words ?? "",
    });
    detail.textContent = warning?.detail ? t(warning.detail.key, warning.detail.vars) : "";
    detail.hidden = !warning?.detail;
    dismiss.checked = false;
    proceed = onProceed;
    lastFocused = document.activeElement;
    overlay.hidden = false;
    // The safe choice is the default focus: one more Enter adds entropy
    // instead of deriving.
    moreButton.focus();
  };
  moreButton.addEventListener("click", close);
  proceedButton.addEventListener("click", () => {
    if (dismiss.checked) dismissal.dismiss();
    const run = proceed;
    close();
    run?.();
  });
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) close();
  });
  overlay.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      close();
      return;
    }
    // Focus trap: the modal gates key creation, so keyboard focus cycles
    // within the dialog instead of escaping to the background behind it.
    if (event.key === "Tab") {
      event.preventDefault();
      nextDialogFocus(focusables, document.activeElement, event.shiftKey)?.focus();
    }
  });
  return { open, close, isOpen: () => !overlay.hidden, isDismissed: dismissal.isDismissed };
};
