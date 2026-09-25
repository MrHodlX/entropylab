// Shared-fingerprint confirmation (GHSA-6rr2-5r82-grwc follow-up).
//
// A master fingerprint is 4 display bytes, so a newly derived wallet can show
// the same fingerprint as a different wallet already open in Key Station.
// Both tabs are then correct but look identical: same label, same LifeHash.
// Before such a wallet is committed as a tab, this modal says so; the user
// either proceeds ("I Understand") or cancels, which discards the derivation.
//
// The pattern mirrors low-entropy-confirm.js: a pure card-markup function,
// one shared overlay built by the init function, user-facing strings set
// through textContent (never a template attribute), and the shared focus
// trap. Escape and a backdrop click cancel.

import { t } from "./i18n.js";
import { trapModalFocus } from "./modal-focus.js";

export const fingerprintCollisionCardHtml = () => `
  <div class="modal-card is-warning fingerprint-collision-card" id="fingerprint-collision-dialog" role="dialog" aria-modal="true" aria-labelledby="fingerprint-collision-title" aria-describedby="fingerprint-collision-message">
    <svg class="modal-warning-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 2.5 20h19L12 3z"/><path d="M12 10v4M12 17.5h.01"/></svg>
    <p class="modal-warning-title" id="fingerprint-collision-title"></p>
    <p class="fingerprint-collision-message" id="fingerprint-collision-message"></p>
    <p class="edge-note is-private" id="fingerprint-collision-advice"></p>
    <div class="row fingerprint-collision-actions tool-actions">
      <button class="btn primary" id="fingerprint-collision-proceed" type="button"></button>
      <button class="btn secondary" id="fingerprint-collision-cancel" type="button"></button>
    </div>
  </div>`;

// Builds the one shared overlay. `open(fingerprint, onProceed, onCancel)`
// shows the warning for that fingerprint; exactly one of the callbacks runs.
export const initFingerprintCollisionConfirm = () => {
  if (document.getElementById("fingerprint-collision-overlay")) return null;
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay fingerprint-collision-overlay no-print";
  overlay.id = "fingerprint-collision-overlay";
  overlay.hidden = true;
  overlay.innerHTML = fingerprintCollisionCardHtml();
  document.body.append(overlay);
  const message = overlay.querySelector("#fingerprint-collision-message"),
    advice = overlay.querySelector("#fingerprint-collision-advice"),
    cancelButton = overlay.querySelector("#fingerprint-collision-cancel"),
    proceedButton = overlay.querySelector("#fingerprint-collision-proceed");
  overlay.querySelector("#fingerprint-collision-title").textContent = t("Shared fingerprint");
  advice.textContent = t("Rename one of the tabs to tell them apart by clicking on the tab label.");
  proceedButton.textContent = t("I Understand");
  cancelButton.textContent = t("Cancel");
  let lastFocused = null, pending = null;

  const settle = (proceed) => {
    const callbacks = pending;
    pending = null;
    overlay.hidden = true;
    lastFocused?.focus?.({ preventScroll: true });
    lastFocused = null;
    (proceed ? callbacks?.onProceed : callbacks?.onCancel)?.();
  };
  const open = (fingerprint, onProceed, onCancel) => {
    if (pending) settle(false);
    message.textContent = t("Another wallet open in this session also has fingerprint {fingerprint}. A fingerprint is only 4 bytes, so different wallets can share one: these are separate wallets.", { fingerprint });
    pending = { onProceed, onCancel };
    lastFocused = document.activeElement;
    overlay.hidden = false;
    proceedButton.focus();
  };
  proceedButton.addEventListener("click", () => settle(true));
  cancelButton.addEventListener("click", () => settle(false));
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) settle(false);
  });
  overlay.addEventListener("keydown", (event) => {
    if (event.key === "Escape") settle(false);
  });
  trapModalFocus(overlay, () => [proceedButton, cancelButton]);
  return { open, isOpen: () => !overlay.hidden };
};
