// Low-entropy confirmation (issue #416): the below-recommendation predicate,
// the overlay card structure, the session-scoped dismissal store, and the
// focus-trap cycling. The interactive flow (appear / cancel / proceed /
// session-dismiss / bypass / focus containment) is covered by the browser
// suite (test/browser-suite.html), which drives the Derive Key button through
// the overlay.
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createLowEntropyDismissal,
  lowEntropyConfirmCardHtml,
  nextDialogFocus,
} from "../src/js/low-entropy-confirm.js";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

// The predicate's dependencies, extracted from app.js exactly as the cards
// suite does, with the seed-length table carrying the hash-roll
// recommendations the app ships.
const hodlSeedLengths = {
  12: { words: 12, bits: 128, bytes: 16, hashRolls: 50 },
  15: { words: 15, bits: 160, bytes: 20, hashRolls: 62 },
  18: { words: 18, bits: 192, bytes: 24, hashRolls: 75 },
  21: { words: 21, bits: 224, bytes: 28, hashRolls: 87 },
  24: { words: 24, bits: 256, bytes: 32, hashRolls: 99 },
};
function hodlSeedConfig(words = 24) {
  return hodlSeedLengths[Number(words)] || hodlSeedLengths[24];
}
const hodlSplitDiceString = new Function(`${loadSlice("hodlSplitDiceString")}; return hodlSplitDiceString;`)();
const hodlDiceEntropyBits = new Function(`${loadSlice("hodlDiceEntropyBits")}; return hodlDiceEntropyBits;`)();
const hodlNormalizeCardToken = new Function(`${loadSlice("hodlNormalizeCardToken")}; return hodlNormalizeCardToken;`)();
const hodlCardWithoutReplacementBits = new Function(`${loadSlice("hodlCardWithoutReplacementBits")}; return hodlCardWithoutReplacementBits;`)();
const hodlCardNeeded = new Function(
  "hodlSeedConfig",
  "hodlCardWithoutReplacementBits",
  `${loadSlice("hodlCardNeeded")}; return hodlCardNeeded;`,
)(hodlSeedConfig, hodlCardWithoutReplacementBits);
const hodlCardsHashInput = new Function(`${loadSlice("hodlCardsHashInput")}; return hodlCardsHashInput;`)();
const hodlParseCards = new Function(
  "hodlCardNeeded",
  "hodlNormalizeCardToken",
  "hodlCardWithoutReplacementBits",
  "hodlCardsHashInput",
  `${loadSlice("hodlParseCards")}; return hodlParseCards;`,
)(hodlCardNeeded, hodlNormalizeCardToken, hodlCardWithoutReplacementBits, hodlCardsHashInput);
const hodlLowEntropyWarningFor = new Function(
  "hodlSeedConfig",
  "hodlSplitDiceString",
  "hodlDiceEntropyBits",
  "hodlParseCards",
  `${loadSlice("hodlNote")}; ${loadSlice("hodlLowEntropyWarningFor")}; return hodlLowEntropyWarningFor;`,
)(hodlSeedConfig, hodlSplitDiceString, hodlDiceEntropyBits, hodlParseCards);

const rolls = (n) => "1".repeat(n);
// n unique cards without replacement: a full deck, then a second shuffle
// (which may repeat ranks/suits, exactly like the real second deck).
const DECK = ["AS", "2S", "3S", "4S", "5S", "6S", "7S", "8S", "9S", "TS", "JS", "QS", "KS"];
const cards = (n) => {
  const suits = ["S", "H", "C", "D"];
  const deck = suits.flatMap((suit) => DECK.map((card) => card.slice(0, -1) + suit));
  return [...deck, ...deck].slice(0, n).join(" ");
};

test("hashed dice below the recommended rolls warn with the estimate", () => {
  const warning = hodlLowEntropyWarningFor("dice", "coldcard", rolls(10), 24);
  assert.ok(warning, "10 of 99 rolls did not warn");
  assert.equal(warning.bits, "25.8");
  assert.equal(warning.recommended, 256);
  assert.equal(warning.words, 24);
  assert.deepEqual(warning.detail, { key: "{have} of {n} recommended rolls", vars: { have: 10, n: 99 } });
  const coleman = hodlLowEntropyWarningFor("dice", "coleman", rolls(10), 24);
  assert.ok(coleman, "the Keystone dice method did not warn either");
});

test("hashed dice at or above the recommendation derive without a warning", () => {
  assert.equal(hodlLowEntropyWarningFor("dice", "coldcard", rolls(99), 24), null);
  assert.equal(hodlLowEntropyWarningFor("dice", "coldcard", rolls(120), 24), null);
  assert.equal(hodlLowEntropyWarningFor("dice", "coldcard", rolls(50), 12), null, "12-word recommendation is 50 rolls");
  const short12 = hodlLowEntropyWarningFor("dice", "coldcard", rolls(49), 12);
  assert.ok(short12 && short12.recommended === 128 && short12.detail.vars.n === 50, "12-word threshold did not follow the seed-length table");
});

test("hashed cards below the recommended deal warn with the estimate", () => {
  const warning = hodlLowEntropyWarningFor("cards", "hashed", cards(3), 24);
  assert.ok(warning, "3 of 58 cards did not warn");
  assert.equal(warning.bits, "17.0");
  assert.equal(warning.recommended, 256);
  assert.deepEqual(warning.detail, { key: "{have} of {need} recommended cards", vars: { have: 3, need: 58 } });
  assert.equal(hodlLowEntropyWarningFor("cards", "hashed", cards(58), 24), null, "a complete 58-card deal still warned");
  assert.equal(hodlLowEntropyWarningFor("cards", "hashed", cards(52), 12), null, "a full deck meets the 12-word recommendation");
});

test("sources without a fall-short recommendation never warn", () => {
  // D++/BitBox dice and direct cards only enable Derive once their full
  // construction is entered; number bases require the exact digit count; the
  // seed and private-key modes import existing material.
  assert.equal(hodlLowEntropyWarningFor("dice", "dplus", rolls(10), 24), null);
  assert.equal(hodlLowEntropyWarningFor("dice", "bitbox", rolls(10), 24), null);
  assert.equal(hodlLowEntropyWarningFor("cards", "direct", "A284", 24), null);
  assert.equal(hodlLowEntropyWarningFor("hex", "hex", "ab", 24), null);
  assert.equal(hodlLowEntropyWarningFor("seed", "words", "abandon", 24), null);
  assert.equal(hodlLowEntropyWarningFor("key", "brain", "correct horse", 24), null);
});

test("empty inputs never warn — Derive is disabled for those anyway", () => {
  assert.equal(hodlLowEntropyWarningFor("dice", "coldcard", "", 24), null);
  assert.equal(hodlLowEntropyWarningFor("cards", "hashed", "", 24), null);
});

test("the Derive Key handler consults the warning before deriving", () => {
  const handler = loadSlice("hodlHandleDerivationButton");
  assert.ok(handler.includes("hodlLowEntropyWarning()"), "the key-station handler never asks for the warning");
  assert.ok(handler.includes("isDismissed"), "the handler never checks the session dismissal");
  assert.ok(handler.includes('kind === "key"'), "the gate must not cover the multisig station");
});

test("the card markup is an accessible dialog with both actions and the checkbox", () => {
  const html = lowEntropyConfirmCardHtml();
  assert.ok(html.includes('role="dialog"'), "the card is not a dialog");
  assert.ok(html.includes('aria-modal="true"'), "the dialog is not modal");
  assert.ok(html.includes('aria-labelledby="low-entropy-title"'), "the dialog is not labelled");
  assert.ok(html.includes('id="low-entropy-more"'), "the Add More Entropy button is missing");
  assert.ok(html.includes('id="low-entropy-proceed"'), "the I Understand, Proceed button is missing");
  assert.ok(html.includes('type="checkbox" id="low-entropy-dismiss"'), "the Don't-show-again checkbox is missing");
  // Translated strings land in text content only, never in template
  // attributes (test/i18n-attribute-guard.test.mjs enforces the same).
  assert.ok(!/hodlT\w*\(/.test(html), "markup carries call-site translations");
});

test("the session dismissal defaults to showing the warning", () => {
  const dismissal = createLowEntropyDismissal();
  assert.equal(dismissal.isDismissed(), false, "a fresh session reads as dismissed");
  dismissal.dismiss();
  assert.equal(dismissal.isDismissed(), true, "the dismissal did not stick for the session");
});

test("the dismissal is session-scoped: a new session shows the warning again", () => {
  const first = createLowEntropyDismissal();
  first.dismiss();
  const next = createLowEntropyDismissal();
  assert.equal(next.isDismissed(), false, "the dismissal leaked into the next session");
});

test("the focus trap cycles forward and backward through the dialog", () => {
  const dismiss = { id: "dismiss" }, more = { id: "more" }, proceed = { id: "proceed" };
  const focusables = [dismiss, more, proceed];
  assert.equal(nextDialogFocus(focusables, more, false), proceed, "Tab did not advance to Proceed");
  assert.equal(nextDialogFocus(focusables, proceed, false), dismiss, "Tab did not wrap to the first control");
  assert.equal(nextDialogFocus(focusables, dismiss, false), more);
  assert.equal(nextDialogFocus(focusables, more, true), dismiss, "Shift+Tab did not move back to the checkbox");
  assert.equal(nextDialogFocus(focusables, dismiss, true), proceed, "Shift+Tab did not wrap to the last control");
  assert.equal(nextDialogFocus(focusables, proceed, true), more);
  assert.equal(nextDialogFocus(focusables, null, false), dismiss, "focus outside the dialog did not land on the first control");
  assert.equal(nextDialogFocus([], more, false), null, "an empty dialog must not invent a focus target");
});
