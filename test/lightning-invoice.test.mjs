// Tests for the Lightning invoice decoder card (the BOLT11/BOLT12 section of
// src/js/lightning.js and its markup in src/shell.html): the decode flow
// against a hand-rolled DOM stub, and the static wiring contracts (card in
// the Lightning panel, buttons, wipe hooks). Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

// "Please send $3 for a cup of coffee" — the BOLT11 spec vector.
const COFFEE =
  "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
const SPEC_NODE_ID = "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad";
const SPEC_PAYMENT_HASH = "0001020304050607080900010203040506070809000102030405060708090102";
const SPEC_SECRET = "1111111111111111111111111111111111111111111111111111111111111111";

// ── DOM stub (no library; the same style as sp-send-session.test.mjs) ──────

const makeEl = () => ({
  value: "",
  textContent: "",
  innerHTML: "",
  hidden: false,
  checked: false,
  listeners: {},
  addEventListener(type, fn) {
    (this.listeners[type] ||= []).push(fn);
  },
  fire(type, event) {
    (this.listeners[type] || []).forEach((fn) => fn(event));
  },
});
const elements = new Map();
globalThis.document = {
  getElementById: (id) => {
    if (!elements.has(id)) elements.set(id, makeEl());
    return elements.get(id);
  },
};

const { hodlInitLn } = await import("../src/js/lightning.js");

const initCard = (network = "mainnet") => {
  elements.clear();
  hodlInitLn({ qrSvg: () => "<svg>qr</svg>", networkChoice: () => network });
  return {
    input: document.getElementById("ln-inv-input"),
    out: document.getElementById("ln-inv-out"),
    error: document.getElementById("ln-inv-error"),
    decode: document.getElementById("ln-inv-decode"),
    clear: document.getElementById("ln-inv-clear"),
  };
};

test("decode renders payment hash, recovered node id, and signature state — secret hidden", () => {
  const ui = initCard();
  ui.input.value = COFFEE;
  ui.decode.onclick();
  assert.equal(ui.error.textContent, "");
  assert.ok(ui.out.innerHTML.includes(SPEC_PAYMENT_HASH), "payment hash rendered");
  assert.ok(ui.out.innerHTML.includes(SPEC_NODE_ID), "recovered node id rendered");
  assert.ok(ui.out.innerHTML.includes("Signature valid"), "signature state rendered");
  assert.ok(ui.out.innerHTML.includes("0.0025 BTC (250000000 msat)"), "amount rendered");
  assert.ok(ui.out.innerHTML.includes("1 cup coffee"), "description rendered");
  assert.ok(!ui.out.innerHTML.includes(SPEC_SECRET), "payment secret absent until reveal");
  assert.ok(ui.out.innerHTML.includes("<svg>qr</svg>"), "QR rendered");
});

test("reveal shows the payment secret; clear wipes input, output, and secret", () => {
  const ui = initCard();
  ui.input.value = COFFEE;
  ui.decode.onclick();
  document.getElementById("ln-inv-reveal").fire("change", { target: { checked: true } });
  assert.ok(ui.out.innerHTML.includes(SPEC_SECRET), "secret rendered after reveal");
  ui.clear.onclick();
  assert.equal(ui.input.value, "");
  assert.equal(ui.out.innerHTML, "");
  assert.equal(ui.error.textContent, "");
});

test("testnet invoice on a mainnet page decodes with a loud wrong-chain warning", () => {
  const ui = initCard("testnet");
  ui.input.value = COFFEE; // mainnet invoice
  ui.decode.onclick();
  assert.ok(ui.out.innerHTML.includes(SPEC_NODE_ID), "still decodes");
  assert.ok(ui.out.innerHTML.includes('class="warn"'), "warning banner rendered");
  assert.ok(ui.out.innerHTML.includes("page network is testnet"), "warning names the page network");
});

test("rejected input shows an error and no partial result", () => {
  const ui = initCard();
  ui.input.value = "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt"; // bad checksum
  ui.decode.onclick();
  assert.ok(ui.error.textContent.length > 0, "error shown");
  assert.equal(ui.out.innerHTML, "");
  ui.input.value = "";
  ui.decode.onclick();
  assert.ok(ui.error.textContent.length > 0, "empty paste is an error too");
});

// ── static wiring contracts ────────────────────────────────────────────────

test("invoice card lives in the Lightning panel with Decode and Clear buttons", () => {
  const shell = read("src/shell.html");
  assert.match(shell, /<section class="card no-print tool-card" id="ln-inv-card" role="tabpanel" hidden>/);
  assert.match(shell, /<button class="btn primary" id="ln-inv-decode" type="button">Decode<\/button>/);
  assert.match(shell, /<button class="btn secondary" id="ln-inv-clear" type="button">Clear<\/button>/);
  // The textarea ships empty: no value attribute, no content.
  assert.match(shell, /<textarea id="ln-inv-input"[^>]*><\/textarea>/);
  // It sits after the node-identity card, inside the same Lightning panel.
  assert.ok(shell.indexOf('id="ln-card"') < shell.indexOf('id="ln-inv-card"'), "after #ln-card");
});

test("the workspace switcher shows the invoice card only for the Lightning tab", () => {
  const app = read("src/js/app.js");
  assert.match(app, /document\.getElementById\("ln-inv-card"\)\.hidden = id !== "ln";/);
});

test("session clear wipes invoice state alongside the other Lightning fields", () => {
  const app = read("src/js/app.js");
  assert.match(app, /hodlLnInvWipeMem\(\);/);
  for (const id of ["ln-inv-input", "ln-inv-out", "ln-inv-error"]) {
    assert.ok(app.includes(`"${id}"`), `clearSecretFields references ${id}`);
  }
  const lightning = read("src/js/lightning.js");
  assert.match(lightning, /export function hodlLnInvWipeMem\(\)/);
});
