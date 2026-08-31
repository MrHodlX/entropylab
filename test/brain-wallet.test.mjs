// Brain-wallet passphrase normalization and SHA-256 compatibility.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}") {
      depth--;
      if (depth === 0) {
        end = index + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

const Z = (input) => new Uint8Array(createHash("sha256").update(input).digest());
const helpers = new Function(
  "Z",
  "TextEncoder",
  `${loadSlice("hodlBrainWalletPassphrase")};${loadSlice("hodlBrainWalletPrivateKey")};return { hodlBrainWalletPassphrase, hodlBrainWalletPrivateKey };`,
)(Z, TextEncoder);

test("brain-wallet recovery hashes exact text by default", () => {
  const passphrase = " recovery phrase \t\n";
  const expected = createHash("sha256").update(passphrase, "utf8").digest("hex");
  assert.equal(Buffer.from(helpers.hodlBrainWalletPrivateKey(passphrase)).toString("hex"), expected);
  assert.equal(helpers.hodlBrainWalletPassphrase(passphrase), passphrase);
});

test("opt-in trimming removes boundary whitespace before hashing", () => {
  const passphrase = " \trecovery phrase\n ";
  const expected = createHash("sha256").update("recovery phrase", "utf8").digest("hex");
  assert.equal(Buffer.from(helpers.hodlBrainWalletPrivateKey(passphrase, true)).toString("hex"), expected);
  assert.equal(helpers.hodlBrainWalletPassphrase(passphrase, true), "recovery phrase");
});

test("exact mode accepts whitespace while trim mode rejects an empty result", () => {
  assert.equal(helpers.hodlBrainWalletPassphrase(" \t\n"), " \t\n");
  assert.throws(() => helpers.hodlBrainWalletPassphrase(" \t\n", true), /leaves an empty brain-wallet recovery passphrase/);
  assert.throws(() => helpers.hodlBrainWalletPassphrase(""), /Enter the brain-wallet recovery passphrase/);
});

const lab = new Function(
  "Z",
  "M",
  `${loadSlice("hodlBrainLabEntropy")};return { hodlBrainLabEntropy };`,
)(Z, { encode: (bytes) => Buffer.from(bytes).toString("hex") });

test("brain-wallet lab hashes exact UTF-8 text as 256-bit BIP39 entropy", () => {
  const text = " recovery phrase \t\n";
  const expected = createHash("sha256").update(text, "utf8").digest("hex");
  const result = lab.hodlBrainLabEntropy(text);
  assert.equal(result.ok, true);
  assert.equal(result.hex, expected);
  assert.equal(result.bits, 256);
  assert.equal(result.sourceBits, 256);
  assert.equal(result.method, "brain-lab");
  assert.equal(result.bytes.length, 32);
  assert.match(result.notes.join(" "), /24 words/);
  assert.match(result.warnings.join(" "), /entropy of this text, not the 24-word count/);
  assert.match(result.warnings.join(" "), /unsalted and fast/);
  assert.match(result.warnings.join(" "), /not a BIP39 passphrase/);
  assert.match(result.warnings.join(" "), /not a Bitcoin Core hdseed/);
  assert.match(result.warnings.join(" "), /not mean it is the same wallet/);
});

test("brain-wallet lab rejects empty text and keeps private-key hashing separate", () => {
  assert.equal(lab.hodlBrainLabEntropy("").ok, false);
  const text = "correct horse battery staple";
  const labHex = lab.hodlBrainLabEntropy(text).hex;
  const scalarHex = Buffer.from(helpers.hodlBrainWalletPrivateKey(text)).toString("hex");
  assert.equal(labHex, scalarHex);
  assert.equal(app.includes('Ne === "brain-lab"'), true);
  assert.match(app, /function hodlBrainWalletPrivateKey\(/);
  assert.match(app, /function hodlBrainLabEntropy\(/);
});
