// Single-key print / save card: calculator export of an already-derived
// Key Station address plus that child's WIF. Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  addressTail,
  pinDescriptorIndex,
  formatPrintedAt,
  cardQrSvg,
  cardFromWallet,
  cardHtml,
  cardSaveDocument,
  publicOnly,
  cardPageStyles,
} from "../src/js/single-key-card.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const moduleSource = read("src/js/single-key-card.js");
const appSource = read("src/js/app.js");
const shell = read("src/shell.html");
const css = read("src/css/styles.css");
const pkg = JSON.parse(read("package.json"));

const WIF_COMPRESSED = "L1aW4aubDFB7yfras2S1eNAhkYp4RkjU1VXxxm5FPFAhkYzR3b5b";
const WIF_UNCOMPRESSED = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
const ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const MINIKEY = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy";

const printedAt = "2026-09-09T20:00:00-04:00";

const singleWallet = {
  kind: "single",
  network: "mainnet",
  wifCompressed: WIF_COMPRESSED,
  wifUncompressed: WIF_UNCOMPRESSED,
  pubkeyCompressed: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  p2pkhCompressed: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
  p2shP2wpkh: "3JvL6Ymt8MVWiCNHC7oWn1aQdZKeWRvpdC",
  p2wpkh: ADDRESS,
  p2tr: "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
  minikey: null,
};

const hdWallet = {
  kind: "hd",
  network: "mainnet",
  mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
  masterFingerprint: "d4a0c0ab",
  passphrase: "do-not-print-this-passphrase",
  accounts: [
    {
      def: { id: "bip84", label: "Native SegWit", script: "p2wpkh" },
      receiveDescriptor: "wpkh([d4a0c0ab/84h/0h/0h]xpub6C6nQwHaWbSfzjtFuEgeSoX4qGnaugQw4aJ1P7N4pYo3sNU5mXtg3uA2cW5K5example/0/*)#checksum",
      addressBranches: [
        {
          branch: 0,
          publicDescriptor: "wpkh([d4a0c0ab/84h/0h/0h]xpub6C6nQwHaWbSfzjtFuEgeSoX4qGnaugQw4aJ1P7N4pYo3sNU5mXtg3uA2cW5K5example/0/*)#checksum",
          rows: [{ index: 0, path: "m/84'/0'/0'/0/0", address: ADDRESS, wif: WIF_COMPRESSED }],
        },
      ],
    },
  ],
};

test("addressTail takes the last four characters", () => {
  assert.equal(addressTail(ADDRESS), "f3t4");
  assert.equal(addressTail("abc"), "abc");
  assert.equal(addressTail(""), "");
});

test("pinDescriptorIndex pins the receive wildcard and drops a stale checksum", () => {
  const input = "wpkh([d4a0c0ab/84h/0h/0h]xpubABC/0/*)#deadbeef";
  assert.equal(pinDescriptorIndex(input, 0), "wpkh([d4a0c0ab/84h/0h/0h]xpubABC/0/0)");
  assert.equal(pinDescriptorIndex(input, 7), "wpkh([d4a0c0ab/84h/0h/0h]xpubABC/0/7)");
  assert.equal(pinDescriptorIndex("wpkh(02ab)/0/*'", 3), "wpkh(02ab)/0/3'");
  assert.equal(pinDescriptorIndex("", 0), "");
  assert.equal(pinDescriptorIndex(input, -1), "");
});

test("formatPrintedAt uses the machine clock, not a CSPRNG", () => {
  const date = new Date("2026-09-09T16:00:00.000Z");
  const text = formatPrintedAt(date);
  assert.match(text, /^2026-09-09T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/);
  assert.equal(formatPrintedAt(date), formatPrintedAt(date));
});

test("cardQrSvg matches the app's dark-on-white address QR palette", () => {
  const svg = cardQrSvg(ADDRESS);
  assert.match(svg, /^<svg/);
  assert.ok(svg.includes("#111111"));
  assert.ok(svg.includes("#ffffff"));
  assert.notEqual(cardQrSvg(ADDRESS), cardQrSvg(WIF_COMPRESSED));
});

test("a single-key wallet with a WIF is eligible", () => {
  const card = cardFromWallet(singleWallet, { scriptId: "bip84", scriptLabel: "Native SegWit", revealPrivate: true, printedAt, version: "0.1.3", commitShort: "247dfab" });
  assert.equal(card.eligible, true);
  assert.equal(card.address, ADDRESS);
  assert.equal(card.addressTail, "f3t4");
  assert.equal(card.wif, WIF_COMPRESSED);
  assert.equal(card.wifEncoding, "compressed");
  assert.equal(card.includePrivate, true);
  assert.equal(card.descriptor, "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)");
  assert.match(card.source, /Calculator, not a generator/);
  assert.doesNotMatch(card.source, /L1aW4aub|5HueCGU8|legal winner/);
});

test("Taproot cards label the WIF as the BIP86 internal key", () => {
  const card = cardFromWallet(singleWallet, { scriptId: "bip86", scriptLabel: "Taproot", revealPrivate: true, printedAt });
  assert.equal(card.taprootInternalKey, true);
  assert.equal(card.script, "p2tr");
  assert.match(card.descriptor, /^tr\(/);
  const html = cardHtml(card);
  assert.match(html, /BIP86 internal key/);
});

test("an HD receive row pins the public descriptor to that index", () => {
  const card = cardFromWallet(hdWallet, { scriptId: "bip84", scriptLabel: "Native SegWit", revealPrivate: true, printedAt });
  assert.equal(card.eligible, true);
  assert.equal(card.path, "m/84'/0'/0'/0/0");
  assert.equal(card.fingerprint, "d4a0c0ab");
  assert.equal(card.descriptor, "wpkh([d4a0c0ab/84h/0h/0h]xpub6C6nQwHaWbSfzjtFuEgeSoX4qGnaugQw4aJ1P7N4pYo3sNU5mXtg3uA2cW5K5example/0/0)");
  assert.doesNotMatch(card.descriptor, /#/);
  const html = cardHtml(card);
  assert.doesNotMatch(html, /do-not-print-this-passphrase/);
  assert.doesNotMatch(html, /legal winner thank/);
});

test("watch-only xpub imports and multisig are hidden", () => {
  const watch = cardFromWallet({
    kind: "hd",
    network: "mainnet",
    accounts: [{ def: { id: "bip84", script: "p2wpkh" }, receive: [{ index: 0, address: ADDRESS, wif: null }], receiveDescriptor: "wpkh(xpubABC/0/*)#abcd1234" }],
  }, { scriptId: "bip84" });
  assert.equal(watch.eligible, false);
  assert.match(watch.reason, /Watch-only|spend secret/);

  const msig = cardFromWallet({ kind: "msig", network: "mainnet" }, { scriptId: "bip84" });
  assert.equal(msig.eligible, false);
  assert.match(msig.reason, /Multisig/);
});

test("the public face never contains the WIF", () => {
  const card = cardFromWallet(singleWallet, { scriptId: "bip84", revealPrivate: false, printedAt, version: "0.1.3" });
  assert.equal(card.includePrivate, false);
  const html = cardHtml(publicOnly(card));
  assert.match(html, /Receive address/);
  assert.match(html, /Last 4 · f3t4/);
  assert.doesNotMatch(html, /PRIVATE KEY|Private key \(WIF\)|Mini private key/);
  assert.ok(!html.includes(WIF_COMPRESSED));
  assert.ok(!html.includes(WIF_UNCOMPRESSED));
  assert.doesNotMatch(html, /Fold here/);
});

test("the private face has a huge WIF label, encoding, fold line, and last four", () => {
  const card = cardFromWallet(singleWallet, { scriptId: "bip84", scriptLabel: "Native SegWit", revealPrivate: true, printedAt, version: "0.1.3", commitShort: "247dfab" });
  const html = cardHtml(card);
  assert.match(html, /Private key \(WIF\) — spend/);
  assert.match(html, /Fold here · cover the private face · last 4 · f3t4/);
  assert.match(html, /compressed/);
  assert.ok(html.includes(WIF_COMPRESSED));
  assert.ok(html.includes(WIF_UNCOMPRESSED));
  assert.match(html, /Anyone who sees this WIF can spend this address/);
  assert.match(html, /EntropyLab v0\.1\.3 · 247dfab · printed 2026-09-09T20:00:00-04:00/);
  assert.match(html, /Calculator, not a generator/);
  assert.equal((html.match(/<svg/g) || []).length, 2);
});

test("a minikey is the spend secret when present", () => {
  const card = cardFromWallet({ ...singleWallet, minikey: MINIKEY }, { scriptId: "bip84", revealPrivate: true, printedAt });
  assert.equal(card.wif, MINIKEY);
  assert.match(cardHtml(card), /Mini private key — spend/);
  assert.ok(cardHtml(card).includes(MINIKEY));
});

test("the saved document inlines print CSS and does not phone home", () => {
  const card = cardFromWallet(singleWallet, { scriptId: "bip84", revealPrivate: true, printedAt, version: "0.1.3" });
  const html = cardSaveDocument(card);
  assert.match(html, /^<!DOCTYPE html>/);
  assert.match(html, /This file includes a private key/);
  assert.ok(html.includes(cardPageStyles.split("\n")[0]));
  assert.doesNotMatch(html, /<script/i);
  assert.doesNotMatch(html, /https?:\/\/(?!www\.w3\.org\/)/);
});

test("the module does not invent entropy", () => {
  assert.doesNotMatch(moduleSource, /getRandomValues|Math\.random/);
  assert.match(moduleSource, /Calculator, not a generator/);
});

test("Key Station wires Print and Save next to the recovery sheet, with no Paper Wallet tab", () => {
  assert.match(appSource, /from "\.\/single-key-card\.js"/);
  assert.match(appSource, /hodlT\("Print single-key card"\)/);
  assert.match(appSource, /hodlT\("Save single-key card"\)/);
  assert.match(appSource, /id="print-single-key-card"/);
  assert.match(appSource, /id="save-single-key-card"/);
  assert.match(appSource, /afterprint/);
  assert.match(appSource, /hodlTearSingleKeyCard/);
  assert.match(shell, /id="single-key-card-confirm"/);
  assert.match(shell, /id="single-key-card-print"/);
  assert.doesNotMatch(shell, /Paper Wallet/);
  assert.doesNotMatch(appSource, /Paper Wallet/);
  const tabs = [...shell.matchAll(/workspace-tab-full">([^<]+)</g)].map((match) => match[1]);
  assert.deepEqual(tabs, ["Keys", "Vanity", "BIP-85", "Multi Signature", "Silent Payments", "PSBT", "Journal"]);
  assert.match(css, /print-single-key-card/);
  assert.match(css, /save-single-key-card/);
  assert.match(css, /html\.printing-single-key-card/);
});

test("package.json lists this suite in test:ci", () => {
  assert.match(pkg.scripts["test:ci"], /test\/single-key-card\.test\.mjs/);
});
