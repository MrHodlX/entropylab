// Entropy Journal: dice-derived AES-GCM, no invented secret entropy.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DICE_MIN_ROLLS,
  METHODS,
  addEntry,
  assertDiceKey,
  createDocument,
  diceBits,
  emptyDocument,
  encodeFile,
  openDocument,
  parseDiceTranscript,
  parseFile,
  removeEntry,
  searchEntries,
  sealDocument,
  snapshotFromKeyState,
  wipeDocument,
} from "../src/js/journal.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const source = readFileSync(join(root, "src/js/journal.js"), "utf8");

const fifty = "123456".repeat(9) + "12"; // 56 rolls
const fiftyOther = "654321".repeat(9) + "65";
const now = new Date("2026-09-01T15:04:05.000Z");
const fill = (length, start = 1) => Uint8Array.from({ length }, (_, i) => (start + i) & 255);

test("dice transcripts count only the digits 1-6 and estimate bits", () => {
  const parsed = parseDiceTranscript("1 2,3;4|5\n6abc");
  assert.equal(parsed.digits, "123456");
  assert.equal(parsed.count, 6);
  assert.equal(parsed.leftover, "abc");
  assert.equal(diceBits(50).toFixed(2), (50 * Math.log2(6)).toFixed(2));
  assert.throws(() => assertDiceKey("12345"), /at least 50/);
  assert.throws(() => assertDiceKey(fifty + "x"), /digits 1/);
  assert.deepEqual(assertDiceKey(`  ${fifty}  `).digits, fifty);
  assert.throws(() => assertDiceKey(fifty, { confirm: fiftyOther }), /do not match/);
  assert.equal(assertDiceKey(fifty, { confirm: fifty.split("").join(" ") }).count >= DICE_MIN_ROLLS, true);
});

test("the journal never invents secret entropy or talks to the network", () => {
  const code = source.replace(/\/\/.*$/gm, "");
  assert.doesNotMatch(code, /Math\.random|fetch\b|XMLHttpRequest|WebSocket|localStorage|indexedDB/);
  assert.match(source, /crypto\.getRandomValues\(bytes\)/);
  assert.match(source, /Public AEAD parameters only/);
  assert.match(source, /never a typed password/);
});

test("entries store the raw input, phrase, label, ISO time, and optional wallet link", () => {
  const doc = emptyDocument();
  const entry = addEntry(doc, {
    method: "dice",
    input: "1 2 3 4 5 6",
    phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident",
    label: "Coldcard stash",
    notes: "garage",
    walletId: 3,
    walletName: "aabbccdd",
    fingerprint: "AABBCCDD",
  }, now);
  assert.equal(entry.id, 1);
  assert.equal(entry.input, "1 2 3 4 5 6");
  assert.equal(entry.created, "2026-09-01T15:04:05.000Z");
  assert.equal(entry.fingerprint, "aabbccdd");
  assert.equal(doc.nextId, 2);
  assert.equal(searchEntries(doc, "stash").length, 1);
  assert.equal(searchEntries(doc, "nope").length, 0);
  removeEntry(doc, 1);
  assert.equal(doc.entries.length, 0);
  assert.throws(() => addEntry(doc, { method: "dice", input: "1", phrase: "x" }, now), /label/);
  assert.throws(() => addEntry(doc, { method: "nostr", label: "x" }, now), /method/);
  assert.deepEqual(METHODS, ["dice", "coin", "hex", "brain", "seed", "cards"]);
});

test("a session key snapshot prefers the live dice / brain / seed transcript", () => {
  const dice = snapshotFromKeyState({
    id: 4,
    isLab: false,
    mode: "dice",
    diceMethod: "coldcard",
    name: "deadbeef",
    fields: { dice: "4 1 4 2 6 3" },
    result: { mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow", masterFingerprint: "deadbeef" },
  });
  assert.equal(dice.method, "dice");
  assert.equal(dice.input, "4 1 4 2 6 3");
  assert.equal(dice.phrase.startsWith("legal winner"), true);
  assert.equal(dice.walletId, 4);
  const brain = snapshotFromKeyState({
    id: 5,
    isLab: false,
    mode: "key",
    name: "brain",
    fields: { keyKind: "brain", privateKeys: { brain: "correct horse" } },
    result: { mnemonic: "one two three" },
  });
  assert.equal(brain.method, "brain");
  assert.equal(brain.input, "correct horse");
  assert.equal(snapshotFromKeyState({ isLab: true, mode: "dice", fields: { dice: "123" } }), null);
});

test("AES-GCM round-trips with dice and fails on the wrong rolls", async () => {
  let calls = 0;
  const randomBytes = (n) => {
    calls += 1;
    return fill(n, calls * 3);
  };
  const created = await createDocument(fifty, fifty.split("").join("\n"), randomBytes);
  assert.equal(created.doc.entries.length, 0);
  addEntry(created.doc, { method: "hex", input: "ab", phrase: "seed words here", label: "lab" }, now);
  const file = await sealDocument(created.doc, created.key, created.salt, randomBytes);
  assert.equal(file.entropylabJournal, 1);
  assert.equal(file.kdf, "HKDF-SHA-256");
  assert.equal(file.cipher, "AES-256-GCM");
  assert.equal(file.salt.length, 32);
  assert.equal(file.iv.length, 24);
  assert.match(file.ciphertext, /^[0-9a-f]+$/);
  const packed = JSON.stringify(file);
  const opened = await openDocument(packed, fifty);
  assert.equal(opened.doc.entries[0].label, "lab");
  assert.equal(opened.doc.entries[0].input, "ab");
  assert.equal(opened.doc.entries[0].phrase, "seed words here");
  await assert.rejects(() => openDocument(packed, fiftyOther), /Wrong dice/);
  wipeDocument(opened.doc);
  assert.equal(opened.doc.entries.length, 0);
});

test("encodeFile stores salt and IV next to the ciphertext", () => {
  const file = encodeFile({ salt: fill(16), iv: fill(12, 9), ciphertext: fill(32, 4) });
  const parsed = parseFile(JSON.stringify(file));
  assert.equal(parsed.salt.length, 16);
  assert.equal(parsed.iv.length, 12);
  assert.equal(parsed.ciphertext.length, 32);
  assert.throws(() => parseFile("{}"), /not an EntropyLab journal/);
  assert.throws(() => parseFile("{"), /not valid JSON/);
});
