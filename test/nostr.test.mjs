// Official NIP-06 test vectors (nips.nostr.com/6) plus NIP-19 round-trips.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  deriveNip06FromMnemonic,
  encodeNote,
  encodeNpub,
  encodeNsec,
  inspectNostrInput,
  isValidSecp256k1Secret,
  nip06Path,
  parseAccount,
  wipeNostrResult,
  xonlyFromPrivateKey,
} from "../src/js/nostr.js";
import { hex as hexCoder } from "@scure/base";

const VECTOR_1 = {
  mnemonic: "leader monkey parrot ring guide accident before fence cannon height naive bean",
  privHex: "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
  nsec: "nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp",
  pubHex: "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
  npub: "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu",
};

const VECTOR_2 = {
  mnemonic: "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade",
  privHex: "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add",
  nsec: "nsec1c9wh8xy5eqdzln7n5t0ctgxjcrdug73gp5yj0x03gntn67h83twssdfhel",
  pubHex: "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573",
  npub: "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h",
};

test("NIP-06 path is SLIP-44 coin type 1237 with a hardened account", () => {
  assert.equal(nip06Path(0), "m/44'/1237'/0'/0/0");
  assert.equal(nip06Path(1), "m/44'/1237'/1'/0/0");
  assert.equal(parseAccount("0"), 0);
  assert.throws(() => parseAccount(-1), /account must be an integer/);
  assert.throws(() => parseAccount(1.5), /account must be an integer/);
});

test("NIP-06 vector 1 matches nips.nostr.com/6", () => {
  const result = deriveNip06FromMnemonic(VECTOR_1.mnemonic);
  assert.equal(result.path, "m/44'/1237'/0'/0/0");
  assert.equal(result.privHex, VECTOR_1.privHex);
  assert.equal(result.nsec, VECTOR_1.nsec);
  assert.equal(result.pubHex, VECTOR_1.pubHex);
  assert.equal(result.npub, VECTOR_1.npub);
  wipeNostrResult(result);
});

test("NIP-06 vector 2 matches nips.nostr.com/6", () => {
  const result = deriveNip06FromMnemonic(VECTOR_2.mnemonic);
  assert.equal(result.privHex, VECTOR_2.privHex);
  assert.equal(result.nsec, VECTOR_2.nsec);
  assert.equal(result.pubHex, VECTOR_2.pubHex);
  assert.equal(result.npub, VECTOR_2.npub);
  wipeNostrResult(result);
});

test("a BIP39 passphrase changes the NIP-06 nsec", () => {
  const none = deriveNip06FromMnemonic(VECTOR_1.mnemonic, "");
  const withPass = deriveNip06FromMnemonic(VECTOR_1.mnemonic, "TREZOR");
  assert.notEqual(withPass.nsec, none.nsec);
  assert.notEqual(withPass.npub, none.npub);
  wipeNostrResult(none);
  wipeNostrResult(withPass);
});

test("NIP-19 nsec and npub round-trip the published vectors", () => {
  const priv = hexCoder.decode(VECTOR_1.privHex);
  const pub = hexCoder.decode(VECTOR_1.pubHex);
  assert.equal(encodeNsec(priv), VECTOR_1.nsec);
  assert.equal(encodeNpub(pub), VECTOR_1.npub);
  const inspected = inspectNostrInput(VECTOR_1.nsec);
  assert.equal(inspected.kind, "private");
  assert.equal(inspected.nsec, VECTOR_1.nsec);
  assert.equal(inspected.npub, VECTOR_1.npub);
  const pubOnly = inspectNostrInput(VECTOR_1.npub);
  assert.equal(pubOnly.kind, "public");
  assert.equal(pubOnly.npub, VECTOR_1.npub);
  assert.equal(pubOnly.nsec, "");
  wipeNostrResult(inspected);
  wipeNostrResult(pubOnly);
});

test("64-character hex is a private key when it is a valid scalar", () => {
  const inspected = inspectNostrInput(VECTOR_2.privHex);
  assert.equal(inspected.kind, "private");
  assert.equal(inspected.nsec, VECTOR_2.nsec);
  assert.equal(inspected.npub, VECTOR_2.npub);
  wipeNostrResult(inspected);
});

test("note1 encodes and decodes a 32-byte event id", () => {
  const id = hexCoder.decode(VECTOR_1.pubHex);
  const note = encodeNote(id);
  assert.match(note, /^note1[0-9a-z]+$/);
  const inspected = inspectNostrInput(note);
  assert.equal(inspected.kind, "note");
  assert.equal(inspected.eventHex, VECTOR_1.pubHex);
  assert.equal(inspected.note, note);
  wipeNostrResult(inspected);
});

test("inspect rejects mixed-case bech32 and empty input", () => {
  assert.throws(() => inspectNostrInput(""), /Paste an nsec/);
  assert.throws(() => inspectNostrInput("nsec1QQQQ"), /Invalid nsec/);
  const mixed = VECTOR_1.nsec.slice(0, 8).toUpperCase() + VECTOR_1.nsec.slice(8);
  assert.throws(() => inspectNostrInput(mixed), /Invalid nsec/);
});

test("x-only pubkey is the compressed secp point without the prefix", () => {
  const priv = hexCoder.decode(VECTOR_1.privHex);
  assert.equal(hexCoder.encode(xonlyFromPrivateKey(priv)), VECTOR_1.pubHex);
  assert.equal(isValidSecp256k1Secret(priv), true);
  assert.equal(isValidSecp256k1Secret(new Uint8Array(32)), false);
});

test("the Nostr calculator never invents entropy or talks to relays", () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../src/js/nostr.js"), "utf8");
  assert.doesNotMatch(src, /Math\.random|getRandomValues|fetch\b|WebSocket|XMLHttpRequest/);
});
