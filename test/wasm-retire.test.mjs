// End session retires both WebAssembly modules. Copies the modules cannot
// erase (dependency heap copies such as HMAC engines and bip39::Mnemonic,
// rust-bitcoin's per-pair copies) "remain until heap reuse" (SECURITY.md);
// zeroing the whole linear memory removes them all at once.
//
// Contract: after retirement every byte of each module's linear memory is
// zero, and every later call is refused with the session-ended error rather
// than running on the zeroed memory. Its own test file, so retiring the
// modules here cannot affect another suite.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { heap, retireWasm, wasmExports } from "../src/js/entropylab-wasm.js";
import { sha256 } from "../src/js/hashes.js";
import { psbtInspectDoc, psbtLoaderHeap, retirePsbtWasm } from "../src/js/psbt-wasm.js";

// BIP-174 valid vector 2 (hex form), the published vector the PSBT suites run.
const VALID_PSBT = new Uint8Array(Buffer.from(
  "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffff" +
  "ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40" +
  "bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000" +
  "0001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf133" +
  "6f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1" +
  "f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000",
  "hex",
));
// SHA-256("abc"), FIPS 180-2 appendix B.1.
const ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const allZero = (bytes) => bytes.every((b) => b === 0);

test("retiring the crypto module zeroes its whole memory and refuses every later call", () => {
  assert.equal(Buffer.from(sha256(new TextEncoder().encode("abc"))).toString("hex"), ABC_SHA256);
  const memory = heap();
  assert.ok(!allZero(memory), "the module's memory holds its data before retirement");
  retireWasm();
  assert.ok(allZero(new Uint8Array(memory.buffer)), "bytes survived retirement");
  assert.throws(() => wasmExports(), /session has ended/);
  assert.throws(() => sha256(new TextEncoder().encode("abc")), /session has ended/);
});

test("retiring the PSBT module zeroes its whole memory and refuses every later call", () => {
  assert.ok(psbtInspectDoc(VALID_PSBT).inputs?.length, "the published vector must parse before retirement");
  const memory = psbtLoaderHeap();
  assert.ok(!allZero(memory));
  retirePsbtWasm();
  assert.ok(allZero(new Uint8Array(memory.buffer)), "bytes survived retirement");
  assert.throws(() => psbtLoaderHeap(), /session has ended/);
  assert.throws(() => psbtInspectDoc(VALID_PSBT), /session has ended/);
});
