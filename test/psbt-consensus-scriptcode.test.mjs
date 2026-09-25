// The scriptCode an ECDSA or tapscript signature commits to, against Bitcoin
// Core's consensus rules rather than against another wallet library.
//
// Contract: a partial signature is reported invalid exactly when no
// execution of its script could accept it — so a signature Core would accept
// on some path is never reported, and one Core rejects on every path always
// is. Before the spending transaction exists, the path (which IF branches run)
// is open, so every OP_CODESEPARATOR a path could execute last before a
// signature check is a scriptCode start the signature may have used. The
// rules pinned here, each from Core's interpreter:
//
//   - legacy and BIP143 hash from just past the last executed
//     OP_CODESEPARATOR; a separator at the top level of the script always
//     executes, one inside IF/ELSE only on that branch;
//   - legacy (not BIP143) removes OP_CODESEPARATOR opcodes from the
//     scriptCode, and removes the signature itself (FindAndDelete, whole
//     canonical pushes only; CHECKMULTISIG removes every signature it is
//     given);
//   - the hash type byte is committed as given (0x00, 0x41, ... are consensus
//     valid in legacy and BIP143 — STRICTENC is policy), high-S signatures
//     are consensus valid (LOW_S is policy), strict DER (BIP66) is consensus;
//   - tapscript commits to the opcode position of the last executed
//     OP_CODESEPARATOR (BIP342), 0xffffffff when none ran.
//
// Oracles: Bitcoin Core's own tx_valid.json / tx_invalid.json vectors (see
// test/fixtures/core/extract.mjs for provenance and pairings), plus generated
// scripts whose separators the generator places itself, signed over digests
// from @scure/btc-signer (an independent implementation) for the scriptCode
// the rules above name. The digest-level legacy rules are pinned separately
// against Core's sighash.json in psbt-wasm's Rust tests.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Transaction, p2tr } from "@scure/btc-signer";
import { tapLeafHash } from "@scure/btc-signer/payment.js";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const VECTORS = JSON.parse(readFileSync(join(root, "test/fixtures/core/tx-scriptcode-vectors.json"), "utf8"));

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const unhex = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const cat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));
const le32 = (n) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];
const le64 = (n) => { const out = []; let v = BigInt(n); for (let i = 0; i < 8; i++, v >>= 8n) out.push(Number(v & 255n)); return out; };
const compactSize = (n) => (n < 0xfd ? [n] : n <= 0xffff ? [0xfd, n & 255, n >>> 8] : [0xfe, ...le32(n)]);
const varBytes = (bytes) => [...compactSize(bytes.length), ...bytes];
const hash160 = (bytes) => ripemd160(sha256(bytes));

// --- PSBTs from Core's vectors ----------------------------------------------

// The vector's transaction with every scriptSig and witness emptied: the
// PSBT's unsigned transaction.
const unsignedTx = (txHex) => {
  const b = unhex(txHex);
  let o = 0;
  const take = (n) => { const r = b.subarray(o, o + n); o += n; return r; };
  const varint = () => {
    const first = b[o++];
    if (first < 0xfd) return first;
    const width = first === 0xfd ? 2 : 4;
    let v = 0;
    for (let i = 0; i < width; i++) v += b[o++] * 2 ** (8 * i);
    return v;
  };
  const out = [...take(4)];
  const segwit = b[o] === 0 && b[o + 1] === 1;
  if (segwit) o += 2;
  const inputs = varint();
  out.push(...compactSize(inputs));
  for (let i = 0; i < inputs; i++) {
    out.push(...take(36));
    take(varint());
    out.push(0, ...take(4));
  }
  const outputs = varint();
  out.push(...compactSize(outputs));
  for (let i = 0; i < outputs; i++) { out.push(...take(8)); out.push(...varBytes(take(varint()))); }
  if (segwit) for (let i = 0; i < inputs; i++) for (let n = varint(); n--;) take(varint());
  out.push(...take(4));
  return Uint8Array.from(out);
};

const kv = (key, value) => [...varBytes(key), ...varBytes(value)];
// One PSBT for one check: every input declares its prevout as a witness UTXO
// (Core's vectors give the script and amount, not the previous
// transaction), and the checked input carries the redeem/witness script and
// the partial signatures.
const psbtFor = (vector, check, { partialSigs = check.partialSigs, prevouts = vector.prevouts, witnessScript = check.witnessScript, redeemScript = check.redeemScript } = {}) => {
  const out = [0x70, 0x73, 0x62, 0x74, 0xff, ...kv([0x00], unsignedTx(vector.tx)), 0x00];
  prevouts.forEach((prevout, index) => {
    out.push(...kv([0x01], [...le64(prevout.amount), ...varBytes(unhex(prevout.scriptPubKey))]));
    if (index === check.input) {
      if (redeemScript) out.push(...kv([0x04], unhex(redeemScript)));
      if (witnessScript) out.push(...kv([0x05], unhex(witnessScript)));
      for (const { pubkey, signature } of partialSigs) out.push(...kv([0x02, ...unhex(pubkey)], unhex(signature)));
    }
    out.push(0x00);
  });
  for (let n = outputCount(unsignedTx(vector.tx)); n--;) out.push(0x00); // one empty map per output
  return Uint8Array.from(out);
};
const outputCount = (tx) => {
  let o = 4;
  const varint = () => { const first = tx[o++]; if (first < 0xfd) return first; const width = first === 0xfd ? 2 : 4; let v = 0; for (let i = 0; i < width; i++) v += tx[o++] * 2 ** (8 * i); return v; };
  for (let n = varint(); n--;) { o += 36; const scriptSig = varint(); o += scriptSig + 4; }
  return varint();
};

// The partial-signature verdicts psbtInspectDoc reports for one input.
const invalidSigs = (psbt, input) =>
  psbtInspectDoc(psbt).problems.filter((problem) => problem.scope === `input ${input}` && problem.code === "partial_sig_invalid");

const relabel = (signature) => {
  const bytes = unhex(signature);
  bytes[bytes.length - 1] ^= 0x01; // ALL<->0, NONE<->SINGLE: always another digest
  return hex(bytes);
};

// --- 1. Core's vectors -------------------------------------------------------

for (const vector of VECTORS.cases) {
  vector.checks.forEach((check, n) => {
    test(`Core ${vector.source} input ${check.input} #${n}: ${check.expect} — ${check.why}`, () => {
      const flagged = invalidSigs(psbtFor(vector, check), check.input);
      if (check.expect === "valid") {
        assert.deepEqual(flagged.map((problem) => problem.message), [], "Core accepts this spend, so each of its signatures verified");
        // The same signatures with another hash type must all be reported:
        // proof that the verifier computed a digest and checked each one.
        const relabelled = check.partialSigs.map((sig) => ({ ...sig, signature: relabel(sig.signature) }));
        assert.equal(invalidSigs(psbtFor(vector, check, { partialSigs: relabelled }), check.input).length, check.partialSigs.length);
      } else {
        assert.equal(flagged.length, check.partialSigs.length, "Core rejects this spend because these signatures do not verify");
      }
    });
  });
}

test("Core's vectors cover what they are extracted for", () => {
  assert.equal(VECTORS.source.tag, "v31.1");
  const checks = VECTORS.cases.flatMap((vector) => vector.checks);
  assert.ok(checks.filter((check) => check.expect === "valid").length >= 20);
  assert.ok(checks.filter((check) => check.expect === "invalid").length >= 6);
  assert.ok(checks.some((check) => check.witnessScript), "BIP143 spends");
  assert.ok(checks.some((check) => check.redeemScript && !check.witnessScript), "legacy P2SH spends");
  assert.ok(checks.some((check) => !check.redeemScript && !check.witnessScript), "bare legacy spends");
});

// Core's valid signatures moved onto a script where their scriptCode no
// longer exists. Each vector names the start its signature hashed from; the
// edit removes or adds exactly the separator that start depends on.
const vectorBySource = (prefix) => VECTORS.cases.find((vector) => vector.source.startsWith(prefix));
const withScriptPubKey = (vector, input, scriptPubKey) =>
  vector.prevouts.map((prevout, index) => (index === input ? { ...prevout, scriptPubKey } : prevout));

test("a signature hashed from a separator is refused once that separator is gone", () => {
  // <K> CODESEPARATOR CHECKSIG: the signature commits to CHECKSIG alone.
  const vector = vectorBySource("tx_valid.json (326882a7f22b5191");
  const [check] = vector.checks;
  const spk = vector.prevouts[0].scriptPubKey;
  assert.match(spk, /^21[0-9a-f]{66}abac$/);
  const without = spk.replace(/abac$/, "ac");
  assert.equal(invalidSigs(psbtFor(vector, check, { prevouts: withScriptPubKey(vector, 0, without) }), 0).length, 1);
});

test("a signature over the whole script is refused once a top-level separator precedes its CHECKSIG", () => {
  // CODESEPARATOR <K> CHECKSIG, signed over <K> CHECKSIG; move the separator
  // between the key push and CHECKSIG and only CHECKSIG is hashed.
  const vector = vectorBySource("tx_valid.json (bc7fd132fcf81791");
  const [check] = vector.checks;
  const spk = vector.prevouts[0].scriptPubKey;
  assert.match(spk, /^ab21[0-9a-f]{66}ac$/);
  const moved = spk.slice(2, -2) + "abac";
  assert.equal(invalidSigs(psbtFor(vector, check, { prevouts: withScriptPubKey(vector, 0, moved) }), 0).length, 1);
});

test("a BIP143 signature hashed from a separator is refused once that separator is gone", () => {
  // <K1> CHECKSIGVERIFY CODESEPARATOR <K2> CHECKSIG: K2's signature commits to <K2> CHECKSIG.
  const vector = vectorBySource("tx_valid.json (6eb316926b1c5d56");
  const check = vector.checks.find((c) => c.input === 1 && c.partialSigs[0].pubkey.startsWith("0255a962"));
  const witnessScript = check.witnessScript.replace("adab21", "ad21");
  const prevouts = withScriptPubKey(vector, 1, hex(cat([0x00, 0x20], sha256(unhex(witnessScript)))));
  assert.equal(invalidSigs(psbtFor(vector, check, { prevouts, witnessScript }), 1).length, 1);
});

// --- 2. encodings consensus accepts that policy does not --------------------

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const derInts = (signature) => {
  const b = unhex(signature);
  const lenR = b[3];
  return { r: b.subarray(4, 4 + lenR), s: b.subarray(6 + lenR, 6 + lenR + b[5 + lenR]), type: b[b.length - 1] };
};
const derInt = (value) => {
  let bytes = unhex(value.toString(16).padStart(64, "0"));
  while (bytes.length > 1 && bytes[0] === 0 && !(bytes[1] & 0x80)) bytes = bytes.subarray(1);
  return bytes[0] & 0x80 ? cat([0], bytes) : bytes;
};
const der = (r, s, type) => hex(cat([0x30, r.length + s.length + 4, 0x02, r.length], r, [0x02, s.length], s, [type]));
const big = (bytes) => BigInt(`0x${hex(bytes) || "0"}`);

test("a high-S signature is consensus valid (LOW_S is policy), in BIP143 and legacy alike", () => {
  for (const prefix of ["tx_valid.json (01c0cf7fba650638", "tx_valid.json (b5b598de91787439"]) {
    const vector = vectorBySource(prefix);
    const check = vector.checks[0];
    const [{ pubkey, signature }] = check.partialSigs;
    const { r, s, type } = derInts(signature);
    const flipped = N - big(s);
    const highS = flipped > N / 2n ? flipped : big(s);
    const lowS = flipped > N / 2n ? big(s) : flipped;
    for (const value of [highS, lowS]) {
      const partialSigs = [{ pubkey, signature: der(r, derInt(value), type) }];
      assert.deepEqual(invalidSigs(psbtFor(vector, check, { partialSigs }), check.input), [], `${prefix} S=${value > N / 2n ? "high" : "low"}`);
    }
  }
});

test("a signature BIP66 rejects is refused even where lax DER parsing would read it", () => {
  const vector = vectorBySource("tx_valid.json (01c0cf7fba650638");
  const check = vector.checks[0];
  const [{ pubkey, signature }] = check.partialSigs;
  const { r, s, type } = derInts(signature);
  // A superfluous leading zero on S (its top bit is clear, so none is needed).
  const lowS = big(s) > N / 2n ? N - big(s) : big(s);
  const padded = cat([0], derInt(lowS));
  assert.ok(!(padded[1] & 0x80));
  assert.equal(invalidSigs(psbtFor(vector, check, { partialSigs: [{ pubkey, signature: der(r, padded, type) }] }), check.input).length, 1);
});

// --- 3. generated scripts ----------------------------------------------------

const mulberry32 = (seed) => {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};
const FUZZ_SEED = 0xc0de5e9;
const rand = mulberry32(FUZZ_SEED);
const rint = (n) => Math.floor(rand() * n);
const randomBytes = (n) => Uint8Array.from({ length: n }, () => rint(256));
const randomKey = () => { for (;;) { const key = randomBytes(32); if (secp256k1.utils.isValidSecretKey(key)) return key; } };
const SCURE_OPTS = { allowUnknownOutputs: true, allowUnknownInputs: true, allowUnknownVersion: true, disableScriptCheck: true };
const p2wpkh = (pub) => cat([0x00, 0x14], hash160(pub));
const p2sh = (redeem) => cat([0xa9, 0x14], hash160(redeem), [0x87]);
const p2wsh = (script) => cat([0x00, 0x20], sha256(script));

const OP = { IF: 0x63, ELSE: 0x67, ENDIF: 0x68, DROP: 0x75, NOP: 0x61, CODESEPARATOR: 0xab, CHECKSIG: 0xac };
// A filler the verifier must read past: a push (whose data may contain 0xab
// bytes, which are data, not separators) dropped again, or a NOP.
const filler = () => {
  if (rint(3) === 0) return [OP.NOP];
  const data = randomBytes(1 + rint(30));
  if (rint(2)) data[rint(data.length)] = OP.CODESEPARATOR;
  return [data.length, ...data, OP.DROP];
};

// A script ending in <K> CHECKSIG, built from segments: fillers, top-level
// separators, IF blocks with a separator, and IF/ELSE blocks with a separator
// in either arm. The generator picks which branches run and records where
// each separator ends, so it knows the start Core hashes the CHECKSIG's
// scriptCode from on that path: just past the last separator that ran.
const generate = (pub) => {
  const bytes = [...filler()];
  const separators = []; // { end, runs, topLevel }
  let hashedFrom = 0;
  const separator = (runs, topLevel) => {
    bytes.push(OP.CODESEPARATOR);
    separators.push({ end: bytes.length, runs, topLevel });
    if (runs) hashedFrom = bytes.length;
  };
  for (let n = 1 + rint(5); n > 0; n--) {
    const roll = rint(4);
    if (roll === 0) bytes.push(...filler());
    else if (roll === 1) separator(true, true);
    else if (roll === 2) {
      const taken = rint(2) === 1;
      bytes.push(OP.IF, ...filler());
      separator(taken, false);
      bytes.push(...filler(), OP.ENDIF);
    } else {
      const taken = rint(2) === 1;
      bytes.push(OP.IF);
      if (rint(2)) separator(taken, false);
      bytes.push(OP.ELSE, ...filler());
      if (rint(2)) separator(!taken, false);
      bytes.push(OP.ENDIF);
    }
  }
  const checksigAt = bytes.length + 34;
  bytes.push(33, ...pub, OP.CHECKSIG);
  // A separator after the CHECKSIG never changes what it hashed.
  if (rint(2)) bytes.push(OP.CODESEPARATOR);
  return { script: Uint8Array.from(bytes), hashedFrom, checksigAt, topLevelSeparator: separators.some((s) => s.topLevel && s.end <= checksigAt) };
};

const buildSpend = (legacy, pub, script, type) => {
  const tx = new Transaction({ ...SCURE_OPTS, version: 2, lockTime: rint(2 ** 31) });
  const amount = BigInt(1000 + rint(1e8));
  const inputs = 1 + rint(3), idx = rint(inputs);
  for (let j = 0; j < inputs; j++) {
    const signed = j === idx;
    const prevScript = signed ? (legacy ? p2sh(script) : p2wsh(script)) : p2wpkh(secp256k1.getPublicKey(randomKey(), true));
    if (signed && legacy) {
      const prev = new Transaction({ ...SCURE_OPTS, version: 2 });
      prev.addInput({ txid: randomBytes(32), index: 0, sequence: 0xffffffff });
      prev.addOutput({ script: prevScript, amount });
      tx.addInput({ txid: prev.id, index: 0, sequence: 0xfffffffd, nonWitnessUtxo: prev.toBytes(true, false), redeemScript: script });
    } else {
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence: 0xfffffffd, witnessUtxo: { script: prevScript, amount }, ...(signed ? { witnessScript: script } : {}) });
    }
  }
  const outputs = 1 + rint(3);
  for (let k = 0; k < outputs; k++) tx.addOutput({ script: p2wpkh(secp256k1.getPublicKey(randomKey(), true)), amount: 1000n });
  // Legacy SIGHASH_SINGLE with no output at the input's index signs the
  // constant digest 1, whatever the scriptCode.
  const singleBug = legacy && (type & 0x1f) === 3 && idx >= outputs;
  // scure's legacy preimage strips separators from what it is given, as
  // Core's SerializeScriptCode does; BIP143's hashes the bytes as given.
  const digestFrom = (start) => (legacy ? tx.preimageLegacy(idx, script.subarray(start), type) : tx.preimageWitnessV0(idx, script.subarray(start), type, amount));
  return { tx, idx, digestFrom, singleBug };
};
const signedPsbt = ({ tx, idx }, key, digest, type) => {
  const copy = Transaction.fromPSBT(tx.toPSBT(), SCURE_OPTS);
  const signature = cat(secp256k1.sign(digest, key, { prehash: false, format: "der" }), [type]);
  copy.updateInput(idx, { partialSig: [[secp256k1.getPublicKey(key, true), signature]] }, true);
  return copy.toPSBT();
};

test(`generated separator placements: the path's scriptCode verifies, starts no path uses are refused (seed 0x${FUZZ_SEED.toString(16)})`, () => {
  let refusedWhole = 0, conditional = 0, singleBug = 0;
  for (let i = 0; i < 64; i++) {
    const legacy = i % 2 === 0, type = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83][rint(6)];
    const key = randomKey(), pub = secp256k1.getPublicKey(key, true);
    const { script, hashedFrom, checksigAt, topLevelSeparator } = generate(pub);
    const spend = buildSpend(legacy, pub, script, type);
    const label = `case ${i} (${legacy ? "legacy P2SH" : "P2WSH"}, script ${hex(script)}, hashed from ${hashedFrom})`;
    if (hashedFrom > 0 && script.subarray(0, hashedFrom).includes(OP.IF)) conditional += 1;

    assert.deepEqual(invalidSigs(signedPsbt(spend, key, spend.digestFrom(hashedFrom), type), spend.idx).map((p) => p.message), [], `${label}: the path's scriptCode`);
    if (spend.singleBug) {
      singleBug += 1;
      continue;
    }
    // From the CHECKSIG opcode itself: no separator ends there.
    assert.equal(invalidSigs(signedPsbt(spend, key, spend.digestFrom(checksigAt), type), spend.idx).length, 1, `${label}: from the CHECKSIG`);
    // The whole script, when a top-level separator always runs before the
    // CHECKSIG (the script opens with a filler, so the bytes differ).
    if (topLevelSeparator) {
      assert.equal(invalidSigs(signedPsbt(spend, key, spend.digestFrom(0), type), spend.idx).length, 1, `${label}: the whole script`);
      refusedWhole += 1;
    }
  }
  assert.ok(refusedWhole >= 8 && conditional >= 8 && singleBug >= 1, `coverage: ${refusedWhole} top-level refusals, ${conditional} conditional starts, ${singleBug} SIGHASH_SINGLE-bug digests`);
});

test("BIP143 commits to the hash type byte as given: undefined types are consensus valid", () => {
  for (const type of [0x00, 0x04, 0x41, 0x7f, 0x80, 0xc3, 0xff]) {
    const key = randomKey(), pub = secp256k1.getPublicKey(key, true);
    const tx = new Transaction({ ...SCURE_OPTS, version: 2 });
    const amount = 50_000n;
    tx.addInput({ txid: randomBytes(32), index: 0, witnessUtxo: { script: p2wpkh(pub), amount } });
    tx.addInput({ txid: randomBytes(32), index: 1, witnessUtxo: { script: p2wpkh(pub), amount } });
    tx.addOutput({ script: p2wpkh(pub), amount: 1000n });
    const scriptCode = cat([0x76, 0xa9, 0x14], hash160(pub), [0x88, 0xac]);
    const digest = tx.preimageWitnessV0(1, scriptCode, type, amount);
    const spend = { tx, idx: 1 };
    assert.deepEqual(invalidSigs(signedPsbt(spend, key, digest, type), 1).map((p) => p.message), [], `0x${type.toString(16)}`);
    // The byte is inside the digest: the normalized type's digest is another one.
    const normalized = (type & 0x80) | ([2, 3].includes(type & 0x1f) ? type & 0x1f : 1);
    if (normalized !== type) {
      const other = tx.preimageWitnessV0(1, scriptCode, normalized, amount);
      assert.equal(invalidSigs(signedPsbt(spend, key, other, type), 1).length, 1, `0x${type.toString(16)} signed as 0x${normalized.toString(16)}`);
    }
  }
});

// --- 4. tapscript: the OP_CODESEPARATOR position (BIP342) --------------------

const TAP_KEYS = [1, 2].map((n) => { const key = new Uint8Array(32); key[31] = n; return key; });
const tapCase = (leafFor, codeSeparator) => {
  const [internal, signer] = TAP_KEYS;
  const x = schnorr.getPublicKey(signer);
  const leaf = leafFor(x);
  const out = p2tr(schnorr.getPublicKey(internal), { script: leaf }, undefined, true);
  const amount = 70_000n;
  const tx = new Transaction({ ...SCURE_OPTS, version: 2 });
  tx.addInput({ txid: new Uint8Array(32).fill(7), index: 0, witnessUtxo: { script: out.script, amount }, tapLeafScript: out.tapLeafScript });
  tx.addOutput({ script: p2wpkh(secp256k1.getPublicKey(signer, true)), amount: 1000n });
  const digest = tx.preimageWitnessV1(0, [out.script], 0x00, [amount], codeSeparator, leaf, 0xc0);
  const signature = schnorr.sign(digest, signer, new Uint8Array(32));
  tx.updateInput(0, { tapScriptSig: [[{ pubKey: x, leafHash: tapLeafHash(leaf, 0xc0) }, signature]] }, true);
  return psbtInspectDoc(tx.toPSBT()).problems.filter((problem) => problem.scope === "input 0" && problem.code === "tap_sig_invalid");
};
const NONE_RAN = -1; // scure writes it as 0xffffffff

for (const [name, leafFor, valid, invalid] of [
  // opcode positions count every opcode, pushes included: [push, sep, ...]
  ["CODESEPARATOR <x> CHECKSIG", (x) => cat([0xab, 0x20], x, [0xac]), [0], [NONE_RAN, 1]],
  ["<x> CODESEPARATOR CHECKSIG", (x) => cat([0x20], x, [0xab, 0xac]), [1], [NONE_RAN, 0]],
  ["<x> CHECKSIG CODESEPARATOR", (x) => cat([0x20], x, [0xac, 0xab]), [NONE_RAN], [2]],
  ["IF CODESEPARATOR ENDIF <x> CHECKSIG", (x) => cat([0x63, 0xab, 0x68, 0x20], x, [0xac]), [1, NONE_RAN], [0, 2]],
  ["IF CODESEPARATOR ELSE CODESEPARATOR ENDIF <x> CHECKSIG", (x) => cat([0x63, 0xab, 0x67, 0xab, 0x68, 0x20], x, [0xac]), [1, 3], [NONE_RAN, 0]],
  ["CODESEPARATOR IF CODESEPARATOR ENDIF <x> CHECKSIG", (x) => cat([0xab, 0x63, 0xab, 0x68, 0x20], x, [0xac]), [0, 2], [NONE_RAN]],
]) {
  test(`tapscript ${name}: signs position ${valid.join(" or ")}, not ${invalid.join(" or ")}`, () => {
    for (const position of valid) assert.deepEqual(tapCase(leafFor, position).map((p) => p.message), [], `position ${position}`);
    for (const position of invalid) assert.equal(tapCase(leafFor, position).length, 1, `position ${position}`);
  });
}
