// #535: the scriptCode separator analysis (psbt-wasm/src/scriptcode.rs,
// code_starts) is quadratic and unbudgeted — a crafted PSBT freezes the
// inspector's main thread. The 256-check budget counts signature
// verifications, not this analysis, which runs first (verify.rs:266).
//
// Behavior-only on purpose: each case must make psbtInspectDoc RETURN inside
// a deadline — a verdict, a deliberate refusal, or verification_incomplete
// all pass; only a hang or a trap fails. A wasm infinite loop cannot be
// interrupted by node:test's timeout, so every run happens in a worker with
// its own deadline, like the #525 crafted-inputs test. Deliberate refusals
// (e.g. "too large to inspect safely") come back as ordinary errors and
// pass; a WebAssembly.RuntimeError (a real trap) fails.
//
// Two requirements, not one: the deadline alone would pass a fix that only
// shaves the constant, so the scaling check compares the same shape at two
// sizes — quadratic shows as a ratio near 4, anything sub-quadratic near 1.
//
// The control case proves the harness measures time correctly: it must
// return fast.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Worker } from "node:worker_threads";
import { Transaction } from "@scure/btc-signer";
import { p2tr, tapLeafHash } from "@scure/btc-signer/payment.js";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";

const unhex = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const le32 = (n) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];
const compactSize = (n) => (n < 0xfd ? [n] : n <= 0xffff ? [0xfd, n & 255, (n >>> 8) & 255] : [0xfe, ...le32(n)]);
const kv = (key, value) => [key.length, ...key, ...compactSize(value.length), ...value];

const OP_IF = 0x63, OP_ENDIF = 0x68, OP_CODESEPARATOR = 0xab, OP_CHECKSIG = 0xac;
const SCURE_OPTS = { allowUnknownOutputs: true, allowUnknownInputs: true, allowUnknownVersion: true, disableScriptCheck: true };

// A signature that parses, on a key that exists: a fix that only reorders
// the cheap checks (DER, key parse) above the analysis must not turn this
// suite green — the analysis itself has to get fast.
const VALID_PUBKEY = secp256k1.getPublicKey(new Uint8Array([...new Uint8Array(31), 1]), true);
const STRICT_DER_SIG = unhex("300602010102010101"); // 8-byte strict-DER (r=1, s=1) + SIGHASH_ALL

const separatorsInARow = (count) => {
  const script = new Uint8Array(count + 1);
  script.fill(OP_CODESEPARATOR, 0, count);
  script[count] = OP_CHECKSIG;
  return script;
};
const nestedIfSeparator = (depth) => {
  const script = new Uint8Array(depth * 2 + depth + 1);
  let i = 0;
  for (let n = 0; n < depth; n++) { script[i++] = OP_IF; script[i++] = OP_CODESEPARATOR; }
  script[i++] = OP_CHECKSIG;
  for (let n = 0; n < depth; n++) script[i++] = OP_ENDIF;
  return script;
};

// Minimal raw-transaction builder: version 2, one dummy input, the given
// [sats, scriptBytes] outputs, locktime 0. Script lengths are compactSize —
// a multi-MB attack script does not fit in one length byte. Returns
// { hex, txid } with the txid in display order.
const prevTx = (...outputs) => {
  const le64 = (value) => {
    let n = BigInt(value);
    const bytes = [];
    for (let i = 0; i < 8; i++) { bytes.push(Number(n & 255n)); n >>= 8n; }
    return bytes;
  };
  const bytes = new Uint8Array([
    ...le32(2), 1, ...new Uint8Array(32), ...le32(0xffffffff), 0, ...le32(0xffffffff),
    outputs.length,
    ...outputs.flatMap(([value, script]) => [...le64(value), ...compactSize(script.length), ...script]),
    ...le32(0),
  ]);
  const hash = createHash("sha256").update(createHash("sha256").update(bytes).digest()).digest();
  return { hex: Buffer.from(bytes).toString("hex"), txid: Buffer.from(hash).reverse().toString("hex") };
};

// One input spending a bare legacy output carrying the attack script, with
// `sigs` partial signatures (the analysis reruns per signature today).
const hostileLegacyPsbt = (script, sigs = 1) => {
  const prev = prevTx([1000, script]);
  const unsigned = new Uint8Array([
    ...le32(2), 1, ...unhex(prev.txid).reverse(), ...le32(0), 0, ...le32(0xffffffff),
    1, ...[244, 1, 0, 0, 0, 0, 0, 0], 1, 0x51,
    ...le32(0),
  ]);
  const sigEntries = Array.from({ length: sigs }, (_, i) => {
    const pub = i === 0 ? VALID_PUBKEY : secp256k1.getPublicKey(new Uint8Array([...new Uint8Array(31), i + 1]), true);
    return kv([0x02, ...pub], STRICT_DER_SIG);
  });
  return new Uint8Array([
    ...unhex("70736274ff"),
    ...kv([0x00], unsigned), 0x00,
    ...kv([0x00], unhex(prev.hex)),
    ...sigEntries.flat(), 0x00,
    0x00,
  ]);
};

// The same shape as a P2WSH witnessScript, the form the issue first
// reported: code_starts also walks witness scripts (SigVersion::WitnessV0).
const hostileP2wshPsbt = (witnessScript) => {
  const spk = new Uint8Array([0x00, 0x20, ...createHash("sha256").update(witnessScript).digest()]);
  const tx = new Transaction({ ...SCURE_OPTS, version: 2 });
  tx.addInput({ txid: new Uint8Array(32), index: 0, sequence: 0xffffffff, witnessUtxo: { script: spk, amount: 1000n }, witnessScript });
  tx.addOutput({ script: new Uint8Array([0x51]), amount: 500n });
  const psbt = Transaction.fromPSBT(tx.toPSBT(), SCURE_OPTS);
  psbt.updateInput(0, { partialSig: [[VALID_PUBKEY, STRICT_DER_SIG]] });
  return psbt.toPSBT();
};

// A taproot script-path input whose leaf is the attack script: the tapscript
// path (verify.rs:385) has no 10,000-byte or 201-opcode limit to bail on.
const tapscriptLeafPsbt = (leaf) => {
  const internalKey = schnorr.getPublicKey(new Uint8Array([...new Uint8Array(31), 1]));
  const payment = p2tr(internalKey, [{ script: leaf, version: 0xc0 }], undefined, true);
  const signerKey = new Uint8Array([...new Uint8Array(31), 7]);
  const xonly = schnorr.getPublicKey(signerKey);
  const tx = new Transaction({ ...SCURE_OPTS, version: 2 });
  tx.addInput({ txid: new Uint8Array(32), index: 0, sequence: 0xffffffff, witnessUtxo: { script: payment.script, amount: 1000n } });
  tx.addOutput({ script: new Uint8Array([0x51]), amount: 500n });
  const psbt = Transaction.fromPSBT(tx.toPSBT(), SCURE_OPTS);
  psbt.updateInput(0, {
    tapLeafScript: payment.tapLeafScript,
    tapScriptSig: [[{ pubKey: xonly, leafHash: tapLeafHash(leaf, 0xc0) }, new Uint8Array(64).fill(1)]],
  });
  return psbt.toPSBT();
};

const DEADLINE_MS = 20000;
const inspectInWorker = (psbt, timeoutMs = DEADLINE_MS) =>
  new Promise((resolve, reject) => {
    const worker = new Worker(
      `const { parentPort, workerData } = require("node:worker_threads");
       import(workerData.moduleUrl).then((m) => {
         const t0 = Date.now();
         const doc = m.psbtInspectDoc(new Uint8Array(workerData.psbt));
         parentPort.postMessage({ problems: doc.problems.map((p) => ({ code: p.code, message: p.message })), ms: Date.now() - t0 });
       }).catch((error) => parentPort.postMessage({ errorName: error?.name || "Error", errorMessage: String(error?.message || error) }));`,
      { eval: true, workerData: { moduleUrl: new URL("../src/js/psbt-wasm.js", import.meta.url).href, psbt } }
    );
    const deadline = setTimeout(() => {
      worker.terminate();
      reject(new Error(`psbtInspectDoc did not return within ${timeoutMs}ms (module hung, #535)`));
    }, timeoutMs);
    worker.once("message", (msg) => { clearTimeout(deadline); worker.terminate(); resolve(msg); });
    worker.once("error", (error) => { clearTimeout(deadline); worker.terminate(); reject(error); });
  });

// A pass means real evidence: a signature-reached verdict (any sig problem,
// verification_incomplete, or verification_budget), or the one deliberate
// refusal we know — the size guard. A trap fails, and so does any other
// throw: a parse error on a malformed builder is how a vacuous green reads.
const outcome = async (psbt) => {
  const result = await inspectInWorker(psbt);
  assert.notEqual(result.errorName, "RuntimeError", `the module trapped: ${result.errorMessage}`);
  if (result.errorMessage) {
    assert.match(result.errorMessage, /too large to inspect safely/, `unexpected throw (not a known refusal): ${result.errorMessage}`);
    return result;
  }
  assert.ok(result.problems?.some((p) => /sig|verification_incomplete|verification_budget/.test(p.code) || /^cannot be valid/.test(p.message)),
    `the input's signature was never reached: ${JSON.stringify(result.problems)}`);
  return result;
};

// BIP66 shape check, matching Core's IsValidSignatureEncoding for the DER
// prefix: sig[0] is 0x30 and sig[1] covers the rest minus the sighash byte.
const isStrictDer = (sig) => sig.length >= 9 && sig[0] === 0x30 && sig[1] === sig.length - 3;

test("a small separator script answers immediately (control)", async () => {
  const script = new Uint8Array([0x51, OP_CODESEPARATOR, 0x52, OP_CHECKSIG]);
  const result = await outcome(hostileLegacyPsbt(script));
  assert.ok(result.problems.some((p) => /sig/.test(p.code)), `the input's signature was checked, got [${result.problems.map((p) => p.code)}]`);
  assert.ok(result.ms < 2000, `the control took ${result.ms}ms — the harness is not measuring time correctly`);
});

// Every hostile builder must produce a PSBT that parses back, and the
// shared signature must be strict-DER. This is what catches builder bugs —
// a malformed test PSBT reads as a fast pass at the deadline otherwise.
test("the hostile builders produce parseable PSBTs with a strict-DER signature", () => {
  assert.ok(isStrictDer(STRICT_DER_SIG), "the shared signature is not BIP66-strict DER");
  for (const [name, psbt] of [
    ["bare legacy", hostileLegacyPsbt(nestedIfSeparator(4))],
    ["bare legacy, two signatures", hostileLegacyPsbt(nestedIfSeparator(4), 2)],
    ["P2WSH witnessScript", hostileP2wshPsbt(nestedIfSeparator(4))],
    ["tapscript leaf", tapscriptLeafPsbt(nestedIfSeparator(4))],
  ]) {
    const parsed = Transaction.fromPSBT(psbt, SCURE_OPTS);
    assert.ok(parsed.inputs.length > 0, `${name}: the PSBT did not parse back`);
  }
});

for (const [name, psbt] of [
  ["2.56M separators in a row, bare legacy (2.56 MB)", () => hostileLegacyPsbt(separatorsInARow(2_560_000))],
  ["80k nested IF+separator, bare legacy (240 KB)", () => hostileLegacyPsbt(nestedIfSeparator(80_000))],
  ["120k nested IF+separator, bare legacy (360 KB)", () => hostileLegacyPsbt(nestedIfSeparator(120_000))],
  ["80k separators in a row, P2WSH witnessScript (80 KB)", () => hostileP2wshPsbt(separatorsInARow(80_000))],
  ["80k nested IF+separator with two partial signatures", () => hostileLegacyPsbt(nestedIfSeparator(80_000), 2)],
  ["40k nested IF+separator in a tapscript leaf (120 KB)", () => tapscriptLeafPsbt(nestedIfSeparator(40_000))],
  ["80k nested IF+separator in a tapscript leaf (240 KB)", () => tapscriptLeafPsbt(nestedIfSeparator(80_000))],
]) {
  test(`scriptCode analysis returns inside the deadline: ${name} (#535)`, async () => {
    const result = await outcome(psbt());
    assert.ok(result, `expected psbtInspectDoc to return, got ${JSON.stringify(result)}`);
  });
}

// The deadline alone passes a fix that only shaves the constant. The same
// shape at 2x size must not cost ~4x: a sub-quadratic answer lands near 1.
test("the tapscript path scales sub-quadratically (#535)", async () => {
  const small = await outcome(tapscriptLeafPsbt(nestedIfSeparator(40_000)));
  const large = await outcome(tapscriptLeafPsbt(nestedIfSeparator(80_000)));
  assert.ok(small.ms > 0 && large.ms > 0);
  const ratio = large.ms / small.ms;
  assert.ok(ratio < 3, `40k → ${small.ms}ms, 80k → ${large.ms}ms (ratio ${ratio.toFixed(1)}): still quadratic`);
});
