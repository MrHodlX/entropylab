// Deterministic vanity grind: salt + counter → same key. Never invents entropy.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { p2pkh, p2sh, p2wpkh, p2tr } from "@scure/btc-signer";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");
const template = readFileSync(join(root, "..", "src/index.html"), "utf8");
const gpuSrc = readFileSync(join(root, "..", "src/js/vanity-gpu.js"), "utf8");
const vanitySrc = readFileSync(join(root, "..", "src/js/vanity.js"), "utf8");

const {
  vanityFilterPrefix,
  vanityNeedle,
  vanityEstimate,
  vanityStartPriv,
  vanityPrivAt,
  vanityCandidate,
  vanityGrind,
  vanityGpuAvailable,
  vanityScriptOf,
  VANITY_BECH32,
  VANITY_BASE58,
  VANITY_ORDER,
} = await import(join(root, "..", "src/js/vanity.js"));

const {
  vanityGpuGrind,
} = await import(join(root, "..", "src/js/vanity-gpu.js"));
const bytesToBig = (bytes) => BigInt("0x" + Buffer.from(bytes).toString("hex"));

test("script type maps onto the four single-sig templates and never invents Taproot SLIP", () => {
  assert.equal(vanityScriptOf("bip44"), "p2pkh");
  assert.equal(vanityScriptOf("bip49"), "p2sh-p2wpkh");
  assert.equal(vanityScriptOf("bip84"), "p2wpkh");
  assert.equal(vanityScriptOf("bip86"), "p2tr");
});

test("prefix filter keeps charset and strips a typed HRP", () => {
  // bech32 has no 1, b, i, o — "hodl" keeps h/d/l only.
  assert.equal(vanityFilterPrefix("p2wpkh", "mainnet", "HODL!"), "hdl");
  assert.equal(vanityFilterPrefix("p2wpkh", "mainnet", "bc1qhodl"), "hdl");
  assert.equal(vanityNeedle("p2wpkh", "mainnet", "hodl"), "bc1qhdl");
  assert.equal(vanityNeedle("p2tr", "testnet", "aa"), "tb1paa");
  assert.equal(vanityNeedle("sp", "mainnet", "sat"), "sp1qsat");
  assert.equal(vanityNeedle("p2pkh", "mainnet", "Love"), "1Love");
  // base58 has no 0, O, I, l — lowercase L drops.
  assert.equal(vanityFilterPrefix("p2pkh", "mainnet", "hodl"), "hod");
  assert.equal(vanityEstimate("p2wpkh", "ab").charset, 32);
  assert.equal(vanityEstimate("p2pkh", "A").charset, 58);
  assert.equal(VANITY_BECH32.includes("o"), false);
  assert.equal(VANITY_BASE58.includes("o"), true);
  assert.equal(VANITY_BASE58.includes("l"), false);
});

test("priv_i is SHA-256(salt) + i mod n, matching an independent encoder", () => {
  const salt = "correct horse battery staple";
  const digest = createHash("sha256").update(salt, "utf8").digest();
  const start = bytesToBig(digest) % VANITY_ORDER;
  const ours = vanityStartPriv(salt);
  assert.equal(Buffer.from(ours).toString("hex"), start.toString(16).padStart(64, "0"));
  const plus3 = vanityPrivAt(ours, 3);
  const expect = (start + 3n) % VANITY_ORDER;
  assert.equal(Buffer.from(plus3).toString("hex"), expect.toString(16).padStart(64, "0"));
  const noblePub = secp256k1.getPublicKey(plus3, true);
  const cand = vanityCandidate(salt, 3, "p2wpkh", "mainnet");
  assert.equal(cand.address, p2wpkh(noblePub).address);
  assert.equal(cand.offset, 3);
});

test("the same salt and offset reproduce every script type against scure", () => {
  const salt = "entropylab-vanity-vector";
  const priv = vanityPrivAt(vanityStartPriv(salt), 7);
  const pub = secp256k1.getPublicKey(priv, true);
  assert.equal(vanityCandidate(salt, 7, "p2pkh", "mainnet").address, p2pkh(pub).address);
  assert.equal(vanityCandidate(salt, 7, "p2wpkh", "mainnet").address, p2wpkh(pub).address);
  assert.equal(vanityCandidate(salt, 7, "p2tr", "mainnet").address, p2tr(pub.slice(1)).address);
  const nested = p2sh(p2wpkh(pub)).address;
  assert.equal(vanityCandidate(salt, 7, "p2sh-p2wpkh", "mainnet").address, nested);
});

test("silent payment grind keeps the scan key fixed and changes only spend", async () => {
  const a = vanityCandidate("sp-salt", 0, "sp", "mainnet");
  const b = vanityCandidate("sp-salt", 1, "sp", "mainnet");
  assert.equal(Buffer.from(a.scanPriv).toString("hex"), Buffer.from(b.scanPriv).toString("hex"));
  assert.notEqual(Buffer.from(a.spendPriv).toString("hex"), Buffer.from(b.spendPriv).toString("hex"));
  assert.match(a.address, /^sp1q/);
  assert.notEqual(a.address, b.address);
  const hits = await vanityGrind({ salt: "sp-salt", prefix: a.address.slice(4, 6), kind: "sp", network: "mainnet", start: 0, count: 8, gpu: false });
  assert.ok(hits.length >= 1);
  assert.equal(hits[0].address.slice(0, 6), a.address.slice(0, 6));
});

test("CPU grind finds a 1-character bech32 prefix without inventing entropy", async () => {
  const hits = await vanityGrind({ salt: "unit-test-salt", prefix: "q", kind: "p2wpkh", network: "mainnet", start: 0, count: 64, gpu: false });
  assert.ok(hits.length >= 1, "expected at least one bc1q q-prefix in 64 tries");
  assert.match(hits[0].address, /^bc1q/);
  const replay = vanityCandidate("unit-test-salt", hits[0].offset, "p2wpkh", "mainnet");
  assert.equal(replay.address, hits[0].address);
});

test("empty prefix is rejected and GPU is reported unavailable under Node", async () => {
  await assert.rejects(() => vanityGrind({ salt: "x", prefix: "", kind: "p2wpkh", network: "mainnet", start: 0, count: 1 }), /prefix/);
  assert.equal(vanityGpuAvailable(), false);
  assert.equal(await vanityGpuGrind({ salt: "x", kind: "p2wpkh", network: "mainnet", start: 0, count: 4, needle: "bc1q" }), null);
  assert.match(gpuSrc, /vanityGpuAvailable/);
  assert.match(gpuSrc, /self-test/);
  assert.match(gpuSrc, /write_pubs/);
  assert.doesNotMatch(vanitySrc, /Math\.random\s*\(/);
  assert.doesNotMatch(vanitySrc, /getRandomValues\s*\(/);
  assert.doesNotMatch(gpuSrc, /Math\.random\s*\(/);
  assert.doesNotMatch(gpuSrc, /getRandomValues\s*\(/);
  assert.match(vanitySrc, /Calculator, not a generator/);
});

test("both page templates ship collapsed grinders that do not auto-run", () => {
  for (const markup of [template, app]) {
    assert.match(markup, /<details class="vanity-grind no-print" id="vanity-details">/);
    assert.match(markup, /<summary>Vanity address grinder<\/summary>/);
    assert.match(markup, /<details class="vanity-grind no-print" id="vanity-sp-details">/);
    assert.match(markup, /<summary>Vanity silent payment address<\/summary>/);
    assert.match(markup, /Idle\. Press Start grind\. Nothing runs by itself\./);
    assert.match(markup, /id="vanity-go"/);
    assert.match(markup, /id="vanity-sp-go"/);
  }
  assert.match(app, /function hodlInitVanity\(/);
  assert.match(app, /hodlVanityStop\(\)/);
  assert.doesNotMatch(app, /vanityGrind\([^)]+\)\s*;/);
});
