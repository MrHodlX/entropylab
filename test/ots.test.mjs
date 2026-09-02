// OpenTimestamps calculator: official detached proofs, no network, no LGPL.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import {
  HEADER_BYTES,
  equalBytes,
  hashSha256,
  inspectProof,
  parseChainInput,
  parseProof,
  proofMatchesBytes,
  reverseBytes,
  summarizeInspect,
  verifyBitcoinAttestation
} from "../src/js/ots.js";
import { hex as hexCoder } from "../src/js/coders.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const fixtures = join(root, "test/fixtures/ots");
const read = (name) => readFileSync(join(fixtures, name));
const readSource = () => readFileSync(join(root, "src/js/ots.js"), "utf8");

const HELLO_DIGEST = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340";
const HELLO_INTERNAL_MERKLE = "007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a";
const HELLO_DISPLAY_MERKLE = "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00";
const HELLO_HEIGHT = 358391;

function headerWithMerkle(merkleHex, nTime = 1432826116) {
  const header = new Uint8Array(HEADER_BYTES);
  header.set(hexCoder.decode(merkleHex), 36);
  header[68] = nTime & 0xff;
  header[69] = (nTime >>> 8) & 0xff;
  header[70] = (nTime >>> 16) & 0xff;
  header[71] = (nTime >>> 24) & 0xff;
  return header;
}

test("source-guard: ots.js never phones home or invents entropy", () => {
  const raw = readSource();
  const source = raw.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
  assert.doesNotMatch(source, /\bfetch\s*\(/);
  assert.doesNotMatch(source, /\bWebSocket\b/);
  assert.doesNotMatch(source, /\blocalStorage\b/);
  assert.doesNotMatch(source, /\bIndexedDB\b/);
  assert.doesNotMatch(source, /\bMath\.random\b/);
  assert.doesNotMatch(source, /\bgetRandomValues\b/);
  assert.match(raw, /javascript-opentimestamps \(LGPL-3\.0\)/);
  assert.match(raw, /header is user-supplied/);
});

test("SHA-256 of Hello World! matches the published OTS file hash", () => {
  const file = read("hello-world.txt");
  assert.equal(file.toString("utf8"), "Hello World!\n");
  assert.equal(hexCoder.encode(hashSha256(file)), HELLO_DIGEST);
  assert.equal(hexCoder.encode(hashSha256(file)), createHash("sha256").update(file).digest("hex"));
});

test("hello-world.txt.ots walks to Bitcoin block 358391", () => {
  const proof = parseProof(read("hello-world.txt.ots"));
  assert.equal(proof.fileHashHex, HELLO_DIGEST);
  assert.equal(proof.attestations.length, 1);
  const [attestation] = proof.attestations;
  assert.equal(attestation.type, "bitcoin");
  assert.equal(attestation.height, HELLO_HEIGHT);
  assert.equal(attestation.digestHex, HELLO_INTERNAL_MERKLE);
  assert.equal(hexCoder.encode(reverseBytes(attestation.digest)), HELLO_DISPLAY_MERKLE);
  assert.equal(proofMatchesBytes(proof, read("hello-world.txt")), true);
  assert.equal(proofMatchesBytes(proof, new TextEncoder().encode("nope")), false);
});

test("incomplete.txt.ots is pending, never a pass", () => {
  const proof = parseProof(read("incomplete.txt.ots"));
  const result = inspectProof(proof, { bytes: read("incomplete.txt") });
  assert.equal(result.status, "pending");
  assert.deepEqual(result.pending, ["https://alice.btc.calendar.opentimestamps.org"]);
  assert.equal(result.bitcoin.length, 0);
  assert.match(summarizeInspect(result), /Incomplete/);
  assert.doesNotMatch(summarizeInspect(result), /attests/);
});

test("wrong original file is a hard fail even with a matching header", () => {
  const proof = parseProof(read("hello-world.txt.ots"));
  const chain = parseChainInput(hexCoder.encode(headerWithMerkle(HELLO_INTERNAL_MERKLE)));
  const result = inspectProof(proof, { bytes: new TextEncoder().encode("Hello World?"), chain });
  assert.equal(result.status, "wrong-file");
});

test("pasted 80-byte header verifies; a lying merkle root does not", () => {
  const proof = parseProof(read("hello-world.txt.ots"));
  const good = parseChainInput(hexCoder.encode(headerWithMerkle(HELLO_INTERNAL_MERKLE)));
  const ok = inspectProof(proof, { bytes: read("hello-world.txt"), chain: good });
  assert.equal(ok.status, "verified");
  assert.equal(ok.bitcoin[0].height, HELLO_HEIGHT);
  assert.equal(ok.bitcoin[0].nTime, 1432826116);
  assert.equal(ok.bitcoin[0].time, new Date(1432826116 * 1000).toISOString().replace(".000Z", "Z"));
  assert.match(summarizeInspect(ok), /block 358391/);

  const bad = parseChainInput(hexCoder.encode(headerWithMerkle("11".repeat(32))));
  const mismatch = inspectProof(proof, { bytes: read("hello-world.txt"), chain: bad });
  assert.equal(mismatch.status, "mismatch");
});

test("32-byte merkle root accepts bitcoin-cli display order", () => {
  const proof = parseProof(read("hello-world.txt.ots"));
  const display = parseChainInput(HELLO_DISPLAY_MERKLE);
  const result = inspectProof(proof, { chain: display });
  assert.equal(result.status, "verified");
  assert.equal(result.bitcoin[0].merkleOrder, "display");
  assert.equal(result.bitcoin[0].nTime, null);
});

test("no header is unverified, not a green check", () => {
  const proof = parseProof(read("hello-world.txt.ots"));
  const result = inspectProof(proof, { bytes: read("hello-world.txt") });
  assert.equal(result.status, "unverified");
  assert.equal(result.bitcoin[0].status, "unverified");
  assert.match(summarizeInspect(result), /Paste the header/);
});

test("verifyBitcoinAttestation refuses a missing header", () => {
  const none = verifyBitcoinAttestation({ type: "bitcoin", height: 1, digestHex: "00" }, null);
  assert.equal(none.status, "unverified");
  assert.equal(none.reason, "no-header");
});

test("header parser rejects the wrong length", () => {
  assert.throws(() => parseChainInput("00"), /80-byte/);
  assert.ok(equalBytes(parseChainInput(HELLO_INTERNAL_MERKLE).merkle, hexCoder.decode(HELLO_INTERNAL_MERKLE)));
});
