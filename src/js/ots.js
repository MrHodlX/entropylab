// OpenTimestamps calculator for EntropyLab.
//
// Reimplementation of Peter Todd's detached-proof format (magic, version,
// commitment ops, Bitcoin / pending attestations). Public domain, like the
// rest of this page. Do not vendor javascript-opentimestamps (LGPL-3.0).
//
// This is a calculator, not a calendar client:
//   - Hash bytes with SHA-256 so the user can stamp them elsewhere.
//   - Parse a complete .ots, replay sha256 / ripemd160 / prepend / append,
//     and compare the Bitcoin attestation digest to a header the *user*
//     pasted from their node.
//   - Incomplete (pending calendar) proofs stay incomplete. No fetch, no
//     upgrade, no explorer, no bitcoind RPC.
//
// Todd's format does not embed the block header. Recording it would invite
// implementations to accept the proof's own header instead of an independent
// lookup. EntropyLab keeps that invariant: the header is user-supplied.
//
// Hashes go through hashes.js (bitcoin_hashes WASM). No second SHA-256 stack.

import { ripemd160, sha256 } from "./hashes.js";
import { hex as hexCoder } from "./coders.js";

export const OTS_VERSION = 1;
export const OTS_MAGIC = hexCoder.decode("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294");
export const OTS_INFO = "entropylab-ots-v1";
export const MAX_MSG_LENGTH = 4096;
export const MAX_RESULT_LENGTH = 4096;
export const RECURSION_LIMIT = 256;
export const HEADER_BYTES = 80;
export const MERKLE_BYTES = 32;

export const OP = Object.freeze({
  SHA1: 0x02,
  RIPEMD160: 0x03,
  SHA256: 0x08,
  KECCAK256: 0x67,
  APPEND: 0xf0,
  PREPEND: 0xf1,
  REVERSE: 0xf2,
  HEXLIFY: 0xf3
});

export const OP_NAME = Object.freeze({
  [OP.SHA1]: "sha1",
  [OP.RIPEMD160]: "ripemd160",
  [OP.SHA256]: "sha256",
  [OP.KECCAK256]: "keccak256",
  [OP.APPEND]: "append",
  [OP.PREPEND]: "prepend",
  [OP.REVERSE]: "reverse",
  [OP.HEXLIFY]: "hexlify"
});

export const ATTESTATION = Object.freeze({
  PENDING: hexCoder.decode("83dfe30d2ef90c8e"),
  BITCOIN: hexCoder.decode("0588960d73d71901"),
  LITECOIN: hexCoder.decode("06869a0d73d71b45")
});

export function wipeBytes(bytes) {
  if (bytes && bytes.fill) bytes.fill(0);
  return bytes;
}

export function equalBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function reverseBytes(bytes) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[bytes.length - 1 - i];
  return out;
}

export function concatBytes(...chunks) {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function parseHexBytes(text) {
  if (typeof text !== "string") throw new Error("Expected hex text.");
  const compact = text.replace(/\s+/g, "").replace(/^0x/i, "");
  if (!compact) throw new Error("Empty hex.");
  return hexCoder.decode(compact);
}

export function hashSha256(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error("SHA-256 input must be bytes.");
  return sha256(bytes);
}

class Reader {
  constructor(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error("OpenTimestamps proof must be bytes.");
    this.bytes = bytes;
    this.i = 0;
  }
  get left() {
    return this.bytes.length - this.i;
  }
  take(n) {
    if (!Number.isSafeInteger(n) || n < 0 || this.i + n > this.bytes.length) {
      throw new Error("Truncated OpenTimestamps proof.");
    }
    const slice = this.bytes.subarray(this.i, this.i + n);
    this.i += n;
    return slice;
  }
  u8() {
    return this.take(1)[0];
  }
  // Unsigned little-endian base128, as in python-opentimestamps serialize.py.
  varuint() {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (shift > 63) throw new Error("OpenTimestamps varuint is too large.");
      const b = this.u8();
      value += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return value;
      shift += 7;
    }
  }
  varbytes(max = MAX_RESULT_LENGTH) {
    const n = this.varuint();
    if (n > max) throw new Error("OpenTimestamps field exceeds the 4096-byte op limit.");
    return this.take(n);
  }
}

function tagEquals(a, b) {
  return equalBytes(a, b);
}

function applyOp(tag, arg, msg) {
  if (msg.length > MAX_MSG_LENGTH) throw new Error("OpenTimestamps message exceeds the 4096-byte op limit.");
  let out;
  if (tag === OP.SHA256) out = sha256(msg);
  else if (tag === OP.RIPEMD160) out = ripemd160(msg);
  else if (tag === OP.APPEND) out = concatBytes(msg, arg);
  else if (tag === OP.PREPEND) out = concatBytes(arg, msg);
  else if (tag === OP.SHA1 || tag === OP.KECCAK256 || tag === OP.REVERSE || tag === OP.HEXLIFY) {
    throw new Error(`OpenTimestamps op ${OP_NAME[tag]} is not supported in this calculator.`);
  } else {
    throw new Error(`Unknown OpenTimestamps op 0x${tag.toString(16)}.`);
  }
  if (!out.length || out.length > MAX_RESULT_LENGTH) throw new Error("OpenTimestamps op produced an empty or oversized result.");
  return out;
}

function parseAttestation(reader, msg) {
  const tag = reader.take(8);
  const payload = reader.varbytes(8192);
  const inner = new Reader(payload);
  if (tagEquals(tag, ATTESTATION.BITCOIN)) {
    const height = inner.varuint();
    if (msg.length !== MERKLE_BYTES) throw new Error("Bitcoin attestation digest is not 32 bytes.");
    return {
      type: "bitcoin",
      height,
      digest: new Uint8Array(msg),
      digestHex: hexCoder.encode(msg)
    };
  }
  if (tagEquals(tag, ATTESTATION.PENDING)) {
    const uriBytes = inner.varbytes(1000);
    return { type: "pending", uri: new TextDecoder().decode(uriBytes) };
  }
  if (tagEquals(tag, ATTESTATION.LITECOIN)) {
    return { type: "unsupported", chain: "litecoin", height: inner.varuint() };
  }
  return { type: "unknown", tag: hexCoder.encode(tag) };
}

function parseTimestamp(reader, msg, depth) {
  if (depth <= 0) throw new Error("OpenTimestamps proof exceeded the recursion limit.");
  const attestations = [];
  const steps = [];
  const one = (tag) => {
    if (tag === 0x00) {
      attestations.push(parseAttestation(reader, msg));
      return;
    }
    const name = OP_NAME[tag];
    const arg = tag === OP.APPEND || tag === OP.PREPEND ? new Uint8Array(reader.varbytes()) : null;
    const next = applyOp(tag, arg, msg);
    steps.push({ op: name || `0x${tag.toString(16)}`, argHex: arg ? hexCoder.encode(arg) : "" });
    const child = parseTimestamp(reader, next, depth - 1);
    attestations.push(...child.attestations);
    steps.push(...child.steps);
  };
  let tag = reader.u8();
  while (tag === 0xff) {
    one(reader.u8());
    tag = reader.u8();
  }
  one(tag);
  return { attestations, steps };
}

export function parseProof(bytes) {
  const reader = new Reader(bytes);
  const magic = reader.take(OTS_MAGIC.length);
  if (!equalBytes(magic, OTS_MAGIC)) throw new Error("Not an OpenTimestamps detached proof (bad magic).");
  const version = reader.u8();
  if (version !== OTS_VERSION) throw new Error(`Unsupported OpenTimestamps version ${version}.`);
  const fileHashOp = reader.u8();
  if (fileHashOp !== OP.SHA256) throw new Error("This calculator only opens SHA-256 detached proofs.");
  const fileHash = new Uint8Array(reader.take(32));
  const tree = parseTimestamp(reader, fileHash, RECURSION_LIMIT);
  if (reader.left !== 0) throw new Error("OpenTimestamps proof has trailing bytes.");
  return {
    version,
    fileHashOp: "sha256",
    fileHash,
    fileHashHex: hexCoder.encode(fileHash),
    attestations: tree.attestations,
    steps: tree.steps
  };
}

export function digestFile(bytes, fileHashOp = "sha256") {
  if (fileHashOp !== "sha256") throw new Error("This calculator only hashes with SHA-256.");
  return sha256(bytes);
}

export function proofMatchesBytes(proof, bytes) {
  return equalBytes(proof.fileHash, digestFile(bytes, proof.fileHashOp));
}

export function parseChainInput(text) {
  const bytes = parseHexBytes(text);
  if (bytes.length === HEADER_BYTES) {
    return {
      kind: "header",
      header: bytes,
      merkle: bytes.subarray(36, 68),
      nTime: bytes[68] + bytes[69] * 256 + bytes[70] * 65536 + bytes[71] * 16777216
    };
  }
  if (bytes.length === MERKLE_BYTES) {
    return { kind: "merkle", merkle: bytes, nTime: null };
  }
  throw new Error("Paste an 80-byte Bitcoin header or a 32-byte merkle root, as hex.");
}

function formatUnixTime(nTime) {
  if (!Number.isFinite(nTime) || nTime < 0) return null;
  return new Date(nTime * 1000).toISOString().replace(".000Z", "Z");
}

export function verifyBitcoinAttestation(attestation, chain) {
  if (!attestation || attestation.type !== "bitcoin") {
    return { status: "unverified", reason: "no-bitcoin" };
  }
  if (!chain) {
    return {
      status: "unverified",
      reason: "no-header",
      height: attestation.height,
      digestHex: attestation.digestHex
    };
  }
  const internal = equalBytes(attestation.digest, chain.merkle);
  const display = chain.kind === "merkle" && equalBytes(attestation.digest, reverseBytes(chain.merkle));
  if (!internal && !display) {
    return {
      status: "mismatch",
      height: attestation.height,
      digestHex: attestation.digestHex,
      merkleHex: hexCoder.encode(chain.merkle),
      nTime: chain.nTime,
      time: formatUnixTime(chain.nTime)
    };
  }
  return {
    status: "verified",
    height: attestation.height,
    digestHex: attestation.digestHex,
    merkleOrder: internal ? "internal" : "display",
    nTime: chain.nTime,
    time: formatUnixTime(chain.nTime)
  };
}

export function inspectProof(proof, options = {}) {
  const bitcoin = proof.attestations.filter((item) => item.type === "bitcoin");
  const pending = proof.attestations.filter((item) => item.type === "pending");
  const other = proof.attestations.filter((item) => item.type !== "bitcoin" && item.type !== "pending");
  let bytesMatch = null;
  if (options.bytes) bytesMatch = proofMatchesBytes(proof, options.bytes);
  const chain = options.chain || null;
  const bitcoinResults = bitcoin.map((item) => verifyBitcoinAttestation(item, chain));
  const verified = bitcoinResults.filter((item) => item.status === "verified");
  const mismatched = bitcoinResults.filter((item) => item.status === "mismatch");
  let status = "unverified";
  if (bytesMatch === false) status = "wrong-file";
  else if (verified.length) status = "verified";
  else if (mismatched.length) status = "mismatch";
  else if (pending.length && !bitcoin.length) status = "pending";
  return {
    status,
    fileHashHex: proof.fileHashHex,
    bytesMatch,
    bitcoin: bitcoinResults,
    pending: pending.map((item) => item.uri),
    other,
    steps: proof.steps.length
  };
}

export function summarizeInspect(result) {
  if (result.status === "wrong-file") {
    return "The supplied bytes do not match the SHA-256 the proof commits to.";
  }
  if (result.status === "pending") {
    const uri = result.pending[0] || "a calendar";
    return `Incomplete. Pending at ${uri}. Stamp or upgrade on a networked machine; this page will not fetch it.`;
  }
  if (result.status === "verified") {
    const hit = result.bitcoin.find((item) => item.status === "verified");
    const when = hit.time ? ` as of ${hit.time}` : "";
    const timeNote = hit.nTime == null ? " (merkle root only — paste the 80-byte header for nTime)" : "";
    return `Bitcoin attests this existed before block ${hit.height}${when}${timeNote}.`;
  }
  if (result.status === "mismatch") {
    const hit = result.bitcoin.find((item) => item.status === "mismatch");
    return `The pasted header's merkle root does not match the proof's digest for block ${hit.height}. A lying header makes a lying timestamp.`;
  }
  if (result.bitcoin.length) {
    const hit = result.bitcoin[0];
    return `Bitcoin attestation at height ${hit.height}. Paste the header (or merkle root) from your node to finish verification. Pending is not a pass.`;
  }
  return "No Bitcoin attestation in this proof.";
}
