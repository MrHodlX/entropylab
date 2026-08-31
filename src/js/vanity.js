// Deterministic vanity address grinder.
//
// Calculator, not a generator. Counter i maps to
//   priv_i = (SHA-256(utf8(salt)) + i) mod n
// Same salt and counter always reproduce the same key. Key material is never
// drawn from a PRNG or a CSPRNG.
//
// Regular addresses follow the Key Derivation script type. Silent Payments
// keep one scan key per salt (SHA-256(salt || 0x00)) and grind the spend
// key (SHA-256(salt || 0x01) + i), so the reusable scan key stays put.
//
// GPU is optional: WebGPU runs the same offsets after a CPU self-test. If
// the adapter is missing or the self-test fails, the CPU incremental
// P + i·G loop is used. Nothing here is stored; salts live in page RAM.

import { sha256, hash160 } from "./hashes.js";
import { secp256k1 } from "./secp256k1.js";
import { addressFor } from "./addresses.js";
import { encodeSilentPaymentAddress } from "./bip352.js";
import { encodeWifCompressed } from "./bip85.js";
import { vanityGpuAvailable, vanityGpuGrind } from "./vanity-gpu.js";

export const VANITY_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const VANITY_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
export const VANITY_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export const VANITY_BATCH = 2048;
export const VANITY_DEFAULT_COUNT = 250000;

const textEncoder = new TextEncoder();

const hexToBytes = (hex) => {
  if (typeof hex !== "string" || hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new Error("Invalid hexadecimal input.");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const bytesToBig = (bytes) => BigInt("0x" + bytesToHex(bytes));
const bigToBytes32 = (value) => {
  const hex = value.toString(16).padStart(64, "0");
  if (hex.length > 64) throw new Error("Scalar does not fit in 32 bytes.");
  return hexToBytes(hex);
};

export const vanityScriptOf = (accountId) => {
  if (accountId === "bip44") return "p2pkh";
  if (accountId === "bip49") return "p2sh-p2wpkh";
  if (accountId === "bip86") return "p2tr";
  return "p2wpkh";
};

export const vanityKindCharset = (kind) => {
  if (kind === "p2pkh" || kind === "p2sh-p2wpkh") return VANITY_BASE58;
  return VANITY_BECH32;
};

export const vanityHrpPrefix = (kind, network) => {
  if (kind === "p2pkh") return network === "testnet" ? "m" : "1";
  if (kind === "p2sh-p2wpkh") return network === "testnet" ? "2" : "3";
  if (kind === "p2tr") return network === "testnet" ? "tb1p" : "bc1p";
  if (kind === "sp") return network === "testnet" ? "tsp1q" : "sp1q";
  return network === "testnet" ? "tb1q" : "bc1q";
};

const stripKnownPrefix = (kind, network, raw) => {
  let text = String(raw ?? "");
  if (kind === "p2pkh" || kind === "p2sh-p2wpkh") return text;
  text = text.toLowerCase();
  const hrp = vanityHrpPrefix(kind, network);
  if (text.startsWith(hrp)) return text.slice(hrp.length);
  return text;
};

export function vanityFilterPrefix(kind, network, raw) {
  const charset = vanityKindCharset(kind);
  const body = stripKnownPrefix(kind, network, raw);
  let out = "";
  for (const ch of body) {
    if (kind === "p2pkh" || kind === "p2sh-p2wpkh") {
      if (charset.includes(ch)) out += ch;
    } else if (charset.includes(ch.toLowerCase())) out += ch.toLowerCase();
  }
  return out;
}

export function vanityNeedle(kind, network, prefix) {
  const filtered = vanityFilterPrefix(kind, network, prefix);
  if (!filtered) return "";
  const hrp = vanityHrpPrefix(kind, network);
  if (kind === "p2pkh" || kind === "p2sh-p2wpkh") {
    if (filtered.startsWith(hrp)) return filtered;
    return hrp + filtered;
  }
  return hrp + filtered;
}

export function vanityEstimate(kind, prefix) {
  const n = String(prefix ?? "").length;
  if (!n) return { charset: vanityKindCharset(kind).length, attempts: 1, bits: 0 };
  const charset = vanityKindCharset(kind).length;
  const attempts = charset ** n;
  return { charset, attempts, bits: n * Math.log2(charset) };
}

export function vanityStartPriv(salt) {
  const bytes = sha256(textEncoder.encode(String(salt ?? "")));
  const value = bytesToBig(bytes) % VANITY_ORDER;
  if (value === 0n) throw new Error("SHA-256(salt) is not a valid secp256k1 scalar. Change the salt.");
  bytes.fill(0);
  return bigToBytes32(value);
}

export function vanityTaggedPriv(salt, tag) {
  const text = textEncoder.encode(String(salt ?? ""));
  const payload = new Uint8Array(text.length + 1);
  payload.set(text);
  payload[text.length] = tag;
  const bytes = sha256(payload);
  payload.fill(0);
  const value = bytesToBig(bytes) % VANITY_ORDER;
  if (value === 0n) throw new Error("Tagged SHA-256(salt) is not a valid secp256k1 scalar. Change the salt.");
  bytes.fill(0);
  return bigToBytes32(value);
}

export function vanityPrivAt(startPriv, offset) {
  if (!(startPriv instanceof Uint8Array) || startPriv.length !== 32) throw new Error("Start private key must be 32 bytes.");
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("Vanity counter must be a non-negative integer.");
  let value = (bytesToBig(startPriv) + BigInt(offset)) % VANITY_ORDER;
  if (value === 0n) value = 1n;
  return bigToBytes32(value);
}

export function vanityAddressFromPriv(priv, kind, network) {
  const pub = secp256k1.getPublicKey(priv, true);
  try {
    if (kind === "sp") throw new Error("Silent payment addresses need a scan key and a spend key.");
    return addressFor(kind, pub, network);
  } finally {
    pub.fill(0);
  }
}

export function vanitySilentPaymentFromSalt(salt, offset, network) {
  const scanPriv = vanityTaggedPriv(salt, 0);
  const spend0 = vanityTaggedPriv(salt, 1);
  const spendPriv = vanityPrivAt(spend0, offset);
  const scanPub = secp256k1.getPublicKey(scanPriv, true);
  const spendPub = secp256k1.getPublicKey(spendPriv, true);
  const hrp = network === "testnet" ? "tsp" : "sp";
  try {
    const address = encodeSilentPaymentAddress(secp256k1.Point.fromBytes(scanPub), secp256k1.Point.fromBytes(spendPub), hrp);
    return {
      address,
      scanPriv,
      spendPriv,
      scanWif: encodeWifCompressed(scanPriv, network === "testnet"),
      spendWif: encodeWifCompressed(spendPriv, network === "testnet"),
    };
  } finally {
    scanPub.fill(0);
    spendPub.fill(0);
  }
}

export function vanityCandidate(salt, offset, kind, network) {
  if (kind === "sp") {
    const found = vanitySilentPaymentFromSalt(salt, offset, network);
    return { offset, address: found.address, scanPriv: found.scanPriv, spendPriv: found.spendPriv, scanWif: found.scanWif, spendWif: found.spendWif };
  }
  const start = vanityStartPriv(salt);
  const priv = vanityPrivAt(start, offset);
  start.fill(0);
  const address = vanityAddressFromPriv(priv, kind, network);
  const wif = encodeWifCompressed(priv, network === "testnet");
  return { offset, address, priv, wif };
}

const yieldSlice = () => new Promise((resolve) => {
  if (typeof requestAnimationFrame === "function") requestAnimationFrame(() => resolve());
  else setTimeout(resolve, 0);
});

function matchAddress(address, needle, kind) {
  if (!needle) return false;
  if (kind === "p2pkh" || kind === "p2sh-p2wpkh") return address.startsWith(needle);
  return address.toLowerCase().startsWith(needle);
}

export async function vanityGrind(options, hooks = {}) {
  const salt = String(options.salt ?? "");
  const kind = options.kind || "p2wpkh";
  const network = options.network || "mainnet";
  const start = Number.isSafeInteger(options.start) ? options.start : 0;
  const count = Number.isSafeInteger(options.count) && options.count > 0 ? options.count : VANITY_DEFAULT_COUNT;
  const needle = vanityNeedle(kind, network, options.prefix);
  if (!needle) throw new Error("Enter a vanity prefix using the characters this address type allows.");
  if (start < 0) throw new Error("Start counter must be zero or greater.");
  const onProgress = hooks.onProgress || (() => {});
  const signal = hooks.signal;
  const wantGpu = Boolean(options.gpu) && kind !== "p2tr";
  const t0 = typeof performance !== "undefined" ? performance.now() : Date.now();

  if (wantGpu) {
    try {
      const gpuHits = await vanityGpuGrind({ salt, kind, network, start, count, needle }, { signal, onProgress });
      if (gpuHits) return gpuHits;
    } catch {
      // CPU fallback is the contract: a GPU miss must not invent keys.
    }
  }

  const found = [];
  if (kind === "sp") {
    const scanPriv = vanityTaggedPriv(salt, 0);
    const spend0 = vanityTaggedPriv(salt, 1);
    const scanPoint = secp256k1.Point.fromBytes(secp256k1.getPublicKey(scanPriv, true));
    const hrp = network === "testnet" ? "tsp" : "sp";
    let spendPriv = vanityPrivAt(spend0, start);
    let spendPoint = secp256k1.Point.fromBytes(secp256k1.getPublicKey(spendPriv, true));
    const G = secp256k1.Point.BASE;
    spend0.fill(0);
    let i = start;
    const end = start + count;
    while (i < end) {
      if (signal?.aborted) break;
      const limit = Math.min(end, i + VANITY_BATCH);
      for (; i < limit; i++) {
        const address = encodeSilentPaymentAddress(scanPoint, spendPoint, hrp);
        if (matchAddress(address, needle, kind)) {
          const priv = vanityPrivAt(vanityTaggedPriv(salt, 1), i);
          found.push({
            offset: i,
            address,
            scanPriv: scanPriv.slice(),
            spendPriv: priv,
            scanWif: encodeWifCompressed(scanPriv, network === "testnet"),
            spendWif: encodeWifCompressed(priv, network === "testnet"),
          });
          if (!options.findAll) {
            onProgress({ tried: i - start + 1, found: found.length, gpu: false, done: true });
            return found;
          }
        }
        spendPoint = spendPoint.add(G);
      }
      const elapsed = Math.max(1, (typeof performance !== "undefined" ? performance.now() : Date.now()) - t0);
      onProgress({ tried: i - start, found: found.length, gpu: false, rate: (i - start) / (elapsed / 1000) });
      await yieldSlice();
    }
    onProgress({ tried: i - start, found: found.length, gpu: false, done: true });
    return found;
  }

  const startPriv = vanityStartPriv(salt);
  let point = secp256k1.Point.fromBytes(secp256k1.getPublicKey(startPriv, true));
  if (start) point = point.add(secp256k1.Point.BASE.multiply(BigInt(start)));
  const G = secp256k1.Point.BASE;
  let i = start;
  const end = start + count;
  while (i < end) {
    if (signal?.aborted) break;
    const limit = Math.min(end, i + VANITY_BATCH);
    for (; i < limit; i++) {
      const pub = point.toBytes(true);
      const address = addressFor(kind, pub, network);
      pub.fill(0);
      if (matchAddress(address, needle, kind)) {
        const priv = vanityPrivAt(startPriv, i);
        found.push({
          offset: i,
          address,
          priv,
          wif: encodeWifCompressed(priv, network === "testnet"),
        });
        if (!options.findAll) {
          startPriv.fill(0);
          onProgress({ tried: i - start + 1, found: found.length, gpu: false, done: true });
          return found;
        }
      }
      point = point.add(G);
    }
    const elapsed = Math.max(1, (typeof performance !== "undefined" ? performance.now() : Date.now()) - t0);
    onProgress({ tried: i - start, found: found.length, gpu: false, rate: (i - start) / (elapsed / 1000) });
    await yieldSlice();
  }
  startPriv.fill(0);
  onProgress({ tried: i - start, found: found.length, gpu: false, done: true });
  return found;
}

export { vanityGpuAvailable, hash160, bytesToHex };
