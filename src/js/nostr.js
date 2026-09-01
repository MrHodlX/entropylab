// Nostr key calculator: NIP-06 derivation and NIP-19 nsec/npub/note inspect.
// Same secp256k1 curve as Bitcoin. This does not invent entropy, does not
// talk to relays, and does not sign events. NIP-06 is unrecommended for new
// identities (prefer a dedicated nsec); it exists here so a user-supplied
// BIP39 seed can be turned into the nsec/npub a Nostr client actually wants
// without typing that seed into the client.
import { HDKey } from "./hdkey.js";
import { secp256k1 } from "./secp256k1.js";
import { mnemonicToSeedSync } from "./bip39.js";
import { toWords, fromWords } from "./bech32.js";
import { hex as hexCoder } from "./coders.js";

export const NOSTR_PURPOSE = 44;
export const NOSTR_COIN_TYPE = 1237; // SLIP-44
export const INDEX_MIN = 0;
export const INDEX_MAX = 2147483647;
export const SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const NIP19_HRPS = Object.freeze({ nsec: "nsec", npub: "npub", note: "note" });

export function wipeBytes(bytes) {
  if (bytes && bytes.fill) bytes.fill(0);
  return bytes;
}

export function wipeNostrResult(result) {
  if (!result) return;
  wipeBytes(result.privateKey);
  wipeBytes(result.publicKey);
  wipeBytes(result.eventId);
  result.nsec = "";
  result.npub = "";
  result.privHex = "";
  result.pubHex = "";
  result.note = "";
  result.eventHex = "";
}

export function parseAccount(value, label = "account") {
  const n = typeof value === "number" ? value : Number(String(value ?? "").trim());
  if (!Number.isInteger(n) || n < INDEX_MIN || n > INDEX_MAX) {
    throw new Error(`${label} must be an integer from ${INDEX_MIN} to ${INDEX_MAX}.`);
  }
  return n;
}

export function nip06Path(account = 0) {
  return `m/44'/1237'/${parseAccount(account)}'/0/0`;
}

export function isValidSecp256k1Secret(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return false;
  let n = 0n;
  for (let i = 0; i < 32; i++) n = (n << 8n) | BigInt(bytes[i]);
  return n > 0n && n < SECP256K1_ORDER;
}

export function xonlyFromPrivateKey(privateKey) {
  if (!isValidSecp256k1Secret(privateKey)) throw new Error("Nostr private key must be a secp256k1 scalar in 1..n-1.");
  const pub = secp256k1.getPublicKey(privateKey, true);
  return pub.slice(1, 33);
}

function polymod(values) {
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= BECH32_GEN[i];
  }
  return chk >>> 0;
}

function hrpExpand(hrp) {
  const out = [];
  for (const ch of hrp) out.push(ch.charCodeAt(0) >>> 5);
  out.push(0);
  for (const ch of hrp) out.push(ch.charCodeAt(0) & 31);
  return out;
}

function bech32CreateChecksum(hrp, data) {
  const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
  return checksum;
}

function bech32Encode(hrp, words) {
  if (typeof hrp !== "string" || !hrp) throw new Error("bech32 hrp must be a non-empty string.");
  for (const word of words) if ((word & 31) !== word) throw new Error("bech32 data word out of range.");
  const checksum = bech32CreateChecksum(hrp, words);
  let out = hrp + "1";
  for (const word of words.concat(checksum)) out += BECH32_CHARSET[word];
  return out;
}

function bech32Decode(text) {
  if (typeof text !== "string" || !text) return null;
  if (text !== text.toLowerCase() && text !== text.toUpperCase()) return null;
  const lower = text.toLowerCase();
  const pos = lower.lastIndexOf("1");
  if (pos < 1 || pos + 7 > lower.length) return null;
  const hrp = lower.slice(0, pos);
  const data = [];
  for (const ch of lower.slice(pos + 1)) {
    const value = BECH32_CHARSET.indexOf(ch);
    if (value < 0) return null;
    data.push(value);
  }
  if (polymod(hrpExpand(hrp).concat(data)) !== 1) return null;
  return { prefix: hrp, words: data.slice(0, -6) };
}

export function encodeNsec(privateKey) {
  if (!isValidSecp256k1Secret(privateKey)) throw new Error("nsec payload must be a secp256k1 scalar in 1..n-1.");
  return bech32Encode(NIP19_HRPS.nsec, toWords(privateKey));
}

export function encodeNpub(xonly) {
  if (!(xonly instanceof Uint8Array) || xonly.length !== 32) throw new Error("npub payload must be a 32-byte x-only public key.");
  return bech32Encode(NIP19_HRPS.npub, toWords(xonly));
}

export function encodeNote(eventId) {
  if (!(eventId instanceof Uint8Array) || eventId.length !== 32) throw new Error("note payload must be a 32-byte event id.");
  return bech32Encode(NIP19_HRPS.note, toWords(eventId));
}

function decodeNip19Bytes(text, hrp) {
  const decoded = bech32Decode(String(text || "").trim());
  if (!decoded || decoded.prefix !== hrp) return null;
  let bytes;
  try {
    bytes = fromWords(decoded.words);
  } catch {
    return null;
  }
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return null;
  return bytes;
}

export function keyFromPrivateBytes(privateKey) {
  const publicKey = xonlyFromPrivateKey(privateKey);
  return {
    kind: "private",
    path: "",
    privateKey,
    publicKey,
    nsec: encodeNsec(privateKey),
    npub: encodeNpub(publicKey),
    privHex: hexCoder.encode(privateKey),
    pubHex: hexCoder.encode(publicKey),
    note: "",
    eventId: null,
    eventHex: "",
  };
}

export function keyFromPublicBytes(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) throw new Error("npub payload must be a 32-byte x-only public key.");
  return {
    kind: "public",
    path: "",
    privateKey: null,
    publicKey,
    nsec: "",
    npub: encodeNpub(publicKey),
    privHex: "",
    pubHex: hexCoder.encode(publicKey),
    note: "",
    eventId: null,
    eventHex: "",
  };
}

export function inspectNostrInput(text) {
  const raw = String(text || "").trim();
  if (!raw) throw new Error("Paste an nsec, npub, note, or 64-character hex key.");
  const lower = raw.toLowerCase();
  if (lower.startsWith("nsec1")) {
    const bytes = decodeNip19Bytes(raw, "nsec");
    if (!bytes) throw new Error("Invalid nsec.");
    if (!isValidSecp256k1Secret(bytes)) throw new Error("nsec payload is not a secp256k1 scalar in 1..n-1.");
    return keyFromPrivateBytes(bytes);
  }
  if (lower.startsWith("npub1")) {
    const bytes = decodeNip19Bytes(raw, "npub");
    if (!bytes) throw new Error("Invalid npub.");
    return keyFromPublicBytes(bytes);
  }
  if (lower.startsWith("note1")) {
    const bytes = decodeNip19Bytes(raw, "note");
    if (!bytes) throw new Error("Invalid note id.");
    return {
      kind: "note",
      path: "",
      privateKey: null,
      publicKey: null,
      nsec: "",
      npub: "",
      privHex: "",
      pubHex: "",
      note: encodeNote(bytes),
      eventId: bytes,
      eventHex: hexCoder.encode(bytes),
    };
  }
  const hex = lower.startsWith("0x") ? lower.slice(2) : lower;
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("Paste an nsec, npub, note, or 64-character hex key.");
  const bytes = hexCoder.decode(hex);
  if (isValidSecp256k1Secret(bytes)) return keyFromPrivateBytes(bytes);
  return keyFromPublicBytes(bytes);
}

export function deriveNip06FromRoot(root, account = 0) {
  if (!root || typeof root.derive !== "function") throw new Error("NIP-06 needs a BIP32 root private key.");
  if (!root.privateKey) throw new Error("NIP-06 needs a BIP32 root private key. Watch-only keys cannot derive children.");
  const path = nip06Path(account);
  const node = root.derive(path);
  try {
    if (!node.privateKey) throw new Error("NIP-06 derivation produced no private key.");
    const result = keyFromPrivateBytes(node.privateKey.slice());
    result.path = path;
    result.kind = "nip06";
    return result;
  } finally {
    if (node && node !== root && typeof node.wipePrivateData === "function") node.wipePrivateData();
  }
}

export function deriveNip06FromMnemonic(mnemonic, passphrase = "", account = 0) {
  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  let root;
  try {
    root = HDKey.fromMasterSeed(seed);
    return deriveNip06FromRoot(root, account);
  } finally {
    wipeBytes(seed);
    if (root && typeof root.wipePrivateData === "function") root.wipePrivateData();
  }
}

export function deriveNip06FromSeed(seed, account = 0) {
  if (!(seed instanceof Uint8Array) || seed.length < 16) throw new Error("NIP-06 needs a BIP39 seed.");
  const root = HDKey.fromMasterSeed(seed);
  try {
    return deriveNip06FromRoot(root, account);
  } finally {
    if (typeof root.wipePrivateData === "function") root.wipePrivateData();
  }
}
