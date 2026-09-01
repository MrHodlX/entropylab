// Entropy Journal: an encrypted, downloadable notebook of entropy the user
// already produced. It is a calculator companion, not a password manager and
// not a key generator. The AES-256-GCM key is HKDF-SHA-256 of dice rolls the
// user supplies — never a typed password, never CSPRNG for secret material.
// getRandomValues for secret material.
//
// crypto.getRandomValues is used only for the public HKDF salt (16 bytes,
// once per journal) and the public AES-GCM IV (12 bytes, once per save).
// Both are stored in the downloaded file in the clear. They are AEAD
// parameters, not wallet entropy, and cannot become keys, seeds, or
// passphrases. Same dice plus the same file always decrypts; a new journal
// with the same dice is a different file because the salt is different.
import { hex as hexCoder } from "./coders.js";

export const JOURNAL_VERSION = 1;
export const JOURNAL_KDF = "HKDF-SHA-256";
export const JOURNAL_CIPHER = "AES-256-GCM";
export const JOURNAL_INFO = "entropylab-journal-v1";
export const JOURNAL_VERIFY_PREFIX = "entropylab-journal-verify:";
export const SALT_BYTES = 16;
export const IV_BYTES = 12;
export const DICE_MIN_ROLLS = 50; // log2(6)*50 ≈ 129 bits
export const DICE_RECOMMENDED_ROLLS = 99; // log2(6)*99 ≈ 256 bits
export const METHODS = Object.freeze(["dice", "coin", "hex", "brain", "seed", "cards"]);
export const METHOD_LABELS = Object.freeze({
  dice: "Dice rolls",
  coin: "Coin flips",
  hex: "Hex",
  brain: "Brain-wallet text",
  seed: "Manual seed",
  cards: "Playing cards",
});

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function wipeBytes(bytes) {
  if (bytes && bytes.fill) bytes.fill(0);
  return bytes;
}

export function wipeEntry(entry) {
  if (!entry) return;
  entry.input = "";
  entry.phrase = "";
  entry.label = "";
  entry.notes = "";
  entry.walletName = "";
  entry.fingerprint = "";
}

export function wipeDocument(doc) {
  if (!doc) return;
  for (const entry of doc.entries || []) wipeEntry(entry);
  doc.entries = [];
  doc.nextId = 1;
}

export function diceBits(rolls) {
  const n = typeof rolls === "number" ? rolls : 0;
  return n <= 0 ? 0 : n * Math.log2(6);
}

export function parseDiceTranscript(text) {
  const raw = String(text ?? "");
  const rolls = [];
  let leftover = "";
  for (const ch of raw) {
    if (/\s|,|;|\|/.test(ch)) continue;
    if (ch >= "1" && ch <= "6") rolls.push(ch);
    else leftover += ch;
  }
  return {
    digits: rolls.join(""),
    count: rolls.length,
    bits: diceBits(rolls.length),
    leftover,
  };
}

export function assertDiceKey(text, { confirm } = {}) {
  const parsed = parseDiceTranscript(text);
  if (parsed.count < DICE_MIN_ROLLS) {
    throw new Error(`Journal key needs at least ${DICE_MIN_ROLLS} six-sided dice rolls (about 129 bits). You entered ${parsed.count}.`);
  }
  if (parsed.leftover) throw new Error("Journal key dice must be the digits 1–6. Other characters were entered.");
  if (confirm != null) {
    const other = parseDiceTranscript(confirm);
    if (other.digits !== parsed.digits) throw new Error("The two dice transcripts do not match.");
  }
  return parsed;
}

// Public AEAD parameters only. Not secret wallet entropy.
export function publicRandomBytes(length) {
  if (!Number.isInteger(length) || length < 1 || length > 1024) throw new Error("Random length must be an integer from 1 to 1024.");
  if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") {
    throw new Error("This host has no CSPRNG. Open EntropyLab in a current browser on a trusted computer.");
  }
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function requireSubtle() {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error("Web Crypto is unavailable. Open this file in a current browser (a secure context).");
  }
  return crypto.subtle;
}

export async function verifyDigest(digits) {
  const subtle = requireSubtle();
  const bytes = encoder.encode(JOURNAL_VERIFY_PREFIX + digits);
  try {
    return new Uint8Array(await subtle.digest("SHA-256", bytes));
  } finally {
    wipeBytes(bytes);
  }
}

export async function deriveJournalKey(digits, salt) {
  if (typeof digits !== "string" || !digits) throw new Error("Journal key dice are missing.");
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) throw new Error("Journal salt must be 16 bytes.");
  const subtle = requireSubtle();
  const ikm = encoder.encode(digits);
  let baseKey;
  try {
    baseKey = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    return await subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(JOURNAL_INFO) },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    wipeBytes(ikm);
  }
}

export function emptyDocument() {
  return { version: JOURNAL_VERSION, nextId: 1, entries: [] };
}

export function normalizeEntry(entry, now = new Date()) {
  const method = String(entry?.method || "").trim();
  if (!METHODS.includes(method)) throw new Error("Journal method must be dice, coin, hex, brain, seed, or cards.");
  const label = String(entry?.label ?? "").trim();
  if (!label) throw new Error("Every journal entry needs a label.");
  const created = entry?.created ? String(entry.created) : now.toISOString();
  if (!/^\d{4}-\d{2}-\d{2}T/.test(created)) throw new Error("Journal timestamp must be ISO-8601.");
  const walletId = entry?.walletId == null || entry.walletId === "" ? null : Number(entry.walletId);
  if (walletId != null && (!Number.isInteger(walletId) || walletId < 0)) throw new Error("Session wallet id must be a whole number.");
  return {
    id: Number.isInteger(entry?.id) && entry.id > 0 ? entry.id : 0,
    method,
    input: String(entry?.input ?? ""),
    phrase: String(entry?.phrase ?? ""),
    label,
    notes: String(entry?.notes ?? ""),
    created,
    walletId,
    walletName: String(entry?.walletName ?? ""),
    fingerprint: String(entry?.fingerprint ?? "").toLowerCase(),
  };
}

export function addEntry(doc, fields, now = new Date()) {
  if (!doc || !Array.isArray(doc.entries)) throw new Error("Journal document is missing.");
  const entry = normalizeEntry({ ...fields, id: doc.nextId || 1 }, now);
  doc.entries = [...doc.entries, entry];
  doc.nextId = entry.id + 1;
  return entry;
}

export function replaceEntry(doc, id, fields) {
  if (!doc || !Array.isArray(doc.entries)) throw new Error("Journal document is missing.");
  const index = doc.entries.findIndex((entry) => entry.id === id);
  if (index < 0) throw new Error("That journal entry is not in this file.");
  const previous = doc.entries[index];
  const entry = normalizeEntry({ ...previous, ...fields, id: previous.id, created: previous.created });
  const next = doc.entries.slice();
  wipeEntry(previous);
  next[index] = entry;
  doc.entries = next;
  return entry;
}

export function removeEntry(doc, id) {
  if (!doc || !Array.isArray(doc.entries)) throw new Error("Journal document is missing.");
  const index = doc.entries.findIndex((entry) => entry.id === id);
  if (index < 0) throw new Error("That journal entry is not in this file.");
  const next = doc.entries.slice();
  wipeEntry(next[index]);
  next.splice(index, 1);
  doc.entries = next;
}

export function searchEntries(doc, query) {
  const entries = doc?.entries || [];
  const needle = String(query ?? "").trim().toLowerCase();
  if (!needle) return entries.slice();
  return entries.filter((entry) => String(entry.label || "").toLowerCase().includes(needle));
}

export function snapshotFromKeyState(state) {
  if (!state || state.isLab) return null;
  const fields = state.fields || {};
  const mode = state.mode || "";
  let method = "seed";
  let input = "";
  if (mode === "dice") {
    method = "dice";
    input = state.diceMethod === "dplus" ? fields.dplusDice || "" : state.diceMethod === "bitbox" ? fields.bitboxDice || "" : fields.dice || "";
  } else if (mode === "cards") {
    method = "cards";
    input = state.cardMethod === "direct" ? fields.directCards || "" : fields.cards || "";
  } else if (mode === "hex") {
    method = "hex";
    const format = state.entropyFormat || "hex";
    input = fields[format] || fields.hex || "";
  } else if (mode === "seed") {
    method = "seed";
    input = state.seedMethod === "numbers" ? fields.seedNumbers || "" : fields.seed || "";
  } else if (mode === "key") {
    const kind = fields.keyKind || "";
    if (kind === "brain") {
      method = "brain";
      input = (fields.privateKeys && fields.privateKeys.brain) || fields.key || fields.brainLab || "";
    } else {
      method = "seed";
      input = (fields.privateKeys && (fields.privateKeys[kind] || fields.privateKeys.wif)) || fields.key || "";
    }
  }
  const phrase = state.result?.mnemonic || "";
  if (!String(input).trim() && !String(phrase).trim()) return null;
  return {
    method,
    input: String(input),
    phrase: String(phrase),
    label: String(state.name || state.result?.masterFingerprint || "").trim(),
    notes: fields.pass ? "BIP-39 passphrase was in effect on the linked key. The passphrase itself is not stored here unless you paste it." : "",
    walletId: state.id,
    walletName: String(state.name || ""),
    fingerprint: String(state.result?.masterFingerprint || "").toLowerCase(),
  };
}

export function encodeFile({ salt, iv, ciphertext }) {
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) throw new Error("Journal salt must be 16 bytes.");
  if (!(iv instanceof Uint8Array) || iv.length !== IV_BYTES) throw new Error("Journal IV must be 12 bytes.");
  if (!(ciphertext instanceof Uint8Array) || !ciphertext.length) throw new Error("Journal ciphertext is missing.");
  return {
    entropylabJournal: JOURNAL_VERSION,
    kdf: JOURNAL_KDF,
    cipher: JOURNAL_CIPHER,
    salt: hexCoder.encode(salt),
    iv: hexCoder.encode(iv),
    ciphertext: hexCoder.encode(ciphertext),
  };
}

export function parseFile(text) {
  let parsed;
  try {
    parsed = typeof text === "string" ? JSON.parse(text) : text;
  } catch {
    throw new Error("That file is not valid JSON.");
  }
  if (!parsed || parsed.entropylabJournal !== JOURNAL_VERSION) throw new Error("That file is not an EntropyLab journal.");
  if (parsed.kdf !== JOURNAL_KDF || parsed.cipher !== JOURNAL_CIPHER) throw new Error("This journal uses an unsupported cipher.");
  let salt, iv, ciphertext;
  try {
    salt = hexCoder.decode(String(parsed.salt || ""));
    iv = hexCoder.decode(String(parsed.iv || ""));
    ciphertext = hexCoder.decode(String(parsed.ciphertext || ""));
  } catch {
    throw new Error("That journal file is missing salt, IV, or ciphertext.");
  }
  if (salt.length !== SALT_BYTES || iv.length !== IV_BYTES || !ciphertext.length) {
    throw new Error("That journal file is missing salt, IV, or ciphertext.");
  }
  return { salt, iv, ciphertext };
}

function parseDocument(plain) {
  let parsed;
  try {
    parsed = JSON.parse(plain);
  } catch {
    throw new Error("The journal file is corrupt.");
  }
  if (!parsed || parsed.version !== JOURNAL_VERSION || !Array.isArray(parsed.entries)) {
    throw new Error("The journal file is corrupt.");
  }
  const nextId = Number.isInteger(parsed.nextId) && parsed.nextId > 0 ? parsed.nextId : 1;
  const entries = parsed.entries.map((entry) => normalizeEntry(entry));
  return { version: JOURNAL_VERSION, nextId, entries };
}

export async function sealDocument(doc, key, salt, randomBytes = publicRandomBytes) {
  if (!key) throw new Error("Unlock the journal before saving.");
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) throw new Error("Journal salt must be 16 bytes.");
  const subtle = requireSubtle();
  const iv = randomBytes(IV_BYTES);
  const plain = encoder.encode(JSON.stringify({
    version: JOURNAL_VERSION,
    nextId: doc.nextId,
    entries: doc.entries,
  }));
  try {
    const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
    return encodeFile({ salt, iv, ciphertext });
  } finally {
    wipeBytes(plain);
  }
}

export async function openDocument(file, digits) {
  const parsed = parseFile(file);
  const key = await deriveJournalKey(digits, parsed.salt);
  const subtle = requireSubtle();
  let plainBytes;
  try {
    plainBytes = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: parsed.iv }, key, parsed.ciphertext));
  } catch {
    throw new Error("Wrong dice, or the file is damaged.");
  }
  try {
    const doc = parseDocument(decoder.decode(plainBytes));
    const digest = await verifyDigest(digits);
    return { key, salt: parsed.salt, doc, verify: digest };
  } finally {
    wipeBytes(plainBytes);
    wipeBytes(parsed.iv);
    wipeBytes(parsed.ciphertext);
  }
}

export async function createDocument(dice, confirm, randomBytes = publicRandomBytes) {
  const parsed = assertDiceKey(dice, { confirm });
  const salt = randomBytes(SALT_BYTES);
  const key = await deriveJournalKey(parsed.digits, salt);
  const digest = await verifyDigest(parsed.digits);
  return { key, salt, doc: emptyDocument(), verify: digest };
}
