// Single-key print / save card.
//
// A calculator export of one already-derived Key Station address and that
// child's spend secret (WIF or Casascius minikey). It does not generate
// entropy, keys, or passphrases. Hidden for multisig, Silent Payments, and
// watch-only xpub imports: those have no single spend secret to print.
//
// The public face is the receive address. The private face (only after the
// operator confirms, and only while Show private recovery material is on)
// is the WIF for that one address. An account xprv is never printed: that
// would expand the backup past this child.

import { renderSVG as uqrRenderSvg } from "uqr";

const escapeHtml = (text) => {
  const entities = { "&": "\u0026amp;", "<": "\u0026lt;", ">": "\u0026gt;", '"': "\u0026quot;", "'": "\u0026#39;" };
  return Array.from(String(text ?? ""), (character) => entities[character] ?? character).join("");
};

const SCRIPT_ADDRESS_FIELD = {
  bip44: "p2pkhCompressed",
  bip49: "p2shP2wpkh",
  bip84: "p2wpkh",
  bip86: "p2tr",
};

const SCRIPT_ID = {
  bip44: "p2pkh",
  bip49: "p2sh-p2wpkh",
  bip84: "p2wpkh",
  bip86: "p2tr",
};

const DEFAULT_REASON = "Needs a derived single-signature address and a WIF or mini key.";

export const cardPageStyles = `
.single-key-card { box-sizing: border-box; width: 100%; max-width: 190mm; margin: 0 auto; padding: 6mm 7mm 8mm; color: #111; background: #fff; font-family: "Segoe UI", system-ui, sans-serif; }
.single-key-card * { box-sizing: border-box; }
.single-key-card-head { display: flex; align-items: center; gap: 8px; margin: 0 0 4mm; }
.single-key-card-logo { display: flex; width: 28px; height: 28px; flex: none; }
.single-key-card-logo svg { width: 28px; height: 28px; display: block; }
.single-key-card-logo .site-logo-dark { display: none; }
.single-key-card-logo .site-logo-light { display: block; }
.single-key-card-brand { font-size: 16px; font-weight: 700; letter-spacing: 0.02em; }
.single-key-card-kicker { margin-left: auto; font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; color: #444; }
.single-key-card-face { display: grid; grid-template-columns: 38mm 1fr; gap: 5mm; align-items: start; }
.single-key-card-qr { width: 38mm; height: 38mm; }
.single-key-card-qr svg { width: 38mm; height: 38mm; display: block; background: #fff; }
.single-key-card-meta { min-width: 0; }
.single-key-card h1 { margin: 0 0 2mm; font-size: 13px; letter-spacing: 0.08em; text-transform: uppercase; }
.single-key-card .mono { font-family: ui-monospace, "Cascadia Code", Menlo, Consolas, monospace; font-size: 12px; line-height: 1.35; overflow-wrap: anywhere; word-break: break-all; }
.single-key-card .muted { color: #444; font-size: 11px; margin: 1mm 0 0; }
.single-key-card-tail { margin: 2mm 0 0; font-size: 18px; font-weight: 700; letter-spacing: 0.12em; font-family: ui-monospace, Menlo, Consolas, monospace; }
.single-key-card-fold { margin: 5mm 0 4mm; border: 0; border-top: 1.5px dashed #111; padding-top: 2mm; text-align: center; font-size: 11px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
.single-key-card-private { padding-top: 1mm; }
.single-key-card-private-face { display: grid; grid-template-columns: 52mm 1fr; gap: 5mm; align-items: start; }
.single-key-card-wif-qr { width: 52mm; height: 52mm; }
.single-key-card-wif-qr svg { width: 52mm; height: 52mm; display: block; background: #fff; }
.single-key-card-wif-label { margin: 0 0 2mm; font-size: 16px; font-weight: 800; letter-spacing: 0.04em; text-transform: uppercase; color: #111; }
.single-key-card-warn { margin: 2mm 0 0; font-size: 11px; font-weight: 700; }
.single-key-card-foot { margin: 4mm 0 0; font-size: 10px; color: #444; }
@page { size: auto; margin: 10mm; }
@media print {
  .single-key-card { max-width: none; page-break-inside: avoid; break-inside: avoid; }
}
`.trim();

export function addressTail(address, n = 4) {
  const text = String(address ?? "").trim();
  if (!text) return "";
  const take = Math.min(Math.max(1, n), text.length);
  return text.slice(-take);
}

export function pinDescriptorIndex(descriptor, index) {
  if (descriptor == null || descriptor === "") return "";
  if (!Number.isSafeInteger(index) || index < 0) return "";
  let body = String(descriptor);
  const hash = body.lastIndexOf("#");
  if (hash >= 0) body = body.slice(0, hash);
  // Pin the address wildcard (`/0/*` inside `wpkh(.../0/*)#cs`). Leave a
  // stale checksum off rather than reprinting one that no longer matches.
  const wildcard = body.lastIndexOf("/" + "*");
  if (wildcard < 0) return body;
  const after = body.slice(wildcard + 2);
  if (after.startsWith("'")) return `${body.slice(0, wildcard)}/${index}'${after.slice(1)}`;
  return `${body.slice(0, wildcard)}/${index}${after}`;
}

export function formatPrintedAt(date = new Date()) {
  const pad = (value, width = 2) => String(value).padStart(width, "0");
  const offset = -date.getTimezoneOffset();
  const sign = offset >= 0 ? "+" : "-";
  const abs = Math.abs(offset);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}

export function cardQrSvg(value) {
  return uqrRenderSvg(String(value ?? ""), { ecc: "M", border: 2, pixelSize: 4, blackColor: "#111111", whiteColor: "#ffffff" });
}

function ineligible(reason) {
  return {
    eligible: false,
    reason: reason || DEFAULT_REASON,
    includePrivate: false,
    address: "",
    addressTail: "",
    path: "",
    scriptId: "",
    scriptLabel: "",
    script: "",
    network: "",
    fingerprint: "",
    source: "",
    version: "",
    commitShort: "",
    printedAt: "",
    wif: "",
    wifCompressed: "",
    wifUncompressed: "",
    minikey: "",
    wifEncoding: "",
    taprootInternalKey: false,
    descriptor: "",
    logoHtml: "",
  };
}

function pubkeyDescriptor(script, pubkeyCompressed) {
  const key = String(pubkeyCompressed ?? "").trim();
  if (!key) return "";
  if (script === "p2tr") {
    const xonly = key.length === 66 && /^0[23]/i.test(key) ? key.slice(2) : key;
    return `tr(${xonly})`;
  }
  if (script === "p2pkh") return `pkh(${key})`;
  if (script === "p2sh-p2wpkh") return `sh(wpkh(${key}))`;
  return `wpkh(${key})`;
}

function accountBranches(account) {
  if (account?.addressBranches?.length) return account.addressBranches;
  return [
    { branch: 0, rows: account?.receive || [], publicDescriptor: account?.receiveDescriptor },
    { branch: 1, rows: account?.change || [], publicDescriptor: account?.changeDescriptor },
  ].filter((entry) => (entry.rows && entry.rows.length) || entry.publicDescriptor);
}

function firstReceive(account) {
  const branches = accountBranches(account);
  const receive = branches.find((entry) => entry.branch === 0) || branches[0];
  return { branch: receive, row: receive?.rows?.[0] || null };
}

function cardSource(wallet) {
  if (wallet?.kind === "single") {
    if (wallet.minikey) return "Casascius mini private key you entered. Calculator, not a generator.";
    return "Private key you entered. Calculator, not a generator.";
  }
  if (wallet?.mnemonic) return "Derived from a seed you entered. Calculator, not a generator.";
  if (wallet?.importedPrivateKey) return "Imported extended private key. Calculator, not a generator.";
  if (wallet?.rootXprv) return "Derived from a root extended private key you entered. Calculator, not a generator.";
  return "Derived from user-supplied key material. Calculator, not a generator.";
}

function payloadBase(options) {
  return {
    eligible: true,
    reason: "",
    includePrivate: Boolean(options.includePrivate),
    version: options.version || "",
    commitShort: options.commitShort || "",
    printedAt: options.printedAt || formatPrintedAt(),
    logoHtml: options.logoHtml || "",
    source: options.source || "",
    fingerprint: options.fingerprint || "",
    network: options.network || "",
    scriptId: options.scriptId || "",
    scriptLabel: options.scriptLabel || "",
    script: options.script || "",
    path: options.path || "",
    address: options.address || "",
    addressTail: addressTail(options.address),
    wif: options.wif || "",
    wifCompressed: options.wifCompressed || "",
    wifUncompressed: options.wifUncompressed || "",
    minikey: options.minikey || "",
    wifEncoding: options.wifEncoding || "",
    taprootInternalKey: Boolean(options.taprootInternalKey),
    descriptor: options.descriptor || "",
  };
}

export function publicOnly(payload) {
  if (!payload) return ineligible();
  return {
    ...payload,
    includePrivate: false,
    wif: "",
    wifCompressed: "",
    wifUncompressed: "",
    minikey: "",
  };
}

export function cardFromWallet(wallet, options = {}) {
  if (!wallet) return ineligible("Derive a Key Station key first.");
  if (wallet.kind === "msig") return ineligible("Multisig wallets do not have a single spend secret.");
  if (wallet.kind !== "single" && wallet.kind !== "hd") return ineligible("This card is for a single-signature Key Station key.");

  const scriptId = options.scriptId || "bip84";
  const scriptLabel = options.scriptLabel || "";
  const revealPrivate = Boolean(options.revealPrivate);
  const common = {
    version: options.version || "",
    commitShort: options.commitShort || "",
    printedAt: options.printedAt || formatPrintedAt(),
    logoHtml: options.logoHtml || "",
    source: cardSource(wallet),
    fingerprint: wallet.masterFingerprint || "",
    network: wallet.network || "",
    scriptId,
    scriptLabel,
  };

  if (wallet.kind === "single") {
    const field = SCRIPT_ADDRESS_FIELD[scriptId] || SCRIPT_ADDRESS_FIELD.bip84;
    const script = SCRIPT_ID[scriptId] || SCRIPT_ID.bip84;
    const address = wallet[field] || wallet.p2wpkh || "";
    const wif = wallet.wifCompressed || wallet.wifUncompressed || "";
    const minikey = wallet.minikey || "";
    if (!address || (!wif && !minikey)) return ineligible(DEFAULT_REASON);
    const taprootInternalKey = script === "p2tr";
    const wifEncoding = wallet.wifCompressed ? "compressed" : wallet.wifUncompressed ? "uncompressed" : minikey ? "minikey" : "";
    return payloadBase({
      ...common,
      script,
      path: "",
      address,
      wif: minikey || wif,
      wifCompressed: wallet.wifCompressed || "",
      wifUncompressed: wallet.wifUncompressed || "",
      minikey,
      wifEncoding,
      taprootInternalKey,
      descriptor: pubkeyDescriptor(script, wallet.pubkeyCompressed),
      includePrivate: revealPrivate,
    });
  }

  const account = (wallet.accounts || []).find((candidate) => candidate.def?.id === scriptId) || wallet.accounts?.[0];
  if (!account) return ineligible(DEFAULT_REASON);
  const { branch, row } = firstReceive(account);
  if (!row?.address) return ineligible("Derive a receive address first.");
  if (!row.wif && !wallet.minikey) return ineligible("Watch-only keys have no spend secret to print.");
  const script = account.def?.script || SCRIPT_ID[scriptId] || "p2wpkh";
  const descriptor = pinDescriptorIndex(branch?.publicDescriptor || account.receiveDescriptor || "", row.index ?? 0);
  return payloadBase({
    ...common,
    script,
    scriptLabel: scriptLabel || account.def?.label || "",
    path: row.path || "",
    address: row.address,
    wif: row.wif || "",
    wifCompressed: row.wif || "",
    wifUncompressed: "",
    minikey: "",
    wifEncoding: "compressed",
    taprootInternalKey: script === "p2tr",
    descriptor,
    includePrivate: revealPrivate,
  });
}

function metaLine(label, value) {
  if (!value) return "";
  return `<p class="muted">${escapeHtml(label)}<br><span class="mono">${escapeHtml(value)}</span></p>`;
}

export function cardHtml(payload) {
  if (!payload?.eligible || !payload.address) return "";
  const priv = Boolean(payload.includePrivate && (payload.wif || payload.minikey));
  const logo = payload.logoHtml
    ? `<span class="single-key-card-logo site-logo" aria-hidden="true">${payload.logoHtml}</span>`
    : "";
  const scriptBits = [payload.scriptLabel, payload.network].filter(Boolean).join(" · ");
  const addressQr = cardQrSvg(payload.address);
  const privateBlock = priv ? privateFaceHtml(payload) : "";
  return `<article class="single-key-card" data-address-tail="${escapeHtml(payload.addressTail)}">
    <header class="single-key-card-head">${logo}<span class="single-key-card-brand">EntropyLab</span><span class="single-key-card-kicker">Single-key card</span></header>
    <section class="single-key-card-public" aria-label="Receive address">
      <div class="single-key-card-face">
        <div class="single-key-card-qr qr" aria-label="Receive address QR code">${addressQr}</div>
        <div class="single-key-card-meta">
          <h1>Receive address</h1>
          ${scriptBits ? `<p class="muted">${escapeHtml(scriptBits)}</p>` : ""}
          <p class="mono">${escapeHtml(payload.address)}</p>
          <p class="single-key-card-tail">Last 4 · ${escapeHtml(payload.addressTail)}</p>
          ${metaLine("Derivation path", payload.path)}
          ${metaLine("Master fingerprint", payload.fingerprint)}
        </div>
      </div>
    </section>
    ${privateBlock}
    <p class="single-key-card-foot">${escapeHtml(payload.source)} EntropyLab v${escapeHtml(payload.version)}${payload.commitShort ? ` · ${escapeHtml(payload.commitShort)}` : ""}${payload.printedAt ? ` · printed ${escapeHtml(payload.printedAt)}` : ""}</p>
  </article>`;
}

function privateFaceHtml(payload) {
  const secret = payload.minikey || payload.wif;
  const secretQr = cardQrSvg(secret);
  const secretName = payload.minikey ? "Mini private key" : "Private key (WIF)";
  const encoding = payload.wifEncoding === "uncompressed"
    ? "uncompressed"
    : payload.minikey
      ? "Casascius minikey"
      : "compressed";
  const taproot = payload.taprootInternalKey
    ? `<p class="single-key-card-warn">Taproot: this WIF is the BIP86 internal key, not the tweaked output key.</p>`
    : "";
  const otherWif = payload.wifCompressed && payload.wifUncompressed
    ? `${metaLine("WIF compressed", payload.wifCompressed)}${metaLine("WIF uncompressed", payload.wifUncompressed)}`
    : payload.wifUncompressed && payload.wif !== payload.wifUncompressed
      ? metaLine("WIF uncompressed", payload.wifUncompressed)
      : "";
  return `<div class="single-key-card-fold">Fold here · cover the private face · last 4 · ${escapeHtml(payload.addressTail)}</div>
    <section class="single-key-card-private" aria-label="Private key">
      <div class="single-key-card-private-face">
        <div class="single-key-card-wif-qr qr" aria-label="${escapeHtml(secretName)} QR code">${secretQr}</div>
        <div class="single-key-card-meta">
          <p class="single-key-card-wif-label">${escapeHtml(secretName)} — spend</p>
          <p class="mono">${escapeHtml(secret)}</p>
          <p class="muted">${escapeHtml(encoding)}</p>
          ${otherWif}
          ${taproot}
          ${metaLine("Address descriptor (this index)", payload.descriptor)}
          <p class="single-key-card-warn">Anyone who sees this WIF can spend this address. Keep the private face covered.</p>
        </div>
      </div>
    </section>`;
}

export function cardSaveDocument(payload) {
  const inner = cardHtml(payload);
  const notice = payload.includePrivate
    ? "This file includes a private key for one address."
    : "Watch-only. This file has no private key.";
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EntropyLab single-key card</title>
<style>
html, body { margin: 0; background: #fff; color: #111; }
${cardPageStyles}
</style>
</head>
<body>
<p class="single-key-card-foot" style="max-width:190mm;margin:8px auto 0;padding:0 7mm;">${escapeHtml(notice)}</p>
${inner}
</body></html>
`;
}
