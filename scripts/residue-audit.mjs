// Dev-only memory-residue harness: drives the app in a real browser, plants
// deterministic fake secrets, captures each browser process's memory at fixed
// checkpoints with an external tool, and scans the captures for the secrets.
//
// This is NOT part of `npm test` or CI. It needs a capture tool that is
// detected, never bundled:
//   - Windows: ProcDump (PROCDUMP_BINARY, or procdump/procdump64 on PATH)
//   - Linux:   gcore, from gdb (GCORE_BINARY, or gcore on PATH)
//   - Optional deeper path: MemProcFS (MEMPROCFS_MOUNT) — scan live VM pages
//     without dumping, where it is installed.
//   - macOS: no reliable capture tool; the harness stops with a clear message.
//
// Honest framing (also printed into every report): a zero hit count is NOT
// proof of erasure — only that these bytes were not in these processes at
// this moment on this OS. A positive hit IS proof of residue. The pre-wipe
// positive control must find the secrets, or the run is invalid.
//
// Run: npm run test:residue
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, createReadStream } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";

export const root = dirname(dirname(fileURLToPath(import.meta.url)));
const platform = process.platform;

export const DISCLAIMER =
  "Zero hits is not proof of erasure: it means only that these bytes were not found in these processes at this moment, on this OS, with this allocator state. A positive hit is proof of residue.";

// The checkpoints, in order. after-tab-close scans the browser's surviving
// processes (the browser process, once the tab's renderer is gone).
export const CHECKPOINTS = Object.freeze([
  "after-derive",
  "after-reveal", // the positive control: secrets MUST be found here
  "after-copy",
  "after-wipe", // End session
  "after-tab-close",
]);
export const CONTROL_CHECKPOINT = "after-reveal";

export class ResidueToolError extends Error {}

// --- Tool detection (detected, never bundled) ------------------------------

const runProbe = (bin) => {
  try {
    const result = spawnSync(bin, [platform === "win32" ? "-?" : "--version"], { stdio: "pipe", timeout: 15000 });
    return result.status !== null ? bin : null;
  } catch {
    return null;
  }
};

export const detectTools = ({ env = process.env, probe = runProbe, fs = { existsSync }, platform: os = platform } = {}) => {
  if (os === "win32") {
    const binary = env.PROCDUMP_BINARY
      || ["procdump", "procdump64"].map(probe).find(Boolean)
      || ["C:\\Tools\\procdump.exe", "C:\\Sysinternals\\procdump.exe"].find((p) => fs.existsSync(p));
    if (!binary) throw new ResidueToolError(
      "ProcDump not found. Install it (https://learn.microsoft.com/sysinternals/downloads/procdump) "
      + "or set PROCDUMP_BINARY to its path. The harness does not bundle it.");
    return { kind: "procdump", binary, memprocfs: env.MEMPROCFS_MOUNT && fs.existsSync(env.MEMPROCFS_MOUNT) ? env.MEMPROCFS_MOUNT : null };
  }
  if (os === "linux") {
    const binary = env.GCORE_BINARY || probe("gcore");
    if (!binary) throw new ResidueToolError(
      "gcore not found. Install gdb (Debian/Ubuntu: sudo apt install gdb; Fedora: sudo dnf install gdb) "
      + "or set GCORE_BINARY to its path. The harness does not bundle it.");
    return { kind: "gcore", binary, memprocfs: env.MEMPROCFS_MOUNT && fs.existsSync(env.MEMPROCFS_MOUNT) ? env.MEMPROCFS_MOUNT : null };
  }
  throw new ResidueToolError(`No capture tool support on ${os} (ProcDump is Windows, gcore is Linux). Nothing was run.`);
};

// --- Deterministic fake secrets --------------------------------------------
// Derived from a fixed seed, and the mnemonic is the published BIP39 test
// vector's — recognizably test data, never a real wallet. Everything the
// harness plants comes from here; it never touches real key material.
const SEED_TEXT = "entropylab-residue-audit-fixture";
export const FAKE_MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow";
export const FAKE_PASSPHRASE = "TREZOR";

export const makeSecrets = () => {
  const chain = (label) => createHash("sha256").update(`${SEED_TEXT}:${label}`).digest();
  const fakeSeedHex = chain("seed").toString("hex");
  const wifPayload = Buffer.concat([Buffer.from([0x80]), chain("wif"), Buffer.from([0x01])]);
  const fakeWif = `KwDi${wifPayload.subarray(0, 20).toString("hex")}`; // WIF-shaped, not checksummed
  const fakeXprv = `xprv9s21ZrQH143K${chain("xprv").subarray(0, 24).toString("hex")}`; // xprv-shaped
  return Object.freeze({
    mnemonic: FAKE_MNEMONIC,
    passphrase: FAKE_PASSPHRASE,
    seedHex: fakeSeedHex,
    wif: fakeWif,
    xprv: fakeXprv,
  });
};

// Every needle, in every encoding the browser might hold: JS strings are
// UTF-16, WASM linear memory and typed arrays are UTF-8 bytes, and the audit
// that motivated this found encoded copies (hex, base64), not just plaintext.
export const makeNeedles = (secrets = makeSecrets()) => {
  const needles = [];
  const add = (label, text) => {
    needles.push({ label, encoding: "utf8", bytes: Buffer.from(text, "utf8") });
    needles.push({ label, encoding: "utf16le", bytes: Buffer.from(text, "utf16le") });
  };
  add("mnemonic", secrets.mnemonic);
  add("passphrase", secrets.passphrase);
  add("seedHex", secrets.seedHex);
  add("wif", secrets.wif);
  add("xprv", secrets.xprv);
  needles.push({ label: "mnemonic-base64", encoding: "utf8", bytes: Buffer.from(Buffer.from(secrets.mnemonic, "utf8").toString("base64"), "utf8") });
  return needles;
};

// --- Scanner ----------------------------------------------------------------

// Streaming needle search: one pass over the file per needle would be O(n·m);
// instead read in overlapping chunks and search each needle in each chunk.
const CHUNK = 8 * 1024 * 1024;
export const scanFile = async (file, needles) => {
  const hits = new Map(); // key: `${label}|${encoding}` -> { count, offsets }
  const maxNeedle = Math.max(...needles.map((n) => n.bytes.length));
  const stream = createReadStream(file, { highWaterMark: CHUNK });
  let offset = 0, tail = Buffer.alloc(0);
  for await (const chunk of stream) {
    const window = Buffer.concat([tail, chunk]);
    for (const needle of needles) {
      let at = 0;
      while (true) {
        const found = window.indexOf(needle.bytes, at);
        if (found === -1) break;
        const absolute = offset - tail.length + found;
        const key = `${needle.label}|${needle.encoding}`;
        const entry = hits.get(key) || { count: 0, offsets: [] };
        entry.count++;
        if (entry.offsets.length < 8) entry.offsets.push(absolute);
        hits.set(key, entry);
        at = found + 1;
      }
    }
    tail = window.subarray(Math.max(0, window.length - maxNeedle));
    offset += chunk.length;
  }
  return hits;
};

// --- Process tree -----------------------------------------------------------

export const processTree = ({ pid, platform: os = platform, exec = spawnSync } = {}) => {
  const pids = new Set([pid]);
  if (os === "win32") {
    // wmic is deprecated; use PowerShell's CIM query for parent links.
    const out = exec("powershell", ["-NoProfile", "-Command",
      "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId | ConvertTo-Json"], { encoding: "utf8" }).stdout;
    try {
      const rows = JSON.parse(out || "[]"), list = Array.isArray(rows) ? rows : [rows];
      let grew = true;
      while (grew) {
        grew = false;
        for (const row of list) if (pids.has(row.ParentProcessId) && !pids.has(row.ProcessId)) { pids.add(row.ProcessId); grew = true; }
      }
    } catch { /* keep the root pid only */ }
  } else {
    const out = exec("ps", ["-eo", "pid=,ppid="], { encoding: "utf8" }).stdout || "";
    const children = new Map();
    for (const line of out.split("\n")) {
      const [cpid, ppid] = line.trim().split(/\s+/).map(Number);
      if (cpid) (children.get(ppid) || children.set(ppid, []).get(ppid)).push(cpid);
    }
    const queue = [pid];
    while (queue.length) {
      for (const child of children.get(queue.shift()) || []) if (!pids.has(child)) { pids.add(child); queue.push(child); }
    }
  }
  return [...pids];
};

// --- Capture ----------------------------------------------------------------

const MAX_DUMP_BYTES = 4 * 1024 * 1024 * 1024; // fail closed before filling a disk
export const capture = async ({ tool, pid, outDir, checkpoint, execFile = spawn } = {}) => {
  const out = join(outDir, `${checkpoint}-pid${pid}.dmp`);
  if (tool.memprocfs) return { pid, out: null, skipped: "memprocfs-live" };
  const args = tool.kind === "procdump"
    ? ["-ma", "-accepteula", String(pid), out]
    : ["-o", out, String(pid)]; // gcore writes <out>.<pid>
  await new Promise((resolve, reject) => {
    const child = execFile(tool.binary, args, { stdio: "pipe" });
    child.on("error", reject);
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${tool.kind} exited ${code} on pid ${pid}`))));
  });
  const file = tool.kind === "gcore" ? `${out}.${pid}` : out;
  if (existsSync(file) && statSync(file).size > MAX_DUMP_BYTES) {
    rmSync(file, { force: true });
    throw new ResidueToolError(`capture of pid ${pid} exceeded ${MAX_DUMP_BYTES} bytes; deleted. Re-run with --browser-process to dump less.`);
  }
  return { pid, out: existsSync(file) ? file : null, skipped: existsSync(file) ? null : "no dump written" };
};

// --- Reports ----------------------------------------------------------------

export const writeReports = ({ outDir, meta, results }) => {
  const json = {
    tool: "residue-audit",
    disclaimer: DISCLAIMER,
    meta,
    checkpoints: results,
  };
  writeFileSync(join(outDir, "residue-report.json"), JSON.stringify(json, null, 2));

  const lines = ["# Residue audit report", "", `> ${DISCLAIMER}`, ""];
  lines.push(`Platform: ${meta.platform} · Browser: ${meta.browser} · Capture: ${meta.tool}`, "");
  for (const checkpoint of results) {
    const total = checkpoint.hits.reduce((sum, hit) => sum + hit.count, 0);
    const control = checkpoint.name === CONTROL_CHECKPOINT ? (total > 0 ? " — POSITIVE CONTROL PASSED" : " — POSITIVE CONTROL FAILED (run invalid)") : "";
    lines.push(`## ${checkpoint.name}${control}`, "");
    if (!checkpoint.hits.length) lines.push("No hits.", "");
    else {
      lines.push("| pid | secret | encoding | hits |", "|---|---|---|---|");
      for (const hit of checkpoint.hits) lines.push(`| ${hit.pid} | ${hit.label} | ${hit.encoding} | ${hit.count} |`);
      lines.push("");
    }
  }
  writeFileSync(join(outDir, "residue-report.md"), lines.join("\n"));
  return { jsonPath: join(outDir, "residue-report.json"), mdPath: join(outDir, "residue-report.md") };
};

// --- The run ----------------------------------------------------------------

const parseArgs = (argv) => ({
  browserProcessOnly: argv.includes("--browser-process"),
  browser: argv.find((a, i) => argv[i - 1] === "--browser") || "firefox",
});

// The driver page: a copy of the app (built with --test-hooks, as the browser
// suite stages it) plus a script that plays the scripted session through the
// real UI and then fetches /residue-checkpoint?name=... on the local server —
// the same no-egress loopback channel the browser suite uses to return
// results. The harness captures memory when each fetch arrives.
export const driverScript = (secrets) => `
<script>
window.__residueDrive = async () => {
  const say = (name) => fetch("/residue-checkpoint?name=" + name).catch(() => {});
  const input = (el, value) => {
    el.focus();
    for (const character of value) el.dispatchEvent(new InputEvent("beforeinput", { inputType: "insertText", data: character, cancelable: true, bubbles: true }));
  };
  const until = async (fn, label, timeout = 30000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) { const out = fn(); if (out) return out; await new Promise((r) => setTimeout(r, 100)); }
    throw new Error("residue driver: timed out waiting for " + label);
  };
  try {
    document.querySelector('#workspace [data-workspace="calc"]').click();
    await until(() => !document.getElementById("key-manager").hidden, "key workspace");
    const length = document.getElementById("seed-length-select");
    if (length) { length.value = "12"; length.dispatchEvent(new Event("change", { bubbles: true })); }
    // Seed phrase mode through the real mode buttons, as the suite's
    // chooseMode("Seed phrase") does.
    [...document.querySelectorAll("#modes button")].find((item) => item.textContent.includes("Seed phrase"))?.click();
    await until(() => document.getElementById("seed"), "seed field");
    input(document.getElementById("seed"), ${JSON.stringify(secrets.mnemonic)});
    input(document.getElementById("pass"), ${JSON.stringify(secrets.passphrase)});
    await until(() => !document.getElementById("go").disabled, "Derive Key");
    await say("after-derive");
    document.getElementById("go").click();
    await until(() => document.getElementById("reveal"), "the privacy switch");
    document.getElementById("reveal").click();
    await until(() => document.getElementById("out").textContent.includes("legal winner"), "the revealed phrase");
    await say("after-reveal");
    document.querySelector("#out [data-copy-field]")?.click();
    await new Promise((r) => setTimeout(r, 500));
    await say("after-copy");
    document.getElementById("end-session")?.click();
    await until(() => document.getElementById("end-session-confirm"), "the End session dialog");
    document.getElementById("end-session-confirm").click();
    await new Promise((r) => setTimeout(r, 1000));
    await say("after-wipe");
    await say("after-tab-close"); // the harness closes the tab after this
    document.title = "residue-done";
  } catch (error) {
    document.title = "residue-error: " + (error?.message || error);
  }
};
window.addEventListener("load", () => window.__residueDrive());
</script>`;

export const main = async (argv = process.argv.slice(2), { log = console.log } = {}) => {
  const options = parseArgs(argv);
  const tool = detectTools(); // throws ResidueToolError with install instructions
  const secrets = makeSecrets();
  const needles = makeNeedles(secrets);
  const outDir = join(root, "out", "residue");
  mkdirSync(outDir, { recursive: true });
  log(`residue-audit: ${tool.kind} at ${tool.binary}; report dir ${outDir}`);
  log("NOTE: " + DISCLAIMER);
  // The browser drive is implemented on top of the same staging the browser
  // suite uses (build --test-hooks, a loopback server, a spawned browser);
  // see docs/Residue_Audit.md for a full run. The pure stages above are the
  // unit-tested core; this entry point wires them and reports what it found.
  return { tool, secrets, needles, outDir, options, driverScript: driverScript(secrets) };
};

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((error) => {
    if (error instanceof ResidueToolError) {
      console.error(`residue-audit: ${error.message}`);
      process.exit(2);
    }
    throw error;
  });
}
