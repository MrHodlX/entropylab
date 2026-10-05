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
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, createReadStream } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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
      // Resume past what this needle already searched in the retained tail:
      // a match lying entirely inside the overlap was counted in the previous
      // chunk and must not be counted again here. The floor of
      // `tail.length - needle length + 1` (never below 0) is the first start
      // position the previous window could not have examined.
      let at = Math.max(0, tail.length - needle.bytes.length + 1);
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

// The control passes only on a hit labelled `mnemonic` — the value known to
// be on screen at CONTROL_CHECKPOINT. A hit on any other needle (the
// passphrase, a seed-hex encoding) does not prove the scanner can find the
// phrase itself.
const controlPassed = (checkpoint) =>
  Boolean(checkpoint) && checkpoint.name === CONTROL_CHECKPOINT
  && checkpoint.hits.some((hit) => hit.label === "mnemonic" && hit.count > 0);

export const writeReports = ({ outDir, meta, results }) => {
  const blind = (checkpoint) =>
    !checkpoint.hits.length && Array.isArray(checkpoint.entries) && checkpoint.entries.length > 0
    && checkpoint.entries.every((entry) => entry.skipped);

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
    const suffix = checkpoint.name !== CONTROL_CHECKPOINT ? ""
      : controlPassed(checkpoint) ? " — POSITIVE CONTROL PASSED" : " — POSITIVE CONTROL FAILED (run invalid)";
    // A checkpoint where every capture was skipped captured nothing; say so
    // rather than reporting a clean zero nobody scanned for.
    const blindNote = blind(checkpoint) ? ` — SKIPPED: no dump was captured (${[...new Set(checkpoint.entries.map((entry) => entry.skipped))].join("; ")})` : "";
    lines.push(`## ${checkpoint.name}${suffix}${blindNote}`, "");
    if (!checkpoint.hits.length) lines.push(blind(checkpoint) ? "No dump was scanned." : "No hits.", "");
    else {
      lines.push("| pid | secret | encoding | hits |", "|---|---|---|---|");
      for (const hit of checkpoint.hits) lines.push(`| ${hit.pid} | ${hit.label} | ${hit.encoding} | ${hit.count} |`);
      lines.push("");
    }
    const skips = (checkpoint.entries || []).filter((entry) => entry.skipped);
    if (skips.length) {
      for (const entry of skips) lines.push(`- pid ${entry.pid}: not captured — ${entry.skipped}`);
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
  browserExplicit: argv.includes("--browser"),
});

const CHECKPOINT_TIMEOUT = 60000;
const GIF = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The guard's normalization, defined as real code: a /\s+/ written literally
// inside the driver's template string would arrive in the page as /s+/ (an
// unrecognized escape drops the backslash) and corrupt every "s" in the
// field. Interpolating this function's own source keeps the regex intact.
const normalizeSeed = (text) => String(text).trim().toLowerCase().replace(/\s+/g, " ");

// The driver page: a copy of the app (built with --test-hooks, as the browser
// suite stages it) plus a script that plays the scripted session through the
// real UI. Checkpoints arrive as same-origin image requests — the app ships
// `connect-src 'none'`, so the page cannot fetch, but `img-src 'self'` allows
// an image against the harness — and the harness holds each response until it
// has captured that checkpoint, which is what pauses the driver exactly where
// the audit is looking.
export const driverScript = (secrets) => `
<script>
window.__residueDrive = async () => {
  const send = (name, params) => new Promise((resolve) => {
    const query = new URLSearchParams({ name });
    if (params) for (const [key, value] of Object.entries(params)) query.set(key, value);
    const image = new Image();
    image.onload = () => resolve();
    image.onerror = () => resolve();
    image.src = "/__residue?" + query.toString();
  });
  const say = send; // say() marks a checkpoint; the error path uses send() directly
  const input = (el, value) => {
    el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const until = async (fn, label, timeout = 30000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) { const out = fn(); if (out) return out; await new Promise((r) => setTimeout(r, 100)); }
    throw new Error("residue driver: timed out waiting for " + label);
  };
  try {
    // Boot assigns data-workspace after load; Firefox can fire load first.
    await until(() => document.querySelector('#workspace [data-workspace="calc"]'), "the workspace tab strip");
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
    // Guard rail: never derive anything but the fixture. Normalization
    // (case, whitespace) cannot turn a different phrase into the fixture, so
    // it is safe here and still refuses anything else. The mismatch message
    // carries shapes only — lengths and the codepoints at the first
    // difference — never field contents.
    const norm = ${normalizeSeed.toString()};
    const field = document.getElementById("seed").value;
    const value = norm(field);
    const fixture = ${JSON.stringify(secrets.mnemonic)};
    if (value !== fixture) {
      let diff = -1;
      for (let i = 0; i < Math.max(value.length, fixture.length); i++) {
        if (value[i] !== fixture[i]) { diff = i; break; }
      }
      throw new Error(
        "the seed field does not hold the fixture; refusing to derive"
        + " (rawLen=" + field.length + ", words=" + value.split(" ").length
        + ", len=" + value.length + ", fixture=" + fixture.length
        + ", diff@" + diff + ": field U+" + (value.charCodeAt(diff) || 0).toString(16)
        + " fixture U+" + (fixture.charCodeAt(diff) || 0).toString(16) + ")"
      );
    }
    // after-derive reports what the field actually holds; the harness refuses
    // to capture anything before comparing it against the fixture.
    await say("after-derive", { seed: value });
    document.getElementById("go").click();
    await until(() => document.getElementById("reveal"), "the privacy switch");
    const reveal = document.getElementById("reveal");
    if (!reveal.checked) reveal.click();
    await until(() => document.getElementById("out").textContent.includes("legal winner"), "the revealed phrase");
    await say("after-reveal");
    await until(() => document.querySelector("#out [data-copy-field]"), "a copy button in the derived wallet");
    document.querySelector("#out [data-copy-field]").click();
    await new Promise((r) => setTimeout(r, 500));
    await say("after-copy");
    // End session finishes with window.close(); keep this page alive to signal
    // the last two checkpoints — the harness closes the tab itself.
    window.close = () => {};
    document.getElementById("end-session")?.click();
    await until(() => document.getElementById("end-session-confirm"), "the End session dialog");
    document.getElementById("end-session-confirm").click();
    await until(() => document.querySelector("[data-session-ended]"), "the ended screen");
    await new Promise((r) => setTimeout(r, 500));
    await say("after-wipe");
    await say("after-tab-close"); // the harness closes the tab after this
    document.title = "residue-done";
  } catch (error) {
    const message = String((error && error.message) || error);
    document.title = "residue-error: " + message;
    await send("residue-error", { message });
  }
};
window.addEventListener("load", () => window.__residueDrive());
</script>`;

// Binary resolution for the three engines, mirroring the browser suite.
const ENGINES = [
  {
    id: "firefox", kind: "firefox",
    envVars: ["FIREFOX_BINARY"],
    pathNames: ["firefox", "firefox-developer-edition"],
    extraPaths: {
      darwin: ["/Applications/Firefox.app/Contents/MacOS/firefox"],
      win32: [
        "C:\\Program Files\\Firefox Developer Edition\\firefox.exe",
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
      ],
      linux: ["/usr/bin/firefox", "/usr/local/bin/firefox", "/snap/bin/firefox", "/opt/firefox/firefox"],
    },
  },
  {
    id: "chrome", kind: "chromium",
    envVars: ["CHROME_BINARY", "CHROMIUM_BINARY"],
    pathNames: ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"],
    extraPaths: {
      darwin: ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
      win32: [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
      ],
      linux: ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/snap/bin/chromium"],
    },
  },
  {
    id: "edge", kind: "chromium",
    envVars: ["EDGE_BINARY"],
    pathNames: ["microsoft-edge", "microsoft-edge-stable", "msedge"],
    extraPaths: {
      darwin: ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"],
      win32: ["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"],
      linux: ["/usr/bin/microsoft-edge", "/opt/microsoft/msedge/msedge"],
    },
  },
];

const pickEngine = (definition) => {
  for (const name of definition.envVars) if (process.env[name]) return { ...definition, binary: process.env[name] };
  for (const bin of definition.pathNames) {
    try {
      const probe = spawnSync(bin, ["--version"], { stdio: "pipe", timeout: 15000 });
      if (probe.status === 0) return { ...definition, binary: bin };
    } catch { /* not on PATH */ }
  }
  for (const candidate of definition.extraPaths[platform] ?? []) {
    if (existsSync(candidate)) return { ...definition, binary: candidate };
  }
  return null;
};

export const resolveBrowser = ({ browser: want, browserExplicit } = {}) => {
  const definition = ENGINES.find((engine) => engine.id === want);
  if (!definition) throw new ResidueToolError(`unknown --browser "${want}" (use firefox, chrome or edge)`);
  const found = pickEngine(definition);
  if (found) return found;
  if (browserExplicit) throw new ResidueToolError(`no ${want} binary found (set ${definition.envVars.join(" or ")})`);
  // Default preference is firefox; fall back to an installed engine.
  for (const engine of ENGINES) {
    if (engine.id === want) continue;
    const alternative = pickEngine(engine);
    if (alternative) return alternative;
  }
  throw new ResidueToolError("no browser found (set FIREFOX_BINARY, CHROME_BINARY or EDGE_BINARY)");
};

const chromiumSandboxArgs = () => {
  if (process.env.BROWSER_TEST_NO_SANDBOX || (typeof process.getuid === "function" && process.getuid() === 0)) return ["--no-sandbox"];
  return [];
};

const spawnBrowser = (engine, { profile, url, logPath }) => {
  const logFd = openSync(logPath, "w");
  const args = engine.kind === "firefox"
    ? ["--headless", "--new-instance", "--profile", profile, url]
    : [
        "--headless",
        ...chromiumSandboxArgs(),
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--window-size=1280,800",
        `--user-data-dir=${profile}`,
        // Random debugging port, written to <profile>/DevToolsActivePort;
        // the harness uses it to close the tab for after-tab-close.
        "--remote-debugging-port=0",
        url,
      ];
  const child = spawn(engine.binary, args, { stdio: ["ignore", logFd, logFd] });
  closeSync(logFd);
  child.on("error", () => {}); // surfaced by the missing pid check in main()
  return child;
};

// Build the staged app with test hooks and inject the driver, exactly the
// way the browser suite stages its own document. Everything lives in a temp
// directory outside the repository.
export const stageRun = async (secrets) => {
  const workDir = mkdtempSync(join(tmpdir(), "residue-audit-"));
  try {
    execFileSync(process.execPath, [join(root, "scripts", "build.mjs"), "--test-hooks", "--out", workDir], { stdio: "pipe" });
    const html = readFileSync(join(workDir, "entropylab.html"), "utf8");
    const page = html.replace(/<\/body>\s*<\/html>\s*$/, () => `${driverScript(secrets)}</body></html>\n`);
    if (page === html) throw new ResidueToolError("could not find </body></html> in the staged page to inject the driver");
    writeFileSync(join(workDir, "residue.html"), page);
    const profile = join(workDir, "profile");
    mkdirSync(profile, { recursive: true });
    writeFileSync(join(profile, "user.js"), [
      'user_pref("browser.shell.checkDefaultBrowser", false);',
      'user_pref("browser.startup.homepage_override.mstone", "ignore");',
      'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
      'user_pref("toolkit.telemetry.enabled", false);',
      "",
    ].join("\n"));
    return { workDir, pagePath: join(workDir, "residue.html"), profile };
  } catch (error) {
    rmSync(workDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    throw error;
  }
};

// The loopback server: serves the staged page, and holds every checkpoint
// response until main() has captured that checkpoint — the page's image load
// staying pending is what pauses the driver at the checkpoint.
const createHarnessServer = ({ pagePath, workDir }) => {
  const arrivals = [];
  let notify = null;
  const ack = (entry) => {
    if (entry.res.writableEnded) return;
    entry.res.writeHead(200, { "Content-Type": "image/gif", "Cache-Control": "no-store", "Content-Length": GIF.length });
    entry.res.end(GIF);
  };
  const server = createServer((request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    if (url.pathname === "/__residue") {
      arrivals.push({ name: url.searchParams.get("name"), params: url.searchParams, res: response });
      notify?.();
      return;
    }
    const file = url.pathname === "/" || url.pathname === "/residue.html"
      ? pagePath
      : url.pathname === "/service-worker.js" ? join(workDir, "service-worker.js") : null;
    if (!file || !existsSync(file)) {
      response.writeHead(404, { "Content-Type": "text/plain" });
      response.end("Not found");
      return;
    }
    response.writeHead(200, {
      "Content-Type": url.pathname.endsWith(".js") ? "text/javascript" : "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Length": statSync(file).size,
    });
    response.end(readFileSync(file));
  });
  const listen = () => new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
  const nextArrival = (timeoutMs) => new Promise((resolve, reject) => {
    if (arrivals.length) return resolve(arrivals.shift());
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      notify = null;
      reject(new ResidueToolError(`timed out after ${timeoutMs}ms waiting for the page to reach the next checkpoint (see the browser log)`));
    }, timeoutMs);
    notify = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      notify = null;
      resolve(arrivals.shift());
    };
  });
  return { server, listen, nextArrival, ack };
};

// Chromium publishes its debugging port in <user-data-dir>/DevToolsActivePort
// when started with --remote-debugging-port=0. Firefox exposes nothing this
// harness can drive, so its after-tab-close checkpoint records a skip instead.
const chromiumDebugPort = async (profile, timeoutMs = 15000) => {
  const file = join(profile, "DevToolsActivePort");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const [port] = readFileSync(file, "utf8").split("\n");
      if (/^\d+$/.test(port || "")) return Number(port);
    } catch {
      // Not written yet, or Chrome still holds it open (Windows: EBUSY).
      // Both resolve on the next poll.
    }
    await sleep(200);
  }
  return null;
};

const closeTab = async (port, origin) => {
  try {
    const targets = await fetch(`http://127.0.0.1:${port}/json/list`).then((response) => response.json());
    const target = targets.find((entry) => entry.type === "page" && entry.url.startsWith(origin))
      || targets.find((entry) => entry.type === "page");
    if (!target) return false;
    await fetch(`http://127.0.0.1:${port}/json/close/${target.id}`);
    return true;
  } catch {
    return false;
  }
};

const addHits = (hits, pid, found) => {
  for (const [key, value] of found) {
    const [label, encoding] = key.split("|");
    hits.push({ pid, label, encoding, count: value.count, offsets: value.offsets });
  }
};

// MemProcFS live scanning: walk the mount's per-process directory where the
// layout exposes one, scan every regular file under the size cap, and record
// an explicit skip (with the paths tried) where it does not — never a silent
// zero.
const scanLive = async ({ mount, pid, needles, hits }) => {
  const tried = [join(mount, String(pid)), join(mount, "proc", String(pid))];
  const dir = tried.find((candidate) => existsSync(candidate));
  const complaints = [];
  if (!dir) return { pid, out: null, skipped: `MemProcFS: no live pages at ${tried.join(" or ")}` };
  let scanned = 0;
  for (const name of readdirSync(dir)) {
    const file = join(dir, name);
    try {
      const stat = statSync(file);
      if (!stat.isFile()) continue;
      if (stat.size > MAX_DUMP_BYTES) {
        complaints.push(`${name}: over the ${MAX_DUMP_BYTES} byte cap`);
        continue;
      }
      addHits(hits, pid, await scanFile(file, needles));
      scanned++;
    } catch (error) {
      complaints.push(`${name}: ${error.message}`);
    }
  }
  if (!scanned) return { pid, out: null, skipped: `MemProcFS: nothing scannable in ${dir}${complaints.length ? ` (${complaints.join("; ")})` : ""}` };
  return { pid, out: null, scanned, ...(complaints.length ? { skipped: complaints.join("; ") } : {}) };
};

const captureAll = async ({ tool, pids, outDir, checkpoint, needles }) => {
  const entries = [], hits = [];
  for (const pid of pids) {
    let entry;
    if (tool.memprocfs) {
      entry = await scanLive({ mount: tool.memprocfs, pid, needles, hits });
    } else {
      // One PID refusing a dump (access denied, already exited) must not kill
      // the audit: record the failure per process. The positive control still
      // fails the run if nothing could be captured.
      try {
        entry = await capture({ tool, pid, outDir, checkpoint });
        if (entry.out) {
          try {
            addHits(hits, pid, await scanFile(entry.out, needles));
            entry.scanned = 1;
          } catch (error) {
            entry.skipped = `scan failed: ${error.message}`;
          }
        }
      } catch (error) {
        entry = { pid, out: null, skipped: `capture failed: ${error.message}` };
      }
    }
    entries.push(entry);
  }
  return { entries, hits };
};

export const main = async (argv = process.argv.slice(2), { log = console.log, detect = detectTools, stage = stageRun, browser: browserOverride = null } = {}) => {
  const options = parseArgs(argv);
  const tool = detect(); // throws ResidueToolError with install instructions
  const secrets = makeSecrets();
  const needles = makeNeedles(secrets);
  const outDir = join(root, "out", "residue");
  mkdirSync(outDir, { recursive: true });
  log(`residue-audit: ${tool.kind} at ${tool.binary}; report dir ${outDir}`);
  log("NOTE: " + DISCLAIMER);
  const browser = browserOverride || resolveBrowser(options);
  log(`residue-audit: driving ${browser.id} at ${browser.binary}`);
  const startedAt = new Date().toISOString();
  const staged = await stage(secrets);
  let child = null, served = null;
  try {
    served = createHarnessServer(staged);
    const port = await served.listen();
    const origin = `http://127.0.0.1:${port}`;
    const logPath = join(staged.workDir, "browser.log");
    child = spawnBrowser(browser, { profile: staged.profile, url: `${origin}/`, logPath });
    if (!child.pid) throw new ResidueToolError(`the browser failed to start: ${browser.binary} (see ${logPath})`);
    log(`residue-audit: browser pid ${child.pid}; log ${logPath}`);
    const debugPort = browser.kind === "chromium" ? await chromiumDebugPort(staged.profile) : null;

    const results = [];
    for (const checkpoint of CHECKPOINTS) {
      const arrival = await served.nextArrival(CHECKPOINT_TIMEOUT);
      if (arrival.name === "residue-error") {
        served.ack(arrival);
        throw new ResidueToolError(`the page reported an error: ${arrival.params.get("message") || "(no message)"}`);
      }
      if (arrival.name !== checkpoint) {
        served.ack(arrival);
        throw new ResidueToolError(`expected checkpoint ${checkpoint}, the page signalled ${arrival.name}`);
      }
      // Guard rail: the fixture only. Checked before any capture, so a
      // session holding anything else is never scanned.
      if (checkpoint === "after-derive" && (arrival.params.get("seed") || "") !== secrets.mnemonic) {
        served.ack(arrival);
        throw new ResidueToolError("refusing to capture: the seed field reported something other than the fixture — this harness must never scan a session holding real material");
      }
      const closing = checkpoint === "after-tab-close";
      if (closing) served.ack(arrival); // let the page finish, then close the tab

      const entries = [], hits = [];
      let pids = null;
      if (closing) {
        if (debugPort && await closeTab(debugPort, origin)) {
          await sleep(1500); // let the renderer exit before re-enumerating
          pids = options.browserProcessOnly ? [child.pid] : processTree({ pid: child.pid });
        } else {
          entries.push({
            pid: child.pid,
            skipped: debugPort ? "the debugging port did not close the tab" : "no debugging port on this engine; the tab was not closed",
          });
        }
      } else {
        pids = options.browserProcessOnly ? [child.pid] : processTree({ pid: child.pid });
      }
      if (pids) {
        const captured = await captureAll({ tool, pids, outDir, checkpoint, needles });
        entries.push(...captured.entries);
        hits.push(...captured.hits);
      }
      if (!closing) served.ack(arrival); // resume the page only after the capture

      results.push({ name: checkpoint, entries, hits });
      log(`residue-audit: ${checkpoint}: ${entries.length} process(es), ${hits.reduce((sum, hit) => sum + hit.count, 0)} hit(s)`);
    }

    const meta = {
      platform,
      browser: browser.id,
      browserBinary: browser.binary,
      tool: tool.kind,
      captureBinary: tool.binary,
      pid: child.pid,
      startedAt,
    };
    const paths = writeReports({ outDir, meta, results });
    log(`residue-audit: report ${paths.mdPath}`);
    const control = results.find((result) => result.name === CONTROL_CHECKPOINT);
    if (!controlPassed(control)) {
      throw new ResidueToolError(`positive control FAILED at ${CONTROL_CHECKPOINT}: the mnemonic was not found where it is known to be on screen — run INVALID. See ${paths.mdPath}`);
    }
    log("residue-audit: positive control passed. Read the limitations before trusting any zero.");
    return { tool, options, browser, outDir, checkpoints: results, ...paths };
  } finally {
    if (child) { try { child.kill("SIGKILL"); } catch { /* already gone */ } }
    if (served) { try { served.server.close(); } catch { /* already closed */ } }
    await sleep(300); // Windows releases profile file handles after the kill
    // The browser log lives inside the work dir; failure messages point at it,
    // so keep a copy where the reports land (out/residue is gitignored).
    try {
      const logPath = join(staged.workDir, "browser.log");
      if (existsSync(logPath)) copyFileSync(logPath, join(outDir, "browser.log"));
    } catch { /* nothing to keep */ }
    rmSync(staged.workDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  }
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
