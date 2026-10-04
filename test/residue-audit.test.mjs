// Unit tests for the pure parts of the dev-only residue harness
// (scripts/residue-audit.mjs): tool detection, the deterministic fake-secret
// factory, the needle scanner, the report writer, and the checkpoint list.
// These run without any capture tool installed — the full harness needs
// ProcDump (Windows) or gcore (Linux) and is run by hand.
// Run with `npm test` (part of the CI list).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CHECKPOINTS,
  CONTROL_CHECKPOINT,
  DISCLAIMER,
  ResidueToolError,
  detectTools,
  makeSecrets,
  makeNeedles,
  scanFile,
  writeReports,
  driverScript,
} from "../scripts/residue-audit.mjs";

const tmp = () => mkdtempSync(join(tmpdir(), "residue-test-"));

test("the checkpoint list is the documented order, with the positive control before the wipe", () => {
  assert.deepEqual([...CHECKPOINTS], ["after-derive", "after-reveal", "after-copy", "after-wipe", "after-tab-close"]);
  assert.equal(CONTROL_CHECKPOINT, "after-reveal");
  assert.ok(CHECKPOINTS.indexOf(CONTROL_CHECKPOINT) < CHECKPOINTS.indexOf("after-wipe"), "the control must run while secrets are still on screen");
});

test("tool detection: Windows needs ProcDump, with env override winning", () => {
  const fsNever = { existsSync: () => false };
  assert.throws(
    () => detectTools({ env: {}, probe: () => null, fs: fsNever, platform: "win32" }),
    (error) => error instanceof ResidueToolError && /ProcDump not found/.test(error.message) && /PROCDUMP_BINARY/.test(error.message),
  );
  const viaEnv = detectTools({ env: { PROCDUMP_BINARY: "C:\\tools\\procdump.exe" }, probe: () => null, fs: fsNever, platform: "win32" });
  assert.equal(viaEnv.kind, "procdump");
  assert.equal(viaEnv.binary, "C:\\tools\\procdump.exe");
  const viaPath = detectTools({ env: {}, probe: (bin) => (bin === "procdump64" ? "procdump64" : null), fs: fsNever, platform: "win32" });
  assert.equal(viaPath.binary, "procdump64");
  const viaInstallDir = detectTools({ env: {}, probe: () => null, fs: { existsSync: (p) => p === "C:\\Sysinternals\\procdump.exe" }, platform: "win32" });
  assert.equal(viaInstallDir.binary, "C:\\Sysinternals\\procdump.exe");
});

test("tool detection: Linux needs gcore, and MemProcFS is an optional extra, never required", () => {
  const fsNever = { existsSync: () => false };
  assert.throws(
    () => detectTools({ env: {}, probe: () => null, fs: fsNever, platform: "linux" }),
    (error) => error instanceof ResidueToolError && /gcore not found/.test(error.message),
  );
  const withGcore = detectTools({ env: {}, probe: (bin) => (bin === "gcore" ? "gcore" : null), fs: fsNever, platform: "linux" });
  assert.equal(withGcore.kind, "gcore");
  assert.equal(withGcore.memprocfs, null, "no MemProcFS mount, no deep mode");
  const deep = detectTools({ env: { MEMPROCFS_MOUNT: "/mem" }, probe: () => "gcore", fs: { existsSync: (p) => p === "/mem" }, platform: "linux" });
  assert.equal(deep.memprocfs, "/mem");
});

test("tool detection: other platforms fail clearly and run nothing", () => {
  assert.throws(
    () => detectTools({ env: {}, probe: () => null, fs: { existsSync: () => false }, platform: "darwin" }),
    (error) => error instanceof ResidueToolError && /darwin|No capture tool support/.test(error.message),
  );
});

test("the fake secrets are deterministic, well-shaped, and the mnemonic is the published test vector", () => {
  const first = makeSecrets(), second = makeSecrets();
  assert.deepEqual(first, second, "the factory must be deterministic");
  assert.equal(first.mnemonic.split(" ").length, 12);
  assert.equal(first.mnemonic, "legal winner thank year wave sausage worth useful legal winner thank yellow", "the published BIP39 vector, recognizable as test data");
  assert.match(first.seedHex, /^[0-9a-f]{64}$/);
  assert.match(first.wif, /^KwDi[0-9a-f]{40}$/, "WIF-shaped, not checksummed — never spendable");
  assert.match(first.xprv, /^xprv9s21ZrQH143K[0-9a-f]{48}$/, "xprv-shaped, not a real key");
  assert.equal(first.passphrase, "TREZOR");
});

test("needles cover every secret in UTF-8 and UTF-16LE, plus a base64 form", () => {
  const needles = makeNeedles();
  const byLabel = new Map();
  for (const needle of needles) byLabel.set(needle.label, (byLabel.get(needle.label) || 0) + 1);
  for (const label of ["mnemonic", "passphrase", "seedHex", "wif", "xprv"]) {
    assert.equal(byLabel.get(label), 2, `${label} needs both encodings`);
  }
  assert.equal(byLabel.get("mnemonic-base64"), 1, "the audit found encoded copies; scan for one");
  const utf16 = needles.find((n) => n.label === "passphrase" && n.encoding === "utf16le");
  assert.deepEqual([...utf16.bytes.subarray(0, 4)], [0x54, 0x00, 0x52, 0x00], "UTF-16LE: T\\0R\\0");
});

test("the scanner finds needles in both encodings with correct offsets, and reports zero for clean buffers", async () => {
  const dir = tmp();
  try {
    const secrets = makeSecrets(), needles = makeNeedles();
    const file = join(dir, "dump.bin");
    const pad = Buffer.alloc(1024, 0x41);
    const utf8Needle = Buffer.from(secrets.passphrase, "utf8");
    const utf16Needle = Buffer.from(secrets.mnemonic, "utf16le");
    writeFileSync(file, Buffer.concat([pad, utf8Needle, Buffer.alloc(512, 0x42), utf16Needle, Buffer.alloc(64, 0x43)]));
    const hits = await scanFile(file, needles);
    const passUtf8 = hits.get("passphrase|utf8");
    assert.equal(passUtf8.count, 1);
    assert.equal(passUtf8.offsets[0], 1024);
    const mnemUtf16 = hits.get("mnemonic|utf16le");
    assert.equal(mnemUtf16.count, 1);
    assert.equal(mnemUtf16.offsets[0], 1024 + utf8Needle.length + 512);
    assert.equal(hits.get("wif|utf8"), undefined, "a secret that was never planted must not appear");

    const clean = join(dir, "clean.bin");
    writeFileSync(clean, Buffer.alloc(4096, 0));
    const none = await scanFile(clean, needles);
    assert.equal(none.size, 0, "a clean buffer reports no hits");

    const empty = join(dir, "empty.bin");
    writeFileSync(empty, "");
    assert.equal((await scanFile(empty, needles)).size, 0, "an empty dump is handled");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the scanner catches a needle split across the chunk boundary", async () => {
  const dir = tmp();
  try {
    const secrets = makeSecrets(), needles = makeNeedles();
    const needle = Buffer.from(secrets.seedHex, "utf8");
    const file = join(dir, "boundary.bin");
    // Plant the needle straddling the 8 MiB chunk boundary.
    const before = Buffer.alloc(8 * 1024 * 1024 - 10, 0x44);
    writeFileSync(file, Buffer.concat([before, needle, Buffer.alloc(64, 0x45)]));
    const hits = await scanFile(file, needles);
    assert.equal(hits.get("seedHex|utf8").count, 1, "a needle split across chunks was missed");
    assert.equal(hits.get("seedHex|utf8").offsets[0], before.length);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the driver script embeds only the fake secrets and parses as JavaScript", () => {
  const secrets = makeSecrets();
  const script = driverScript(secrets);
  assert.match(script, new RegExp(secrets.mnemonic));
  assert.match(script, new RegExp(secrets.passphrase));
  assert.doesNotMatch(script, /seedHex|fakeWif/, "the driver plants only the mnemonic and passphrase");
  // Every checkpoint the harness expects is signalled, in order.
  const order = [...script.matchAll(/say\("([a-z-]+)"\)/g)].map((match) => match[1]);
  assert.deepEqual(order, ["after-derive", "after-reveal", "after-copy", "after-wipe", "after-tab-close"]);
  // The embedded script is syntactically valid JS (strip the wrapper tags).
  const js = script.replace(/<\/?script>/g, "");
  new Function(js); // throws on a syntax error
});

test("the reports carry the disclaimer and call out the positive control", () => {
  const dir = tmp();
  try {
    const { jsonPath, mdPath } = writeReports({
      outDir: dir,
      meta: { platform: "win32", browser: "firefox", tool: "procdump" },
      results: [
        { name: "after-reveal", hits: [{ pid: 1234, label: "mnemonic", encoding: "utf16le", count: 3 }] },
        { name: "after-wipe", hits: [] },
      ],
    });
    const json = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.equal(json.disclaimer, DISCLAIMER);
    assert.equal(json.checkpoints.length, 2);
    const md = readFileSync(mdPath, "utf8");
    assert.match(md, /Zero hits is not proof of erasure/);
    assert.match(md, /after-reveal — POSITIVE CONTROL PASSED/);
    assert.match(md, /after-wipe[\s\S]*?No hits\./);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a run whose positive control finds nothing is marked invalid in the report", () => {
  const dir = tmp();
  try {
    const { mdPath } = writeReports({
      outDir: dir,
      meta: { platform: "linux", browser: "chrome", tool: "gcore" },
      results: [{ name: "after-reveal", hits: [] }],
    });
    assert.match(readFileSync(mdPath, "utf8"), /POSITIVE CONTROL FAILED \(run invalid\)/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
