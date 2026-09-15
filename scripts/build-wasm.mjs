// Builds the WASM artifacts from the pinned Rust sources and writes them as
// committed, importable JS modules (base64 + sha256 of the wasm bytes):
//   entropylab-wasm/ -> src/js/entropylab-wasm-b64.js
//   psbt-wasm/       -> src/js/psbt-wasm-b64.js
//   vanity-wasm/     -> src/js/vanity-wasm-b64.js
//
// The generated modules are committed so that `npm run build` keeps working
// with Node alone. CI rebuilds them from the Rust sources (pinned by each
// crate's rust-toolchain.toml and Cargo.lock) inside the digest-pinned
// toolchain image defined by Dockerfile.wasm (pinned base image, apt
// snapshot, clang, and Rust — issue #449), builds them twice from scratch,
// and fails unless both runs are byte-identical; it then runs the WASM test
// suites against the fresh build, so a stale committed copy cannot survive.
// The artifact job commits the pinned image's copy back after each merge.
// SOURCE_DATE_EPOCH below keeps the wall clock out of the binaries, and
// build-host paths are remapped so they do not carry the builder's home
// directory.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

// Keep the wall clock out of the binaries: clang and rustc honor
// SOURCE_DATE_EPOCH (reproducible-builds.org), so default it to the current
// commit's timestamp — two builds of the same commit always agree, on any
// machine, without stamping in when the build happened.
if (!process.env.SOURCE_DATE_EPOCH) {
  let stamp;
  try {
    stamp = execFileSync("git", ["log", "-1", "--format=%ct"], { cwd: root, encoding: "utf8" }).trim();
  } catch {
    throw new Error("SOURCE_DATE_EPOCH is unset and the commit timestamp is unreadable (not a git checkout?) — set SOURCE_DATE_EPOCH explicitly");
  }
  process.env.SOURCE_DATE_EPOCH = stamp;
}

// Without a remap, rustc bakes the builder's absolute paths (e.g.
// /home/<user>/.cargo/...) into panicking code of registry sources, which
// both fingerprints the build host and breaks cross-machine comparisons.
const home = process.env.HOME ?? "";
const rustflags = [
  `--remap-path-prefix=${home}/.cargo/=cargo/`,
  `--remap-path-prefix=${home}/.rustup/=rustup/`,
].join(" ");

const crates = [
  {
    dir: "entropylab-wasm",
    wasm: "entropylab_wasm.wasm",
    out: "src/js/entropylab-wasm-b64.js",
    symbol: "ENTROPYLAB_WASM_B64",
    blurb: `// libsecp256k1 v0.4.1 (vendored by secp256k1-sys 0.10.1 via secp256k1 0.29.1),
// bitcoin_hashes 0.14.101, rust-bitcoin 0.32.11, rust-bip39 2.2.2,
// base58ck 0.1.101, bech32 0.11.1, and scrypt 0.12.0 (see
// entropylab-wasm/Cargo.lock) compiled to WebAssembly from entropylab-wasm/
// with the pinned Rust 1.95.0 toolchain.
//
// This artifact also compiles in the AEZ v5 module vendored at
// entropylab-wasm/src/aez/ from the zears crate 0.2.1
// (https://codeberg.org/dunj3/zears). Unlike the rest of EntropyLab (public
// domain), that module — and this derived artifact — carry the MIT license:
//
//   Copyright 2025 Daniel Schadt
//
//   Permission is hereby granted, free of charge, to any person obtaining a
//   copy of this software and associated documentation files (the
//   "Software"), to deal in the Software without restriction, including
//   without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to
//   permit persons to whom the Software is furnished to do so, subject to
//   the following conditions:
//
//   The above copyright notice and this permission notice shall be included
//   in all copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
//   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
//   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//`,
  },
  {
    dir: "psbt-wasm",
    wasm: "psbt_wasm.wasm",
    out: "src/js/psbt-wasm-b64.js",
    symbol: "PSBT_WASM_B64",
    blurb: `// rust-bitcoin 0.32.102 (see psbt-wasm/Cargo.lock) compiled to WebAssembly
// from psbt-wasm/ with the pinned Rust 1.95.0 toolchain.`,
  },
  {
    dir: "vanity-wasm",
    wasm: "vanity_wasm.wasm",
    out: "src/js/vanity-wasm-b64.js",
    symbol: "VANITY_WASM_B64",
    blurb: `// libsecp256k1 0.8.0 (vendored by secp256k1-sys 0.14.0, see
// vanity-wasm/Cargo.lock) plus sha2 0.10.9 / ripemd 0.1.3, compiled to
// WebAssembly from vanity-wasm/ with the pinned Rust 1.95.0 toolchain.`,
  },
];

for (const crate of crates) {
  const crateDir = join(root, crate.dir);
  const wasmPath = join(crateDir, `target/wasm32-unknown-unknown/release/${crate.wasm}`);
  const outPath = join(root, crate.out);

  execFileSync(
    "cargo",
    ["build", "--locked", "--release", "--target", "wasm32-unknown-unknown"],
    { cwd: crateDir, stdio: "inherit", env: { ...process.env, RUSTFLAGS: rustflags } }
  );

  const wasm = readFileSync(wasmPath);
  const sha256 = createHash("sha256").update(wasm).digest("hex");
  const b64 = wasm.toString("base64");

  const out = `// GENERATED FILE - do not edit. Rebuild with \`npm run build:wasm\`.
${crate.blurb} wasm sha256: ${sha256}
export const ${crate.symbol} =
  "${b64}";
`;

  writeFileSync(outPath, out);
  console.log(`Built ${crate.dir} WASM artifact`);
  console.log(`  ${wasm.length} bytes wasm, sha256 ${sha256}`);
  console.log(`  wrote ${outPath} (${Buffer.byteLength(out, "utf8")} bytes)`);
}
