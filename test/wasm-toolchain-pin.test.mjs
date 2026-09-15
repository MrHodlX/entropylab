// WASM toolchain pin guard (issue #449): the crypto WASM is libsecp256k1's C
// compiled by clang, and a floating toolchain makes the bytes move between
// machines. Dockerfile.wasm pins everything that can move — the base image by
// digest, apt to a dated snapshot.ubuntu.com snapshot, clang and Rust to
// exact versions — and the build-wasm CI job builds the artifacts twice from
// scratch inside that image and fails unless both runs are byte-identical.
// This suite fails if any of those pins, or the reproducibility gate, goes
// soft.
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const dockerfile = read("Dockerfile.wasm");
const workflow = read(".github/workflows/ci-cd.yml");
const wasmArtifacts = ["src/js/entropylab-wasm-b64.js", "src/js/psbt-wasm-b64.js", "src/js/vanity-wasm-b64.js"];

test("the WASM builder image is pinned to a base-image digest", () => {
  assert.match(
    dockerfile,
    /^FROM ubuntu:24\.04@sha256:[0-9a-f]{64}$/m,
    "Dockerfile.wasm must pin the base image by manifest digest, not a floating tag",
  );
});

test("apt is pinned to a dated snapshot.ubuntu.com snapshot", () => {
  assert.match(dockerfile, /snapshot\.ubuntu\.com\/ubuntu\//, "apt sources must point at snapshot.ubuntu.com");
  assert.match(dockerfile, /APT_SNAPSHOT=\d{8}T\d{6}Z/, "the snapshot must be a dated timestamp");
  assert.match(
    dockerfile,
    /\/etc\/apt\/sources\.list\.d\/ubuntu\.sources/,
    "the pinned snapshot must replace the floating apt sources",
  );
});

test("the clang package versions are pinned", () => {
  assert.match(dockerfile, /clang=\d[^\s]*/, "the clang metapackage version must be pinned");
  assert.match(dockerfile, /clang-18=\d[^\s]*/, "the clang-18 package version must be pinned");
});

test("the image's Rust toolchain matches the crates' rust-toolchain.toml", () => {
  for (const crate of ["entropylab-wasm", "psbt-wasm", "vanity-wasm"]) {
    const channel = read(`${crate}/rust-toolchain.toml`).match(/^channel = "([^"]+)"$/m)?.[1];
    assert.ok(channel, `${crate}/rust-toolchain.toml declares no channel`);
    assert.ok(
      dockerfile.includes(`--default-toolchain ${channel}`),
      `Dockerfile.wasm must install the ${channel} toolchain pinned by ${crate}/rust-toolchain.toml`,
    );
  }
  assert.match(dockerfile, /rustup target add wasm32-unknown-unknown/, "the image must add the wasm32 target");
});

test("the build-wasm job builds the pinned image and gates on byte identity", () => {
  const job = workflow.match(/^  build-wasm:\n([\s\S]*?)(?=^  \w)/m)?.[1] ?? "";
  assert.ok(job, "the build-wasm job is missing");
  assert.match(job, /docker build -f Dockerfile\.wasm/, "the build-wasm job must build the pinned image");
  const builds = job.match(/npm run build:wasm/g) ?? [];
  assert.ok(builds.length >= 2, "the build-wasm job must build the artifacts twice");
  assert.match(job, /rm -rf .*target/, "the second build must start from scratch");
  assert.match(job, /wasm-sha256-run1\.txt/, "the first build's digests must be recorded");
  assert.match(job, /wasm-sha256-run2\.txt/, "the second build's digests must be recorded");
  assert.match(
    job,
    /diff wasm-sha256-run1\.txt wasm-sha256-run2\.txt/,
    "the job must fail when the two builds differ",
  );
});

test("both SHA256SUMS.txt producers hash the three WASM artifacts", () => {
  const line = `sha256sum entropylab.html ${wasmArtifacts.join(" ")} > SHA256SUMS.txt`;
  const occurrences = workflow.split(line).length - 1;
  assert.equal(occurrences, 2, "the build and artifact jobs must both publish the WASM artifact hashes");
});

test("the WASM build keeps the wall clock out of the binaries", () => {
  const buildScript = read("scripts/build-wasm.mjs");
  assert.match(buildScript, /process\.env\.SOURCE_DATE_EPOCH/, "build-wasm.mjs must set SOURCE_DATE_EPOCH");
  assert.match(
    buildScript,
    /git", \["log", "-1", "--format=%ct"\]/,
    "SOURCE_DATE_EPOCH must default to the current commit's timestamp",
  );
});
