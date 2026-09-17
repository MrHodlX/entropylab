// Toolchain pins must agree across the files that carry them, or
// "reproducible build" quietly means something different depending on where
// it runs: the CI workflow's NODE_VERSION drives every GitHub job, the
// Dockerfile's ARG NODE_VERSION drives the dev image, and each crate's
// rust-toolchain.toml drives `npm run build:wasm` (the image's
// `rustup target add --toolchain` must name the same channel). This suite
// owns the agreement; the pins themselves live in those files.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

test("the CI workflow and the Dockerfile pin the same exact Node version", () => {
  const workflow = read(".github/workflows/ci-cd.yml").match(/^  NODE_VERSION: "([^"]+)"$/m);
  const dockerfile = read("Dockerfile").match(/^ARG NODE_VERSION=v(.+)$/m);
  assert.ok(workflow, "ci-cd.yml carries an exact NODE_VERSION pin");
  assert.ok(dockerfile, "Dockerfile carries ARG NODE_VERSION");
  assert.equal(workflow[1], dockerfile[1]);
});

test("all WASM crates and the dev image pin the same Rust channel", () => {
  const channels = ["entropylab-wasm", "psbt-wasm", "vanity-wasm"].map((crate) => {
    const channel = read(`${crate}/rust-toolchain.toml`).match(/^channel = "([^"]+)"$/m);
    assert.ok(channel, `${crate}/rust-toolchain.toml pins a channel`);
    return channel[1];
  });
  assert.equal(new Set(channels).size, 1, "the three crates pin one channel");
  const image = read("Dockerfile").match(/--toolchain (\S+)/);
  assert.ok(image, "Dockerfile adds the wasm target for an explicit toolchain");
  assert.equal(image[1], channels[0]);
});
