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

// The crates build-wasm compiles, derived from the build script itself so a
// crate added there without the matching pins fails here rather than
// drifting past a hard-coded list.
const buildCrates = () => [...read("scripts/build-wasm.mjs").matchAll(/^\s+dir: "([^"]+)",$/gm)].map((m) => m[1]);

test("the CI workflow and the Dockerfile pin the same exact Node version", () => {
  const workflow = read(".github/workflows/ci-cd.yml").match(/^  NODE_VERSION: "([^"]+)"$/m);
  const dockerfile = read("Dockerfile").match(/^ARG NODE_VERSION=v(.+)$/m);
  assert.ok(workflow, "ci-cd.yml carries an exact NODE_VERSION pin");
  assert.ok(dockerfile, "Dockerfile carries ARG NODE_VERSION");
  assert.equal(workflow[1], dockerfile[1]);
});

test("all WASM crates and the dev image pin the same Rust channel", () => {
  const channels = buildCrates().map((crate) => {
    const channel = read(`${crate}/rust-toolchain.toml`).match(/^channel = "([^"]+)"$/m);
    assert.ok(channel, `${crate}/rust-toolchain.toml pins a channel`);
    return channel[1];
  });
  assert.equal(new Set(channels).size, 1, "the three crates pin one channel");
  const image = read("Dockerfile").match(/--toolchain (\S+)/);
  assert.ok(image, "Dockerfile adds the wasm target for an explicit toolchain");
  assert.equal(image[1], channels[0]);
});

// #527: the warm-up must pre-fetch every crate's dependency graph, and the
// shared CARGO_HOME must be writable by the image's default user — otherwise
// the documented `docker compose run dev npm run build:wasm` needs network
// and dies on the root-owned registry, which CI never sees (it runs as root).
// The crate list comes from build-wasm.mjs, so a crate added there without a
// warm-up fails here.
test("the dev image pre-fetches every crate and chowns the cargo home to dev", () => {
  const dockerfile = read("Dockerfile");
  const block = dockerfile.match(/RUN cd (\/warm\/\S+) \\\n[\s\S]*?cargo fetch/);
  assert.ok(block, "the image warms the cargo registry before switching to dev");
  const fetched = [block[1], ...[...dockerfile.matchAll(/&& cd (\/warm\/\S+) \\\n\s*&& cargo fetch/g)].map((m) => m[1])];
  for (const crate of buildCrates()) {
    const warmDir = dockerfile.match(new RegExp(`^COPY ${crate}/ (/warm/\\S+)/$`, "m"));
    assert.ok(warmDir, `Dockerfile copies ${crate} into the warm-up`);
    assert.ok(fetched.includes(warmDir[1]), `${crate}'s dependency graph is cargo-fetched in the warm-up`);
  }
  const chown = dockerfile.match(/^RUN chown -R dev:dev (.+?)( && .*)?$/m);
  assert.ok(chown, "the image chowns shared caches to the dev user");
  assert.match(chown[1], /\/usr\/local\/npm-cache/);
  assert.match(chown[1], /\/usr\/local\/cargo/, "CARGO_HOME is writable by dev (issue #527)");
});

test("the dev image pins linux/amd64, one Ubuntu snapshot, and exact clang", () => {
  const dockerfile = read("Dockerfile");
  assert.match(dockerfile, /^FROM --platform=linux\/amd64 ubuntu:24\.04@sha256:496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4$/m);
  assert.doesNotMatch(dockerfile, /sha256:69cecf4bbf72d2d44a9eef1b71fb98c7fb973d78af11399deccef19beb008ad9/, "the multi-arch index is not a clang pin");
  assert.match(dockerfile, /^ARG UBUNTU_SNAPSHOT=20260916T000000Z$/m);
  assert.match(dockerfile, /snapshot\.ubuntu\.com\/ubuntu\/\$\{UBUNTU_SNAPSHOT\}/);
  assert.match(dockerfile, /^ARG CLANG_VERSION=1:18\.0-59~exp2$/m);
  assert.match(dockerfile, /^ARG CLANG18_VERSION=1:18\.1\.3-1ubuntu1$/m);
  assert.match(dockerfile, /"clang=\$\{CLANG_VERSION\}"/);
  assert.match(dockerfile, /"clang-18=\$\{CLANG18_VERSION\}"/);
  // clang-18 pins libllvm18 and friends with `=` but only lower-bounds
  // libclang-cpp18, which the clang binary links.
  assert.match(dockerfile, /"libclang-cpp18=\$\{CLANG18_VERSION\}"/);
  assert.match(dockerfile, /snapshot="https:\/\/snapshot\.ubuntu\.com\/ubuntu\/\$\{UBUNTU_SNAPSHOT\}"/, "the snapshot is fetched over https");
  assert.doesNotMatch(dockerfile, /http:\/\/snapshot\.ubuntu\.com/, "the snapshot service is served over https");
});

test("the snapshot bootstrap skips TLS peer checks for ca-certificates only, and fails loudly", () => {
  const dockerfile = read("Dockerfile");
  // The base image has no CA bundle. Only the first index fetch and the
  // ca-certificates install may skip peer checks (apt's InRelease signature
  // check still covers both); every later apt call verifies TLS.
  const unverified = (dockerfile.match(/^.*Verify-Peer=false.*$/gm) ?? []).map((line) => line.trim());
  assert.deepEqual(unverified, [
    "apt-get -o Acquire::https::Verify-Peer=false update --error-on=any; \\",
    "apt-get -o Acquire::https::Verify-Peer=false install -y --no-install-recommends \\",
  ]);
  assert.match(dockerfile, /Verify-Peer=false install -y --no-install-recommends \\\n\s+ca-certificates; \\\n\s+apt-get update --error-on=any; \\\n/);
  assert.doesNotMatch(dockerfile, /apt\.conf/, "the bootstrap option must not persist into apt configuration");
  // Without --error-on=any a failed index fetch is only a warning, and the
  // build dies later on "Unable to locate package" (exit 100).
  assert.match(dockerfile, /^\s+apt-get update --error-on=any; \\$/m);
  // A sources file the sed does not fully rewrite must stop the build rather
  // than install from the live archive.
  assert.match(dockerfile, /pinned=\$\(grep -c "\^URIs: \$\{snapshot\}\/\*\$" "\$sources" \|\| true\)/);
  assert.match(dockerfile, /if \[ "\$uris" -eq 0 \] \|\| \[ "\$pinned" -ne "\$uris" \]; then/);
});

test("build-wasm compiles inside that image and stamps the commit time", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const job = workflow.match(/^  build-wasm:\n[\s\S]*?(?=^  [\w-]+:)/m)?.[0] ?? "";
  assert.match(job, /platforms: linux\/amd64/);
  // A real command line inside the container script, not a mention of it.
  assert.match(job, /docker run --rm --platform linux\/amd64 [\s\S]*?entropylab-dev:local[\s\S]*?^ +npm run build:wasm$/m);
  assert.match(job, /safe\.directory \/workspace/);
  assert.doesNotMatch(job, /rm -rf/, "the runner must not delete root-owned target directories");
  const source = read("scripts/build-wasm.mjs");
  assert.match(source, /safe\.directory=\*/);
  assert.match(source, /SOURCE_DATE_EPOCH/);
  assert.match(source, /--format=%ct/);
});

test("reproduce compares a second in-image build with the bytes the candidate publishes", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const reproduce = workflow.match(/^  reproduce:\n[\s\S]*?(?=^  [\w-]+:)/m)?.[0] ?? "";
  assert.match(reproduce, /^    needs: \[build-wasm\]/m);
  assert.match(reproduce, /name: entropylab-wasm/);
  assert.match(reproduce, /diff \/tmp\/wasm-first\.hashes \/tmp\/wasm-published\.hashes/);
  assert.match(reproduce, /--platform linux\/amd64/);
});

// upload-artifact roots a multi-file artifact at the least common ancestor of
// its paths (actions/upload-artifact, src/shared/search.ts), and
// download-artifact extracts a named artifact straight into `path`. This
// models that layout so every job that downloads the WASM modules reads them
// where they actually land, not where the upload found them.
function artifactEntries(paths) {
  const split = paths.map((path) => path.split("/"));
  let depth = 0;
  while (split.every((parts) => depth < parts.length - 1 && parts[depth] === split[0][depth])) depth += 1;
  return split.map((parts) => parts.slice(depth).join("/"));
}
const workflowJob = (workflow, name) =>
  workflow.match(new RegExp(`^  ${name}:\\n[\\s\\S]*?(?=^  [\\w-]+:|(?![\\s\\S]))`, "m"))?.[0] ?? "";
const workflowSteps = (job) => job.match(/^      - [\s\S]*?(?=^      - |(?![\s\S]))/gm) ?? [];
const artifactStep = (job, action) =>
  workflowSteps(job).find((step) => step.includes(`actions/${action}@`) && /^\s+name: entropylab-wasm$/m.test(step)) ?? "";

test("the uploaded WASM modules land where every downstream job reads them", () => {
  const workflow = read(".github/workflows/ci-cd.yml");
  const uploaded = artifactStep(workflowJob(workflow, "build-wasm"), "upload-artifact")
    .match(/path: \|\n((?: {12}\S+\n)+)/)?.[1].trim().split(/\s+/) ?? [];
  assert.deepEqual(uploaded, ["src/js/entropylab-wasm-b64.js", "src/js/psbt-wasm-b64.js", "src/js/vanity-wasm-b64.js"]);
  const entries = artifactEntries(uploaded);
  assert.deepEqual(entries, ["entropylab-wasm-b64.js", "psbt-wasm-b64.js", "vanity-wasm-b64.js"], "the artifact is rooted at src/js");
  const downloadDir = (name) => artifactStep(workflowJob(workflow, name), "download-artifact").match(/^\s+path: (\S+)$/m)?.[1];
  // The site build consumes the fresh modules in place of the committed ones.
  assert.deepEqual(entries.map((entry) => `${downloadDir("build")}/${entry}`), uploaded);
  // reproduce hashes them inside the container, through the /workspace mount.
  const reproduce = workflowJob(workflow, "reproduce");
  for (const entry of entries) {
    const landed = `/workspace/${downloadDir("reproduce")}/${entry}`;
    assert.ok(reproduce.includes(`${landed} `) || reproduce.includes(`${landed}\n`), `reproduce must hash ${landed}, where the download puts it`);
  }
});
