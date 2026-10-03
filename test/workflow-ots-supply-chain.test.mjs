// Audit SC-2: the timestamp, OTS upgrade and release-asset jobs install the
// OpenTimestamps client from PyPI. Pinning only the top-level package left its
// eight dependencies floating and nothing hash-checked, in jobs that also hold
// the release-push token. The install must take exactly the locked wheels or
// fail, and no step that runs the client may see the push token. A textual
// guard cannot parse YAML, but it fails the moment any of these lines move.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(root, path), "utf8");
const lockPath = ".github/ots-requirements.txt";
const workflows = readdirSync(join(root, ".github/workflows"))
  .filter((name) => /\.ya?ml$/.test(name))
  .map((name) => ({ name, text: read(`.github/workflows/${name}`) }));

const jobBlock = (workflow, name) =>
  workflow.match(new RegExp(`^  ${name}:\\n[\\s\\S]*?(?=^  [a-z0-9_-]+:\\n|(?![\\s\\S]))`, "m"))?.[0] ?? "";
const steps = (job) => job.split(/^ {6}- /m).slice(1);

// opentimestamps-client 0.7.2's dependency closure, from the requires_dist
// metadata PyPI publishes for it and for each dependency in turn.
const closure = [
  "opentimestamps-client",
  "opentimestamps",
  "python-bitcoinlib",
  "pycryptodomex",
  "GitPython",
  "gitdb",
  "smmap",
  "PySocks",
  "appdirs",
];

const lockEntries = () =>
  read(lockPath)
    .replace(/\\\n\s*/g, " ")
    .split("\n")
    .filter((line) => line.trim() && !line.trim().startsWith("#"));

test("the OTS lock pins every package of the client's closure by version and wheel hash", () => {
  const entries = lockEntries();
  const names = [];
  for (const entry of entries) {
    const match = entry.match(/^([A-Za-z0-9._-]+)==([0-9][0-9A-Za-z.]*)((?: +--hash=sha256:[0-9a-f]{64})+)\s*$/);
    assert.ok(match, `${entry} must be name==version with sha256 hashes and nothing else`);
    names.push(match[1].toLowerCase());
  }
  assert.ok(entries.some((entry) => entry.startsWith("opentimestamps-client==0.7.2 ")), "the client stays at 0.7.2");
  assert.deepEqual([...names].sort(), closure.map((name) => name.toLowerCase()).sort(), "the lock is exactly the closure");
});

test("every pip install in CI takes only the hash-locked OTS wheels", () => {
  let installs = 0;
  for (const { name, text } of workflows) {
    for (const [line] of text.matchAll(/^.*\bpip3?"? install\b.*$/gm)) {
      installs += 1;
      for (const flag of ["--require-hashes", "--no-deps", "--only-binary :all:", `-r "$GITHUB_WORKSPACE/${lockPath}"`]) {
        assert.ok(line.includes(flag), `${name}: ${line.trim()} lacks ${flag}`);
      }
      assert.doesNotMatch(line, /==/, `${name}: pins belong in ${lockPath}, not on the command line`);
    }
  }
  assert.equal(installs, 3, "the timestamp, upgrade and release-asset jobs each install the client once");
});

test("no step that runs the OTS client can reach the release-push token", () => {
  for (const [file, job] of [
    ["ci-cd.yml", "timestamp"],
    ["ots-upgrade.yml", "upgrade"],
  ]) {
    const block = jobBlock(read(`.github/workflows/${file}`), job);
    assert.ok(block, `${file}:${job} exists`);
    const all = steps(block);
    const checkout = all.find((step) => step.includes("actions/checkout@"));
    assert.match(checkout, /persist-credentials: false/, `${file}:${job} must not leave GITHUB_TOKEN in .git/config`);
    const runsOts = all.filter((step) => /"\$OTS"|\bpip"? install/.test(step));
    assert.ok(runsOts.length >= 2, `${file}:${job} installs and runs the client`);
    for (const step of runsOts) {
      assert.doesNotMatch(step, /secrets\./, `${file}:${job}: a step that runs OTS code must not hold a secret`);
    }
    const pushes = all.filter((step) => step.includes("secrets.RELEASE_PUSH_TOKEN"));
    assert.equal(pushes.length, 1, `${file}:${job} pushes from exactly one step`);
    const [push] = pushes;
    assert.match(push, /^ {8}env:\n {10}PUSH_TOKEN: \$\{\{ secrets\.RELEASE_PUSH_TOKEN \}\}$/m, "the token arrives through env, not inlined into the script");
    assert.doesNotMatch(push.split(/\n {8}run: /)[1] ?? "", /\$\{\{/, "the push script has no expression substitution");
    assert.match(push, /^ {8}if: steps\.[a-z]+\.outputs\.committed == 'true'$/m, "the push runs only when the OTS step committed a proof");
    assert.ok(all.indexOf(push) > Math.max(...runsOts.map((step) => all.indexOf(step))), "the push comes after every OTS step");
  }
});
