// When the Jev adversarial run fails (test/adversarial/outcome.mjs). The
// nightly is green only if no scenario did something the app must never do.
//
// Contract: a scenario fails the run when the harness's own checks caught a
// network attempt, an uncaught exception or rejection, a failed invariant or
// a dead page, or when Jev's verdict is "broken". "ok", "suspect" and a
// missing verdict (no API key, the API down) never fail it: a suspect is for
// a person to read, and an outage is not the app's fault.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runFailures } from "./adversarial/outcome.mjs";

// One scenario's results, clean unless a test says otherwise.
const row = (overrides = {}) => ({ name: "scenario", choice: "ok", net: 0, exceptions: 0, rejections: 0, inv: 0, alive: true, failures: [], ...overrides });

test("a clean run, and verdicts that are for a person to read, do not fail", () => {
  assert.deepEqual(runFailures([row(), row({ name: "dice-oversized", choice: "suspect" })]), []);
  assert.deepEqual(runFailures([row({ choice: "(none)" })]), [], "a missing verdict failed the run");
  assert.deepEqual(runFailures([]), []);
});

test("each thing the app must never do fails the run, naming the scenario", () => {
  const cases = [
    [{ net: 2 }, /network/],
    [{ exceptions: 1 }, /exception/],
    [{ rejections: 3 }, /rejection/],
    [{ inv: 1, failures: ["120,000 identical rolls were reported as fair"] }, /120,000 identical rolls were reported as fair/],
    [{ alive: false }, /not alive/],
    [{ choice: "broken" }, /broken/],
  ];
  for (const [overrides, reason] of cases) {
    const failures = runFailures([row(), row({ name: "hostile", ...overrides })]);
    assert.equal(failures.length, 1, `${JSON.stringify(overrides)} did not fail exactly the one scenario`);
    assert.match(failures[0], /^hostile: /, "the failure does not name its scenario");
    assert.match(failures[0], reason);
  }
});

test("every reason a scenario fails is listed, and every failing scenario", () => {
  const failures = runFailures([row({ name: "a", net: 1, choice: "broken" }), row({ name: "b", exceptions: 1 })]);
  assert.equal(failures.length, 3);
  assert.deepEqual(failures.map((failure) => failure.split(":")[0]), ["a", "a", "b"]);
});
