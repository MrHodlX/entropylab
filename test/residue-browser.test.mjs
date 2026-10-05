// Exercise the residue driver's actual Chromium input path, without claiming
// any memory measurement: checkpoints here are assertions, not dump adapters.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import * as audit from "../scripts/residue-audit.mjs";

// Contract: trusted native beforeinput must reach the passphrase vault and
// derive the independently pinned wallet; a blocked edit must fail closed.
test("residue driver uses native input and rejects missed input or copy", { timeout: 180000 }, async t => {
  let engine;
  try { engine = audit.resolveBrowser({ browser: "chrome", browserExplicit: false }); }
  catch (error) {
    if (!/no browser found/.test(error.message)) throw error;
    t.skip("Chrome/Chromium or Edge is required for the live residue input checks");
    return;
  }
  const staged = await audit.stageRun();
  const served = audit.createHarnessServer(staged);
  try {
    const port = await served.listen();
    for (const fault of ["none", "passphrase", "copy"]) {
      const blocked = fault === "passphrase";
      const name = blocked ? "blocked beforeinput rejects the wrong xprv"
        : fault === "copy" ? "a blocked copy cannot pass the clipboard digest check" : "trusted beforeinput reaches the masked vault";
      await t.test(name, async () => {
        const profile = join(staged.workDir, `${fault}-profile`);
        mkdirSync(profile);
        const child = audit.spawnBrowser(engine, { profile, logPath: join(staged.workDir, `${fault}.log`) });
        const client = audit.createPipeClient(child.stdio[3], child.stdio[4]);
        const secrets = audit.makeSecrets(), checkpoints = [], replies = [];
        const observedClient = {
          async send(...args) {
            const result = await client.send(...args);
            if (args[0] === "Runtime.evaluate" && args[1].expression.includes("clipboard.readText")) {
              assert.equal(result.result.value.length, 1);
              assert.match(result.result.value[0], /^[a-f0-9]{64}$/, "clipboard read returned plaintext through CDP");
            }
            replies.push(result);
            return result;
          },
        };
        try {
          const page = await audit.createPage(observedClient, `http://127.0.0.1:${port}`);
          const run = audit.driveSession(page, secrets, async name => {
            checkpoints.push(name);
            if (name === "before-input") {
              await page.evaluate(`(() => {
                window.__residueInputEvents = [];
                document.addEventListener("beforeinput", event => {
                  if (event.target.id !== "pass") return;
                  window.__residueInputEvents.push({ trusted: event.isTrusted, type: event.inputType, cancelable: event.cancelable });
                  ${blocked ? "event.preventDefault(); event.stopImmediatePropagation();" : ""}
                }, true);
                ${fault === "copy" ? `document.addEventListener("click", event => {
                  if (!event.target.closest("#form [data-copy-seed-phrase]")) return;
                  event.preventDefault(); event.stopImmediatePropagation();
                }, true);` : ""}
              })()`);
            }
            if (name === "after-derive") {
              const events = await page.evaluate("window.__residueInputEvents");
              assert.ok(events.length > 0, "Input.insertText never emitted beforeinput");
              assert.ok(events.every(event => event.trusted && event.cancelable && event.type === "insertText"));
              const field = await page.evaluate(`({ length: document.getElementById("pass").value.length, plaintext: /[A-Za-z]/.test(document.getElementById("pass").value) })`);
              assert.equal(field.plaintext, false, "the passphrase remained as field text");
              assert.equal(field.length > 0, !blocked, "the vault did not reflect the native edit");
            }
            if (name === audit.CONTROL_CHECKPOINT) {
              const beforeControl = JSON.stringify(replies);
              for (const label of ["xprv", "wif"]) assert.ok(!beforeControl.includes(secrets[label]), `${label} entered the protocol before the control`);
            }
          });
          if (blocked) {
            await assert.rejects(run, /does not match the fixture's xprv/);
            assert.ok(!checkpoints.includes("after-copy"), "a missed passphrase edit passed fixture validation");
          } else if (fault === "copy") {
            await assert.rejects(run, /secret copy did not succeed/);
            assert.ok(!checkpoints.includes("after-copy"), "a no-op copy passed fixture validation");
          } else {
            await run;
            assert.deepEqual(checkpoints, [...audit.CHECKPOINTS]);
            const allReplies = JSON.stringify(replies);
            for (const label of ["xprv", "wif"]) assert.ok(!allReplies.includes(secrets[label]), `${label} entered the debugging return buffers`);
          }
        } finally {
          client.dispose();
          const exited = child.exitCode !== null || child.signalCode !== null || !child.pid
            ? Promise.resolve() : new Promise(resolve => child.once("exit", resolve));
          child.kill("SIGKILL");
          await exited;
        }
      });
    }
  } finally {
    await new Promise(resolve => served.server.close(resolve));
    rmSync(staged.workDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  }
});
