// SLIP-132 display is a prefix swap only: as pasted, Core xpub/xprv, descriptor.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let paren = 0, body = -1;
  for (let index = start; index < app.length; index++) {
    if (app[index] === "(") paren++;
    else if (app[index] === ")") {
      paren--;
      if (paren === 0) {
        body = app.indexOf("{", index);
        break;
      }
    }
  }
  let depth = 0;
  for (let index = body; index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

const { hodlAccountExportFamily } = new Function(`${loadSlice("hodlAccountExportFamily")}; return { hodlAccountExportFamily };`)();

test("derived SLIP family follows path/script match and never invents Taproot", () => {
  assert.equal(hodlAccountExportFamily({ id: "bip44", purpose: 44 }), "x");
  assert.equal(hodlAccountExportFamily({ id: "bip49", purpose: 49 }), "y");
  assert.equal(hodlAccountExportFamily({ id: "bip84", purpose: 84 }), "z");
  assert.equal(hodlAccountExportFamily({ id: "bip86", purpose: 86 }), "x");
  assert.equal(hodlAccountExportFamily({ id: "bip84", purpose: 48 }), "x");
  assert.equal(hodlAccountExportFamily({ id: "bip49", purpose: 84 }), "x");
});

test("imported generic xprv is not rewrapped unless the pasted prefix already matches", () => {
  assert.equal(hodlAccountExportFamily({ id: "bip84", purpose: 84 }, { imported: true, importedFamily: "x" }), "x");
  assert.equal(hodlAccountExportFamily({ id: "bip84", purpose: 84 }, { imported: true, importedFamily: "z" }), "z");
  assert.equal(hodlAccountExportFamily({ id: "bip49", purpose: 49 }, { imported: true, importedFamily: "y" }), "y");
  assert.equal(hodlAccountExportFamily({ id: "bip84", purpose: 84 }, { imported: true, importedFamily: "y" }), "x");
  assert.equal(hodlAccountExportFamily({ id: "bip86", purpose: 86 }, { imported: true, importedFamily: "z" }), "x");
});

test("watch-only display lists as-pasted, Core generic, then matching SLIP", () => {
  assert.match(app, /function hodlSlip132Fields\(/);
  assert.match(app, /As pasted/);
  assert.match(app, /Bitcoin Core \$\{coreLabel\}/);
  assert.match(app, /SLIP-132 \$\{slipLabel\}/);
  assert.match(app, /Prefix swap only \(same payload, new version bytes and checksum\)/);
  assert.match(app, /x = legacy, y = nested BIP49, z = native BIP84, Y = nested BIP48 nested-msig, Z = native BIP48 native-msig/);
  assert.match(app, /Testnet: t \/ u \/ v \/ U \/ V/);
  assert.match(app, /No Taproot SLIP prefix/);
  assert.match(app, /Script lives in the descriptor, not the prefix/);
});
