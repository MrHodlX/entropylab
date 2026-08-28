// Copy control for entropy seed-word grids.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");
const css = readFileSync(join(root, "..", "src/css/styles.css"), "utf8");
const template = readFileSync(join(root, "..", "src/index.html"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

function hodlSeedConfig(words = 24) {
  return { 12: { words: 12 }, 18: { words: 18 }, 24: { words: 24 } }[Number(words)] || { words: 24 };
}

const hodlSeedPhraseCopyText = new Function(
  "hodlSeedConfig",
  "Pt",
  `${loadSlice("hodlSeedPhraseCopyText")}; return hodlSeedPhraseCopyText;`,
)(hodlSeedConfig, 24);

test("copy text is empty until every slot is filled", () => {
  assert.equal(hodlSeedPhraseCopyText(["abandon", "ability"], 12), "");
  assert.equal(hodlSeedPhraseCopyText(["abandon", "", "ability"], 3), "");
  assert.equal(hodlSeedPhraseCopyText(Array(23).fill("abandon"), 24), "");
});

test("copy text is space-separated BIP39 words when all N slots are filled", () => {
  const words = Array.from({ length: 12 }, (_, index) => `word${index + 1}`);
  assert.equal(hodlSeedPhraseCopyText(words, 12), words.join(" "));
});

test("hashed-dice style full preview from a short source still copies", () => {
  const preview = Array.from({ length: 24 }, (_, index) => `seed${index + 1}`);
  assert.equal(hodlSeedPhraseCopyText(preview, 24), preview.join(" "));
});

test("dice, cards, and hex status rows render a copy control next to the grid", () => {
  assert.match(app, /hodlSeedMetaRowMarkup\("dice-meta",!0\)/);
  assert.match(app, /hodlSeedMetaRowMarkup\("cards-meta"\)/);
  assert.match(app, /hodlSeedMetaRowMarkup\("entropy-meta",!0\)/);
  assert.match(app, /data-copy-seed-phrase/);
  assert.match(template, /data-copy-seed-phrase/);
  assert.match(app, /function hodlRenderDiceWordGrid\(/);
  assert.match(app, /button\.disabled=!phrase/);
});

test("copy icon is grey when disabled and orange when the grid is complete", () => {
  assert.match(css, /\.seed-phrase-copy:disabled \{ color: var\(--faint\)/);
  assert.match(css, /\.seed-phrase-copy:not\(:disabled\) \{\s*color: var\(--accent\)/);
  assert.doesNotMatch(css, /\.dice-word-grid[^{]*seed-phrase-copy/);
});

test("clipboard write uses navigator.clipboard with an execCommand fallback", () => {
  assert.match(app, /navigator\.clipboard\.writeText\(phrase\)/);
  assert.match(app, /document\.execCommand\("copy"\)/);
  assert.match(app, /hodlInitSeedPhraseCopy\(\)/);
});
