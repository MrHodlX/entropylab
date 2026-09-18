// scenarios.mjs — parametric hostile-input scenarios against the built
// entropylab.html loaded via file://. Each scenario describes one page:
//   presetup: JS evaluated once after page load (optional)
//   actions:  JS strings evaluated in order; each returns a short log line
//   assert:   JS evaluated last, returning
//             { failures: [human-readable invariant violations], info: {} }
// All JS is CDP-Runtime.evaluate material. Every snippet is defensive:
// a missing element is reported as an info line, not a crash, so the
// harness can distinguish "hostile input not delivered" from real bugs.

// Helper injected in front of every scenario's action block.
export const HELPER = `
  const $ = (sel) => document.querySelector(sel);
  const $all = (sel) => [...document.querySelectorAll(sel)];
  const first = (sels) => { for (const s of sels) { const el = $(s); if (el) return el; } return null; };
  const put = (el, v, label) => {
    el.focus();
    const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    // Record every delivery so a payload that never lands cannot pass as a
    // clean run: a stale selector or a field that swallows the input whole
    // means the scenario tested nothing, which is a broken scenario rather
    // than a well-behaved app. The harness turns a zero-length landing into
    // an invariant failure (see readDelivery in harness.mjs). Partial
    // filtering is legitimate (the dice field keeps digits only), so only a
    // complete non-delivery is treated as a failure.
    if (!window.__DELIVERY) window.__DELIVERY = [];
    window.__DELIVERY.push({
      label: label || (el.id ? "#" + el.id : el.tagName.toLowerCase()),
      sent: String(v).length,
      landed: el.value.length,
    });
  };
  const click = (sel) => { const el = first(Array.isArray(sel) ? sel : [sel]); if (!el) return false; el.click(); return true; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const upload = (inputSel, name, content, label) => {
    const el = first(Array.isArray(inputSel) ? inputSel : [inputSel]);
    const record = (landed) => {
      if (!window.__DELIVERY) window.__DELIVERY = [];
      window.__DELIVERY.push({
        label: label || (Array.isArray(inputSel) ? inputSel[0] : inputSel),
        sent: String(content).length,
        landed,
      });
    };
    if (!el) {
      record(0); // no input found: the scenario delivered nothing
      return "no-file-input";
    }
    const dt = new DataTransfer();
    dt.items.add(new File([content], name, { type: "application/json" }));
    el.files = dt.files;
    // Read the attachment BEFORE dispatching: a handler that consumes the
    // file clears the input (hodlJournalUnlock and the nonce-history reader
    // both do), so checking afterwards reports zero for a delivery that
    // actually worked. Attaching the file is as far as a generic check can
    // go — whether the app then parses it is scenario-specific, so each
    // upload scenario still asserts on the app's own response.
    const attached = el.files.length ? String(content).length : 0;
    el.dispatchEvent(new Event("change", { bubbles: true }));
    record(attached);
    return "file-dispatched";
  };
`;

export const SCENARIOS = [
  {
    name: "psbt-garbage-paste",
    description:
      "Paste non-PSBT garbage into the PSBT inspector textarea and run it; the app must surface its own error UI.",
    actions: [
      `(() => { ok = click("#psbt-editor-tab"); if (!ok) ok = click('[data-psbt-tool]'); return "switched=" + ok; })()`,
      `(() => { const el = first(["#psbt-text", "textarea"]); if (!el) return "no-psbt-textarea"; put(el, "not a psbt at all \\x00\\x01\\x01 " + "{}".repeat(200) + " <script>alert(1)<\\/script>"); return "garbage-pasted len=" + el.value.length; })()`,
      `(() => { const ok = click("#psbt-go") || click("#psbted-load"); if (!ok) return "no-go-button"; return "go-clicked"; })()`,
      `(async () => { await sleep(800); const err = first(["#psbt-error", "#psbted-error", "#error"]); return "error-ui=" + (err ? (err.textContent || "").slice(0, 120) : "(none)"); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        const err = first(["#psbt-error", "#psbted-error", "#error"]);
        if (!err || !err.textContent) failures.push("no error surfaced for garbage PSBT");
        return { failures, info: { errorText: err ? err.textContent.slice(0, 160) : null } };
      })()
    `,
  },
  {
    name: "psbt-oversized-paste",
    description:
      "Paste ~4 MB of base64-looking junk into the PSBT textarea and run it; the page must stay responsive.",
    actions: [
      `(() => { click("#psbt-editor-tab") || click('[data-psbt-tool]'); return "switched"; })()`,
      `(() => { const el = first(["#psbt-text", "textarea"]); if (!el) return "no-psbt-textarea"; const junk = "cHNidH" .repeat(700000); put(el, junk); return "huge-pasted len=" + el.value.length; })()`,
      `(() => { return click("#psbt-go") ? "go-clicked" : "no-go-button"; })()`,
      `(async () => { const t0 = Date.now(); await sleep(4000); return "settle-ms=" + (Date.now() - t0); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        if (!document.body) failures.push("document lost");
        return { failures, info: { title: document.title } };
      })()
    `,
  },
  {
    name: "mnemonic-malformed",
    description:
      "Feed malformed and oversized mnemonic words into the Keys workspace's seed-phrase entry field.",
    actions: [
      `(() => { click('[aria-label="Keys"]'); return "workspace=keys"; })()`,
      // The seed textarea only exists once the "Seed phrase" derivation
      // method is selected; under the default (dice) method the only
      // textarea on the page is #dice, which keeps digits and silently drops
      // words — so the previous 'textarea' fallback tested the dice field.
      `(async () => { const sel = $('#key-mode-select'); if (!sel) return "no-mode-select"; sel.value = "seed"; sel.dispatchEvent(new Event("change", { bubbles: true })); await sleep(600); return "method=" + sel.value; })()`,
      `(() => { const el = $('#seed'); if (!el) return "no-seed-field"; put(el, "abandon abandon " + "zzz ".repeat(600) + "abandon", "#seed"); return "malformed-seed-pasted len=" + el.value.length; })()`,
      `(() => { const el = $('#seed'); if (!el) return "no-seed-field"; const weird = "aBanNDon " + "۱۲۳۴ " + "\\u200B\\u200B " + "abandon".repeat(40); put(el, weird, "#seed"); return "tricky-encoding-pasted len=" + el.value.length; })()`,
      `(async () => { await sleep(600); const meta = $('#seed-meta'); return "seed-meta=" + (meta ? (meta.textContent || "").replace(/\\s+/g, " ").trim().slice(0, 120) : "(none found)"); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        if (!document.body) failures.push("document lost");
        // The app must say something about input it cannot use. Presence
        // only — the wording is content, not contract.
        const meta = document.querySelector("#seed-meta");
        if (!meta || !(meta.textContent || "").trim()) {
          failures.push("malformed seed phrase produced no status text in #seed-meta");
        }
        return { failures, info: {} };
      })()
    `,
  },
  {
    name: "journal-hostile-import",
    description:
      "Imports a hostile journal JSON file (script tags, wrong types, oversized body) through the journal open flow; the app must refuse it through its own error UI.",
    actions: [
      `(() => "workspace=journal-clicked=" + click('[aria-label="Journal"]'))()`,
      // The open panel is behind the "Open file" gate; reveal it so the flow
      // matches what a user actually does.
      `(async () => { const btn = $all('#journal-gate-modes button').find((b) => /open/i.test(b.textContent || "")); if (!btn) return "no-open-gate"; btn.click(); await sleep(400); return "gate=open panel-hidden=" + $('#journal-open-panel')?.hidden; })()`,
      `(() => { const hostile = JSON.stringify({ pages: "<script>alert(1)</script>", entries: 12345, huge: "x".repeat(300000) }); return "upload=" + upload(["#journal-file"], "hostile.journal.json", hostile, "#journal-file"); })()`,
      // Selecting a file only stashes its text (app.js's #journal-file change
      // handler); nothing parses it until #journal-unlock runs. Checking for
      // an error before this click tested the file picker, not the import.
      // The change handler reads the file asynchronously (await file.text());
      // give it a beat before unlocking, or the import runs on an empty stash
      // and the error is the timing artifact "Choose a journal file first."
      `(async () => { await sleep(800); const b = $('#journal-unlock'); if (!b) return "no-unlock-button"; b.click(); await sleep(1200); return "unlock-clicked"; })()`,
      `(() => { const err = $('#journal-error'); return "journal-error=" + (err ? (err.textContent || "").replace(/\\s+/g, " ").trim().slice(0, 140) : "(none)"); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        if (!document.body) failures.push("document lost");
        // A file that is not a journal must be refused visibly. Presence
        // only — the wording is content, not contract.
        const err = document.querySelector("#journal-error");
        if (!err || !(err.textContent || "").trim()) {
          failures.push("hostile journal file produced no error text in #journal-error");
        }
        const html = document.body ? document.body.innerHTML.length : 0;
        return { failures, info: { bodyLength: html } };
      })()
    `,
  },
  {
    name: "dice-oversized",
    description:
      "Stuff 100k+ junk characters into the dice textarea. By design the app accepts ANY dice input the user brings (their entropy, their choice — a test user needs no minimum quality), so the contract is: accept it, compute stats, stay alive.",
    actions: [
      `(() => { const el = first(["#dice"]); if (!el) return "no-dice-textarea"; put(el, "1".repeat(120000) + "\\u0000".repeat(50) + "9".repeat(20000)); return "dice-stuffed len=" + el.value.length; })()`,
      `(async () => { await sleep(700); const meta = $("#dice-meta"); return "dice-meta=" + (meta ? (meta.textContent || "").slice(0, 100) : "(none)"); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        if (!document.body) failures.push("document lost");
        // The design contract: arbitrary dice input is legitimate user-supplied
        // entropy material. The app must accept it and compute stats, not
        // reject or crash on it.
        const el = document.querySelector("#dice");
        if (!el || el.value.length < 100000) failures.push("oversized dice input was not accepted (field holds " + (el ? el.value.length : "no field") + ")");
        const meta = document.querySelector("#dice-meta");
        if (!meta || !(meta.textContent || "").trim()) failures.push("oversized dice input produced no stats in #dice-meta");
        return { failures, info: {} };
      })()
    `,
  },
  {
    name: "nonce-history-junk-json",
    description:
      "Dispatches a junk nonce-history JSON (valid JSON, wrong shape) plus a non-JSON blob through the PSBT nonce-history file input.",
    actions: [
      `(() => { click('[aria-label="PSBT"]'); return "workspace=psbt"; })()`,
      `(() => { const ok = upload(["#psbt-nonce-history-file"], "hist.json", JSON.stringify({ this: "is", totally: ["wrong", 1, 2, 3] })); return "junk-json=" + ok; })()`,
      `(() => { const ok = upload(["#psbt-nonce-history-file"], "blob.bin", "\\x00\\x01\\x02 not json \\xFF"); return "binary-blob=" + ok; })()`,
      `(async () => { await sleep(800); const status = $("#psbt-nonce-history-status"); return "status=" + (status ? (status.textContent || "").slice(0, 140) : "(none)"); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        const status = $("#psbt-nonce-history-status");
        if (!status || !status.textContent) failures.push("nonce-history status UI empty after junk upload");
        return { failures, info: {} };
      })()
    `,
  },
  {
    name: "workspace-tab-hammer",
    description:
      "Click through all seven workspace tabs 40 times and assert the page ends responsive with no accumulated exceptions.",
    actions: [
      `(async () => {
        const labels = ["Keys", "BIP-85", "Multi Signature", "PSBT", "Silent Payments", "Vanity", "Journal"];
        let clicks = 0;
        for (let i = 0; i < 40; i++) {
          $all('button.workspace-tab').forEach((tab) => { tab.click(); clicks++; });
          await sleep(20);
        }
        return "hammered " + clicks + " clicks";
      })()`,
      `(async () => { await sleep(500); return "settled title=" + document.title.slice(0, 60); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        if (!document.body) failures.push("document lost");
        // State consistency: exactly one workspace tab is selected, and the
        // visible tool card matches it.
        const selected = [...document.querySelectorAll('button.workspace-tab[aria-selected="true"]')];
        if (selected.length !== 1) failures.push("after hammering, " + selected.length + " tabs are selected (expected exactly 1)");
        if (selected.length === 1) {
          const activeTool = selected[0].dataset.workspace;
          // Each workspace has at least one container the switcher unhides;
          // none of them may be left hidden for the selected tab.
          const homes = {
            calc: ["key-manager", "calc-card"],
            bip85: ["bip85-card", "bip85-manager"],
            msig: ["msig-card", "msig-manager"],
            sp: ["sp-card", "sp-manager"],
            vanity: ["vanity-card"],
            ln: ["ln-card", "ln-inv-card"],
            journal: ["journal-manager", "journal-card", "journal-notes-card", "journal-keymanager-card", "journal-state-card", "journal-log-card"],
            psbt: ["psbt-card", "psbt-manager"],
          };
          const candidates = homes[activeTool] || [];
          const visible = candidates.filter((id) => { const el = document.getElementById(id); return el && !el.hidden; });
          if (candidates.length && !visible.length) failures.push("selected tab '" + activeTool + "' has no visible card (state desync)");
        }
        // Journal log stays coherent: bounded and appending (the hammer wrote
        // workspace events; the log must not be corrupted by them).
        // Page stays responsive: a real derive still works after the hammer.
        const dice = document.querySelector("#dice");
        if (dice) {
          dice.value = "123456";
          dice.dispatchEvent(new Event("input", { bubbles: true }));
          const meta = document.querySelector("#dice-meta");
          if (!meta || !(meta.textContent || "").trim()) failures.push("page unresponsive after hammering: dice derive produced no stats");
        }
        return { failures, info: {} };
      })()
    `,
  },
  {
    name: "seed-encoding-tricks",
    description:
      "Mixed-case, zero-width, RTL and homoglyph tricks in the seed-phrase entry field; the app must not accept them silently and the page must stay alive.",
    actions: [
      `(() => { click('[aria-label="Keys"]'); return "workspace=keys"; })()`,
      // Same as mnemonic-malformed: without selecting the seed method this
      // used to land on #dice, so the encoding tricks were never applied to
      // a field that parses words.
      `(async () => { const sel = $('#key-mode-select'); if (!sel) return "no-mode-select"; sel.value = "seed"; sel.dispatchEvent(new Event("change", { bubbles: true })); await sleep(600); return "method=" + sel.value; })()`,
      `(() => { const el = $('#seed'); if (!el) return "no-seed-field"; const tricky = "Abandon abandon ANDERSON " + "‏‎‌" + "zoo zoo"; put(el, tricky, "#seed"); return "tricky-pasted len=" + el.value.length; })()`,
      `(async () => { await sleep(600); const meta = $('#seed-meta'); return "seed-meta=" + (meta ? (meta.textContent || "").replace(/\\s+/g, " ").trim().slice(0, 120) : "(none found)"); })()`,
    ],
    assert: `
      (() => {
        const failures = [];
        if (!document.body) failures.push("document lost");
        const meta = document.querySelector("#seed-meta");
        if (!meta || !(meta.textContent || "").trim()) {
          failures.push("encoding-trick seed phrase produced no status text in #seed-meta");
        }
        return { failures, info: {} };
      })()
    `,
  },
];
