# Residue audit (developer harness)

`npm run test:residue` drives the app in a real browser, plants deterministic
**fake** secrets, captures every browser process's memory at fixed checkpoints,
and scans the captures for those secrets. It answers one question: *when the
app says it wiped a secret, is the secret actually gone from the browser's
memory?*

This is a manual developer tool. It is not part of `npm test` or CI, and it
never touches real key material.

## What it needs (detected, never bundled)

The harness captures memory with an external tool and refuses to run without
one, with an install hint:

| Platform | Tool | Install |
|---|---|---|
| Windows | **ProcDump** | <https://learn.microsoft.com/sysinternals/downloads/procdump>, or set `PROCDUMP_BINARY` to its path |
| Linux | **gcore** (from gdb) | `sudo apt install gdb` / `sudo dnf install gdb`, or set `GCORE_BINARY` |
| macOS | — | No reliable capture tool; the harness stops with a clear message |

An optional deeper path: if **MemProcFS** is installed and its mount point is
set in `MEMPROCFS_MOUNT`, the harness scans the live per-process files instead
of writing dumps — but only where the mount actually exposes the process: it
looks for `<mount>/<pid>/` and `<mount>/proc/<pid>/`, and when neither exists
the capture is recorded as **skipped** with the paths it tried. Never a
silent zero.

## What it does

1. Builds deterministic fake secrets from a fixed seed: the published BIP39
   test mnemonic ("legal winner … yellow", recognizably test data), the
   passphrase `TREZOR`, a fake seed hex, and WIF/xprv-shaped strings that are
   not checksummed and can never spend anything.
2. Stages the app the way the browser suite does — a `--test-hooks` build in
   a temp directory outside the repository, with the scripted driver injected
   before `</body>` — serves it on `127.0.0.1`, and opens it in a headless
   browser. `--browser firefox|chrome|edge` picks the engine (default
   `firefox`, falling back to whichever supported engine is installed when
   the preference is absent); binaries resolve through `FIREFOX_BINARY` /
   `CHROME_BINARY` / `EDGE_BINARY`, then the usual install locations.
3. Runs the scripted session through the app's real UI: pick 12-word seed
   phrase mode, type the fixture mnemonic and passphrase, derive, reveal the
   private values, copy once, then End session.
4. At each checkpoint — `after-derive`, `after-reveal`, `after-copy`,
   `after-wipe` (End session), `after-tab-close` — enumerates the browser's
   whole process tree (Chrome/Edge/Firefox are multi-process) and captures
   each process with the external tool.
5. Scans every capture for every secret in UTF-8 **and** UTF-16LE (page JS
   strings are UTF-16; WASM linear memory is raw UTF-8 bytes), plus a base64
   form of the mnemonic, and reports per-process, per-secret, per-encoding hit
   counts and offsets.

## The checkpoint channel

The app ships `connect-src 'none'`: the page cannot fetch anything, including
the harness. Each checkpoint therefore arrives as a **same-origin image
request** (`img-src 'self'`) at `/__residue?name=…&seed=…`. The harness holds
that response open until it has captured and scanned the checkpoint — the
hold is what keeps the driver paused exactly where the audit is looking —
then answers with a 1×1 GIF and the page continues. An in-page failure uses
the same route with `name=residue-error`; the harness acknowledges it
immediately and fails the run carrying the page's message.

For `after-tab-close` the page reports the checkpoint and stops. On Chromium
the harness then closes the tab over the browser's debugging port
(`--remote-debugging-port=0`, whose port it reads from the profile's
`DevToolsActivePort` file) and scans whatever browser processes survive.
Firefox exposes no such port to this harness, so where no port came up the
checkpoint is recorded **skipped** with that reason instead of pretending a
zero.

## The positive control

At `after-reveal` the secrets **must** be found — they are on screen. The
control passes only on a hit labelled `mnemonic`: finding the passphrase or
an encoding while the phrase itself went unseen does not prove the scanner
can find the phrase. If the control does not pass, the harness itself is
broken (wrong process, wrong encoding, a capture that silently failed), and
the run is marked **INVALID** — the report says so and `npm run test:residue`
exits non-zero. A residue tool that cannot find a secret it knows is on
screen proves nothing when it later reports zero.

## Reading the results

Two reports land in `out/residue/` (gitignored — captures can be gigabytes and
contain real process memory):

- `residue-report.json` — the machine record: tool, platform, browser and its
  pid, the per-checkpoint process lists, every capture attempt with its skip
  reason where there is one, and per-checkpoint × per-pid × per-secret ×
  per-encoding counts and offsets, plus the disclaimer.
- `residue-report.md` — the human version: one table per checkpoint, the
  positive-control verdict first, and a `SKIPPED` heading for any checkpoint
  where **no** dump was captured — a blind checkpoint never reads as a clean
  zero.
- `browser.log` — the browser's own log from the run, copied out of the
  temp staging directory (which is deleted) whenever the run ends.

See `docs/examples/residue-report.example.md` for a sanitised real output.

## Limitations — read this before trusting a zero

**Zero hits is not proof of erasure.** It means only that these bytes were not
found in these processes at this moment, on this OS, with this allocator
state. A positive hit *is* proof of residue.

The harness cannot see:

- **Memory the OS already paged out** (pagefile/swap), hibernation files, or
  crash dumps — the page's residue may be on disk, not in RAM. That is what
  the [Computer Hardening Checklist](Computer_Hardening_Checklist.md) is for.
- **GPU or driver buffers** holding rendered pixels of a revealed secret.
- **Copies inside the OS** (clipboard history, screen capture, accessibility
  trees serialized elsewhere).
- Anything about a **different browser build or OS** — residue is
  allocator-dependent; a zero on Firefox/Linux says nothing about
  Chrome/Windows. That is why the report names the platform and browser.

## Guard rails

- Before deriving, the driver checks the seed field against the fixture and
  refuses to continue if it holds anything else; it also reports the field's
  contents at `after-derive`, and the harness refuses — **before any
  capture** — to run against a session that reported any other mnemonic. The
  fixture is published test data; the harness must never be pointed at a
  session holding real material.
- Each dump is size-capped (4 GB) and deleted rather than kept if exceeded;
  a MemProcFS live file above the same cap is skipped with the reason.
- `--browser-process` dumps only the browser's parent process when the
  question is about browser-process residue (faster, much less disk).
