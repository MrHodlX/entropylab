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
set in `MEMPROCFS_MOUNT`, the harness can scan live process VM pages without
writing dump files.

## What it does

1. Builds deterministic fake secrets from a fixed seed: the published BIP39
   test mnemonic ("legal winner … yellow", recognizably test data), the
   passphrase `TREZOR`, a fake seed hex, and WIF/xprv-shaped strings that are
   not checksummed and can never spend anything.
2. Runs the scripted session in a headless browser through the app's real UI:
   type the seed and passphrase, derive, reveal the private values, copy once.
3. At each checkpoint — `after-derive`, `after-reveal`, `after-copy`,
   `after-wipe` (End session), `after-tab-close` — enumerates the browser's
   whole process tree (Chrome/Edge/Firefox are multi-process) and captures
   each process.
4. Scans every capture for every secret in UTF-8 **and** UTF-16LE (page JS
   strings are UTF-16; WASM linear memory is raw UTF-8 bytes), plus a base64
   form of the mnemonic, and reports per-process, per-secret, per-encoding hit
   counts and offsets.

## The positive control

At `after-reveal` the secrets **must** be found — they are on screen. If the
control finds nothing, the harness itself is broken (wrong process, wrong
encoding, a capture that silently failed), and the run is marked **INVALID**,
not green. A residue tool that cannot find a secret it knows is on screen
proves nothing when it later reports zero.

## Reading the results

Two reports land in `out/residue/` (gitignored — captures can be gigabytes and
contain real process memory):

- `residue-report.json` — the machine record: tool versions, platform, the
  browser pid tree, and per-checkpoint × per-pid × per-secret × per-encoding
  counts, plus the disclaimer.
- `residue-report.md` — the human version: one table per checkpoint, the
  positive-control verdict first.

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

- The harness refuses to run if the page reports any mnemonic other than the
  fixture — it must never be pointed at a session holding real material.
- Each capture is size-capped (4 GB) and deleted rather than kept if exceeded.
- `--browser-process` dumps only the browser's parent process when the
  question is about browser-process residue (faster, much less disk).
