# Residue audit report

> Zero hits is not proof of erasure: it means only that these bytes were not found in these processes at this moment, on this OS, with this allocator state. A positive hit is proof of residue.

Platform: win32 · Browser: chrome · Capture: procdump

## after-derive

| pid | secret | encoding | hits |
|---|---|---|---|
| &lt;pid&gt; | mnemonic | utf16le | 2 |
| &lt;pid&gt; | passphrase | utf16le | 1 |
| &lt;pid&gt; | passphrase | utf8 | 1 |

## after-reveal — POSITIVE CONTROL PASSED

| pid | secret | encoding | hits |
|---|---|---|---|
| &lt;pid&gt; | mnemonic | utf16le | 4 |
| &lt;pid&gt; | passphrase | utf16le | 3 |
| &lt;pid&gt; | seedHex | utf16le | 1 |

## after-copy

| pid | secret | encoding | hits |
|---|---|---|---|
| &lt;pid&gt; | mnemonic | utf16le | 4 |
| &lt;pid&gt; | passphrase | utf16le | 2 |

## after-wipe

| pid | secret | encoding | hits |
|---|---|---|---|
| &lt;pid&gt; | mnemonic | utf16le | 1 |

## after-tab-close

No hits.

---

*Sanitised example: pids and offsets removed, counts illustrative. A real
report writes one table per checkpoint and names every secret/encoding pair
found. The `after-wipe` row above is what a residual copy looks like — a
secret surviving End session in a live process. The `after-tab-close` zero is
the good case, and still not proof: see "Limitations" in
`docs/Residue_Audit.md`.*
