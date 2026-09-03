# Post-Freeze Roadmap

This is the proposed order of work once the current feature freeze lifts.

## 1. MuSig2 (FROST)

First priority. Integrate MuSig2 for multisig key aggregation and signing.
This replaces the earlier "Frost pieces" plan — MuSig2 is the concrete scheme
we want, built on FROST. It changes how transactions are constructed and signed,
so it lands before anything that depends on signing assumptions.

## 2. Tor-friendly mode

Add a Tor-only toggle in settings. When enabled, every outbound request —
plugins, Slipstream, update checks — routes through the Tor daemon via SOCKS5,
with a clear "connected via Tor" indicator in the UI.

Longer term: host the online version as an onion service so air-gapped users
can load it without touching clearnet DNS or certificates.

## 3. Plugin system

Sandboxed iframes talking to the core over a versioned postMessage bridge.
Narrow allowlisted messages only — seeds and private keys never leave the
parent page. Ship a tiny SDK so plugin authors aren't hand-rolling plumbing.
Read-only first; action requests (e.g. "please sign") come later.

## 4. Slipstream (first plugin)

MARA's direct-to-miner relay. The plugin receives already-signed transaction
bytes, posts them to slipstream.mara.com, and returns status. Trust model is
explicit: MARA sees the transaction and the caller's IP, so Tor routing is the
recommended path.

## Deferred

Liquid, Lightning, and Ark stay out until their interfaces stabilize. Pull in
only a thin adapter if something becomes a hard dependency.
