# Field report: krackpot.io, Bitcoin Puzzle #71, and what a browser lottery really costs

Status: measured 2026-10-30 on the 2-core sandbox used for this repository's
benchmarks. Every number below is either read out of the mirrored client source,
queried from `mempool.space`, or measured with the engines in `cpp/`. Nothing here
was taken from a press release.

## 1. What the service does

`krackpot.io` is a browser client (WebGPU/WebGL compute shaders, no backend) that
brute-forces **Bitcoin Puzzle #71**:

| field | value |
| --- | --- |
| address | `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU` |
| range in `src/config.js` | `0x400000000000000000` … `0x7fffffffffffffffff` (2^70 … 2^71−1) |
| pool at audit time | 72 UTXOs, **7.10195986 BTC**, all unspent |
| payout to the solver | `USER_PAYOUT_SATS = 600_000_000n` — a **flat 6 BTC** |
| payout to the developer | remainder ≈ **1.0945 BTC** (after a 69 sat/vB claim fee) |
| claim path | private submission: Rebar Shield, MARA Slipstream, then a Nostr gift wrap |

The client is well built: the private key is generated and used locally, the claim
transaction is signed in the page, and a grep for `fetch`/`XMLHttpRequest`/
`WebSocket`/`sendBeacon` over all 324 KB of mirrored JavaScript (10 modules + 6 shaders) finds exactly two
`fetch` sites — the on-demand `esm.sh` imports of `@scure/btc-signer` and the
endpoints above. No analytics, no telemetry, no exfiltration host. `share.js`
whitelists only `pay=` and `autostart=`, so a shared link cannot change the
target. On that axis the audit is clean.

The interesting part is not trust. It is arithmetic.

## 2. The cost of a search

Puzzle #71 has a public address and no public key, so Pollard's kangaroo — the
algorithm this site demonstrates on its own `/kangaroo` page — does not apply. All
that is left is brute force over a 2^70-key interval: hash each candidate key,
compare the HASH160.

Our fastest local path is the 12-way engine (`sqf_scan_window_12way_hash160`):
one base point per step, then uncompressed + compressed + negated + GLV
λ/λ² mirrors, SHA-256 → RIPEMD-160 in assembly. Measured on this machine:

| window | where the keys sit | throughput |
| --- | --- | --- |
| 2^24 keys | low-range target (fits L1/L2) | 133 kKeys/s |
| 2^20 keys | start point at 2^40 | 35.5 MKeys/s |

Those two rows are not a contradiction — they are the whole story. The 2^40
measurement is what the engine does when the target window is small and recently
computed, which is exactly the case in a size-scaled benchmark. A real sweep of
Puzzle #71 starts at `0x400000000000000000`, where each base point is a fresh
full-width scalar multiplication and nothing stays hot in cache: **133 kKeys/s**,
`2^24` keys in 126 s. The realistic figure is **266× lower** than the pretty one.

Time to cover the keyspace at 133 kKeys/s:

| work | keys | years (this box) |
| --- | --- | --- |
| median (50 % chance) | 5.90e20 | 141,000 |
| full keyspace | 1.18e21 | 281,000 |

For reference, the site's own calculator quotes 22.55 MKeys/s for an RTX 3070 and
829,505 years for the median — same order, same conclusion. A bank of 10^6 GPUs
doing 22.55 MKeys/s each is still ~1.7 years, and that bank does not exist.

## 3. What we actually ran

A bounded, honest attempt — not a claim of victory:

* leased a **2^32-key** block at the floor of the range
  (`0x400000000000000000` … `0x4000000000ffffff`) in the persistent
  anti-duplicate registry, so the same strip can never be swept twice;
* scanned the first **2^24 keys** of it with the 12-way engine: 16,777,216 keys,
  126.1 s, **0 hits** (expected: prior probability 1.4e−14);
* the full 2^32 block at this rate is 9.0 hours, and it moves the probability of a
  hit from 1.4e−14 to 3.6e−12 — both rounded to zero.

The block is recorded in the anti-duplicate registry (export:
`puzzle71_progress.json`), whose guarantee is `STRICT_NON_OVERLAPPING_LOCK`.

## 4. The economics, stated plainly

At 133 kKeys/s and a flat 6 BTC payout:

* expected value per hour: **(133e3 × 3600 / 2^70) × 6 BTC ≈ 2.4e−12 BTC**
  — a fraction of a cent per *year* of runtime;
* power: a 250 W machine at $0.20/kWh burns $0.05/h;
* **EV / electricity ≈ 4e−6.** You are not buying a lottery ticket; you are
  buying a rounding error at retail price.

The old "it only costs you electricity" framing hides the fact that the
electricity itself is a losing bet by six orders of magnitude.

## 5. The second-order risk, which the site is right about

Puzzle 66 and 69 were front-run: the solver broadcast a spend, the public key
appeared in the mempool, a watcher ran a kangaroo over the now-known range, and a
higher-fee replacement took the coins. This repository's `kangaroo.py` and
`cpp/src/*kangaroo*` will do the same thing in minutes **if a public key is ever
exposed for a narrow range** — which is exactly why the claim path here is
private-first. That part of krackpot's design is not marketing; it is the correct
response to a real attack.

## 6. Verdict

* **Honest?** The client's code, payout split and submission path are what they
  say they are. The 6 BTC is a flat fee, so a lucky solver keeps less than half
  the pool — disclosed, and still a real payout.
* **Winnable?** Not by anyone acting alone on consumer hardware. At 133 kKeys/s a
  single machine needs ~10^5 years; the expected value is ~1e−12 BTC/h.
* **Solvable in principle?** Only with a very large GPU herd, and only because the
  range is 2^70 rather than 2^256. `sqrt(2^256) = 2^128` remains out of reach for
  every known method.
* **What would change the answer?** A leaked public key for #71 (kangaroo, hours),
  or a 10^6-GPU farm (still years). Neither is a "try our luck" operation.

The site's own `/kangaroo` page says all of this more elegantly than we can: the
kangaroo only helps when *the range is already known and already narrow*, and
"publishing a public key is normal and safe" absent that condition. Krackpot is a
correct, well-engineered demonstration that the wrong end of a 2^70 keyspace is
still 2^70.
