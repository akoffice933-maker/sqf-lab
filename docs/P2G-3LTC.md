# `path-to-greatness-3ltc` — reconstruction and negative results

Target: **`LUtL7qnm3gzxKjHcfVLSjydqhhinTVmTmS`**, `3.02608794 LTC`.
The hunt publishes eight clues that fold, pairwise, into a 32-byte AES key
(`super_key`) used as `AES-256-CBC(flag, super_key, IV)`.

Status: **the key is still unknown.** This file records what is *verified
reproducible* and where each segment is blocked, because the blocked part is the
useful part.

## Verified decoders (`sqflab/p2g.py`)

| Clue | Artifact | Result |
| --- | --- | --- |
| 2 | `139_scramble.png` | zero-wrap A1Z26 over a 41-char poem → **`directionsshouldbespelledandcheckthefirst`** |
| 3 | `110_wasd.png` | 10×10 arrow grid, 13-cell walk `(col 5,row 6) → (col 3,row 0)` |
| 8 | `clue8` sky strip | three rules over the 13 `Seconds of Dream` track titles; uppercase `NEFRU` squeezes uniquely to `k = −4` → **`tdire`** |

The Clue 2 decoder is asserted at import time: a wrong transcription fails
loudly instead of silently poisoning a sweep.

## Segment ledger — 37,373,278,038 pairs, zero hits

| segment | clues | pairs tested | bottleneck |
| --- | --- | --- | --- |
| 1 | `imagine(16)` + `beach(16)` | 6,749,815,617 | blue-channel sand layer reads **`blUE-hERRing`** → the tower key/lock is a decoy |
| 2 | `chess(12)` + `wonders(20)` | 8,962,520,676 | the true FEN has **no forced mate ≤ 5 plies**; six pictograms are song rebuses |
| 3 | `wasd(8)` + `ship(24)` | 13,861,486,208 | spelled-direction remaps exhausted; the 24-char ship string is under-constrained |
| 4 | `scramble(15)` + `sky(17)` | 7,799,455,537 | `tdire` is fixed, but the dash convention and chunk order remain ambiguous |

Sweeps were run by the AES-NI candidate oracle (`cpp/src/fast_seg_oracle_aesni.c`,
`~33 MKeys/s` per core, 4-way ILP) against the published ciphertext. Every
segment is marked *blocked* rather than *failed*: a wider candidate set is
possible, but nothing in the clues currently justifies one.

## What this teaches

* **A "herring" literally printed in the image** is the cleanest example of a
  decoy that survives months of analysis. The blue channel of `Beach.png` spells
  `blUE-hERRing` at `(x=19..121, y=227..235)`.
* **Bitmap-level transcription errors dominate.** Rotating `139_scramble.png` by
  90° CW is required; the 180° variant is upside-down and yields a plausible but
  wrong plaintext.
* **Chess "solutions" are a trap** without a forced line: `4r3/rkp2p2/1p1p1np1/6N1/3B4/1QP5/2K5/8`
  has no mate in ≤ 5 plies, so any 12-character key derived from it is a guess.

## Reproduce

```bash
python3 -m sqflab p2g clue2      # the Clue 2 instruction
python3 -m sqflab p2g clue8      # rules A, B and C
python3 -m sqflab p2g walk       # the 13-cell wasd path
python3 -m sqflab p2g ledger     # totals above
python3 -m pytest tests/test_p2g.py -q
```
