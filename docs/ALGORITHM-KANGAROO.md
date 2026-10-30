# Pollard kangaroo (lambda) — the baseline

The kangaroo is what you run when memory, not time, is the binding constraint:
`O(√W)` group operations with `O(√W)` (or `O(D)` with distinguished points)
memory instead of `O(√W)` table.

## 1. The idea

A *tame* herd starts at a known scalar (the top of the interval) and walks with
a pseudo-random jump function `x ↦ j(x)` chosen from a fixed table. A *wild*
herd starts at the target point `P = k·G` and uses the **same** function. Because
the walk is deterministic in `x`, once a wild step lands on a point the tame herd
already visited, the two walks merge and the difference of their accumulated
distances is the key:

```
tame point = (b + t)·G          wild point = (k + w)·G
same x  ⇒  b + t = ±(k + w)  ⇒  k = ±(b + t) − w
```

## 2. What the implementation had to get right

`sqflab/kangaroo.py` is a *reference* implementation, and three details make the
difference between `2√W` and `170√W`:

1. **Mean jump `≈ √(W)/2`.** Powers-of-two tables make the walk periodic. This
   was measured: the first version of this file used `2^i` jumps and needed
   5–29 · √W with frequent failures.
2. **Many herds.** A single tame/wild pair crosses the trail's span with about
   one expected hit, i.e. ~63% success. Eight herds (four tame, four wild) with
   independent jump salts bring the measured success rate to 8/8 at `2^24` and
   7/8 at `2^28`.
3. **Per-herd salt in the jump index.** Without it every herd walks along seg-
   ments of the same flow and the pairs stop being independent trials; measured
   success collapsed from >90% to 75%.

## 3. Measured constants

| width | Python multi-herd | C++ classic | C++ RCKangaroo (SOTA v2) |
| --- | --- | --- | --- |
| 2^16 | 1.28 · √W | — | — |
| 2^20 | 1.35 · √W | — | — |
| 2^24 | 1.72 · √W | 4.60 · √W | 4.08 · √W |
| 2^28 | — | 2.72 · √W | 4.15 · √W |
| 2^40 | — | 2.88 · √W | 4.49 · √W |

The C++ numbers look worse than the Python ones only because the C++ engines at
these tiny widths pay fixed overheads (thread pool, DP tables) that dominate a
`2^24` search. At `2^40` the C++ engines run 20–50× faster in wall-clock terms.

## 4. Why RCKangaroo is not automatically better

RCKangaroo (RetiredCoder v4.0, re-implemented in `cpp/src/hash160_addon.cpp`)
adds `±`-reflection on the y-parity, L1S2 2-cycle avoidance and 1/3 tame +
2/3 wild distribution. Those tricks reduce the *constant* of the walk, but they
also increase per-step bookkeeping; on small widths the bookkeeping wins. The
honest summary is in `docs/BENCHMARKS.md`.

## 5. Distinguished points

`kangaroo_solve(..., dp_mask_bits=n)` keeps only x with `n` trailing zero bits.
This caps memory at `O(2^n)` and is what real campaigns use, at the cost of a
longer walk. `registry.submit_dp()` de-duplicates DPs across agents so two
participants never replay the same distinguished point.
