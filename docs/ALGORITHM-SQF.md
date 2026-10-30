# Symmetric Quartet Folding (SQF)

SQF is a **memory-optimised baby-step/giant-step** search with `±` symmetry
applied on both axes of the decomposition. It is not a new asymptotic result;
it is a disciplined way to spend memory instead of time, with the constant
measured rather than assumed.

## 1. The decomposition

Search `k ∈ [a, b]` for `k·G = P`. Let

```
C = ⌊(a + b) / 2⌋          R = max(b − C, C − a)          d = k − C,  |d| ≤ R
```

Choose a baby-table size `M`. Every `|d| ≤ R` can be written as

```
d = q·(2M) + r        with   |r| ≤ M,   |q| ≤ Q = ⌊R/(2M)⌋ + 1
```

so the *baby* half needs only the `M` points `r·G`, and the *giant* half needs
the `2Q + 1` points `(d − q·2M)·G`.

## 2. Where the quartet comes from

Two independent sign symmetries are available:

1. **Baby side:** `x(r·G) = x(−r·G)`. An x-only table entry `x ↦ r` therefore
   answers both `+r` and `−r` — one entry, two candidates.
2. **Giant side:** the search walks `q = +1, +2, …` and `q = −1, −2, …` from the
   same anchor `K₀ = P − C·G`, so each lookup serves both directions.

The product of the two is the **quartet**

```
{ C + q·2M + r,  C + q·2M − r,  C − q·2M + r,  C − q·2M − r }
```

Each of the four is a candidate key; each costs one table lookup and at most one
verification. In `bsgs.py` the giant sign is carried by `signed_q`, the baby sign
by the `±r` loop, and the candidate is `C − signed_q·2M ± r`.

## 3. Table construction: mirror multiples

Naively building `1·G … M·G` costs `M` inversions. Instead, pick a block size
`B` (default 512) and note that

```
x(C + j·G) and x(C − j·G)   share the denominator   x(C) − x(j·G)
```

so **one** inversion yields **two** new points, and Montgomery's trick inverts a
whole block of denominators at once. `folding.mirror_multiples(M)` therefore
costs `M` additions and `≈ 2M/B` inversions. Measured: 4,096 multiples in
**14 inversions** (tests/test_folding.py asserts `< 64`).

## 4. Cost

| phase | additions | inversions |
| --- | --- | --- |
| baby table | `M` | `≈ 2M/B` |
| giant steps | `2Q + 1` | 1 (anchor) |
| **total** | `M + 2Q + 1` | `≈ 2M/B + 1` |

With `M = √(W/2)` this is `≈ 2√W` in the worst case, and `≈ √W` on average
because the loop stops at the first hit. Measured on blind random keys:
**0.94–1.14 · √W** (Python) and **1.04–1.62 · √W** (C++).

Memory: `M` x-coordinates. In the C++ engine that is `M` slots of 8 bytes plus a
bitmap; in Python it is a dict at roughly 120 B/entry, which is why the Python
solver is capped at `2^21` entries by default.

## 5. What is *not* novel

* BSGS, `±`-symmetry and x-only tables are textbook (Shanks; Menezes–van Oorschot–
  Vanstone §3.6; the "kangaroo" family uses the same sign trick).
* SQF does not beat `O(√W)`; nothing here does. The measured constant and the
  memory profile are the contribution.
* Claims of sub-`√W` behaviour via "folding the interval around known keys"
  are unfounded: the fold is a *bijection* on the key space.

## 6. Pseudocode

```python
C, R = centered_window(a, b)
M = min(isqrt((b - a) // 2), max_table)
table = FoldTable(size=M).build()            # x -> r, M additions, ~2M/B inversions
anchor = P - C*G                             # the residual d
step = 2*M*G

check(anchor, 0)                             # r == 0 case
plus = minus = anchor
for q in 1..R//(2M)+1:
    plus  += step ; if hit := table.probe(plus):  verify(C - q*2M ± hit)
    minus -= step ; if hit := table.probe(minus): verify(C + q*2M ± hit)
```

## 7. Honest benchmark rules

`sqflab/bench.py` enforces the three properties described in the README. The
JSON it produces (`benchmarks/results/*.json`) records `bits`, `width`, `ops`,
`ops_over_sqrt`, `seconds`, `table_size` and `verified` per trial, so a reviewer
can recompute every published number.
