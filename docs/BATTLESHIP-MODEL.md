# "Battleship in a single square"

## The mapping

For a puzzle of `n` bits the key space is `[2^(n−1), 2^n)`, i.e. a free
`n − 1` bit string. Split it in half:

```
x = high half / 2^hx        y = low half / 2^hy          hx + hy = n − 1
```

Both coordinates land in `[0, 1)`, so the whole search window becomes a unit
square, a 10×10 board (`A1 … J10`) covers it, and **every cell is an exact,
contiguous scalar interval** — which is precisely what the anti-duplicate
registry needs (`cell_bounds` returns `[start_k, end_k]` with no rounding).

`morton_encode` gives a 1-D Z-order cursor over the square, useful for
allocating nearby cells to nearby workers.

## What the model is good for

* **Scheduling.** A cell is a lease. The board is a map of leased vs. locked
  territory that non-specialists can read at a glance.
* **Coverage accounting.** `cells_partition_the_window`-style tests guarantee no
  scalar is left uncovered by the cell decomposition.
* **Communication.** "We swept Ж4 and З5" is easier to say than two 40-digit
  hex bounds.

## What it is *not* good for

The map is a **bijection**. It does not make `secp256k1` easier, it does not
concentrate solutions, and a "wound" is not damage. Two specific traps:

1. **Wounds are birthday artefacts.** Two herds of `D` distinguished points over
   a 64-bit tag space are expected to contain a pair matching
   `log2(D) + 1` bits. `WoundRadar.nearest()` reports the best match **and**
   `baseline_matched_bits(D)` so the number can be judged against that baseline
   instead of being celebrated.
2. **"The ship wasn't even hit"** usually means the salvo used a 1-D table (only
   the lowest deck) or that `Δx ≠ 0` was treated as a miss. A 2-D wound
   radar (`cpp/src/hash160_addon.cpp`, `sqf_build_multideck_2d_radar`) is a
   legitimate *engineering* fix for that instrumentation bug — and nothing more.

## API

```python
from sqflab.battleship import key_to_square_xy, cell_bounds, cell_label, WoundRadar

x, y = key_to_square_xy(140, k)
start, end = cell_bounds(140, col=6, row=3)   # exact inclusive interval
radar = WoundRadar(tag_bits=64)
radar.nearest(tame_tags, wild_tags)           # best pair + matched bits
radar.baseline_matched_bits(len(tame_tags))   # what chance alone gives
```
