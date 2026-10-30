# Native engines (C++17 + OpenMP + GMP)

```bash
make            # -march=native, tuned for this machine
make NATIVE=0   # portable build (what CI and docs/BENCHMARKS.md use)
make check      # build + run the ctypes smoke tests
```

Everything lands in `build/` and is loaded from Python through
`sqflab.native.engine()` (set `SQF_LAB_LIB` to override the path).

## Libraries

| artifact | source | contents |
| --- | --- | --- |
| `libsqf.so` | `src/sqf_core.cpp` | minimal SQF core: table + giant steps |
| `libsqf_64.so` | `src/sqf_64.cpp` | 64-bit scalar engine with a reusable base table |
| `libsqf_ultra.so` | `src/sqf_ultra.cpp` | wider-window variant with prefetch pipeline |
| `libsqf_dual.so` | `src/hash160_addon.cpp` (includes `sqf_64.cpp`) | **the main library**: SQF blind solve, classic kangaroo, RCKangaroo SOTA v2, HASH160 batch scanning, multideck 2-D radar |
| `libfast_seg_oracle.so` | `src/fast_seg_oracle.c` | AES-NI candidate-pair oracle (P2G rectangles) |
| `libfast_seg_oracle_aesni.so` | `src/fast_seg_oracle_aesni.c` | 4-way ILP AES-NI oracle, ~33 MKeys/s/core |

## Exported entry points worth knowing (`libsqf_dual.so`)

```c
int sqf_linear_bsgs_blind_solve(x[4], y[4], bits, table_bits,
                                *table_ops, *search_ops, *table_sec, *search_sec,
                                *q, *r, *sign);
int sqf_classic_kangaroo_solve(x[4], y[4], bits, dp_bits, seed,
                               *answer, *ops, *dps);
int sqf_rckangaroo_sota_solve(x[4], y[4], bits, dp_bits, seed,
                              *answer, *ops, *dps, *collisions);
int sqf_hash160_scan(...);              /* 12-way P2PKH scanning                */
int sqf_build_multideck_2d_radar(...);  /* 8 decks + 2-D case-shot table        */
int sqf_fire_multideck_2d_salvo(...);   /* salvo against the table              */
```

Key reconstruction for `sqf_linear_bsgs_blind_solve` (the engine searches
`k ∈ [0, 2^bits)`):

```
k = 2^bits / 2  +  q · (2 · 2^table_bits)  +  sign · r
```

`sqflab/native.py` implements exactly this and verifies it against the true key
in `tests/test_native.py` — three random keys per width, `2^24 … 2^40`.

## House rules for this directory

* Every engine increments an operation counter **at the operation site**; the
  counter is part of the ABI, not a comment.
* No engine may allocate unbounded memory: table and DP sizes are parameters.
* `-march=native` is never baked into a published number. The benchmark JSON
  records whether it was used (`NATIVE` flag, `library` path).

## Notes

* The sources carry Russian comments from the research phase; they are kept
  verbatim so the commit history stays honest. New code is English.
* `hash160_addon.cpp` is a single 3.1k-line translation unit that `#include`s
  `sqf_64.cpp`; it is ugly, it builds clean with `-Wall -Wextra` under GCC 14.
