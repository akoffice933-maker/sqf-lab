# Architecture

```
                    ┌──────────────────────────────────────────┐
                    │                sqflab (Python)            │
                    │  curve → folding → bsgs / kangaroo        │
                    │            ↘ bench ↘ cli                  │
                    │  registry ← api.py (apps/lottery)         │
                    │  battleship, p2g, native (ctypes)         │
                    └───────────────┬──────────────────────────┘
                                    │ ctypes
                    ┌───────────────▼──────────────────────────┐
                    │        cpp/ (C++17 + OpenMP, GMP)         │
                    │  sqf_core   sqf_64   sqf_ultra            │
                    │  hash160_addon  (→ libsqf_dual.so)        │
                    │  fast_seg_oracle[_aesni]  (AES-NI sweep)  │
                    └──────────────────────────────────────────┘
```

## Layers and their contracts

| Layer | Contract | Failure mode it prevents |
| --- | --- | --- |
| `curve.py` | pure functions, no global state, no I/O | hidden caching that fakes a speed-up |
| `folding.py` | table construction is measured in inversions **and** additions | "table is free" benchmarks |
| `bsgs.py` / `kangaroo.py` | counters incremented in the loop; no early exit before the operation is counted | formula-based "operations" |
| `bench.py` | secret key never crosses the solver boundary; verification after return | self-fulfilling verification |
| `registry.py` | writers serialised with `BEGIN IMMEDIATE`; keys stored as `blake2b` fingerprints | two agents scanning the same scalar |
| `native.py` | optional; `engine()` returns `None` when the library is absent | hard dependency on a local build |
| `apps/lottery/api.py` | thin HTTP over `registry.py`; no crypto in the server | divergent bookkeeping between agent and pool |

## Why the Python core has no optimisations

`curve.py` uses affine coordinates and one modular inversion per addition — the
slowest possible representation on purpose. It is the **oracle**: every optimisation
in `cpp/` is validated against it, and every benchmark reports both numbers. When
the two disagree, the C++ side is wrong, never the Python side.

`folding.batch_invert` is the single exception: Montgomery's trick is a
mathematical identity, not an engineering shortcut, and it is unit-tested against
`pow(x, -1, p)`.

## Data flow of one blind trial

```
bench.blind_trial(solver, bits)
        │  secret = random in [2^(bits-1), 2^bits - 1]
        │  pub    = secret * G
        ▼
solver(pub, a, b)                       # secret is NOT in scope
        │  builds table, walks, returns k and counters
        ▼
bench: verified = (k == secret)         # verification outside
        │
        ▼
benchmarks/results/*.json               # provenance: seed, machine, compiler
```

## Repository map

```
src/sqflab/          library (installed as the `sqflab` package)
cpp/src + cpp/build  native engines (built, never committed)
apps/lottery         reference pool API + client + agent skill
benchmarks           reproducible measurement scripts and raw JSON
tests                58 tests: unit, property, end-to-end HTTP, native smoke
research/archive     frozen exploration scripts (see research/README.md)
docs                 this file plus algorithms, benchmarks, protocol, ethics
```
