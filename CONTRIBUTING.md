# Contributing

## The review bar

A pull request is merged when it satisfies the repository's two non-negotiables:
**honest measurement** and **scope**.

### 1. Claims must ship measurements

Any change that claims a speed-up, a lower memory footprint or a new search
strategy must include:

1. a run of the blind harness (`benchmarks/run_blind_benchmark.py` or
   `run_native_benchmark.py`) on **fresh random keys** — no known puzzles, no
   fixed seeds unless the same seed is used for the baseline too;
2. `benchmarks/results/<name>.json` committed, produced by that run;
3. operation counters incremented inside the loop — a counter derived from
   `1.5 * sqrt(W)` or from the window width is rejected on sight;
4. verification of the recovered key performed **outside** the solver.

A PR without (1)–(4) is closed with a pointer to this file, however elegant the
code is.

### 2. Scope

In scope: published puzzles, your own keys, measurement, coordination, tooling
quality. Out of scope: third-party wallets, live third-party services, anything
that would be a working exploit against a host you do not own. See
[`docs/ETHICS-AND-SCOPE.md`](docs/ETHICS-AND-SCOPE.md).

## Development workflow

```bash
python3 -m pip install -e ".[dev]"
make test          # 59 tests, ~3 s
make lint
make native NATIVE=0 && make test-all
```

* Python: 3.9+ compatible, no runtime dependencies outside the standard library.
  `ruff` with the repository configuration; type hints on public functions.
* C++: C++17, GCC 12+ / Clang 16+, OpenMP and GMP only. Keep the operation
  counters in the ABI.
* Tests: new behaviour needs a test that fails without it. Property-based style
  is welcome (`tests/test_folding.py` is the model).

## Commit messages

Conventional-ish and specific:

```
fix(bsgs): candidate sign — k = C - q*2M ± r, not C + q*2M ± r
bench(native): add 2^40 row with NATIVE=0
docs(p2g): record the 37.37e9-pair ledger
```

## Reporting a wrong number

Numbers in `docs/` are claims. If you can reproduce a row and disagree, open an
issue with the JSON, the command line and the compiler flags. Corrections are
cheap; wrong constants are expensive.

## Code of conduct

By participating you agree to [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
