# Changelog

All notable changes to this project. Dates are UTC.

## [0.1.0] — 2026-10-30

First public edition: the research scripts become a tested library, and the
claims become measurements.

### Added

* `sqflab.curve` — dependency-free `secp256k1` arithmetic, SEC1 (de)serialisation,
  Base58Check, P2PKH and WIF, verified against public vectors (`k = 1`).
* `sqflab.folding` — SQF primitives: `mirror_multiples` (two points per field
  inversion), x-only `FoldTable` with `±` symmetry, `quartet_candidates`.
* `sqflab.bsgs` — SQF-BSGS solver with in-loop operation counters, explicit
  memory guard, and external verification.
* `sqflab.kangaroo` — multi-herd kangaroo baseline with per-herd jump salts and
  distinguished-point support.
* `sqflab.bench` — blind harness: secret never crosses the solver boundary,
  verification outside the solver, JSON provenance.
* `sqflab.native` — ctypes bindings for the C++ engines, optional at runtime.
* `sqflab.registry` — SQLite/WAL anti-duplicate registry (leases + fingerprints),
  thread-safe, crash-safe.
* `sqflab.battleship` — exact cell↔interval mapping, Morton cursor, wound radar
  with a birthday baseline.
* `sqflab.p2g` — verified `path-to-greatness-3ltc` decoders and segment ledger.
* `sqflab.cli` — `addr`, `solve`, `bench`, `registry`, `p2g`, `battleship`.
* `cpp/` — C++17/OpenMP engines with a portable `Makefile` (`NATIVE=0` for CI).
* `apps/lottery/api.py` — reference HTTP pool with an end-to-end test.
* 58 tests, GitHub Actions CI (Python 3.10–3.13 + native build).

### Fixed

* **SQF candidate sign.** The candidate is `C − signed_q·2M ± r`, not
  `C + signed_q·2M ± r`; the first version silently returned `None` on all
  widths. Caught by the blind harness, which is the point of the harness.
* **Mirror-multiple table.** The centre ladder advanced by `2B` while computing
  the fill point as `centre + 2B·G`; entries at the block boundary were wrong.
  Rewritten as a ladder of `B`-steps; 4,096 multiples now verified element-wise
  against `scalar_mult`.
* **Kangaroo jump table.** Powers of two made the walk periodic (measured
  5–29·√W, frequent failures). Replaced by a spread table with mean `√W/2`, plus
  per-herd jump salts (without salts the herds are correlated and the success
  rate collapses to 75%).
* **Registry threading.** `sqlite3` connections created in one thread rejected
  use from HTTP worker threads; added `check_same_thread=False` plus an internal
  RLock around every statement.

### Changed from the archived scripts

* Hardcoded `/home/user/...` paths replaced by package-relative paths and
  `SQF_LAB_LIB` / `SQF_LAB_DATA` environment variables.
* The "1.5·√W" metric and the "TeraKeys/s" headline are gone: only counted group
  operations and `MEcOps/s` are reported.
* `p2g_3ltc_breakthroughs.py` became `sqflab.p2g`, with the Clue 2 decoder now
  asserted at import time.

### Known limitations

* The 32-byte AES key of `path-to-greatness-3ltc` is still unknown
  (37,373,278,038 pairs tested, zero hits).
* Puzzle `#140` (`2^70` operations, `2^35` bytes of table) is not solvable with
  this software, and no claim in this repository says otherwise.
* The legacy lottery monolith depends on `research/archive/`; new deployments
  should use `apps/lottery/api.py`.
