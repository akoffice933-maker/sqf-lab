# Roadmap

## 0.1 (this release)

- [x] `sqflab.curve` / `folding` / `bsgs` / `kangaroo` reference implementations
- [x] blind benchmark harness with in-loop counters and external verification
- [x] native engines (`cpp/`): SQF-64, RCKangaroo, HASH160 scanner, AES-NI oracle
- [x] persistent anti-duplicate registry + reference HTTP pool API
- [x] `path-to-greatness-3ltc` verified decoders and segment ledger
- [x] battleship scheduling model + wound-radar audit with a birthday baseline
- [x] 59 tests, CI on Python 3.10–3.13, native build on Linux

## 0.2

- [ ] `sqflab.sweep`: multi-process driver that leases blocks from the pool,
      runs the native engine per block, and reports DPs incrementally
- [ ] distinguished-point exchange between pools (two registries, one DP space),
      with a replay-resistant merkle log per block
- [ ] `--engine native` in `cli.py` so `sqflab solve` can pick SQF-64 when the
      library is present
- [ ] GPU (OpenCL) kangaroo backend with the same counter discipline

## 0.3

- [ ] reproducible container image pinning compiler, GMP and CPU flags, so the
      `MEcOps/s` column stops depending on the host
- [ ] statistical harness: confidence intervals for `ops/√W` instead of means
      over three trials
- [ ] end-to-end `path-to-greatness` key search driven by clue-constrained
      candidate generation (documented as blocked, not as solved)

## Explicitly not on the roadmap

* Anything advertising sub-`√W` behaviour for ECDLP on `secp256k1`.
* Tooling aimed at third-party wallets or live third-party services.
* "Folding" tricks that assume knowledge of a neighbouring private key.
