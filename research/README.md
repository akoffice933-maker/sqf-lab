# `research/archive` — frozen laboratory scripts

These are the original exploration scripts, kept for provenance. Two
`# SPDX-...` header lines were prepended to each file for licence compliance;
everything below them is **verbatim**. They are not part of the tested surface
and they are not maintained.

What to expect inside:

* Russian comments and console output;
* hardcoded `/home/user/...` paths;
* scripts that import each other by filename (`from honest_4point_audit import …`);
* one-off analyses of specific Bitcoin puzzles, the a third-party address address, the
  `path-to-greatness` hunt, and various folding variants that were later
  superseded.

## Why keep them at all

1. **Provenance.** Every claim in `docs/` can be traced to the script that
   produced it (`honest_core_vs_kangaroo_benchmark.py`,
   `loocv_mask_and_seed_audit.py`, `multideck_wound_radar_and_firing_range.py`, …).
2. **Negative results.** Much of the value here is *what did not work*
   (LOOCV gains are negative, `1.5·√W` claims were measurement artefacts,
   the beach layer is a decoy).
3. **Context for `apps/lottery/server_legacy.py`**, which imports six of them.

## What replaced them

| old script | new home |
| --- | --- |
| `symmetric_quartet_folding.py`, `sqf_64.py`, `sqf_ultra.py`, `sqf_turbo.py` | `src/sqflab/{curve,folding,bsgs}.py` + `cpp/` |
| `pollard_kangaroo_secp256k1.py`, `full_cycle_kangaroo_attack.py` | `src/sqflab/kangaroo.py` |
| `honest_core_vs_kangaroo_benchmark.py`, `blind_random_benchmark.py` | `src/sqflab/bench.py`, `benchmarks/` |
| `generate_secp256k1_key.py` | `src/sqflab/curve.py` (SEC1/Base58/WIF) |
| `battleship_square_arena.py`, `multideck_wound_radar_and_firing_range.py` | `src/sqflab/battleship.py` |
| `p2g_3ltc_breakthroughs.py` | `src/sqflab/p2g.py` |
| `ai_puzzle_lottery_server.py` | `src/sqflab/registry.py` + `apps/lottery/api.py` |

Data files (`withheld_*.txt`, `*_dps.json`, `*_report.json`) are included because
they are the inputs of published measurements.
