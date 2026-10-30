# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
#!/usr/bin/env python3
"""Blind benchmark: pure-Python SQF-BSGS vs the multi-herd kangaroo baseline.

    python3 benchmarks/run_blind_benchmark.py --bits 16 20 24 26 --trials 3

The harness generates the secret here, hands the solver only ``P = k*G`` and the
window, trusts the solver's own in-loop counters, and verifies the answer
outside the solver.  Anything else is marketing, not measurement.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sqflab.bench import run_suite, write_report  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bits", nargs="+", type=int, default=[16, 20, 24])
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--solvers", nargs="+", default=["sqf", "kangaroo"],
                        choices=["sqf", "kangaroo"])
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--out", default=str(ROOT / "benchmarks" / "results" / "blind_suite_python.json"))
    args = parser.parse_args()

    payload = run_suite(args.solvers, args.bits, trials=args.trials, seed=args.seed)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        write_report(payload, args.out)
    for key, stats in payload["summary"].items():
        print(f"{key:18s} runs={stats['runs']} verified={stats['verified']} "
              f"ops/sqrt(W)={stats['ops_over_sqrt_mean']:.3f} "
              f"time={stats['seconds_mean']:.4f}s ops~{stats['ops_mean']:,}")
    if args.out:
        print(f"report -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
