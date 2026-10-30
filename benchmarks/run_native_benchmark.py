#!/usr/bin/env python3
"""Blind benchmark of the native engines (SQF-64 vs RCKangaroo vs classic kangaroo).

The secret key never leaves this script: only ``P = k*G`` and the window width
are handed to the C++ code, and the reconstruction is verified here afterwards.

    python3 benchmarks/run_native_benchmark.py --bits 24 28 32 --trials 3
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sqflab.curve import scalar_mult  # noqa: E402
from sqflab.native import engine  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bits", nargs="+", type=int, default=[24, 28, 32, 36])
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--engines", nargs="+", default=["sqf", "rckangaroo", "classic"],
                        choices=["sqf", "rckangaroo", "classic"])
    parser.add_argument("--out", default=str(ROOT / "benchmarks" / "results" / "native_suite.json"))
    parser.add_argument("--lib", default=os.environ.get("SQF_LAB_LIB"))
    args = parser.parse_args()

    eng = engine(args.lib)
    if eng is None:
        print("libsqf_dual.so not found -- run `make -C cpp` first", file=sys.stderr)
        return 2

    rows = []
    for bits in args.bits:
        for name in args.engines:
            for trial in range(args.trials):
                k = secrets.randbelow((1 << bits) - 1) + 1
                pub = scalar_mult(k)
                if name == "sqf":
                    res = eng.sqf_blind_solve(pub, bits)
                elif name == "rckangaroo":
                    res = eng.rckangaroo(pub, bits, seed=1000 + bits * 10 + trial)
                else:
                    res = eng.classic_kangaroo(pub, bits, seed=5000 + bits * 10 + trial)
                row = {
                    "engine": name,
                    "bits": bits,
                    "trial": trial,
                    "verified": res.k == k,
                    "ops": res.ops,
                    "ops_over_sqrt": round(res.ops_over_sqrt, 3),
                    "seconds": round(res.seconds, 6),
                    "mecops": round(res.mecops, 2),
                    "table_ops": res.table_ops,
                    "search_ops": res.search_ops,
                }
                rows.append(row)
                print(f"{name:11s} 2^{bits:<3d} trial {trial}  verified={row['verified']}  "
                      f"ops={row['ops']:>10,d}  {row['ops_over_sqrt']:.3f}*sqrt(W)  "
                      f"{row['seconds']:.4f}s  {row['mecops']:.1f} MEcOps/s")

    summary = {}
    for row in rows:
        summary.setdefault(f"{row['engine']}@{row['bits']}", []).append(row)
    summary = {
        key: {
            "runs": len(group),
            "verified": sum(1 for g in group if g["verified"]),
            "ops_over_sqrt_mean": round(statistics.fmean(g["ops_over_sqrt"] for g in group), 3),
            "seconds_mean": round(statistics.fmean(g["seconds"] for g in group), 4),
            "mecops_mean": round(statistics.fmean(g["mecops"] for g in group), 2),
        }
        for key, group in summary.items()
    }
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "library": eng.path,
        "rows": rows,
        "summary": summary,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(payload, indent=2))
    print(f"\nreport -> {args.out}")
    for key, stats in summary.items():
        print(f"{key:18s} {stats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
