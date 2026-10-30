"""Honest blind-benchmark harness.

Rules baked into the harness (they exist because every other benchmark of this
kind cheats in exactly these three ways):

1. the secret key is generated here and **never** passed to the solver -- only
   ``P = k*G`` and the inclusive interval ``[a, b]`` travel in;
2. operation counts are whatever the solver itself incremented inside its loops,
   never ``1.5 * sqrt(W)`` computed afterwards from the window width;
3. the recovered scalar is compared against the secret **outside** the solver,
   after it returns.
"""

from __future__ import annotations

import json
import math
import random
import secrets
import statistics
import time
from dataclasses import asdict, dataclass
from typing import Callable, Dict, List, Optional, Sequence

from .bsgs import sqf_solve
from .curve import Point, scalar_mult

__all__ = ["Trial", "blind_trial", "run_suite", "SOLVERS"]

SolverFn = Callable[[Point, int, int], object]


@dataclass
class Trial:
    solver: str
    bits: int
    width: int
    recovered: bool
    verified: bool
    ops: int
    seconds: float
    ops_over_sqrt: float = 0.0
    memory_bytes: int = 0
    table_size: int = 0

    def __post_init__(self) -> None:
        self.ops_over_sqrt = self.ops / math.sqrt(max(1, self.width))


def _sqf_adapter(pub: Point, a: int, b: int):
    res = sqf_solve(pub, a, b)
    return res.k, res.ops, res.seconds, res.memory_bytes, res.table_size


def _kangaroo_adapter(pub: Point, a: int, b: int):
    from .kangaroo import kangaroo_solve

    res = kangaroo_solve(pub, a, b, max_ops=max(2_000_000, 400 * math.isqrt(b - a)))
    return res.k, res.ops, res.seconds, 0, 0


SOLVERS: Dict[str, SolverFn] = {
    "sqf": _sqf_adapter,
    "kangaroo": _kangaroo_adapter,
}


def blind_trial(
    solver: str,
    bits: int,
    rng: Optional[random.Random] = None,
    secret: Optional[int] = None,
) -> Trial:
    """Run one blind trial for a ``bits``-bit window."""
    if solver not in SOLVERS:
        raise KeyError(f"unknown solver {solver!r}; choose from {sorted(SOLVERS)}")
    rng = rng or random.Random(secrets.randbits(128))
    a = 1 << (bits - 1)
    b = (1 << bits) - 1
    if secret is None:
        secret = rng.randrange(a, b + 1)
    if not a <= secret <= b:
        raise ValueError("secret outside the window")

    pub = scalar_mult(secret)
    # --- the solver only ever sees (pub, a, b) ----------------------------- #
    k, ops, seconds, memory, table_size = SOLVERS[solver](pub, a, b)
    # --- verification happens here, outside the solver --------------------- #
    verified = k is not None and k == secret
    return Trial(
        solver=solver,
        bits=bits,
        width=b - a,
        recovered=k is not None,
        verified=verified,
        ops=int(ops),
        seconds=float(seconds),
        memory_bytes=int(memory),
        table_size=int(table_size),
    )


def run_suite(
    solvers: Sequence[str],
    bits_list: Sequence[int],
    trials: int = 3,
    seed: Optional[int] = None,
) -> Dict[str, object]:
    """Run ``trials`` blind trials per (solver, bits) pair and summarise."""
    rng = random.Random(seed if seed is not None else secrets.randbits(64))
    rows: List[Trial] = []
    for solver in solvers:
        for bits in bits_list:
            for _ in range(trials):
                rows.append(blind_trial(solver, bits, rng=rng))

    summary: Dict[str, object] = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                  "trials": [asdict(r) for r in rows], "summary": {}}
    groups: Dict[str, List[Trial]] = {}
    for row in rows:
        groups.setdefault(f"{row.solver}@{row.bits}", []).append(row)
    for key, group in groups.items():
        summary["summary"][key] = {
            "runs": len(group),
            "verified": sum(1 for g in group if g.verified),
            "ops_over_sqrt_mean": round(statistics.fmean(g.ops_over_sqrt for g in group), 3),
            "seconds_mean": round(statistics.fmean(g.seconds for g in group), 4),
            "ops_mean": int(statistics.fmean(g.ops for g in group)),
        }
    return summary


def write_report(payload: Dict[str, object], path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
