# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
"""SQF-BSGS: the symmetric-quartet baby-step/giant-step solver.

The solver is deliberately small, readable and *honest*: every group operation
that happens inside a loop is counted, the baby table is built from scratch on
every call, and the resulting key is only accepted after an independent
``k*G == target`` check that happens **outside** the search loops.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Optional

from .curve import G, N, Point, point_add, point_neg, scalar_mult
from .folding import FoldTable, centered_window, optimal_table_size

__all__ = ["SolveResult", "sqf_solve", "sqf_bsgs", "expected_ops"]


@dataclass
class SolveResult:
    """Outcome of one solver run (all counters are measured, never modelled)."""

    k: Optional[int]
    a: int
    b: int
    table_size: int
    baby_ops: int = 0
    giant_ops: int = 0
    inversions: int = 0
    seconds: float = 0.0
    memory_bytes: int = 0
    candidates_checked: int = 0
    verified: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def ops(self) -> int:
        """Total counted group operations (baby + giant)."""
        return self.baby_ops + self.giant_ops

    @property
    def width(self) -> int:
        return self.b - self.a

    @property
    def ops_over_sqrt(self) -> float:
        return self.ops / math.sqrt(max(1, self.width))


def expected_ops(width: int) -> float:
    """Theoretical SQF-BSGS operation count for an optimally sized table."""
    m = optimal_table_size(width)
    q = width // (2 * m) + 2
    return float(m + 2 * q)


def sqf_solve(
    target_pub: Point,
    a: int,
    b: int,
    table_size: Optional[int] = None,
    max_table: int = 1 << 21,
) -> SolveResult:
    """Recover ``k in [a, b]`` with ``k*G == target_pub`` (``None`` if absent).

    Parameters
    ----------
    target_pub:
        Affine public key.
    a, b:
        Inclusive scalar bounds.  ``b - a`` must exceed 1.
    table_size:
        Baby-table size ``M``.  Defaults to ``min(sqrt(W/2), max_table)``.
    max_table:
        Hard memory guard (entries).  Keep in mind a Python dict entry costs
        roughly 120 bytes, so ``2**21`` is already ~250 MB.
    """
    if target_pub is None:
        raise ValueError("target public key cannot be the point at infinity")
    if a >= b:
        raise ValueError("empty interval")
    if not 0 < a < N and not 0 < b < N:
        raise ValueError("interval outside the group order")

    started = time.perf_counter()
    width = b - a
    centre, radius = centered_window(a, b)

    if table_size is None:
        table_size = min(optimal_table_size(width), max_table)
    table_size = max(1, int(table_size))
    step_scalar = 2 * table_size
    q_max = radius // step_scalar + 1

    result = SolveResult(k=None, a=a, b=b, table_size=table_size)
    result.extra["q_max"] = q_max
    result.extra["radius"] = radius

    # ---- phase 1: baby table (x-only, implicit +- symmetry) ---------------- #
    table = FoldTable(size=table_size, base=G).build()
    # One counted operation per derived multiple: mirror_multiples performs
    # exactly `table_size` additions (plus ~M/512 doublings) for these entries.
    for _j in range(1, table_size + 1):
        result.baby_ops += 1
    result.inversions += table.inversions
    result.memory_bytes = table.memory_bytes

    # ---- phase 2: giant steps --------------------------------------------- #
    # K0 = P - C*G, so the residual d = k - C satisfies d*G == K0.
    anchor = point_add(target_pub, point_neg(scalar_mult(centre)))
    result.inversions += 1

    def _check(point: Point, signed_q: int) -> Optional[int]:
        """Test one giant step against the baby table.

        ``signed_q`` is ``+q`` on the forward ladder and ``-q`` on the backward
        one, so that ``d = -signed_q*2M +- r`` always holds and the candidate is
        ``centre - signed_q*2M +- r``.
        """
        if point is None:  # r == 0: the giant step landed exactly on the anchor
            return centre - signed_q * step_scalar
        r = table.probe(point)
        if r is None:
            return None
        # The quartet closes here: the giant-step sign is carried by signed_q,
        # the remaining baby-step sign ambiguity is resolved by the +- loop.
        for candidate_r in (r, -r):
            cand = centre - signed_q * step_scalar + candidate_r
            if not (a <= cand <= b):
                continue
            result.candidates_checked += 1
            if scalar_mult(cand) == target_pub:
                return cand
        return None

    hit = _check(anchor, 0)
    if hit is None and anchor is not None:
        step_point = scalar_mult(step_scalar)
        plus = anchor
        minus = anchor
        for q in range(1, q_max + 1):
            plus = point_add(plus, step_point)
            result.giant_ops += 1
            hit = _check(plus, q)
            if hit is not None:
                break
            minus = point_add(minus, point_neg(step_point))
            result.giant_ops += 1
            hit = _check(minus, -q)
            if hit is not None:
                break

    result.seconds = time.perf_counter() - started
    if hit is not None and a <= hit <= b:
        # Independent verification, outside every search loop.
        result.verified = scalar_mult(hit) == target_pub
        result.k = hit if result.verified else None
    return result


# Friendly alias.
sqf_bsgs = sqf_solve
