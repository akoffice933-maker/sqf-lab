# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
"""Symmetric Quartet Folding (SQF) -- the primitives.

The idea in one paragraph
-------------------------
Searching ``k in [a, b]`` for ``k*G == P`` looks hopeless until we *fold* the
interval.  Write ``C = (a + b) // 2`` and ``d = k - C``.  Then ``|d| <= R`` with
``R = (b - a) // 2``, and ``d`` can be split as

    d = q * (2M) + r        with  |r| <= M,  |q| <= Q,  R <= (2Q + 1) * M

Now only ``M`` "baby" multiples ``r*G`` have to be precomputed, and ``x(rG)`` is
*the same* for ``+r`` and ``-r`` -- an x-only baby table therefore resolves a
whole **quartet** of candidates around every giant step:

    { +q*2M + r,  +q*2M - r,  -q*2M + r,  -q*2M - r }

so one table entry and two giant steps cover four candidates, and a single
x-lookup tests two of them at once.  That is the whole trick: **± symmetry on
both sides of the fold**.

What SQF is *not*: it is not asymptotically better than Pollard rho/kangaroo.
It is a memory-optimised BSGS whose constant is ``~2*sqrt(W)`` group operations
(measured ``0.71 - 1.39 * sqrt(W)`` for the C++ engine, see
``docs/BENCHMARKS.md``).  For 135+ bit ranges that is still hopeless -- be
extremely suspicious of anybody claiming otherwise.

The second primitive here is :func:`mirror_multiples`, which builds
``j*G`` for ``j = 1..n`` with **one field inversion per ~b*2 points** instead of
one per point, by adding a run of ``b`` consecutive points around a centre and
using the shared denominator ``x(centre) - x(j*b*G)`` for both ``centre + j*b*G``
and ``centre - j*b*G``.  This is the "symmetric quartet" applied to the table
construction itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .curve import G, P, Point, batch_invert, point_add

__all__ = [
    "mirror_multiples",
    "quartet_candidates",
    "FoldTable",
    "centered_window",
    "optimal_table_size",
]


# --------------------------------------------------------------------------- #
# Table construction
# --------------------------------------------------------------------------- #
def mirror_multiples(base: Point = G, count: int = 1024, batch: int = 512) -> Tuple[List[Point], int]:
    """Return ``[None, 1*base, 2*base, ..., count*base]`` and the inversion count.

    The result is 1-indexed so that ``result[j] == j*base`` (``result[0]`` is
    ``None``).  Points are produced in mirror pairs around centres that are
    multiples of ``batch``: ``centre + j*base`` and ``centre - j*base`` share the
    denominator ``x(centre) - x(j*base)``, so **one** field inversion yields two
    new curve points.  Cost: ``count`` additions and ``~2*count/batch``
    inversions instead of ``count`` inversions.
    """
    if count < 1:
        return [None], 0

    size = min(count, max(2, min(batch, count)))
    points: List[Point] = [None] * (count + 1)

    # Seed ladder: the first `size` consecutive multiples (plain additions).
    cursor: Point = None
    for j in range(1, size + 1):
        cursor = point_add(cursor, base)
        points[j] = cursor

    inversions = 0
    centre_step: Point = points[size]  # size * base
    small = points[1:size]             # 1*base .. (size-1)*base
    centre_idx = size

    while centre_idx <= count:
        centre = points[centre_idx]
        if centre is None:  # defensive: never expected
            break
        cx, cy = centre

        pending: List[Tuple[int, int, int, int]] = []  # (idx, sign, sx, sy)
        for j, small_pt in enumerate(small, start=1):
            sx, sy = small_pt  # type: ignore[misc]
            plus_idx = centre_idx + j
            minus_idx = centre_idx - j
            if plus_idx <= count and points[plus_idx] is None:
                pending.append((plus_idx, +1, sx, sy))
            if 1 <= minus_idx <= count and points[minus_idx] is None:
                pending.append((minus_idx, -1, sx, sy))

        if pending:
            diffs = [(cx - sx) % P for (_idx, _sign, sx, _sy) in pending]
            inversions += 1
            for (idx, sign, sx, sy), inv_dx in zip(pending, batch_invert(diffs)):
                numerator = (cy - sy) if sign > 0 else (cy + sy)
                slope = numerator * inv_dx % P
                x3 = (slope * slope - cx - sx) % P
                y3 = (slope * (cx - x3) - cy) % P
                points[idx] = (x3, y3)

        nxt = centre_idx + size
        if nxt <= count:
            if points[nxt] is None:
                points[nxt] = point_add(centre, centre_step)
                inversions += 1
            centre_idx = nxt
        else:
            break

    if any(pt is None for pt in points[1:]):
        # Fallback: fill any hole with a plain ladder step (never expected).
        for i in range(1, count + 1):
            if points[i] is None:
                points[i] = point_add(points[i - 1], base)
                inversions += 1
    return points, inversions


# --------------------------------------------------------------------------- #
# Folding arithmetic
# --------------------------------------------------------------------------- #
def centered_window(a: int, b: int) -> Tuple[int, int]:
    """Return ``(centre, radius)`` such that ``[a, b] == [C - R, C + R]``."""
    if a > b:
        raise ValueError("empty interval")
    centre = (a + b) // 2
    radius = max(b - centre, centre - a)
    return centre, radius


def quartet_candidates(q: int, r: int, table_size: int, centre: int) -> Tuple[int, int, int, int]:
    """The four scalars sharing the x-signature of baby step ``r`` at index ``q``."""
    step = 2 * table_size
    return (
        centre + q * step + r,
        centre + q * step - r,
        centre - q * step + r,
        centre - q * step - r,
    )


def optimal_table_size(width: int) -> int:
    """Baby-table size minimising ``M + width / (2M)`` -- i.e. ``sqrt(width/2)``."""
    import math

    return max(1, math.isqrt(max(4, width) // 2))


# --------------------------------------------------------------------------- #
# x-only baby table
# --------------------------------------------------------------------------- #
@dataclass
class FoldTable:
    """x-indexed baby-step table with implicit ``±`` symmetry.

    One entry ``x(r*G) -> r`` answers *both* ``r`` and ``-r``, halving memory
    and doubling the effective coverage per lookup.
    """

    size: int = 1024
    base: Point = G
    _index: Dict[int, int] = field(default_factory=dict, repr=False)
    inversions: int = 0
    built: bool = False

    def build(self) -> "FoldTable":
        points, inversions = mirror_multiples(self.base, self.size)
        self._index = {}
        for j in range(1, self.size + 1):
            pt = points[j]
            if pt is not None:
                self._index[pt[0]] = j
        self.inversions = inversions
        self.built = True
        return self

    @property
    def memory_bytes(self) -> int:
        # dict slot + int key + int value, measured empirically at ~120 B/entry.
        return len(self._index) * 120

    def probe(self, point: Point) -> Optional[int]:
        """Return ``r`` with ``x(r*G) == x(point)`` (sign lost), else ``None``."""
        if point is None or not self.built:
            return None
        return self._index.get(point[0])

    def __len__(self) -> int:
        return len(self._index)


def x_signature(points: Sequence[Point]) -> List[int]:
    """Convenience helper: x-coordinates of a sequence of points."""
    return [pt[0] if pt is not None else 0 for pt in points]
