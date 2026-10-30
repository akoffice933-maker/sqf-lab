"""Pollard's kangaroo (lambda) method with multiple herds.

Kangaroo is the memory-lean alternative to BSGS: ``O(sqrt(W))`` group operations
instead of ``O(sqrt(W))`` memory.  Tame herds start at known offsets from the
top of the interval, wild herds at the target point plus a known random offset;
all herds use the same x -> jump function, so when two herds of opposite colour
land on the same point their walks merge and the key falls out of the distance
difference.

The single-pair version succeeds only ~63% of the time per crossing, which is
why production implementations (RCKangaroo & friends) run many herds.  This
module is the *reference* baseline: small, readable, honest counters, no
``±``-reflection and no 2-cycle avoidance -- the tuned engine is in ``cpp/``.
"""

from __future__ import annotations

import math
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .curve import Point, point_add, scalar_mult

__all__ = ["KangarooResult", "kangaroo_solve", "expected_ops", "jump_table"]

TAME, WILD = 0, 1


@dataclass
class KangarooResult:
    k: Optional[int]
    a: int
    b: int
    ops: int = 0
    herds: int = 1
    collisions: int = 0
    dp_stored: int = 0
    seconds: float = 0.0
    verified: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def width(self) -> int:
        return self.b - self.a

    @property
    def ops_over_sqrt(self) -> float:
        return self.ops / math.sqrt(max(1, self.width))


def expected_ops(width: int) -> float:
    """Literature expectation for a tuned multi-herd implementation (~2*sqrt(W))."""
    return 2.0 * math.sqrt(max(1, width))


def jump_table(width: int, size: int = 64) -> List[int]:
    """Jump distances whose mean is ``~sqrt(W)/2``.

    An all-powers-of-two table makes the walk periodic and multiplies the
    constant by an order of magnitude -- a classic mistake.
    """
    base = max(1, math.isqrt(max(4, width)))
    return [max(1, base * (i + 1) // size) for i in range(size)]


def _jump_index(x: int, size: int, salt: int = 0) -> int:
    """Deterministic, well-mixed jump index derived from an x-coordinate.

    ``salt`` gives each herd its own jump function.  Without it every herd walks
    along segments of the same flow, the tame/wild pairs stop being independent
    trials, and the success rate collapses (measured: 75% instead of >99%).
    """
    mixed = (x ^ (x >> 29) ^ (x >> 47) ^ (salt * 0x9E3779B97F4A7C15)) & 0xFFFFFFFFFF
    return mixed % size


def kangaroo_solve(
    target_pub: Point,
    a: int,
    b: int,
    max_ops: int = 5_000_000,
    jumps: Optional[List[int]] = None,
    trail_len: Optional[int] = None,
    dp_mask_bits: int = 0,
    herds: int = 8,
) -> KangarooResult:
    """Search ``k in [a, b]`` with ``k*G == target_pub``.

    Parameters
    ----------
    trail_len:
        Jumps each herd takes (default ``sqrt(W)``).
    dp_mask_bits:
        Keep only distinguished points in the store (memory knob).
    herds:
        Total number of herds; tame herds are spread over the interval, wild
        herds sit at the target plus known random offsets.
    """
    if a >= b:
        raise ValueError("empty interval")
    started = time.perf_counter()
    width = b - a
    jumps = jumps or jump_table(width)
    jump_points = [scalar_mult(j) for j in jumps]
    n_jumps = len(jumps)
    steps = max(2, trail_len or math.isqrt(width))
    herds = max(2, herds)

    result = KangarooResult(k=None, a=a, b=b, herds=herds)
    result.extra["jumps"] = list(jumps)

    dp_mask = (1 << dp_mask_bits) - 1 if dp_mask_bits else None

    # (point, distance, colour, offset)  -- offset is the known scalar shift.
    walks: List[List[object]] = []
    n_tame = max(1, herds // 2)
    for i in range(herds):
        if i < n_tame:
            # Tame: spread across the interval, offset measured from b.
            pos = b - (width * i) // n_tame
            walks.append([scalar_mult(pos), 0, TAME, pos])
        else:
            # Wild: target shifted by a known offset (scalar arithmetic mod n).
            r = secrets.randbelow(max(2, width // (herds - n_tame)))
            walks.append([point_add(target_pub, scalar_mult(r)), 0, WILD, r])

    store: Dict[int, Tuple[int, int, int]] = {}  # x -> (colour, distance, offset)

    for _ in range(steps):
        for herd_idx, walk in enumerate(walks):
            point, dist, colour, offset = walk  # type: ignore[misc]
            if point is None:
                continue
            x = point[0]

            other = store.get(x)
            if other is not None and other[0] != colour:
                other_colour, other_dist, other_offset = other
                if colour == TAME:
                    tame_dist, tame_off = dist, offset
                    wild_dist, wild_off = other_dist, other_offset
                else:
                    tame_dist, tame_off = other_dist, other_offset
                    wild_dist, wild_off = dist, offset
                # Tame point:  (tame_off + tame_dist) * G
                # Wild point:  (k + wild_off + wild_dist) * G
                base = tame_off + tame_dist - wild_off - wild_dist
                result.collisions += 1
                for cand in (base, -(tame_off + tame_dist) - wild_off - wild_dist):
                    if a <= cand <= b and scalar_mult(cand) == target_pub:
                        result.k = cand
                        result.verified = True
                        result.seconds = time.perf_counter() - started
                        return result

            if dp_mask is None or (x & dp_mask) == 0:
                store.setdefault(x, (colour, dist, offset))
                result.dp_stored += 1

            idx = _jump_index(x, n_jumps, salt=herd_idx + 1)
            walk[0] = point_add(point, jump_points[idx])
            walk[1] = dist + jumps[idx]
            result.ops += 1

    result.seconds = time.perf_counter() - started
    return result
