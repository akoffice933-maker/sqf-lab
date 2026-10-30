"""The "battleship in a single square" model: scheduling, not cryptanalysis.

Every scalar ``k`` of an ``n``-bit puzzle lives in ``[2^(n-1), 2^n)``, i.e. it is
a *free* ``n-1`` bit string.  Split those bits in half and you get a point in
the unit square:

    x = high half / 2^hx        y = low half / 2^hy

so a 10x10 board covers the whole search window, and every cell is an exact,
contiguous scalar interval -- perfect for the anti-duplicate registry.  Firing
a salvo at cell ``Ж4`` therefore means "lease this exact sub-interval".

**Honest disclaimer.** The board is a *scheduling and visualisation* device.
The map is a bijection on the key space; it does not make ``secp256k1`` easier,
and "near misses" (a distinguished point whose x-tag shares a long prefix with
another) are exactly what the birthday paradox predicts, not damage.  Cute navy
metaphors are the single most common way people fool themselves in this field.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "COLUMNS",
    "key_to_square_xy",
    "square_xy_to_key",
    "cell_label",
    "cell_bounds",
    "morton_encode",
    "morton_decode",
    "WoundRadar",
    "unsolved_ships",
]

COLUMNS = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"]

#: Bitcoin puzzles with a revealed public key and no known private key.
UNSOLVED_SHIPS = [
    {"puzzle": 140, "pubkey_hex": "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"},
    {"puzzle": 145, "pubkey_hex": "03afdda497369e219a2c1c369954a930e4d3740968e5e4352475bcffce3140dae5"},
    {"puzzle": 150, "pubkey_hex": "03137807790ea7dc6e97901c2bc87411f45ed74a5629315c4e4b03a0a102250c49"},
    {"puzzle": 155, "pubkey_hex": "035cd1854cae45391ca4ec428cc7e6c7d9984424b954209a8eea197b9e364c05f6"},
    {"puzzle": 160, "pubkey_hex": "02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673"},
]


def unsolved_ships() -> List[Dict[str, object]]:
    """The five published-key puzzles nobody has broken."""
    return [dict(ship) for ship in UNSOLVED_SHIPS]


def _split(bits: int) -> Tuple[int, int]:
    """Return ``(hx, hy)``: the number of free bits on each axis."""
    free = bits - 1
    if free < 2:
        return (1, 1)
    hy = free // 2
    return (free - hy, hy)


def key_to_square_xy(bits: int, k: int) -> Tuple[float, float]:
    """Normalised ``(x, y)`` of scalar ``k`` inside the ``bits``-bit window."""
    hx, hy = _split(bits)
    offset = k - (1 << (bits - 1))
    span_x = 1 << hx
    span_y = 1 << hy
    if not 0 <= offset < span_x * span_y:
        raise ValueError("key outside the puzzle window")
    return (offset >> hy) / span_x, (offset & (span_y - 1)) / span_y


def square_xy_to_key(bits: int, x: float, y: float) -> int:
    """Inverse of :func:`key_to_square_xy` (clamped to the half-open square)."""
    hx, hy = _split(bits)
    span_x = 1 << hx
    span_y = 1 << hy
    xi = min(max(int(x * span_x), 0), span_x - 1)
    yi = min(max(int(y * span_y), 0), span_y - 1)
    return (1 << (bits - 1)) + (xi << hy) + yi


def cell_label(x: float, y: float, board: int = 10) -> str:
    """Board label (``A1`` .. ``J10``) of a normalised point.

    The ``1e-12`` nudge absorbs float round-off at exact cell boundaries
    (``x = col/board`` computed as ``0.09999999999999999``): without it a key
    sitting on a boundary would be labelled with the neighbouring cell, which is
    exactly the kind of off-by-one that makes a coverage map lie.
    """
    eps = 1e-12
    col = min(int(x * board + eps), board - 1)
    row = min(int(y * board + eps), board - 1) + 1
    return f"{COLUMNS[col % len(COLUMNS)]}{row}"


def cell_bounds(bits: int, col: int, row: int, board: int = 10) -> Tuple[int, int]:
    """Exact inclusive scalar interval covered by one board cell."""
    hx, hy = _split(bits)
    span_x = 1 << hx
    span_y = 1 << hy
    # ceil(lower edge) and floor(upper edge): the cells then tile the grid with
    # no gap and no overlap, and every integer in [lo, hi] labels as ``col``.
    x_lo = -((-col * span_x) // board)
    x_hi = ((col + 1) * span_x - 1) // board
    y_lo = -((-row * span_y) // board)
    y_hi = ((row + 1) * span_y - 1) // board
    start = (1 << (bits - 1)) + (x_lo << hy) + y_lo
    end = (1 << (bits - 1)) + (x_hi << hy) + y_hi
    return start, end


def morton_encode(x: int, y: int, bits: int) -> int:
    """Bit-interleaved (Z-order) index of a cell -- a 1-D cursor over the square."""
    code = 0
    for i in range(bits):
        code |= ((x >> i) & 1) << (2 * i)
        code |= ((y >> i) & 1) << (2 * i + 1)
    return code


def morton_decode(code: int, bits: int) -> Tuple[int, int]:
    """Inverse of :func:`morton_encode`."""
    x = y = 0
    for i in range(bits):
        x |= ((code >> (2 * i)) & 1) << i
        y |= ((code >> (2 * i + 1)) & 1) << i
    return x, y


@dataclass
class Wound:
    """A distinguished point that sits *unusually* close to another herd."""

    matched_bits: int
    x_a: int
    x_b: int
    xor: int


class WoundRadar:
    """Nearest-neighbour audit over distinguished-point x-tags.

    Two herds of size ``D`` over a 64-bit tag space are expected to contain a
    match of ``~log2(D)`` bits by pure chance; a "wound" is only interesting if
    it beats that baseline.
    """

    def __init__(self, tag_bits: int = 64) -> None:
        self.tag_bits = tag_bits

    def nearest(self, tags: Sequence[int], other: Optional[Sequence[int]] = None) -> Optional[Wound]:
        pool = sorted(tags)
        if len(pool) < 2:
            return None
        candidates = sorted(other) if other else pool
        best: Optional[Wound] = None
        for value in candidates:
            idx = self._bisect(pool, value)
            for pos in (idx - 1, idx, idx + 1):
                if 0 <= pos < len(pool) and pool[pos] != value:
                    xor = pool[pos] ^ value
                    matched = self.tag_bits - xor.bit_length() if xor else self.tag_bits
                    if best is None or matched > best.matched_bits:
                        best = Wound(matched, pool[pos], value, xor)
        return best

    @staticmethod
    def _bisect(sorted_values: Sequence[int], value: int) -> int:
        lo, hi = 0, len(sorted_values)
        while lo < hi:
            mid = (lo + hi) // 2
            if sorted_values[mid] < value:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def baseline_matched_bits(self, herd_size: int) -> float:
        """Expected best-of-pair prefix match for ``herd_size`` random 64-bit tags."""
        return math.log2(max(1, herd_size)) + 1.0
