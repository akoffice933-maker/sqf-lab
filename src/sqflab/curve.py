"""Pure-Python ``secp256k1`` arithmetic used by every solver in this package.

Everything here is intentionally dependency-free and side-effect free so that the
honest-benchmark harness (``sqflab.bench``) can count group operations without
any hidden C acceleration.

The curve is ``y^2 = x^3 + 7`` over ``F_p`` with cofactor 1.
"""

from __future__ import annotations

import hashlib
from typing import List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Curve constants
# --------------------------------------------------------------------------- #
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

Point = Optional[Tuple[int, int]]
"""An affine point, or ``None`` for the point at infinity."""

G: Tuple[int, int] = (GX, GY)


def is_on_curve(point: Point) -> bool:
    """Return ``True`` when ``point`` satisfies the curve equation."""
    if point is None:
        return True
    x, y = point
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + B)) % P == 0


# --------------------------------------------------------------------------- #
# Group law (affine, one modular inversion per add -- see folding.batch_invert
# for the amortisation trick that makes table construction cheap)
# --------------------------------------------------------------------------- #
def point_neg(point: Point) -> Point:
    """Return the additive inverse ``-point``."""
    if point is None:
        return None
    return (point[0], (-point[1]) % P)


def point_add(left: Point, right: Point) -> Point:
    """Add two affine points."""
    if left is None:
        return right
    if right is None:
        return left

    x1, y1 = left
    x2, y2 = right

    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None  # P + (-P) = O
        # Point doubling: slope = (3x^2 + a) / 2y with a = 0.
        slope = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def point_sub(left: Point, right: Point) -> Point:
    """Subtract ``right`` from ``left``."""
    return point_add(left, point_neg(right))


def scalar_mult(k: int, point: Point = G, reduce: bool = True) -> Point:
    """Return ``k * point`` using a left-to-right double-and-add ladder."""
    if point is None:
        return None
    if reduce:
        k %= N
    if k == 0 or point is None:
        return None
    if k < 0:
        return scalar_mult(-k, point_neg(point), reduce=False)

    result: Point = None
    addend: Point = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def multi_scalar_mult(scalars: Sequence[int], points: Sequence[Point]) -> Point:
    """Return ``sum(s_i * P_i)`` (naive; here for readability, not speed)."""
    acc: Point = None
    for s, pt in zip(scalars, points):
        acc = point_add(acc, scalar_mult(s, pt))
    return acc


# --------------------------------------------------------------------------- #
# Batch inversion
# --------------------------------------------------------------------------- #
def batch_invert(values: Sequence[int]) -> List[int]:
    """Montgomery's trick: invert ``len(values)`` field elements with **one** pow.

    Cost: ``1`` modular inversion + ``3 * (n - 1)`` multiplications, instead of
    ``n`` inversions.  This is the primitive that makes the folding table cheap.
    """
    n = len(values)
    if n == 0:
        return []
    prefix = [0] * n
    acc = 1
    for i, value in enumerate(values):
        if value % P == 0:
            raise ZeroDivisionError("cannot batch-invert zero")
        acc = acc * value % P
        prefix[i] = acc
    inv_all = pow(acc, -1, P)
    out = [0] * n
    for i in range(n - 1, 0, -1):
        out[i] = inv_all * prefix[i - 1] % P
        inv_all = inv_all * values[i] % P
    out[0] = inv_all
    return out


# --------------------------------------------------------------------------- #
# Serialisation / addresses
# --------------------------------------------------------------------------- #
def compress(point: Point) -> bytes:
    """SEC1 compressed encoding (``02``/``03`` + X)."""
    if point is None:
        raise ValueError("point at infinity has no SEC1 encoding")
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def serialize_uncompressed(point: Point) -> bytes:
    """SEC1 uncompressed encoding (``04`` + X + Y)."""
    if point is None:
        raise ValueError("point at infinity has no SEC1 encoding")
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def decompress(data: bytes) -> Point:
    """Decode a SEC1 compressed/uncompressed public key."""
    data = bytes(data)
    if len(data) == 65 and data[0] == 4:
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:], "big")
        if not is_on_curve((x, y)):
            raise ValueError("point is not on secp256k1")
        return (x, y)
    if len(data) == 33 and data[0] in (2, 3):
        x = int.from_bytes(data[1:], "big")
        if x >= P:
            raise ValueError("X out of range")
        rhs = (pow(x, 3, P) + B) % P
        y = pow(rhs, (P + 1) // 4, P)
        if y * y % P != rhs:
            raise ValueError("X is not on secp256k1 (no square root)")
        if (y & 1) != (data[0] & 1):
            y = P - y
        return (x, y)
    raise ValueError("unsupported SEC1 encoding")


def hash160(data: bytes) -> bytes:
    """``RIPEMD160(SHA256(data))``."""
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def p2pkh_script_hash(pubkey: bytes) -> bytes:
    """Hash160 of a serialised public key."""
    return hash160(bytes(pubkey))


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(payload: bytes) -> str:
    """Base58Check encoding (Bitcoin alphabet, 4-byte double-SHA256 checksum)."""
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    raw = payload + checksum
    value = int.from_bytes(raw, "big")
    out = []
    while value:
        value, rem = divmod(value, 58)
        out.append(_B58[rem])
    pad = 0
    for byte in raw:
        if byte != 0:
            break
        pad += 1
    return "1" * pad + "".join(reversed(out))


def p2pkh_address(pubkey: bytes, version: int = 0x00) -> str:
    """Legacy P2PKH address for a 33/65-byte public key."""
    return base58check(bytes([version]) + p2pkh_script_hash(pubkey))


def wif(k: int, compressed: bool = True, version: int = 0x80) -> str:
    """Wallet Import Format encoding of a private scalar."""
    if not 0 < k < N:
        raise ValueError("private scalar out of range")
    payload = bytes([version]) + k.to_bytes(32, "big")
    if compressed:
        payload += b"\x01"
    return base58check(payload)


def pubkey_from_private(k: int, compressed: bool = True) -> bytes:
    """Serialise the public key belonging to ``k``."""
    point = scalar_mult(k)
    return compress(point) if compressed else serialize_uncompressed(point)


__all__ = [
    "P",
    "N",
    "A",
    "B",
    "G",
    "Point",
    "is_on_curve",
    "point_add",
    "point_sub",
    "point_neg",
    "scalar_mult",
    "multi_scalar_mult",
    "batch_invert",
    "compress",
    "decompress",
    "serialize_uncompressed",
    "hash160",
    "p2pkh_script_hash",
    "base58check",
    "p2pkh_address",
    "wif",
    "pubkey_from_private",
]
