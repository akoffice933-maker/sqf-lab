"""ctypes bindings for the native engines in ``cpp/``.

The Python package never *requires* the shared libraries: :func:`engine`
returns ``None`` when they are missing, and every caller degrades gracefully.
Build them with ``make -C cpp`` (or ``make -C cpp NATIVE=0`` for portable
code), then either keep the default search path or point ``SQF_LAB_LIB`` at
``libsqf_dual.so``.
"""

from __future__ import annotations

import ctypes
import math
import os
import pathlib
import time
from dataclasses import dataclass
from typing import List, Optional

from .curve import Point

__all__ = ["NativeSolve", "NativeEngine", "engine", "available", "search_paths"]

_ENV_VAR = "SQF_LAB_LIB"


def search_paths() -> List[pathlib.Path]:
    """Places we look for ``libsqf_dual.so``, in order."""
    paths: List[pathlib.Path] = []
    env = os.environ.get(_ENV_VAR)
    if env:
        paths.append(pathlib.Path(env))
    root = pathlib.Path(__file__).resolve().parents[2]
    paths.extend(
        [
            root / "cpp" / "build" / "libsqf_dual.so",
            pathlib.Path.cwd() / "libsqf_dual.so",
            pathlib.Path("/home/user/libsqf_dual.so"),
            pathlib.Path("libsqf_dual.so"),
        ]
    )
    return paths


def _limbs(value: int) -> ctypes.Array:
    arr = (ctypes.c_uint64 * 4)()
    for i in range(4):
        arr[i] = (value >> (64 * i)) & 0xFFFFFFFFFFFFFFFF
    return arr


@dataclass
class NativeSolve:
    """One native solve: the counters come from the C++ engine itself."""

    k: int
    table_ops: int
    search_ops: int
    table_seconds: float
    search_seconds: float
    seconds: float
    bits: int
    extra: dict

    @property
    def ops(self) -> int:
        return self.table_ops + self.search_ops

    @property
    def ops_over_sqrt(self) -> float:
        return self.ops / math.sqrt(1 << self.bits)

    @property
    def mecops(self) -> float:
        return self.ops / max(1e-9, self.seconds) / 1e6


class NativeEngine:
    """Thin wrapper around ``libsqf_dual.so`` (SQF-64, classic and SOTA kangaroo)."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = str(path)
        lib = ctypes.CDLL(self.path)

        lib.sqf_linear_bsgs_blind_solve.argtypes = [
            ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_uint32, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_double), ctypes.POINTER(ctypes.c_double),
            ctypes.POINTER(ctypes.c_int64), ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_int32),
        ]
        lib.sqf_linear_bsgs_blind_solve.restype = ctypes.c_int

        lib.sqf_rckangaroo_sota_solve.argtypes = [
            ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_int64), ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_int32),
        ]
        lib.sqf_rckangaroo_sota_solve.restype = ctypes.c_int

        lib.sqf_classic_kangaroo_solve.argtypes = [
            ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_int64), ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.sqf_classic_kangaroo_solve.restype = ctypes.c_int
        self._lib = lib

    # -- helpers ----------------------------------------------------------- #
    @staticmethod
    def _coords(pub: Point):
        assert pub is not None
        return _limbs(pub[0]), _limbs(pub[1])

    # -- engines ----------------------------------------------------------- #
    def sqf_blind_solve(self, pub: Point, bits: int, table_bits: Optional[int] = None) -> NativeSolve:
        """SQF-64: ``k in [0, 2^bits)`` with the baby table rebuilt from scratch."""
        table_bits = table_bits if table_bits is not None else bits // 2 - 1
        px, py = self._coords(pub)
        t_ops, s_ops = ctypes.c_uint64(0), ctypes.c_uint64(0)
        t_sec, s_sec = ctypes.c_double(0.0), ctypes.c_double(0.0)
        q, r, sign = ctypes.c_int64(0), ctypes.c_uint32(0), ctypes.c_int32(0)
        started = time.perf_counter()
        ok = self._lib.sqf_linear_bsgs_blind_solve(
            px, py, bits, table_bits,
            ctypes.byref(t_ops), ctypes.byref(s_ops),
            ctypes.byref(t_sec), ctypes.byref(s_sec),
            ctypes.byref(q), ctypes.byref(r), ctypes.byref(sign),
        )
        elapsed = time.perf_counter() - started
        if not ok:
            raise RuntimeError(f"SQF-64 failed for a {bits}-bit window")
        m = 1 << table_bits
        k = ((1 << bits) // 2) + q.value * (2 * m) + sign.value * r.value
        return NativeSolve(k, t_ops.value, s_ops.value, t_sec.value, s_sec.value,
                           elapsed, bits, {"table_bits": table_bits})

    def rckangaroo(self, pub: Point, bits: int, dp_bits: Optional[int] = None,
                   seed: int = 1000) -> NativeSolve:
        """SOTA v2 kangaroo (RetiredCoder v4.0: ``±`` reflection + L1S2)."""
        dp_bits = dp_bits if dp_bits is not None else max(6, bits // 2 - 8)
        px, py = self._coords(pub)
        answer, ops = ctypes.c_int64(0), ctypes.c_uint64(0)
        dps, collisions = ctypes.c_uint32(0), ctypes.c_int32(0)
        started = time.perf_counter()
        ok = self._lib.sqf_rckangaroo_sota_solve(
            px, py, bits, dp_bits, seed,
            ctypes.byref(answer), ctypes.byref(ops),
            ctypes.byref(dps), ctypes.byref(collisions),
        )
        elapsed = time.perf_counter() - started
        if not ok:
            raise RuntimeError(f"RCKangaroo failed for a {bits}-bit window")
        return NativeSolve(answer.value, 0, ops.value, 0.0, 0.0, elapsed, bits,
                           {"dp_bits": dp_bits, "dps": dps.value, "collisions": collisions.value})

    def classic_kangaroo(self, pub: Point, bits: int, dp_bits: Optional[int] = None,
                         seed: int = 5000) -> NativeSolve:
        """Classical forward-only kangaroo (the honest baseline in C++)."""
        dp_bits = dp_bits if dp_bits is not None else max(6, bits // 2 - 8)
        px, py = self._coords(pub)
        answer, ops = ctypes.c_int64(0), ctypes.c_uint64(0)
        dps = ctypes.c_uint32(0)
        started = time.perf_counter()
        ok = self._lib.sqf_classic_kangaroo_solve(
            px, py, bits, dp_bits, seed,
            ctypes.byref(answer), ctypes.byref(ops), ctypes.byref(dps),
        )
        elapsed = time.perf_counter() - started
        if not ok:
            raise RuntimeError(f"classic kangaroo failed for a {bits}-bit window")
        return NativeSolve(answer.value, 0, ops.value, 0.0, 0.0, elapsed, bits,
                           {"dp_bits": dp_bits, "dps": dps.value})


_CACHE: dict = {}


def engine(path: Optional[str] = None) -> Optional[NativeEngine]:
    """Return a cached engine, or ``None`` when no library can be loaded."""
    key = path or "auto"
    if key in _CACHE:
        return _CACHE[key]
    candidates = [pathlib.Path(path)] if path else search_paths()
    for candidate in candidates:
        try:
            if candidate.exists():
                _CACHE[key] = NativeEngine(candidate)
                return _CACHE[key]
        except OSError:
            continue
    _CACHE[key] = None
    return None


def available() -> bool:
    """True when a native engine can be loaded."""
    return engine() is not None
