# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
"""Smoke test for the C++ engines (skipped when the shared library is absent)."""

import os
import secrets

import pytest

from sqflab.curve import scalar_mult
from sqflab.native import engine

ENGINE = engine(os.environ.get("SQF_LAB_LIB"))
pytestmark = pytest.mark.skipif(ENGINE is None, reason="libsqf_dual.so not built (make -C cpp)")


@pytest.mark.parametrize("bits", [24, 28])
def test_sqf64_blind_solve(bits):
    for _ in range(3):
        k = secrets.randbelow((1 << bits) - 1) + 1
        result = ENGINE.sqf_blind_solve(scalar_mult(k), bits)
        assert result.k == k
        assert result.ops > 0 and result.seconds > 0
        assert result.ops_over_sqrt < 3.0


@pytest.mark.parametrize("bits", [24, 28])
def test_rckangaroo(bits):
    k = secrets.randbelow((1 << bits) - 1) + 1
    result = ENGINE.rckangaroo(scalar_mult(k), bits)
    assert result.k == k
    assert result.ops > 0


def test_classic_kangaroo():
    bits = 24
    k = secrets.randbelow((1 << bits) - 1) + 1
    result = ENGINE.classic_kangaroo(scalar_mult(k), bits)
    assert result.k == k
