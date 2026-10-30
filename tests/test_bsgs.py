import math

import pytest

from sqflab.bsgs import expected_ops, sqf_solve
from sqflab.curve import scalar_mult


@pytest.mark.parametrize("bits", [12, 16, 18, 20])
def test_blind_recovery(bits):
    a, b = 1 << (bits - 1), (1 << bits) - 1
    for k in (a, a + 1, b, a + (b - a) // 3):
        result = sqf_solve(scalar_mult(k), a, b)
        assert result.k == k
        assert result.verified is True
        assert result.ops > 0


def test_absent_key_returns_none():
    a, b = 1 << 15, (1 << 16) - 1
    outside = b + 12345
    result = sqf_solve(scalar_mult(outside), a, b)
    assert result.k is None and result.verified is False


def test_counters_are_measured_not_modelled():
    a, b = 1 << 19, (1 << 20) - 1
    result = sqf_solve(scalar_mult(a + 4242), a, b)
    width = b - a
    assert result.ops == result.baby_ops + result.giant_ops
    assert result.table_size == min(result.table_size, 1 << 21)
    assert 0 < result.ops_over_sqrt < 4 * max(1.0, expected_ops(width) / math.sqrt(width))


def test_explicit_table_size_and_memory_guard():
    a, b = 1 << 19, (1 << 20) - 1
    result = sqf_solve(scalar_mult(a + 99), a, b, table_size=64)
    assert result.k == a + 99
    assert result.table_size == 64


def test_rejects_degenerate_inputs():
    with pytest.raises(ValueError):
        sqf_solve(scalar_mult(5), 10, 10)
    with pytest.raises(ValueError):
        sqf_solve(None, 1, 10)
