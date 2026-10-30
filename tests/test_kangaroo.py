import pytest

from sqflab.curve import scalar_mult
from sqflab.kangaroo import jump_table, kangaroo_solve


def test_jump_table_mean_is_about_sqrt_over_two():
    width = 1 << 20
    jumps = jump_table(width)
    assert abs(sum(jumps) / len(jumps) - (width ** 0.5) / 2) < 0.1 * width ** 0.5


@pytest.mark.parametrize("bits", [12, 14, 16])
def test_recovers_keys_in_small_windows(bits):
    a, b = 1 << (bits - 1), (1 << bits) - 1
    recovered = 0
    for k in (a, a + 1, b - 1, a + (b - a) // 2):
        result = kangaroo_solve(scalar_mult(k), a, b, herds=8)
        if result.k == k and result.verified:
            recovered += 1
    assert recovered >= 3


def test_out_of_range_target_is_not_reported():
    a, b = 1 << 13, (1 << 14) - 1
    result = kangaroo_solve(scalar_mult(b + 777), a, b, trail_len=64, herds=4)
    assert result.k is None
