# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>

from sqflab.curve import G, point_add, scalar_mult
from sqflab.folding import (
    FoldTable,
    centered_window,
    mirror_multiples,
    optimal_table_size,
    quartet_candidates,
)


def test_mirror_multiples_are_exact():
    for count in (1, 2, 7, 63, 100, 511, 512, 513, 1024):
        points, _ = mirror_multiples(G, count)
        assert len(points) == count + 1
        for j in range(1, count + 1):
            assert points[j] == scalar_mult(j)


def test_mirror_multiples_amortises_inversions():
    points, inversions = mirror_multiples(G, 4096)
    assert all(points[j] == scalar_mult(j) for j in (1, 2, 1023, 2048, 4096))
    assert inversions < 64, "batch inversion should cost ~2*count/batch inversions"


def test_fold_table_has_sign_symmetry():
    table = FoldTable(size=256).build()
    assert len(table) == 256
    for j in (1, 37, 128, 255):
        assert table.probe(scalar_mult(j)) == j
        assert table.probe(point_add(None, scalar_mult(-j))) in (j, None)
        assert table.probe(scalar_mult(j + 1000)) is None


def test_centered_window_covers_interval():
    for a, b in [(1, 10), (2 ** 19, 2 ** 20 - 1), (5, 6)]:
        centre, radius = centered_window(a, b)
        assert centre - radius <= a and b <= centre + radius


def test_quartet_candidates_are_the_four_folds():
    centre, _ = centered_window(1 << 19, (1 << 20) - 1)
    q, r, m = 5, 13, 512
    cands = quartet_candidates(q, r, m, centre)
    step = 2 * m
    assert set(cands) == {
        centre + q * step + r,
        centre + q * step - r,
        centre - q * step + r,
        centre - q * step - r,
    }
    # The shared x-signature lives in residual space: relative to its own giant
    # step every candidate is +-r, and x(r*G) == x(-r*G) is what the x-only baby
    # table exploits (this is the "symmetric" half of SQF).
    target = scalar_mult(r)[0]
    assert scalar_mult(cands[0] - centre - q * step)[0] == target
    assert scalar_mult(cands[1] - centre - q * step)[0] == target
    assert scalar_mult(cands[2] - centre + q * step)[0] == target
    assert scalar_mult(cands[3] - centre + q * step)[0] == target


def test_optimal_table_size_is_about_sqrt_half():
    for bits in (16, 20, 24, 40):
        width = 2 ** bits
        assert abs(optimal_table_size(width) - (width / 2) ** 0.5) < 1
