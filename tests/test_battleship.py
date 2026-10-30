import secrets

from sqflab.battleship import (
    WoundRadar,
    cell_bounds,
    cell_label,
    key_to_square_xy,
    morton_decode,
    morton_encode,
    square_xy_to_key,
    unsolved_ships,
)


def test_square_roundtrip():
    bits = 40
    for _ in range(20):
        k = (1 << (bits - 1)) + secrets.randbelow((1 << (bits - 1)) - 1)
        x, y = key_to_square_xy(bits, k)
        assert 0.0 <= x < 1.0 and 0.0 <= y < 1.0
        assert square_xy_to_key(bits, x, y) == k


def test_cell_bounds_contain_their_keys():
    bits = 32
    free = bits - 1
    hy = free // 2
    hx = free - hy
    span_x, span_y = 1 << hx, 1 << hy
    base = 1 << (bits - 1)
    for col in (0, 4, 9):
        for row in (0, 5, 9):
            start, end = cell_bounds(bits, col, row)
            x_int = col * span_x // 10 + 1
            y_int = row * span_y // 10 + 1
            k = base + (x_int << hy) + y_int
            assert start <= k <= end
            x, y = key_to_square_xy(bits, k)
            assert cell_label(x, y) == f"{'ABCDEFGHIJ'[col]}{row + 1}"


def test_every_key_falls_inside_a_consistent_cell():
    bits = 24
    base = 1 << (bits - 1)
    for _ in range(120):
        k = base + secrets.randbelow((1 << (bits - 1)) - 1)
        x, y = key_to_square_xy(bits, k)
        label = cell_label(x, y)
        col, row = "ABCDEFGHIJ".index(label[0]), int(label[1:]) - 1
        start, end = cell_bounds(bits, col, row)
        assert start <= k <= end, "the reported cell must contain the key"


def test_morton_roundtrip():
    for x, y in [(0, 0), (3, 1), (7, 15), (255, 128)]:
        assert morton_decode(morton_encode(x, y, 8), 8) == (x, y)


def test_wound_radar_finds_the_closest_pair():
    radar = WoundRadar(tag_bits=64)
    wound = radar.nearest([0b1010 << 60, (0b1010 << 60) | 1, 0xFFFFFFFFFFFFFFFF])
    assert wound is not None and wound.matched_bits >= 60


def test_ships_are_published_puzzles():
    ships = unsolved_ships()
    assert [s["puzzle"] for s in ships] == [140, 145, 150, 155, 160]
    assert all(len(s["pubkey_hex"]) in (66, 130) for s in ships)
