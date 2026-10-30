# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
from sqflab.p2g import (
    CLUE2_PLAINTEXT,
    SECONDS_OF_DREAM_TRACKS,
    clue8_rule_a,
    clue8_rule_b,
    clue8_rule_c,
    decode_clue2,
    segment_ledger,
    walk_wasd,
)


def test_clue2_decodes_to_the_instruction():
    assert decode_clue2() == CLUE2_PLAINTEXT
    assert CLUE2_PLAINTEXT.startswith("directions") and CLUE2_PLAINTEXT.endswith("first")


def test_clue8_rule_a_and_b():
    s13_a, digits_a = clue8_rule_a()
    s13_b, digits_b = clue8_rule_b()
    assert len(s13_a) == 13 and len(digits_a) == 17
    assert len(s13_b) == 13 and len(digits_b) == 17
    assert digits_a == "71520219618128920"
    assert digits_b == "51420181512195719"


def test_clue8_rule_c_unique_squeeze():
    payload = clue8_rule_c()
    assert payload["k"] == -4
    assert payload["fixed_columns"] == "tdire"
    assert all(len(v) == 13 for v in payload["variants"].values())
    assert payload["variants"]["dashes_enter"][:5] == "enter"


def test_wasd_walk_is_thirteen_cells():
    path = walk_wasd()
    assert len(path) == 13
    assert path[0][:2] == (5, 6)
    assert path[-1][:2] == (3, 0)
    assert "".join(cell[0] for _, _, cell in path) == "5521235191338"


def test_track_table_is_the_album():
    assert len(SECONDS_OF_DREAM_TRACKS) == 13
    assert SECONDS_OF_DREAM_TRACKS[-1][0] == "Seconds of Dream"


def test_segment_ledger_totals():
    ledger = segment_ledger()
    assert ledger["total_pairs_tested"] == 37_373_278_038
    assert ledger["hits"] == 0
    assert len(ledger["segments"]) == 4
