# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
import json

import pytest

from sqflab.registry import Registry, fingerprint


@pytest.fixture()
def registry(tmp_path):
    with Registry(str(tmp_path / "registry.sqlite3")) as reg:
        yield reg


def test_blocks_never_overlap(registry):
    agent = registry.register_agent("pytest")
    first = registry.claim("puzzle-140", agent_id=agent, bits=32, span=1 << 10)
    second = registry.claim("puzzle-140", agent_id=agent, bits=32, span=1 << 10)
    assert first["end_k"] + 1 == second["start_k"]
    assert first["width"] == 1 << 10


def test_duplicate_range_is_rejected_and_redirected(registry):
    agent = registry.register_agent("pytest")
    first = registry.claim("puzzle-140", agent_id=agent, bits=32, span=256)
    dup = registry.claim(
        "puzzle-140",
        agent_id=agent,
        bits=32,
        span=256,
        start=first["start_k"] + 1,
        end=first["start_k"] + 100,
    )
    assert dup["duplicate_prevented"] is True
    assert dup["start_k"] > first["end_k"]


def test_explicit_free_range_is_accepted(registry):
    registry.claim("label", bits=32, span=16)
    start = (1 << 31) + 0x1000
    block = registry.claim("label", bits=32, start=start, end=start + 255)
    assert block["start_k"] == start and block["duplicate_prevented"] is False


def test_complete_marks_scanned(registry):
    block = registry.claim("label", bits=32, span=64)
    registry.complete(block["block_id"], ops=1234)
    stats = registry.stats("label")
    assert stats["blocks_by_status"]["SCANNED_LOCKED"]["count"] == 1


def test_keys_are_deduplicated(registry):
    assert registry.submit_key(0xABCDEF, bits=24, source="unit") is True
    assert registry.submit_key(0xABCDEF, bits=24, source="unit") is False
    assert registry.has_key(0xABCDEF) is True
    assert registry.stats()["unique_keys_tested"] == 1


def test_fingerprint_is_stable_and_salted():
    assert fingerprint(42) == fingerprint(42)
    assert fingerprint(42) != fingerprint(42, salt="other")
    assert len(fingerprint(42)) == 32


def test_persistence_across_reopen(tmp_path):
    path = str(tmp_path / "persist.sqlite3")
    with Registry(path) as reg:
        block = reg.claim("label", bits=32, span=32)
        reg.submit_key(7, bits=8)
    with Registry(path) as reg:
        assert reg.has_key(7)
        assert reg.stats("label")["blocks_by_status"]["LEASED"]["count"] == 1
        exported = reg.export_json(str(tmp_path / "export.json"), label="label")
    payload = json.loads((tmp_path / "export.json").read_text())
    assert payload["anti_duplicate_guarantee"] == "STRICT_NON_OVERLAPPING_LOCK"
    assert payload["blocks"][0]["block_id"] == block["block_id"]
    assert exported["label"] == "label"


def test_widths_above_63_bits_do_not_overflow(registry):
    """140-bit bounds overflow SQLite's 64-bit CAST; widths are summed in Python."""
    start = 1 << 139
    block = registry.claim("puzzle-140", bits=140, start=start, end=start + (1 << 40) - 1)
    registry.complete(block["block_id"], ops=1 << 40)
    stats = registry.stats("puzzle-140")
    assert stats["blocks_by_status"]["SCANNED_LOCKED"]["width"] == 1 << 40


def test_exhaustion_raises(registry):
    with pytest.raises(RuntimeError):
        registry.claim("tiny", bits=2, span=1 << 3)
