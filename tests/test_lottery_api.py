"""End-to-end test of the reference pool API (real HTTP, real SQLite)."""

import json
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "lottery"))

from api import serve  # noqa: E402


@pytest.fixture()
def pool(tmp_path):
    httpd = serve("127.0.0.1", 0, str(tmp_path / "pool.sqlite3"))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()
    httpd.registry.close()


def _post(base, path, payload):
    request = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read())


def _get(base, path):
    with urllib.request.urlopen(base + path) as response:
        return json.loads(response.read())


def test_full_protocol(pool):
    agent = _post(pool, "/api/agents/register", {"name": "pytest", "model_family": "none"})
    assert agent["ok"] and agent["agent_id"].startswith("agent-")

    first = _post(pool, "/api/ranges/claim",
                  {"agent_id": agent["agent_id"], "label": "puzzle-140",
                   "bits": 40, "span": 1 << 20})
    second = _post(pool, "/api/ranges/claim",
                   {"agent_id": agent["agent_id"], "label": "puzzle-140",
                    "bits": 40, "span": 1 << 20})
    assert first["end_k"] + 1 == second["start_k"], "blocks must be contiguous, never overlapping"

    duplicate = _post(pool, "/api/ranges/claim",
                      {"label": "puzzle-140", "bits": 40, "span": 1 << 20,
                       "start_k_hex": hex(first["start_k"] + 5),
                       "end_k_hex": hex(first["start_k"] + 100)})
    assert duplicate["duplicate_prevented"] is True

    done = _post(pool, "/api/ranges/complete", {"block_id": first["block_id"], "ops": 4096})
    assert done["status"] == "SCANNED_LOCKED"

    key = _post(pool, "/api/submit/key", {"k_hex": "0x1234", "source": "pytest"})
    again = _post(pool, "/api/submit/key", {"k_hex": "0x1234", "source": "pytest"})
    assert key["stored"] is True and again["duplicate"] is True

    state = _get(pool, "/api/state")
    assert state["unique_keys_tested"] == 1
    # the rejected duplicate still hands back a fresh lease, so two stay open
    assert state["blocks_by_status"]["LEASED"]["count"] == 2
    assert state["blocks_by_status"]["SCANNED_LOCKED"]["count"] == 1
    assert state["anti_duplicate_guarantee"] == "STRICT_NON_OVERLAPPING_LOCK"


def test_index_page(pool):
    with urllib.request.urlopen(pool + "/") as response:
        assert b"anti-duplicate pool" in response.read()
