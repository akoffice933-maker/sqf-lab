"""Persistent, crash-safe anti-duplicate scan registry (SQLite).

The rule enforced here is the one every collaborative search needs and almost
none has: **no range and no key is ever tested twice**.  Two mechanisms:

1. ``blocks``  -- every claimed interval is written *before* work starts and
   closed only after it finishes.  Claims are serialised with
   ``BEGIN IMMEDIATE`` and a fresh block always starts at ``max(end_k) + 1`` for
   its label, so two workers can never overlap.  An explicit range that
   intersects an existing block is rejected and the caller is handed the next
   free block instead.
2. ``keys``    -- every tested scalar is stored by ``blake2b`` fingerprint under
   a ``UNIQUE`` index, so a duplicate submission is a no-op that reports
   ``False``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

__all__ = ["Registry", "Block", "fingerprint"]

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;

CREATE TABLE IF NOT EXISTS agents (
    agent_id     TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    model_family TEXT DEFAULT '',
    strategy     TEXT DEFAULT '',
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
    block_id    TEXT PRIMARY KEY,
    agent_id    TEXT,
    label       TEXT NOT NULL,
    start_k     TEXT NOT NULL,
    end_k       TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('LEASED', 'SCANNED_LOCKED', 'RELEASED')),
    ops         INTEGER DEFAULT 0,
    note        TEXT DEFAULT '',
    created_at  TEXT NOT NULL,
    closed_at   TEXT
);
CREATE INDEX IF NOT EXISTS blocks_label_idx ON blocks(label, status);

CREATE TABLE IF NOT EXISTS keys (
    fingerprint TEXT PRIMARY KEY,
    bits        INTEGER,
    source      TEXT DEFAULT '',
    agent_id    TEXT,
    payload     TEXT DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS distinguished_points (
    tag         TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    herd        INTEGER,
    distance    TEXT,
    x_tag       TEXT,
    payload     TEXT DEFAULT '',
    created_at  TEXT NOT NULL
);
"""


def fingerprint(k: int, salt: str = "") -> str:
    """Stable, non-reversible fingerprint of a scalar (never stores the key)."""
    digest = hashlib.blake2b(f"{salt}{int(k)}".encode(), digest_size=16)
    return digest.hexdigest()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class Block:
    block_id: str
    label: str
    start_k: int
    end_k: int
    status: str

    @property
    def width(self) -> int:
        return self.end_k - self.start_k + 1

    def as_dict(self) -> Dict[str, object]:
        return {
            "block_id": self.block_id,
            "label": self.label,
            "start_k": self.start_k,
            "start_k_hex": hex(self.start_k),
            "end_k": self.end_k,
            "end_k_hex": hex(self.end_k),
            "status": self.status,
            "width": self.width,
        }


class Registry:
    """Crash-safe anti-duplicate registry."""

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        # check_same_thread=False + an internal lock: the reference HTTP API is
        # threaded, and BEGIN IMMEDIATE already serialises writers.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, timeout=30.0, isolation_level=None,
                                     check_same_thread=False)
        self._conn.executescript(SCHEMA)

    # -- plumbing ---------------------------------------------------------- #
    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Registry":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- agents ------------------------------------------------------------ #
    def register_agent(self, name: str, model_family: str = "", strategy: str = "") -> str:
        agent_id = f"agent-{uuid.uuid4().hex[:12]}"
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO agents(agent_id, name, model_family, strategy, created_at)"
                " VALUES(?,?,?,?,?)",
                (agent_id, name, model_family, strategy, _now()),
            )
        return agent_id

    # -- ranges ------------------------------------------------------------ #
    def _blocks(self, label: str) -> List[Block]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT block_id, label, start_k, end_k, status FROM blocks WHERE label=?"
                " ORDER BY CAST(start_k AS INTEGER)",
                (label,),
            ).fetchall()
        return [Block(row[0], row[1], int(row[2]), int(row[3]), row[4]) for row in rows]

    @staticmethod
    def default_window(bits: int) -> tuple:
        """Bitcoin-puzzle convention: ``k in [2^(bits-1), 2^bits - 1]``."""
        return 1 << (bits - 1), (1 << bits) - 1

    def claim(
        self,
        label: str,
        agent_id: Optional[str] = None,
        bits: Optional[int] = None,
        span: Optional[int] = None,
        start: Optional[int] = None,
        end: Optional[int] = None,
        note: str = "",
    ) -> Dict[str, object]:
        """Lease a non-overlapping interval for ``label``.

        Either pass an explicit ``start``/``end`` (which is validated against
        existing blocks) or ``bits`` + ``span`` to receive the next free window.
        """
        if bits is None:
            if start is None or end is None:
                raise ValueError("provide either bits or explicit start/end")
            bits = max(2, end.bit_length())
        window_start, window_end = self.default_window(bits)
        if span is None:
            span = 1 << min(bits - 1, 32)

        with self._tx() as conn:
            rows = conn.execute(
                "SELECT start_k, end_k, status FROM blocks WHERE label=?", (label,)
            ).fetchall()
            taken = [(int(r[0]), int(r[1])) for r in rows]

            def overlaps(lo: int, hi: int) -> bool:
                return any(not (hi < t_lo or lo > t_hi) for t_lo, t_hi in taken)

            duplicate_prevented = False
            reason = ""
            if start is not None and end is not None:
                if start < window_start or end > window_end or start > end:
                    raise ValueError("explicit range outside the label window")
                if overlaps(start, end):
                    duplicate_prevented = True
                    reason = "requested range intersects a locked/leased block"
                else:
                    block = Block(f"blk-{uuid.uuid4().hex[:12]}", label, start, end, "LEASED")
                    self._insert_block(conn, block, agent_id, note)
                    return {
                        **block.as_dict(),
                        "duplicate_prevented": False,
                        "reason": "explicit range accepted",
                    }

            # Sequential allocation: always after the highest end ever seen.
            next_start = max([hi for _lo, hi in taken], default=window_start - 1) + 1
            if next_start + span - 1 > window_end:
                raise RuntimeError(f"label {label!r} exhausted")
            block = Block(
                f"blk-{uuid.uuid4().hex[:12]}", label, next_start, next_start + span - 1, "LEASED"
            )
            self._insert_block(conn, block, agent_id, note)
            return {
                **block.as_dict(),
                "duplicate_prevented": duplicate_prevented,
                "reason": reason or "next free block",
            }

    @staticmethod
    def _insert_block(conn: sqlite3.Connection, block: Block, agent_id: Optional[str], note: str) -> None:
        conn.execute(
            "INSERT INTO blocks(block_id, agent_id, label, start_k, end_k, status, note, created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (block.block_id, agent_id, block.label, str(block.start_k), str(block.end_k),
             block.status, note, _now()),
        )

    def complete(self, block_id: str, ops: int = 0, note: str = "") -> Dict[str, object]:
        """Close a lease for good (``SCANNED_LOCKED``)."""
        with self._tx() as conn:
            row = conn.execute(
                "SELECT label, start_k, end_k, status FROM blocks WHERE block_id=?", (block_id,)
            ).fetchone()
            if row is None:
                raise KeyError(block_id)
            conn.execute(
                "UPDATE blocks SET status='SCANNED_LOCKED', ops=?, note=?, closed_at=? WHERE block_id=?",
                (ops, note, _now(), block_id),
            )
        return Block(block_id, row[0], int(row[1]), int(row[2]), "SCANNED_LOCKED").as_dict()

    def release(self, block_id: str) -> None:
        with self._tx() as conn:
            conn.execute("UPDATE blocks SET status='RELEASED', closed_at=? WHERE block_id=?",
                         (_now(), block_id))

    # -- keys -------------------------------------------------------------- #
    def has_key(self, k: int) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM keys WHERE fingerprint=?", (fingerprint(k),)
            ).fetchone()
        return row is not None

    def submit_key(
        self,
        k: int,
        bits: int,
        agent_id: Optional[str] = None,
        source: str = "",
        payload: str = "",
    ) -> bool:
        """Record a tested scalar.  Returns ``False`` when it was already known."""
        try:
            with self._tx() as conn:
                conn.execute(
                    "INSERT INTO keys(fingerprint, bits, source, agent_id, payload, created_at)"
                    " VALUES(?,?,?,?,?,?)",
                    (fingerprint(k), bits, source, agent_id, payload, _now()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def submit_dp(self, label: str, tag: str, herd: int, distance: int, x_tag: str) -> bool:
        try:
            with self._tx() as conn:
                conn.execute(
                    "INSERT INTO distinguished_points(tag, label, herd, distance, x_tag, created_at)"
                    " VALUES(?,?,?,?,?,?)",
                    (tag, label, herd, str(distance), x_tag, _now()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    # -- reporting --------------------------------------------------------- #
    def stats(self, label: Optional[str] = None) -> Dict[str, object]:
        where, params = ("WHERE label=?", (label,)) if label else ("", ())
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*), COALESCE(SUM(CAST(end_k AS INTEGER)"
                " - CAST(start_k AS INTEGER) + 1),0) FROM blocks"
                f" {where} GROUP BY status",
                params,
            ).fetchall()
            keys_total = self._conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
            dp_total = self._conn.execute(
                "SELECT COUNT(*) FROM distinguished_points").fetchone()[0]
        return {
            "generated_at": _now(),
            "label": label,
            "blocks_by_status": {row[0]: {"count": row[1], "width": row[2]} for row in rows},
            "unique_keys_tested": keys_total,
            "distinguished_points": dp_total,
            "anti_duplicate_guarantee": "STRICT_NON_OVERLAPPING_LOCK",
        }

    def export_json(self, path: str, label: Optional[str] = None) -> Dict[str, object]:
        payload = self.stats(label)
        payload["blocks"] = [b.as_dict() for b in self._blocks(label)] if label else []
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        return payload
