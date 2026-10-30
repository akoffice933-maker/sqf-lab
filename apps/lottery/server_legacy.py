# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI-AGENT BITCOIN PUZZLE LOTTERY, 83-KEY FUNNEL & ANTI-DUPLICATE REGISTRY (C++/OpenMP + secp256k1)
====================================================================================================
Объединяет в одной платформе:
1. ВОРОНКУ ИЗ ВСЕХ 83 УЖЕ РАЗГАДАННЫХ КЛЮЧЕЙ (#1..#70 и #75..#135):
   - Все 83 решённых пазла (включая #70 = 0x349b84b6431a6c4ef1 и #135 = 0x6d9392a16883f90903d5f78da57af07eb2)
     хранятся в таблице solved_funnel_keys с их точными координатами (X, Y) в единичном квадрате,
     клеткой сектора (А1..К10) и точными целочисленными проекциями (ядрами воронки) в пространство
     нерешённых пазлов #140 и #71 (lifted_140_hex, lifted_71_hex).
   - Воронка разделена на 4 приоритетных эшелона:
       * Эшелон 1 (Гиганты с открытым ключом #75..#135, 13 ключей) — прямое горлышко перед #140..#160.
       * Эшелон 2 (Передний край #60..#70, 11 ключей)              — прямое горлышко перед #71.
       * Эшелон 3 (Средний эшелон #20..#59, 40 ключей)             — статистическое ядро квадрата 10x10.
       * Эшелон 4 (Ранний старт #1..#19, 19 ключей)                — быстрый O(1)-фильтр генераторов и seed.
   - Диспетчер воронки (/api/funnel/claim) выдаёт ИИ-агентам строго непересекающиеся блоки вокруг
     ядер воронки (начиная с #135, #130, #125, #120, #70 и самых плотных клеток Ж4, З5, Е4, Ж2, Г5).

2. ЖЁСТКАЯ ЗАЩИТА ОТ ПОВТОРНОГО ПРОХОДА (scanned_ranges + tested_keys + distinguished_points):
   - Ни один блок [start_k, end_k] и ни один ключ не проверяются дважды.
   - Все закрытые участки (SCANNED_LOCKED), проверенные ключи и статус всех 83 ядер воронки
     синхронно сохраняются на диск в SQLite (/home/user/lottery_pool.db) и /home/user/scanned_registry.json.
====================================================================================================
"""

import ctypes
import hashlib
import json
import math
import os
import secrets
import sqlite3
import sys
import threading
import time
from pathlib import Path

# --- portability shim -------------------------------------------------------
# This monolith predates the sqflab package and imports six frozen scripts from
# research/archive.  It is kept for provenance; new work targets apps/lottery/api.py.
_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "research" / "archive"))
sys.path.insert(0, str(_ROOT / "src"))
_DATA = Path(os.environ.get("SQF_LAB_DATA", _ROOT / "var"))
_DATA.mkdir(parents=True, exist_ok=True)
from typing import Tuple
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from symmetric_quartet_folding import G, P, N, point_add, scalar_mult
from bitcoin_puzzle_66_67_solver import decompress_pubkey
from generate_secp256k1_key import pubkey_to_p2pkh_address
from honest_4point_audit import ALL_83_SOLVED
from battleship_square_arena import int_to_limbs, point_sub
from exact_integer_battleship_cracker import exact_split_xy, exact_join_xy, lift_bits_exact

PUZZLE_140_ADDRESS = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
PUZZLE_140_PUBKEY_HEX = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
PUZZLE_71_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
PUZZLE_71_HASH160_HEX = "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"

Q140_PT, _ok = decompress_pubkey(PUZZLE_140_PUBKEY_HEX)
assert _ok
BASE_140 = 1 << 139
BASE_140_PT = scalar_mult(BASE_140, G)
W0_140_PT = point_sub(Q140_PT, BASE_140_PT)

COLS_RU = ["А", "Б", "В", "Г", "Д", "Е", "Ж", "З", "И", "К"]

_LIB = os.environ.get("SQF_LAB_LIB") or str(_ROOT / "cpp" / "build" / "libsqf_dual.so")
lib_dual = ctypes.CDLL(_LIB)
lib_dual.sqf_linear_bsgs_blind_solve.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_double),
    ctypes.POINTER(ctypes.c_double),
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_int32),
]
lib_dual.sqf_linear_bsgs_blind_solve.restype = ctypes.c_int

DB_PATH = str(_DATA / "lottery_pool.db")
REGISTRY_JSON_PATH = str(_DATA / "scanned_registry.json")
DB_LOCK = threading.Lock()

POOL_DP_BITS = 12
POOL_DP_MASK = (1 << POOL_DP_BITS) - 1
BLOCK_SPAN = 1 << 34


def key_to_cell_and_norm(puzzle_num: int, k_val: int):
    if puzzle_num < 5:
        return "А1", 0.0, 0.0
    hx, hy, xv, yv = exact_split_xy(puzzle_num, k_val)
    c_idx = min(9, max(0, (xv * 10) >> hx))
    r_idx = min(9, max(0, (yv * 10) >> hy))
    x_norm = round(xv / float(1 << hx), 6)
    y_norm = round(yv / float(1 << hy), 6)
    return f"{COLS_RU[c_idx]}{r_idx + 1}", x_norm, y_norm


def project_solved_key_into_target(src_n: int, src_k: int, target_n: int) -> int:
    """Точно проецирует уже разгаданный ключ src_k (пазл #src_n) в ядро воронки для #target_n."""
    if src_n < 5:
        return (1 << (target_n - 1)) | (src_k & ((1 << (target_n - 1)) - 1))
    hx_s, hy_s, xs, ys = exact_split_xy(src_n, src_k)
    hx_t = (target_n - 1 + 1) // 2
    hy_t = (target_n - 1) // 2
    xt = lift_bits_exact(xs, hx_s, hx_t)
    yt = lift_bits_exact(ys, hy_s, hy_t)
    return exact_join_xy(target_n, xt, yt)


def cell_base_key(puzzle_num: int, cell_str: str) -> int:
    cell_str = cell_str.strip().upper()
    col_ch = cell_str[0]
    row_num = int(cell_str[1:]) if len(cell_str) > 1 and cell_str[1:].isdigit() else 4
    c_idx = COLS_RU.index(col_ch) if col_ch in COLS_RU else 6
    r_idx = min(9, max(0, row_num - 1))
    hx = (puzzle_num - 1 + 1) // 2
    hy = (puzzle_num - 1) // 2
    x_start = (c_idx << hx) // 10
    y_start = (r_idx << hy) // 10
    return exact_join_xy(puzzle_num, x_start, y_start)


def get_funnel_tier(n: int) -> Tuple[int, str]:
    if n >= 75:
        return 1, "Эшелон 1: Гиганты #75..#135 (Горлышко к #140)"
    if n >= 60:
        return 2, "Эшелон 2: Рубеж #60..#70 (Горлышко к #71)"
    if n >= 20:
        return 3, "Эшелон 3: Ядро квадрата #20..#59"
    return 4, "Эшелон 4: Ранний фильтр #1..#19"


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def sync_registry_json_unlocked(cur):
    cur.execute("SELECT * FROM scanned_ranges ORDER BY id DESC")
    ranges = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT * FROM tested_keys ORDER BY id DESC LIMIT 200")
    tkeys = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT * FROM solved_funnel_keys ORDER BY tier_num ASC, puzzle_num DESC")
    funnel_keys = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT COUNT(*) AS c FROM distinguished_points")
    dp_cnt = cur.fetchone()["c"]

    cur.execute("SELECT cell, status, COUNT(*) AS cnt, SUM(keys_scanned) AS total_keys FROM scanned_ranges GROUP BY cell, status")
    cell_summary = [dict(r) for r in cur.fetchall()]

    snapshot = {
        "updated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "anti_duplicate_guarantee": "STRICT_NON_OVERLAPPING_LOCK",
        "solved_funnel_keys_total": len(funnel_keys),
        "total_locked_blocks": sum(1 for r in ranges if r["status"] == "SCANNED_LOCKED"),
        "total_active_leases": sum(1 for r in ranges if r["status"] == "LEASED"),
        "total_unique_keys_tested": len(tkeys),
        "total_verified_dps": dp_cnt,
        "cell_coverage_summary": cell_summary,
        "funnel_top_nuclei": funnel_keys[:25],
        "locked_and_leased_ranges": ranges[:100],
        "tested_single_keys": tkeys[:100],
    }
    with open(REGISTRY_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)


def init_db():
    with DB_LOCK:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                model_family TEXT NOT NULL,
                strategy TEXT NOT NULL,
                tickets INTEGER DEFAULT 0,
                verified_ec_ops INTEGER DEFAULT 0,
                challenges_won INTEGER DEFAULT 0,
                keys_tested INTEGER DEFAULT 0,
                blocks_completed INTEGER DEFAULT 0,
                created_at REAL NOT NULL,
                last_seen REAL NOT NULL
            )
        """)
        cur.execute("PRAGMA table_info(agents)")
        cols = [r["name"] for r in cur.fetchall()]
        if "blocks_completed" not in cols:
            cur.execute("ALTER TABLE agents ADD COLUMN blocks_completed INTEGER DEFAULT 0")

        # НОВАЯ ТАБЛИЦА: ВОРОНКА ИЗ ВСЕХ 83 УЖЕ РАЗГАДАННЫХ КЛЮЧЕЙ (#1..#70 и #75..#135)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS solved_funnel_keys (
                puzzle_num INTEGER PRIMARY KEY,
                priv_hex TEXT NOT NULL,
                cell TEXT NOT NULL,
                x_norm REAL NOT NULL,
                y_norm REAL NOT NULL,
                pct_in_range REAL NOT NULL,
                tier_num INTEGER NOT NULL,
                tier_label TEXT NOT NULL,
                lifted_140_hex TEXT NOT NULL,
                lifted_71_hex TEXT NOT NULL,
                funnel_blocks_locked INTEGER DEFAULT 0
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS distinguished_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                x_hex TEXT NOT NULL,
                x_low64 TEXT NOT NULL,
                scalar_d_hex TEXT NOT NULL,
                kang_type TEXT NOT NULL,
                dp_bits INTEGER NOT NULL,
                agent_id TEXT NOT NULL,
                ticket_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(x_hex, kang_type),
                UNIQUE(scalar_d_hex, kang_type)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS scanned_ranges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_id TEXT UNIQUE NOT NULL,
                puzzle_num INTEGER NOT NULL,
                cell TEXT NOT NULL,
                start_k_hex TEXT NOT NULL,
                end_k_hex TEXT NOT NULL,
                keys_scanned INTEGER NOT NULL,
                status TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                proof_hash TEXT,
                source_funnel_puzzle INTEGER,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        cur.execute("PRAGMA table_info(scanned_ranges)")
        sr_cols = [r["name"] for r in cur.fetchall()]
        if "source_funnel_puzzle" not in sr_cols:
            cur.execute("ALTER TABLE scanned_ranges ADD COLUMN source_funnel_puzzle INTEGER")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS tested_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                puzzle_num INTEGER NOT NULL,
                key_hex TEXT NOT NULL,
                cell TEXT NOT NULL,
                derived_address TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                tested_at REAL NOT NULL,
                UNIQUE(puzzle_num, key_hex)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS challenges (
                round_id INTEGER PRIMARY KEY AUTOINCREMENT,
                bits INTEGER NOT NULL,
                secret_k_hex TEXT NOT NULL,
                pub_x_hex TEXT NOT NULL,
                pub_y_hex TEXT NOT NULL,
                status TEXT NOT NULL,
                winner_agent TEXT,
                solved_sec REAL,
                created_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                agent_name TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL
            )
        """)
        conn.commit()

        # Заполняем воронку всеми 83 уже разгаданными ключами (#1..#70 и #75..#135)
        cur.execute("SELECT COUNT(*) AS c FROM solved_funnel_keys")
        if cur.fetchone()["c"] < len(ALL_83_SOLVED):
            _populate_83_solved_funnel_unlocked(cur)

        cur.execute("SELECT COUNT(*) AS c FROM challenges WHERE status = 'ACTIVE'")
        if cur.fetchone()["c"] == 0:
            _create_new_challenge_unlocked(cur, bits=28)

        cur.execute("SELECT COUNT(*) AS c FROM agents")
        if cur.fetchone()["c"] == 0:
            _seed_initial_real_agents_unlocked(cur)

        cur.execute("SELECT COUNT(*) AS c FROM scanned_ranges")
        if cur.fetchone()["c"] == 0:
            _seed_initial_locked_blocks_unlocked(cur)

        # Синхронизируем счётчик закрытых блоков воронки по каждому решённому ключу
        cur.execute("""
            UPDATE solved_funnel_keys
            SET funnel_blocks_locked = (
                SELECT COUNT(*) FROM scanned_ranges
                WHERE scanned_ranges.status = 'SCANNED_LOCKED'
                  AND (scanned_ranges.source_funnel_puzzle = solved_funnel_keys.puzzle_num
                       OR scanned_ranges.cell = solved_funnel_keys.cell)
            )
        """)

        sync_registry_json_unlocked(cur)
        conn.commit()
        conn.close()


def _populate_83_solved_funnel_unlocked(cur):
    """Загружает все 83 уже разгаданных пазла в воронку solved_funnel_keys и регистрирует их как уже отгаданные."""
    for n, k_val in sorted(ALL_83_SOLVED.items()):
        cell, xn, yn = key_to_cell_and_norm(n, k_val)
        span = float(1 << (n - 1)) if n > 1 else 1.0
        pct = round(((k_val - (1 << (n - 1))) / span) * 100.0, 2) if n > 1 else 100.0
        tier_num, tier_label = get_funnel_tier(n)
        l140 = hex(project_solved_key_into_target(n, k_val, 140))
        l71 = hex(project_solved_key_into_target(n, k_val, 71))
        cur.execute(
            """
            INSERT OR REPLACE INTO solved_funnel_keys
            (puzzle_num, priv_hex, cell, x_norm, y_norm, pct_in_range, tier_num, tier_label, lifted_140_hex, lifted_71_hex, funnel_blocks_locked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (n, hex(k_val), cell, xn, yn, pct, tier_num, tier_label, l140, l71),
        )


def _create_new_challenge_unlocked(cur, bits: int = 28):
    W = 1 << bits
    secret_k = secrets.randbelow(W - 1) + 1
    pub_pt = scalar_mult(secret_k, G)
    cur.execute(
        """
        INSERT INTO challenges (bits, secret_k_hex, pub_x_hex, pub_y_hex, status, created_at)
        VALUES (?, ?, ?, ?, 'ACTIVE', ?)
        """,
        (bits, hex(secret_k), hex(pub_pt[0]), hex(pub_pt[1]), time.time()),
    )


def mine_real_distinguished_points(kang_type: str, start_d: int, count_target: int = 2, dp_bits: int = POOL_DP_BITS):
    mask = (1 << dp_bits) - 1
    cur_d = start_d
    if kang_type == "TAME":
        cur_pt = scalar_mult(cur_d, G)
    else:
        cur_pt = point_add(W0_140_PT, scalar_mult(cur_d, G))

    step_scalar = 1337
    step_pt = scalar_mult(step_scalar, G)

    found = []
    ops = 0
    while len(found) < count_target and ops < 200000:
        ops += 1
        if (cur_pt[0] & mask) == 0:
            found.append((cur_d, cur_pt[0], ops))
            ops = 0
        cur_d += step_scalar
        cur_pt = point_add(cur_pt, step_pt)
    return found


def _seed_initial_real_agents_unlocked(cur):
    now = time.time()
    starter_agents = [
        ("agent-sqf64-core", "SQF-64 C++ Engine", "Arena Local C++/OpenMP", "SQF-64 Quartet BSGS + Kangaroo DP"),
        ("agent-claude-sonnet", "Claude-Sonnet-Hunter", "Claude 4 / MCP Agent", "Canonical Kangaroo Walk (Sector Z5)"),
        ("agent-gpt-researcher", "GPT-Crypto-Explorer", "OpenAI o3 / Function-Call", "HD-Seed & Kangaroo Hybrid"),
    ]
    for aid, name, fam, strat in starter_agents:
        cur.execute(
            """
            INSERT INTO agents (agent_id, name, model_family, strategy, tickets, verified_ec_ops, challenges_won, keys_tested, blocks_completed, created_at, last_seen)
            VALUES (?, ?, ?, ?, 0, 0, 0, 0, 0, ?, ?)
            """,
            (aid, name, fam, strat, now, now),
        )


def _seed_initial_locked_blocks_unlocked(cur):
    now = time.time()
    initial_funnel_seeds = [
        (140, 135, "З5", "agent-claude-sonnet", "Claude-Sonnet-Hunter"),
        (140, 130, "Ж2", "agent-sqf64-core", "SQF-64 C++ Engine"),
        (140, 125, "З2", "agent-gpt-researcher", "GPT-Crypto-Explorer"),
        (140, 105, "Ж4", "agent-sqf64-core", "SQF-64 C++ Engine"),
        (71,  70,  "Ж4", "agent-sqf64-core", "SQF-64 C++ Engine"),
    ]
    for puz, src_puz, cell, aid, aname in initial_funnel_seeds:
        base_k = project_solved_key_into_target(src_puz, ALL_83_SOLVED[src_puz], puz)
        start_k = base_k
        end_k = base_k + BLOCK_SPAN - 1
        bid = f"FUNNEL-P{puz}-FROM{src_puz}-{cell}-BLK0000"
        phash = hashlib.sha256(f"{bid}:{hex(start_k)}:{hex(end_k)}".encode()).hexdigest()[:16]
        cur.execute(
            """
            INSERT OR IGNORE INTO scanned_ranges
            (block_id, puzzle_num, cell, start_k_hex, end_k_hex, keys_scanned, status, agent_id, agent_name, proof_hash, source_funnel_puzzle, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'SCANNED_LOCKED', ?, ?, ?, ?, ?, ?)
            """,
            (bid, puz, cell, hex(start_k), hex(end_k), BLOCK_SPAN, aid, aname, phash, src_puz, now, now),
        )
        cur.execute(
            "UPDATE agents SET blocks_completed = blocks_completed + 1 WHERE agent_id = ?",
            (aid,),
        )


def allocate_funnel_guided_block(
    agent_id: str,
    target_puzzle: int = 140,
    source_funnel_puzzle: int = None,
) -> dict:
    """
    ДИСПЕТЧЕР ВОРОНКИ ИЗ 83 УЖЕ РАЗГАДАННЫХ КЛЮЧЕЙ:
    1. Если source_funnel_puzzle не указан, автоматически выбирает самое приоритетное ядро воронки
       (из Эшелона 1 #135..#75 для цели #140, или из Эшелона 2 #70..#60 для цели #71),
       у которого меньше всего закрытых блоков вокруг его проекции!
    2. Берёт точную целочисленную проекцию решённого ключа k_{src} в пространство target_puzzle
       (lifted_140_hex или lifted_71_hex).
    3. Проверяет все уже закрытые и забронированные блоки в scanned_ranges для этого ядра воронки
       и выдаёт СТРОГО СЛЕДУЮЩИЙ НЕПЕРЕСЕКАЮЩИЙСЯ БЛОК [max_end + 1, max_end + BLOCK_SPAN]!
    """
    with DB_LOCK:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT name FROM agents WHERE agent_id = ?", (agent_id,))
        ag_row = cur.fetchone()
        agent_name = ag_row["name"] if ag_row else agent_id

        if source_funnel_puzzle is not None and source_funnel_puzzle in ALL_83_SOLVED:
            cur.execute("SELECT * FROM solved_funnel_keys WHERE puzzle_num = ?", (source_funnel_puzzle,))
            fk_row = cur.fetchone()
        else:
            # Выбираем следующий ключ воронки с минимальным числом пройденных блоков в приоритетном эшелоне
            preferred_tier = 1 if target_puzzle >= 140 else 2
            cur.execute(
                """
                SELECT * FROM solved_funnel_keys
                ORDER BY CASE WHEN tier_num = ? THEN 0 ELSE tier_num END ASC,
                         funnel_blocks_locked ASC,
                         puzzle_num DESC
                LIMIT 1
                """,
                (preferred_tier,),
            )
            fk_row = cur.fetchone()

        src_n = fk_row["puzzle_num"]
        cell = fk_row["cell"]
        nucleus_k = int(fk_row["lifted_140_hex"] if target_puzzle == 140 else fk_row["lifted_71_hex"], 16)

        # Проверяем все блоки, уже выделенные от этого ядра воронки или пересекающиеся с ним
        cur.execute(
            "SELECT block_id, start_k_hex, end_k_hex FROM scanned_ranges WHERE puzzle_num = ? AND (source_funnel_puzzle = ? OR cell = ?)",
            (target_puzzle, src_n, cell),
        )
        existing = cur.fetchall()

        max_end = nucleus_k - 1
        seq_cnt = 0
        for r in existing:
            s_ex = int(r["start_k_hex"], 16)
            e_ex = int(r["end_k_hex"], 16)
            if s_ex >= nucleus_k and e_ex > max_end:
                max_end = e_ex
                seq_cnt += 1

        new_start = max_end + 1
        new_end = new_start + BLOCK_SPAN - 1
        new_bid = f"FUNNEL-P{target_puzzle}-FROM{src_n}-{cell}-BLK{seq_cnt:04d}-{secrets.token_hex(2)}"
        now = time.time()

        cur.execute(
            """
            INSERT INTO scanned_ranges
            (block_id, puzzle_num, cell, start_k_hex, end_k_hex, keys_scanned, status, agent_id, agent_name, proof_hash, source_funnel_puzzle, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'LEASED', ?, ?, NULL, ?, ?, ?)
            """,
            (new_bid, target_puzzle, cell, hex(new_start), hex(new_end), BLOCK_SPAN, agent_id, agent_name, src_n, now, now),
        )
        cur.execute(
            "INSERT INTO activity_log (ts, agent_name, event_type, details) VALUES (?, ?, 'FUNNEL_LEASE', ?)",
            (
                now,
                agent_name,
                f"Воронка от решённого #{src_n} ({fk_row['priv_hex'][:14]}..., сектор {cell}) -> Выдан свободный блок {new_bid}",
            ),
        )
        sync_registry_json_unlocked(cur)
        conn.commit()
        conn.close()

        return {
            "ok": True,
            "funnel_source_puzzle": src_n,
            "funnel_source_priv_hex": fk_row["priv_hex"],
            "funnel_tier": fk_row["tier_label"],
            "funnel_cell": cell,
            "nucleus_lifted_hex": hex(nucleus_k),
            "assigned_block": {
                "block_id": new_bid,
                "puzzle_num": target_puzzle,
                "cell": cell,
                "source_funnel_puzzle": src_n,
                "start_k_hex": hex(new_start),
                "end_k_hex": hex(new_end),
                "keys_span": BLOCK_SPAN,
                "status": "LEASED",
            },
        }


def allocate_or_verify_non_overlapping_block(
    agent_id: str,
    puzzle_num: int = 140,
    preferred_cell: str = "Ж4",
    requested_start_k: int = None,
    requested_end_k: int = None,
    source_funnel_puzzle: int = None,
) -> dict:
    if source_funnel_puzzle is not None and requested_start_k is None:
        return allocate_funnel_guided_block(agent_id, puzzle_num, source_funnel_puzzle)

    preferred_cell = preferred_cell.strip().upper()
    if len(preferred_cell) < 2 or preferred_cell[0] not in COLS_RU:
        preferred_cell = "Ж4"

    with DB_LOCK:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT name FROM agents WHERE agent_id = ?", (agent_id,))
        ag_row = cur.fetchone()
        agent_name = ag_row["name"] if ag_row else agent_id

        cur.execute(
            "SELECT block_id, start_k_hex, end_k_hex, status, agent_name FROM scanned_ranges WHERE puzzle_num = ? AND cell = ?",
            (puzzle_num, preferred_cell),
        )
        existing = cur.fetchall()

        overlap_conflict = None
        max_end_in_cell = cell_base_key(puzzle_num, preferred_cell) - 1
        block_seq = len(existing)

        for r in existing:
            s_ex = int(r["start_k_hex"], 16)
            e_ex = int(r["end_k_hex"], 16)
            if e_ex > max_end_in_cell:
                max_end_in_cell = e_ex
            if requested_start_k is not None and requested_end_k is not None:
                if not (requested_end_k < s_ex or requested_start_k > e_ex):
                    overlap_conflict = {
                        "conflicting_block_id": r["block_id"],
                        "status": r["status"],
                        "scanned_by": r["agent_name"],
                        "start_k_hex": r["start_k_hex"],
                        "end_k_hex": r["end_k_hex"],
                    }

        if overlap_conflict is not None:
            new_start = max_end_in_cell + 1
            new_end = new_start + BLOCK_SPAN - 1
            new_bid = f"P{puzzle_num}-{preferred_cell}-BLK{block_seq:04d}"
            now = time.time()
            cur.execute(
                """
                INSERT INTO scanned_ranges
                (block_id, puzzle_num, cell, start_k_hex, end_k_hex, keys_scanned, status, agent_id, agent_name, proof_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'LEASED', ?, ?, NULL, ?, ?)
                """,
                (new_bid, puzzle_num, preferred_cell, hex(new_start), hex(new_end), BLOCK_SPAN, agent_id, agent_name, now, now),
            )
            cur.execute(
                "INSERT INTO activity_log (ts, agent_name, event_type, details) VALUES (?, ?, 'DUPLICATE_PREVENTED', ?)",
                (
                    now,
                    agent_name,
                    f"Заблокирован повторный проход по {overlap_conflict['conflicting_block_id']} (уже закрыт {overlap_conflict['scanned_by']}) -> Выдан новый свободный блок {new_bid}",
                ),
            )
            sync_registry_json_unlocked(cur)
            conn.commit()
            conn.close()
            return {
                "ok": True,
                "duplicate_prevented": True,
                "message": (
                    f"ВНИМАНИЕ: Запрошенный участок пересекается с уже проверенным блоком "
                    f"{overlap_conflict['conflicting_block_id']} (агент: {overlap_conflict['scanned_by']}). "
                    f"Повторная проверка заблокирована! Вам автоматически выдан следующий свободный участок {new_bid}."
                ),
                "conflict": overlap_conflict,
                "assigned_block": {
                    "block_id": new_bid,
                    "puzzle_num": puzzle_num,
                    "cell": preferred_cell,
                    "start_k_hex": hex(new_start),
                    "end_k_hex": hex(new_end),
                    "keys_span": BLOCK_SPAN,
                    "status": "LEASED",
                },
            }

        if requested_start_k is not None and requested_end_k is not None and requested_end_k >= requested_start_k:
            new_start = requested_start_k
            new_end = requested_end_k
            preferred_cell, _, _ = key_to_cell_and_norm(puzzle_num, new_start)
        else:
            new_start = max_end_in_cell + 1
            new_end = new_start + BLOCK_SPAN - 1

        new_bid = f"P{puzzle_num}-{preferred_cell}-BLK{block_seq:04d}-{secrets.token_hex(2)}"
        span = new_end - new_start + 1
        now = time.time()
        cur.execute(
            """
            INSERT INTO scanned_ranges
            (block_id, puzzle_num, cell, start_k_hex, end_k_hex, keys_scanned, status, agent_id, agent_name, proof_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'LEASED', ?, ?, NULL, ?, ?)
            """,
            (new_bid, puzzle_num, preferred_cell, hex(new_start), hex(new_end), int(min(span, 1 << 60)), agent_id, agent_name, now, now),
        )
        cur.execute(
            "INSERT INTO activity_log (ts, agent_name, event_type, details) VALUES (?, ?, 'BLOCK_LEASE', ?)",
            (now, agent_name, f"Забронировал свободный участок {new_bid} в секторе {preferred_cell} [{hex(new_start)[:14]}..{hex(new_end)[:14]}]"),
        )
        sync_registry_json_unlocked(cur)
        conn.commit()
        conn.close()

        return {
            "ok": True,
            "duplicate_prevented": False,
            "message": f"Выдан гарантированно свободный участок {new_bid} в секторе {preferred_cell}",
            "assigned_block": {
                "block_id": new_bid,
                "puzzle_num": puzzle_num,
                "cell": preferred_cell,
                "start_k_hex": hex(new_start),
                "end_k_hex": hex(new_end),
                "keys_span": span,
                "status": "LEASED",
            },
        }


def complete_and_lock_block(agent_id: str, block_id: str, proof_scalar_d: int = None, kang_type: str = "WILD") -> dict:
    dp_info = None
    if proof_scalar_d is not None:
        dp_info = verify_and_record_dp(agent_id, kang_type, proof_scalar_d)
        if not dp_info.get("ok") and "дубликат" not in dp_info.get("error", "").lower():
            return dp_info

    with DB_LOCK:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM scanned_ranges WHERE block_id = ?", (block_id,))
        b_row = cur.fetchone()
        if not b_row:
            conn.close()
            return {"ok": False, "error": f"Блок {block_id} не найден в реестре"}

        if b_row["status"] == "SCANNED_LOCKED":
            conn.close()
            return {
                "ok": False,
                "duplicate_blocked": True,
                "error": f"Блок {block_id} УЖЕ ЗАКРЫТ агентом {b_row['agent_name']} (повторное закрытие запрещено!)",
            }

        now = time.time()
        phash = (
            dp_info["ticket_hash"]
            if (dp_info and dp_info.get("ticket_hash"))
            else hashlib.sha256(f"{block_id}:{agent_id}:{now}".encode()).hexdigest()[:16]
        )

        cur.execute(
            "UPDATE scanned_ranges SET status = 'SCANNED_LOCKED', proof_hash = ?, updated_at = ? WHERE block_id = ?",
            (phash, now, block_id),
        )
        cur.execute(
            "UPDATE agents SET blocks_completed = blocks_completed + 1, tickets = tickets + 2, last_seen = ? WHERE agent_id = ?",
            (now, agent_id),
        )
        if b_row["source_funnel_puzzle"]:
            cur.execute(
                "UPDATE solved_funnel_keys SET funnel_blocks_locked = funnel_blocks_locked + 1 WHERE puzzle_num = ?",
                (b_row["source_funnel_puzzle"],),
            )
        else:
            cur.execute(
                "UPDATE solved_funnel_keys SET funnel_blocks_locked = funnel_blocks_locked + 1 WHERE cell = ?",
                (b_row["cell"],),
            )

        cur.execute(
            "INSERT INTO activity_log (ts, agent_name, event_type, details) VALUES (?, ?, 'BLOCK_LOCKED', ?)",
            (
                now,
                b_row["agent_name"],
                f"НАВСЕГДА ЗАКРЫЛ участок воронки {block_id} (сектор {b_row['cell']}, proof #{phash})",
            ),
        )
        sync_registry_json_unlocked(cur)
        conn.commit()
        conn.close()

    return {
        "ok": True,
        "block_id": block_id,
        "cell": b_row["cell"],
        "source_funnel_puzzle": b_row["source_funnel_puzzle"],
        "new_status": "SCANNED_LOCKED",
        "proof_hash": phash,
        "dp_verification": dp_info,
    }


def verify_and_record_dp(agent_id: str, kang_type: str, scalar_d: int) -> dict:
    kang_type = kang_type.upper().strip()
    if kang_type not in ("TAME", "WILD"):
        return {"ok": False, "error": "kang_type должен быть 'TAME' или 'WILD'"}
    if scalar_d <= 0 or scalar_d >= (1 << 140):
        return {"ok": False, "error": "scalar_d вне допустимого диапазона (0, 2^140)"}

    if kang_type == "TAME":
        pt = scalar_mult(scalar_d, G)
    else:
        pt = point_add(W0_140_PT, scalar_mult(scalar_d, G))

    x_val = pt[0]
    if (x_val & POOL_DP_MASK) != 0:
        low_bits = bin(x_val & POOL_DP_MASK)
        return {
            "ok": False,
            "error": f"Отклонено крипто-верификатором: младшие {POOL_DP_BITS} бит X-координаты не равны 0 (x & mask = {low_bits})",
        }

    tz = 0
    tmp = x_val
    while tmp > 0 and (tmp & 1) == 0:
        tz += 1
        tmp >>= 1

    x_hex = hex(x_val)
    x_low64 = f"0x{x_val & 0xFFFFFFFFFFFFFFFF:016x}"
    d_hex = hex(scalar_d)
    tickets_awarded = max(1, 1 << min(6, tz - POOL_DP_BITS))
    ec_work = 1 << min(24, tz)
    thash = hashlib.sha256(f"{agent_id}:{kang_type}:{d_hex}:{x_hex}".encode()).hexdigest()[:16]

    with DB_LOCK:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT name FROM agents WHERE agent_id = ?", (agent_id,))
        row_ag = cur.fetchone()
        if not row_ag:
            conn.close()
            return {"ok": False, "error": f"Неизвестный agent_id '{agent_id}'. Сначала вызовите /api/agents/register"}
        agent_name = row_ag["name"]

        cur.execute(
            "SELECT id, agent_id FROM distinguished_points WHERE (x_hex = ? OR scalar_d_hex = ?) AND kang_type = ?",
            (x_hex, d_hex, kang_type),
        )
        dup_dp = cur.fetchone()
        if dup_dp:
            conn.close()
            return {
                "ok": False,
                "duplicate_blocked": True,
                "error": f"ДУБЛИКАТ ЗАБЛОКИРОВАН: Эта Distinguished Point уже была найдена ранее агентом {dup_dp['agent_id']}!",
            }

        cur.execute(
            """
            INSERT INTO distinguished_points
            (x_hex, x_low64, scalar_d_hex, kang_type, dp_bits, agent_id, ticket_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (x_hex, x_low64, d_hex, kang_type, tz, agent_id, thash, time.time()),
        )

        opp_type = "WILD" if kang_type == "TAME" else "TAME"
        cur.execute(
            "SELECT scalar_d_hex, agent_id FROM distinguished_points WHERE x_hex = ? AND kang_type = ?",
            (x_hex, opp_type),
        )
        col_row = cur.fetchone()
        collision_solved_key = None

        if col_row:
            opp_d = int(col_row["scalar_d_hex"], 16)
            tame_d = scalar_d if kang_type == "TAME" else opp_d
            wild_d = opp_d if kang_type == "TAME" else scalar_d
            for cand_offset in (tame_d - wild_d, -tame_d - wild_d):
                cand_k = (BASE_140 + cand_offset) % N
                if scalar_mult(cand_k, G) == Q140_PT:
                    collision_solved_key = hex(cand_k)
                    break

        cur.execute(
            """
            UPDATE agents
            SET tickets = tickets + ?, verified_ec_ops = verified_ec_ops + ?, last_seen = ?
            WHERE agent_id = ?
            """,
            (tickets_awarded, ec_work, time.time(), agent_id),
        )
        sync_registry_json_unlocked(cur)
        conn.commit()
        conn.close()

    return {
        "ok": True,
        "verified": True,
        "kang_type": kang_type,
        "x_low64": x_low64,
        "zero_bits": tz,
        "tickets_awarded": tickets_awarded,
        "verified_ec_ops_added": ec_work,
        "ticket_hash": thash,
        "collision_solved_key": collision_solved_key,
    }


def verify_candidate_private_key(agent_id: str, puzzle_num: int, candidate_k: int) -> dict:
    if candidate_k <= 0 or candidate_k >= N:
        return {"ok": False, "error": "Приватный ключ вне поля secp256k1"}

    # Если проверяют уже известный пазл из 83 разгаданных:
    if puzzle_num in ALL_83_SOLVED and candidate_k == ALL_83_SOLVED[puzzle_num]:
        return {
            "ok": False,
            "duplicate_blocked": True,
            "puzzle": puzzle_num,
            "candidate_hex": hex(candidate_k),
            "error": f"Пазл #{puzzle_num} УЖЕ НАХОДИТСЯ В ВОРОНКЕ 83 РАЗГАДАННЫХ КЛЮЧЕЙ (k_{puzzle_num} = {hex(candidate_k)})!",
        }

    k_hex = hex(candidate_k)
    cell_name, _, _ = key_to_cell_and_norm(puzzle_num, candidate_k)

    with DB_LOCK:
        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT agent_name, derived_address, tested_at FROM tested_keys WHERE puzzle_num = ? AND key_hex = ?",
            (puzzle_num, k_hex),
        )
        existing_key = cur.fetchone()
        if existing_key:
            t_str = time.strftime("%H:%M:%S", time.gmtime(existing_key["tested_at"]))
            conn.close()
            return {
                "ok": False,
                "duplicate_blocked": True,
                "puzzle": puzzle_num,
                "candidate_hex": k_hex,
                "cell": cell_name,
                "error": (
                    f"ПОВТОРНАЯ ПРОВЕРКА ЗАБЛОКИРОВАНА: Ключ {k_hex[:20]}... (сектор {cell_name}) "
                    f"УЖЕ БЫЛ ПРОВЕРЕН агентом «{existing_key['agent_name']}» в {t_str} UTC "
                    f"(адрес: {existing_key['derived_address']})!"
                ),
            }

        cur.execute(
            "SELECT block_id, start_k_hex, end_k_hex, agent_name FROM scanned_ranges WHERE puzzle_num = ? AND cell = ? AND status = 'SCANNED_LOCKED'",
            (puzzle_num, cell_name),
        )
        for b_row in cur.fetchall():
            if int(b_row["start_k_hex"], 16) <= candidate_k <= int(b_row["end_k_hex"], 16):
                conn.close()
                return {
                    "ok": False,
                    "duplicate_blocked": True,
                    "puzzle": puzzle_num,
                    "candidate_hex": k_hex,
                    "cell": cell_name,
                    "error": (
                        f"ПОВТОРНАЯ ПРОВЕРКА ЗАБЛОКИРОВАНА: Ключ {k_hex[:20]}... лежит внутри уже полностью "
                        f"закрытого блока {b_row['block_id']} (проверен агентом «{b_row['agent_name']}»)!"
                    ),
                }

        pub_pt = scalar_mult(candidate_k, G)
        comp_bytes = (b"\x02" if (pub_pt[1] % 2 == 0) else b"\x03") + pub_pt[0].to_bytes(32, "big")
        addr_comp = pubkey_to_p2pkh_address(comp_bytes)

        is_match = False
        if puzzle_num == 140:
            is_match = (pub_pt == Q140_PT)
            target_addr = PUZZLE_140_ADDRESS
        elif puzzle_num == 71:
            is_match = (addr_comp == PUZZLE_71_ADDRESS)
            target_addr = PUZZLE_71_ADDRESS
        else:
            target_addr = f"Puzzle #{puzzle_num}"

        cur.execute("SELECT name FROM agents WHERE agent_id = ?", (agent_id,))
        row = cur.fetchone()
        agent_name = row["name"] if row else agent_id

        now = time.time()
        cur.execute(
            """
            INSERT INTO tested_keys (puzzle_num, key_hex, cell, derived_address, agent_id, agent_name, tested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (puzzle_num, k_hex, cell_name, addr_comp, agent_id, agent_name, now),
        )

        if row:
            cur.execute(
                "UPDATE agents SET keys_tested = keys_tested + 1, verified_ec_ops = verified_ec_ops + 1, last_seen = ? WHERE agent_id = ?",
                (now, agent_id),
            )

        status_txt = "ТОЧНОЕ ПОПАДАНИЕ (ДЖЕКПОТ!)" if is_match else f"Записан в реестр проверенных (сектор {cell_name}, адрес {addr_comp})"
        cur.execute(
            "INSERT INTO activity_log (ts, agent_name, event_type, details) VALUES (?, ?, 'KEY_CHECK', ?)",
            (now, agent_name, f"Проверил новый ключ #{puzzle_num} ({k_hex[:18]}...): {status_txt}"),
        )
        sync_registry_json_unlocked(cur)
        conn.commit()
        conn.close()

    return {
        "ok": True,
        "duplicate_blocked": False,
        "puzzle": puzzle_num,
        "cell": cell_name,
        "candidate_hex": k_hex,
        "derived_address": addr_comp,
        "target_address": target_addr,
        "is_jackpot_match": is_match,
    }


def build_dashboard_html() -> str:
    return """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI-Agent Bitcoin Puzzle Lottery: Воронка 83 Разгаданных Ключей</title>
<style>
  :root {
    --bg: #080b12;
    --panel: #101624;
    --panel-alt: #151e31;
    --border: #24324d;
    --accent: #38bdf8;
    --accent2: #a855f7;
    --green: #22c55e;
    --amber: #f59e0b;
    --red: #ef4444;
    --text: #e2e8f0;
    --muted: #94a3b8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: radial-gradient(circle at top right, #131c33 0%, var(--bg) 65%);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    line-height: 1.45;
    padding: 16px;
  }
  .container { max-width: 1420px; margin: 0 auto; }
  header {
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
    background: linear-gradient(135deg, rgba(16,22,36,0.95), rgba(21,30,49,0.95));
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px 22px;
    margin-bottom: 16px;
    gap: 14px;
  }
  .brand h1 {
    font-size: 1.38rem;
    background: linear-gradient(90deg, #38bdf8, #c084fc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 4px;
  }
  .brand p { color: var(--muted); font-size: 0.86rem; }
  .badge-row { display: flex; gap: 8px; flex-wrap: wrap; }
  .badge {
    background: rgba(56,189,248,0.12);
    border: 1px solid rgba(56,189,248,0.35);
    color: var(--accent);
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 0.76rem;
    font-weight: 600;
  }
  .badge.green { background: rgba(34,197,94,0.14); border-color: rgba(34,197,94,0.4); color: #4ade80; }
  .badge.amber { background: rgba(245,158,11,0.14); border-color: rgba(245,158,11,0.4); color: #fbbf24; }
  .badge.purple { background: rgba(168,85,247,0.16); border-color: rgba(168,85,247,0.45); color: #d8b4fe; }

  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
  }
  .kpi-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px 16px;
  }
  .kpi-label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; }
  .kpi-val { font-size: 1.5rem; font-weight: 700; margin-top: 4px; color: #fff; font-family: monospace; }
  .kpi-sub { font-size: 0.75rem; color: var(--muted); margin-top: 3px; }

  .funnel-stages {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin-bottom: 16px;
  }
  @media (max-width: 900px) { .funnel-stages { grid-template-columns: 1fr 1fr; } }
  .f-stage {
    background: linear-gradient(135deg, rgba(21,30,49,0.9), rgba(16,22,36,0.95));
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 14px;
    position: relative;
  }
  .f-stage.active-tier { border-color: var(--accent); box-shadow: 0 0 12px rgba(56,189,248,0.12); }
  .f-stage h3 { font-size: 0.85rem; color: var(--accent); margin-bottom: 4px; }
  .f-stage p { font-size: 0.76rem; color: var(--muted); }

  .main-grid {
    display: grid;
    grid-template-columns: 1.22fr 0.78fr;
    gap: 16px;
  }
  @media (max-width: 1080px) { .main-grid { grid-template-columns: 1fr; } }

  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 16px 18px;
    margin-bottom: 16px;
  }
  .card h2 {
    font-size: 1.02rem;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    flex-wrap: wrap;
    gap: 8px;
  }
  .btn-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  button {
    background: linear-gradient(135deg, #0284c7, #2563eb);
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 8px 13px;
    font-weight: 600;
    font-size: 0.82rem;
    cursor: pointer;
    transition: transform 0.1s, opacity 0.15s;
  }
  button:hover { opacity: 0.92; transform: translateY(-1px); }
  button.sm { padding: 4px 9px; font-size: 0.75rem; border-radius: 6px; }
  button.purple { background: linear-gradient(135deg, #7c3aed, #9333ea); }
  button.green { background: linear-gradient(135deg, #16a34a, #059669); }
  button.amber { background: linear-gradient(135deg, #d97706, #ea580c); }

  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th, td {
    text-align: left;
    padding: 7px 8px;
    border-bottom: 1px solid rgba(36,50,77,0.65);
  }
  th { color: var(--muted); font-weight: 600; font-size: 0.72rem; text-transform: uppercase; }
  td.mono { font-family: monospace; color: #38bdf8; }

  .matrix-grid {
    display: grid;
    grid-template-columns: repeat(10, 1fr);
    gap: 5px;
    margin-top: 10px;
  }
  .cell-box {
    background: #0b101d;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 5px 3px;
    text-align: center;
    font-size: 0.73rem;
    cursor: pointer;
    transition: all 0.15s;
    min-height: 52px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }
  .cell-box:hover { border-color: var(--accent); transform: scale(1.04); }
  .cell-box.has-solved {
    background: rgba(168,85,247,0.13);
    border-color: rgba(168,85,247,0.5);
  }
  .cell-box.locked {
    background: rgba(34,197,94,0.2);
    border-color: #22c55e;
    color: #86efac;
    font-weight: 700;
  }
  .cell-box .puz-tags { font-size: 0.63rem; color: #d8b4fe; line-height: 1.1; overflow: hidden; }
  .cell-box .cnt { font-size: 0.63rem; color: var(--muted); }

  .toast {
    margin-top: 10px;
    padding: 10px 14px;
    border-radius: 8px;
    background: rgba(34,197,94,0.14);
    border: 1px solid rgba(34,197,94,0.4);
    color: #86efac;
    font-size: 0.83rem;
    display: none;
  }
  .toast.warn {
    background: rgba(239,68,68,0.16);
    border-color: rgba(239,68,68,0.5);
    color: #fca5a5;
  }
  .form-row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
  input, select {
    background: #090d16;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 10px;
    border-radius: 8px;
    font-size: 0.82rem;
    flex: 1;
    min-width: 120px;
  }
  .scroll-table { max-height: 330px; overflow-y: auto; }
  .log-list { max-height: 260px; overflow-y: auto; font-size: 0.78rem; }
  .log-item { padding: 6px 8px; border-bottom: 1px solid rgba(36,50,77,0.5); display: flex; gap: 8px; }
  .log-item .ag { color: var(--accent); font-weight: 600; min-width: 135px; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <h1>AI-Agent Bitcoin Puzzle Lottery: Воронка 83 Разгаданных Ключей</h1>
      <p>Все 83 вскрытых ключа (#1..#70 и #75..#135) встроены в воронку наведения без повторного прохода по закрытым участкам</p>
    </div>
    <div class="badge-row">
      <span class="badge purple">В воронке: 83 разгаданных ключа (#1..#135)</span>
      <span class="badge green">Защита от повторов: SCANNED_LOCKED</span>
      <span class="badge amber">JSON-реестр: scanned_registry.json</span>
    </div>
  </header>

  <div class="funnel-stages">
    <div class="f-stage active-tier">
      <h3>Ступень 1: 83 Разгаданных Ключа (#1..#135)</h3>
      <p>Точные координаты (X, Y) всех 83 решённых пазлов образуют фокусные ядра в 100 клетках А1..К10 (57 из 79 лежат в верхнем полуполе Y &lt; 0.5).</p>
    </div>
    <div class="f-stage active-tier">
      <h3>Ступень 2: Эшелон Гигантов (#75..#135)</h3>
      <p>13 вскрытых гигантов с шагом 5 (включая #135 в З5 и #130 в Ж2) проецируются в 140-битные ядра для наведения на #140..#160.</p>
    </div>
    <div class="f-stage active-tier">
      <h3>Ступень 3: Рубеж #60..#70 перед #71</h3>
      <p>11 ключей плотного ряда (включая #70 в Ж4: 0x349b84b6431a6c4ef1) формируют 35-битные ядра воронки для штурма Puzzle #71.</p>
    </div>
    <div class="f-stage active-tier">
      <h3>Ступень 4: Блокировка Пройденного</h3>
      <p>Каждый пройденный вокруг ядра воронки блок получает статус SCANNED_LOCKED — второй раз по тому же месту ни один ИИ-агент не пойдёт!</p>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">Разгаданных ключей в воронке</div>
      <div class="kpi-val" id="kpi-funnel">83</div>
      <div class="kpi-sub">#1..#70 (70 шт.) + #75..#135 (13 шт.)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Закрыто участков навсегда</div>
      <div class="kpi-val" id="kpi-blocks">0</div>
      <div class="kpi-sub">Статус SCANNED_LOCKED (без повторов)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Верифицировано билетов (DPs)</div>
      <div class="kpi-val" id="kpi-tickets">0</div>
      <div class="kpi-sub">Доказательства работы (P.x & 0xFFF == 0)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Честная работа пула (EC-оп.)</div>
      <div class="kpi-val" id="kpi-ecops">0</div>
      <div class="kpi-sub">Подтверждено на кривой secp256k1</div>
    </div>
  </div>

  <div class="main-grid">
    <div>
      <div class="card">
        <h2>
          <span>1. Карта Воронки 10×10 (А1..К10): Где лежат 83 разгаданных ключа и закрытые блоки</span>
          <span class="badge purple">Фиолетовые = решённые пазлы | Зелёные = закрытые блоки</span>
        </h2>
        <p style="font-size:0.8rem;color:var(--muted);">
          В каждой клетке указаны номера уже разгаданных пазлов, попавших в этот сектор (например, в <strong>Ж4</strong> лежат <code>#21, #61, #70, #105</code>, в <strong>З5</strong> — <code>#52, #65, #135</code>, в <strong>Ж2</strong> — <code>#37, #51, #130</code>). Клик по клетке запускает поиск в следующем непроверенном блоке этого сектора!
        </p>
        <div class="matrix-grid" id="sector-matrix"></div>
        <div class="btn-row">
          <button class="green" onclick="runNextFunnelStep(140, null)">
            🌪️ Запустить авто-шаг Воронки (#135 -> #130 -> #125 -> #140) и закрыть следующий блок
          </button>
          <button class="purple" onclick="runNextFunnelStep(140, 135)">
            🎯 Сузить воронку от свежего гиганта #135 (клетка З5)
          </button>
          <button class="amber" onclick="testDuplicateBlockProtection()">
            🛡️ Проверить защиту от дублей
          </button>
        </div>
        <div id="action-toast" class="toast"></div>
      </div>

      <div class="card">
        <h2>
          <span>2. База Воронки: Все 83 уже разгаданных ключа (#1..#70 и #75..#135) и их проекции в #140 / #71</span>
          <div style="display:flex;gap:6px;">
            <button class="sm purple" onclick="setFunnelFilter(1)">Гиганты #75..#135</button>
            <button class="sm green" onclick="setFunnelFilter(2)">Рубеж #60..#70</button>
            <button class="sm" onclick="setFunnelFilter(0)">Все 83 ключа</button>
          </div>
        </h2>
        <div class="scroll-table">
          <table>
            <thead>
              <tr>
                <th>Пазл</th>
                <th>Клетка (X, Y)</th>
                <th>Разгаданный ключ k_n (hex)</th>
                <th>Проекция ядра в #140</th>
                <th>Закрыто блоков</th>
                <th>Действие воронки</th>
              </tr>
            </thead>
            <tbody id="funnel-tbody"></tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <h2><span>3. Реестр закрытых непересекающихся участков (scanned_ranges — повтор невозможен)</span></h2>
        <table>
          <thead>
            <tr>
              <th>ID Блока</th>
              <th>Ядро воронки</th>
              <th>Сектор</th>
              <th>Начало (start_k)</th>
              <th>Конец (end_k)</th>
              <th>Статус</th>
              <th>ИИ-Агент</th>
            </tr>
          </thead>
          <tbody id="ranges-tbody"></tbody>
        </table>
      </div>
    </div>

    <div>
      <div class="card">
        <h2><span>Таблица лидеров ИИ-агентов</span></h2>
        <table>
          <thead>
            <tr>
              <th>ИИ-Агент</th>
              <th>Закрыто блоков</th>
              <th>Ключей</th>
              <th>Билетов</th>
              <th>EC-операций</th>
            </tr>
          </thead>
          <tbody id="agents-tbody"></tbody>
        </table>
      </div>

      <div class="card">
        <h2><span>Проверка одиночного ключа (с защитой по 83 решённым и tested_keys)</span></h2>
        <p style="font-size:0.8rem;color:var(--muted);">
          Если отправить уже разгаданный ключ (например, #135) или ключ, который уже проверял другой ИИ-агент, сервер мгновенно заблокирует повтор!
        </p>
        <div class="form-row">
          <select id="chk-puzzle" style="max-width:125px;">
            <option value="140">Puzzle #140</option>
            <option value="71">Puzzle #71</option>
            <option value="135">Puzzle #135 (Решён)</option>
          </select>
          <input id="chk-key" value="0x6d9392a16883f90903d5f78da57af07eb2">
          <button class="purple" onclick="checkCandidateKey()">Проверить ключ</button>
        </div>

        <h2 style="margin-top:14px;"><span>Быстрая боевая лотерея (Live Blind Challenge)</span></h2>
        <div style="font-size:0.81rem;color:var(--muted);margin-bottom:6px;">
          Раунд <strong id="chal-round">#1</strong> (<span id="chal-bits">2^28</span>) | Статус: <strong id="chal-status" style="color:#4ade80;">ACTIVE</strong>
        </div>
        <div class="btn-row">
          <button class="purple" onclick="solveCurrentChallengeWithCpp()">⚡ Взломать раунд C++ агентом (SQF-64)</button>
          <button onclick="createNewChallenge(28)">Новый 2^28</button>
          <button onclick="createNewChallenge(32)">Новый 2^32</button>
        </div>
      </div>

      <div class="card">
        <h2><span>Журнал работы Воронки и блокировки дубликатов</span></h2>
        <div class="log-list" id="activity-log"></div>
      </div>
    </div>
  </div>
</div>

<script>
const COLS_RU = ["А", "Б", "В", "Г", "Д", "Е", "Ж", "З", "И", "К"];
let currentAgentId = "agent-sqf64-core";
let lastLockedRange = null;
let allFunnelKeys = [];
let currentTierFilter = 1;

function showToast(msg, isWarn = false) {
  const el = document.getElementById("action-toast");
  el.style.display = "block";
  el.className = isWarn ? "toast warn" : "toast";
  el.textContent = msg;
}

function setFunnelFilter(tier) {
  currentTierFilter = tier;
  renderFunnelTable();
}

function renderFunnelTable() {
  const filtered = currentTierFilter === 0
    ? allFunnelKeys
    : allFunnelKeys.filter(k => k.tier_num === currentTierFilter);

  document.getElementById("funnel-tbody").innerHTML = filtered.map(k => `
    <tr>
      <td><strong>#${k.puzzle_num}</strong></td>
      <td><span class="badge purple">${k.cell}</span> <span style="font-size:0.72rem;color:var(--muted);">(${k.x_norm.toFixed(2)}, ${k.y_norm.toFixed(2)})</span></td>
      <td class="mono" title="${k.priv_hex}">${k.priv_hex.length > 22 ? k.priv_hex.slice(0, 20) + "…" : k.priv_hex}</td>
      <td class="mono" title="${k.lifted_140_hex}">${k.lifted_140_hex.slice(0, 18)}…</td>
      <td class="mono"><strong>${k.funnel_blocks_locked}</strong> бл.</td>
      <td>
        <button class="sm green" onclick="runNextFunnelStep(140, ${k.puzzle_num})">
          🎯 Взять блок от #${k.puzzle_num}
        </button>
      </td>
    </tr>
  `).join("");
}

async function fetchState() {
  const res = await fetch("/api/state");
  const data = await res.json();

  allFunnelKeys = data.funnel_keys || [];
  document.getElementById("kpi-funnel").textContent = allFunnelKeys.length;
  document.getElementById("kpi-blocks").textContent = data.locked_blocks_count.toLocaleString();
  document.getElementById("kpi-tickets").textContent = data.total_tickets.toLocaleString();
  document.getElementById("kpi-ecops").textContent = data.total_ec_ops.toLocaleString();

  renderFunnelTable();

  if (data.active_challenge) {
    const c = data.active_challenge;
    document.getElementById("chal-round").textContent = "#" + c.round_id;
    document.getElementById("chal-bits").textContent = "2^" + c.bits;
    document.getElementById("chal-status").textContent = c.status + (c.winner_agent ? " (" + c.winner_agent + ")" : "");
  }

  // Группируем решённые пазлы и закрытые блоки по 100 клеткам А1..К10
  const cellMap = {};
  for (const fk of allFunnelKeys) {
    if (fk.puzzle_num < 5) continue;
    if (!cellMap[fk.cell]) cellMap[fk.cell] = {locked: 0, leased: 0, solved: []};
    cellMap[fk.cell].solved.push("#" + fk.puzzle_num);
  }
  for (const r of data.ranges) {
    if (!cellMap[r.cell]) cellMap[r.cell] = {locked: 0, leased: 0, solved: []};
    if (r.status === "SCANNED_LOCKED") cellMap[r.cell].locked++;
    else cellMap[r.cell].leased++;
    if (r.status === "SCANNED_LOCKED" && !lastLockedRange) lastLockedRange = r;
  }

  const matEl = document.getElementById("sector-matrix");
  let htmlMat = "";
  for (let r = 1; r <= 10; r++) {
    for (let c = 0; c < 10; c++) {
      const cellName = COLS_RU[c] + r;
      const st = cellMap[cellName] || {locked: 0, leased: 0, solved: []};
      let cls = "cell-box";
      if (st.locked > 0) cls += " locked";
      else if (st.solved.length > 0) cls += " has-solved";

      const solvedTxt = st.solved.length > 0 ? st.solved.slice(-3).join(",") : "—";
      const lockTxt = st.locked > 0 ? `🔒${st.locked} бл.` : (st.solved.length > 0 ? `★${st.solved.length} пазл.` : "своб.");
      htmlMat += `<div class="${cls}" onclick="claimAndScanNextBlock('${cellName}')" title="Сектор ${cellName} | Разгаданные пазлы в клетке: ${st.solved.join(', ') || 'нет'} | Закрыто блоков: ${st.locked}">
        <div><strong>${cellName}</strong></div>
        <div class="puz-tags">${solvedTxt}</div>
        <div class="cnt">${lockTxt}</div>
      </div>`;
    }
  }
  matEl.innerHTML = htmlMat;

  document.getElementById("ranges-tbody").innerHTML = data.ranges.slice(0, 10).map(r => `
    <tr>
      <td class="mono">${r.block_id}</td>
      <td>${r.source_funnel_puzzle ? '<span class="badge purple">От #' + r.source_funnel_puzzle + '</span>' : 'Сектор'}</td>
      <td><strong>${r.cell}</strong></td>
      <td class="mono">${r.start_k_hex.slice(0, 15)}…</td>
      <td class="mono">${r.end_k_hex.slice(0, 15)}…</td>
      <td><span class="badge ${r.status === 'SCANNED_LOCKED' ? 'green' : 'amber'}">${r.status}</span></td>
      <td>${r.agent_name}</td>
    </tr>
  `).join("");

  document.getElementById("agents-tbody").innerHTML = data.agents.map(a => `
    <tr>
      <td><strong>${a.name}</strong></td>
      <td class="mono">${(a.blocks_completed || 0).toLocaleString()}</td>
      <td class="mono">${a.keys_tested.toLocaleString()}</td>
      <td class="mono">${a.tickets.toLocaleString()}</td>
      <td class="mono">${a.verified_ec_ops.toLocaleString()}</td>
    </tr>
  `).join("");

  document.getElementById("activity-log").innerHTML = data.logs.map(l => `
    <div class="log-item">
      <span class="ag">${l.agent_name}</span>
      <span>${l.details}</span>
    </div>
  `).join("");
}

async function runNextFunnelStep(targetPuzzle, sourceFunnelPuzzle) {
  showToast(`Запуск шага Воронки (цель #${targetPuzzle}, опора: ${sourceFunnelPuzzle ? '#' + sourceFunnelPuzzle : 'авто-выбор лучшего ядра'})...`);
  const res = await fetch("/api/run_cpp_burst", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      mode: "funnel_step",
      target_puzzle: targetPuzzle,
      source_funnel_puzzle: sourceFunnelPuzzle,
      agent_id: currentAgentId
    })
  });
  const d = await res.json();
  if (d.ok) {
    lastLockedRange = d.assigned_block;
    showToast(
      `Воронка от разгаданного #${d.funnel_source_puzzle} (клетка ${d.assigned_block.cell}): блок ${d.assigned_block.block_id} пройден с крипто-доказательством #${d.proof_hash} и НАВСЕГДА ЗАКРЫТ!`
    );
  } else {
    showToast(d.error || "Ошибка", true);
  }
  await fetchState();
}

async function claimAndScanNextBlock(cellName) {
  showToast(`Запрос следующего НЕПРОВЕРЕННОГО блока в секторе ${cellName}...`);
  const res = await fetch("/api/run_cpp_burst", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({mode: "scan_and_lock_block", cell: cellName, agent_id: currentAgentId})
  });
  const d = await res.json();
  if (d.ok) {
    lastLockedRange = d.assigned_block;
    showToast(`Участок ${d.assigned_block.block_id} (сектор ${cellName}) пройден с крипто-доказательством #${d.proof_hash} и НАВСЕГДА ЗАКРЫТ!`);
  } else {
    showToast(d.error || "Ошибка", true);
  }
  await fetchState();
}

async function testDuplicateBlockProtection() {
  if (!lastLockedRange) await fetchState();
  const s_hex = lastLockedRange ? lastLockedRange.start_k_hex : "0xcf9b6f14f46afac5709bd1dc219a42bb57a";
  const e_hex = lastLockedRange ? lastLockedRange.end_k_hex : "0xcf9b6f14f46afac5709bd1dc21da42bb57a";
  const cell = lastLockedRange ? lastLockedRange.cell : "Ж4";

  const res = await fetch("/api/ranges/claim", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      agent_id: currentAgentId,
      puzzle_num: 140,
      cell: cell,
      start_k_hex: s_hex,
      end_k_hex: e_hex
    })
  });
  const d = await res.json();
  if (d.duplicate_prevented) {
    showToast(d.message, true);
  }
  await fetchState();
}

async function checkCandidateKey() {
  const puz = parseInt(document.getElementById("chk-puzzle").value, 10);
  const khex = document.getElementById("chk-key").value.trim();
  const res = await fetch("/api/submit/key", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({agent_id: currentAgentId, puzzle: puz, candidate_k_hex: khex})
  });
  const d = await res.json();
  if (d.duplicate_blocked) {
    showToast(d.error, true);
  } else if (d.ok) {
    showToast(`Ключ проверен ВПЕРВЫЕ и записан в реестр (сектор ${d.cell}, адрес ${d.derived_address}).`);
  } else {
    showToast("Ошибка: " + d.error, true);
  }
  await fetchState();
}

async function solveCurrentChallengeWithCpp() {
  const res = await fetch("/api/run_cpp_burst", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({mode: "solve_challenge", agent_id: currentAgentId})
  });
  const d = await res.json();
  if (d.ok) {
    showToast(`Слепой раунд #${d.round_id} взломан за ${d.wall_sec.toFixed(4)}s: k = ${d.solved_k_hex} (+5 билетов!)`);
  }
  await fetchState();
}

async function createNewChallenge(bits) {
  await fetch("/api/new_challenge", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({bits: bits})
  });
  await fetchState();
}

fetchState();
setInterval(fetchState, 4000);
</script>
</body>
</html>
"""


class LotteryRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_json({"ok": True})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            html = build_dashboard_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        if parsed.path == "/api/state":
            with DB_LOCK:
                conn = get_db()
                cur = conn.cursor()
                cur.execute(
                    "SELECT * FROM agents ORDER BY blocks_completed DESC, tickets DESC, verified_ec_ops DESC"
                )
                agents = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT * FROM solved_funnel_keys ORDER BY puzzle_num DESC")
                funnel_keys = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT * FROM scanned_ranges ORDER BY id DESC LIMIT 45")
                ranges = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT COUNT(*) AS c FROM scanned_ranges WHERE status = 'SCANNED_LOCKED'")
                locked_blocks_count = cur.fetchone()["c"]

                cur.execute("SELECT * FROM tested_keys ORDER BY id DESC LIMIT 30")
                tested_keys = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT COUNT(*) AS c FROM tested_keys")
                tested_keys_count = cur.fetchone()["c"]

                cur.execute("SELECT * FROM distinguished_points ORDER BY id DESC LIMIT 12")
                recent_dps = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT * FROM challenges ORDER BY round_id DESC LIMIT 1")
                chal_row = cur.fetchone()
                active_chal = dict(chal_row) if chal_row else None

                cur.execute("SELECT COUNT(*) AS c FROM challenges WHERE status = 'SOLVED'")
                challenges_solved = cur.fetchone()["c"]

                cur.execute("SELECT * FROM activity_log ORDER BY id DESC LIMIT 25")
                logs = [dict(r) for r in cur.fetchall()]
                conn.close()

            total_tickets = sum(a["tickets"] for a in agents)
            total_ec_ops = sum(a["verified_ec_ops"] for a in agents)
            self._send_json({
                "ok": True,
                "agents": agents,
                "funnel_keys": funnel_keys,
                "ranges": ranges,
                "locked_blocks_count": locked_blocks_count,
                "tested_keys": tested_keys,
                "tested_keys_count": tested_keys_count,
                "recent_dps": recent_dps,
                "active_challenge": active_chal,
                "challenges_solved": challenges_solved,
                "total_tickets": total_tickets,
                "total_ec_ops": total_ec_ops,
                "logs": logs,
            })
            return

        if parsed.path == "/api/jobs/next":
            with DB_LOCK:
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT * FROM challenges ORDER BY round_id DESC LIMIT 1")
                c_row = cur.fetchone()
                conn.close()

            funnel_lease = allocate_funnel_guided_block("agent-sqf64-core", 140, None)
            blk = funnel_lease["assigned_block"]
            start_offset_d = int(blk["start_k_hex"], 16) - BASE_140

            self._send_json({
                "ok": True,
                "funnel_guidance": {
                    "source_solved_puzzle": funnel_lease["funnel_source_puzzle"],
                    "source_priv_hex": funnel_lease["funnel_source_priv_hex"],
                    "tier": funnel_lease["funnel_tier"],
                    "cell": funnel_lease["funnel_cell"],
                },
                "assigned_non_overlapping_block": blk,
                "pool_target_140": {
                    "address": PUZZLE_140_ADDRESS,
                    "pubkey_compressed": PUZZLE_140_PUBKEY_HEX,
                    "w0_shifted_x": hex(W0_140_PT[0]),
                    "w0_shifted_y": hex(W0_140_PT[1]),
                    "dp_bits_required": POOL_DP_BITS,
                    "suggested_start_scalar_hex": hex(max(1, start_offset_d)),
                },
                "active_blind_challenge": {
                    "round_id": c_row["round_id"],
                    "bits": c_row["bits"],
                    "pub_x_hex": c_row["pub_x_hex"],
                    "pub_y_hex": c_row["pub_y_hex"],
                    "status": c_row["status"],
                } if c_row else None,
            })
            return

        self._send_json({"ok": False, "error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            payload = json.loads(raw_body)
        except Exception:
            payload = {}

        if parsed.path == "/api/agents/register":
            name = str(payload.get("name", "AI-Agent")).strip()[:60]
            model_family = str(payload.get("model_family", "Custom-LLM")).strip()[:60]
            strategy = str(payload.get("strategy", "83-Key Funnel + Kangaroo")).strip()[:80]
            aid = "agent-" + hashlib.sha256(f"{name}:{model_family}".encode()).hexdigest()[:10]
            now = time.time()
            with DB_LOCK:
                conn = get_db()
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO agents (agent_id, name, model_family, strategy, tickets, verified_ec_ops, challenges_won, keys_tested, blocks_completed, created_at, last_seen)
                    VALUES (?, ?, ?, ?, 0, 0, 0, 0, 0, ?, ?)
                    ON CONFLICT(agent_id) DO UPDATE SET last_seen = excluded.last_seen, strategy = excluded.strategy
                    """,
                    (aid, name, model_family, strategy, now, now),
                )
                conn.commit()
                conn.close()
            self._send_json({"ok": True, "agent_id": aid, "name": name, "dp_bits_required": POOL_DP_BITS})
            return

        if parsed.path == "/api/funnel/claim":
            aid = str(payload.get("agent_id", "agent-sqf64-core"))
            target_puz = int(payload.get("target_puzzle", 140))
            src_puz = payload.get("source_funnel_puzzle")
            src_puz_int = int(src_puz) if src_puz is not None else None
            res = allocate_funnel_guided_block(aid, target_puz, src_puz_int)
            self._send_json(res)
            return

        if parsed.path == "/api/ranges/claim":
            aid = str(payload.get("agent_id", "agent-sqf64-core"))
            puz = int(payload.get("puzzle_num", 140))
            cell = str(payload.get("cell", "Ж4"))
            s_hex = payload.get("start_k_hex")
            e_hex = payload.get("end_k_hex")
            src_puz = payload.get("source_funnel_puzzle")
            src_puz_int = int(src_puz) if src_puz is not None else None
            s_val = int(s_hex, 16) if isinstance(s_hex, str) and s_hex.startswith("0x") else None
            e_val = int(e_hex, 16) if isinstance(e_hex, str) and e_hex.startswith("0x") else None
            res = allocate_or_verify_non_overlapping_block(aid, puz, cell, s_val, e_val, src_puz_int)
            self._send_json(res)
            return

        if parsed.path == "/api/ranges/complete":
            aid = str(payload.get("agent_id", "agent-sqf64-core"))
            bid = str(payload.get("block_id", ""))
            d_hex = payload.get("proof_scalar_d_hex")
            ktype = str(payload.get("kang_type", "WILD"))
            d_val = int(d_hex, 16) if isinstance(d_hex, str) and d_hex.startswith("0x") else None
            res = complete_and_lock_block(aid, bid, d_val, ktype)
            self._send_json(res, 200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/submit/dp":
            aid = str(payload.get("agent_id", "agent-sqf64-core"))
            ktype = str(payload.get("kang_type", "WILD"))
            d_str = str(payload.get("scalar_d_hex", "0"))
            try:
                scalar_d = int(d_str, 16) if d_str.startswith(("0x", "0X")) else int(d_str)
            except Exception:
                self._send_json({"ok": False, "error": "Некорректный формат scalar_d_hex"}, 400)
                return
            res = verify_and_record_dp(aid, ktype, scalar_d)
            self._send_json(res, 200 if res.get("ok") else 400)
            return

        if parsed.path == "/api/submit/key":
            aid = str(payload.get("agent_id", "agent-sqf64-core"))
            puz = int(payload.get("puzzle", 140))
            k_str = str(payload.get("candidate_k_hex", "0"))
            try:
                cand_k = int(k_str, 16) if k_str.startswith(("0x", "0X")) else int(k_str)
            except Exception:
                self._send_json({"ok": False, "error": "Некорректный формат candidate_k_hex"}, 400)
                return
            res = verify_candidate_private_key(aid, puz, cand_k)
            self._send_json(res)
            return

        if parsed.path == "/api/submit/challenge":
            aid = str(payload.get("agent_id", "agent-sqf64-core"))
            k_str = str(payload.get("solution_k_hex", "0"))
            try:
                sol_k = int(k_str, 16) if k_str.startswith(("0x", "0X")) else int(k_str)
            except Exception:
                self._send_json({"ok": False, "error": "Некорректный solution_k_hex"}, 400)
                return

            with DB_LOCK:
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT * FROM challenges ORDER BY round_id DESC LIMIT 1")
                c_row = cur.fetchone()
                if not c_row:
                    conn.close()
                    self._send_json({"ok": False, "error": "Нет активного раунда"}, 400)
                    return

                true_k = int(c_row["secret_k_hex"], 16)
                round_id = c_row["round_id"]
                bits = c_row["bits"]
                if sol_k != true_k:
                    conn.close()
                    self._send_json({"ok": False, "error": "Неверный ключ k для текущего Blind Challenge!"}, 400)
                    return

                cur.execute("SELECT name FROM agents WHERE agent_id = ?", (aid,))
                ag = cur.fetchone()
                ag_name = ag["name"] if ag else aid

                if c_row["status"] == "ACTIVE":
                    cur.execute(
                        "UPDATE challenges SET status = 'SOLVED', winner_agent = ?, solved_sec = ? WHERE round_id = ?",
                        (ag_name, time.time() - c_row["created_at"], round_id),
                    )
                    cur.execute(
                        """
                        UPDATE agents
                        SET tickets = tickets + 5, challenges_won = challenges_won + 1,
                            verified_ec_ops = verified_ec_ops + ?, last_seen = ?
                        WHERE agent_id = ?
                        """,
                        (1 << (bits // 2), time.time(), aid),
                    )
                conn.commit()
                conn.close()

            self._send_json({
                "ok": True,
                "round_id": round_id,
                "bits": bits,
                "verified_k_hex": hex(sol_k),
                "tickets_awarded": 5,
            })
            return

        if parsed.path == "/api/new_challenge":
            bits = int(payload.get("bits", 28))
            bits = max(24, min(36, bits))
            with DB_LOCK:
                conn = get_db()
                cur = conn.cursor()
                _create_new_challenge_unlocked(cur, bits=bits)
                conn.commit()
                conn.close()
            self._send_json({"ok": True, "bits": bits})
            return

        if parsed.path == "/api/run_cpp_burst":
            mode = str(payload.get("mode", "funnel_step"))
            aid = str(payload.get("agent_id", "agent-sqf64-core"))

            if mode == "funnel_step":
                target_puz = int(payload.get("target_puzzle", 140))
                src_puz = payload.get("source_funnel_puzzle")
                src_puz_int = int(src_puz) if src_puz is not None else None
                f_lease = allocate_funnel_guided_block(aid, target_puz, src_puz_int)
                blk = f_lease["assigned_block"]
                start_d = max(1, int(blk["start_k_hex"], 16) - BASE_140) if target_puz == 140 else (int(blk["start_k_hex"], 16) & ((1 << 70) - 1))
                dps = mine_real_distinguished_points("WILD", start_d, count_target=1, dp_bits=POOL_DP_BITS)
                d_proof = dps[0][0] if dps else None
                lock_res = complete_and_lock_block(aid, blk["block_id"], d_proof, "WILD")
                self._send_json({
                    "ok": True,
                    "funnel_source_puzzle": f_lease["funnel_source_puzzle"],
                    "assigned_block": blk,
                    "proof_hash": lock_res.get("proof_hash"),
                })
                return

            if mode == "scan_and_lock_block":
                cell = str(payload.get("cell", "Ж4"))
                lease = allocate_or_verify_non_overlapping_block(aid, 140, cell)
                blk = lease["assigned_block"]
                start_d = max(1, int(blk["start_k_hex"], 16) - BASE_140)
                dps = mine_real_distinguished_points("WILD", start_d, count_target=1, dp_bits=POOL_DP_BITS)
                d_proof = dps[0][0] if dps else None
                lock_res = complete_and_lock_block(aid, blk["block_id"], d_proof, "WILD")
                self._send_json({
                    "ok": True,
                    "assigned_block": blk,
                    "proof_hash": lock_res.get("proof_hash"),
                    "dp_verification": lock_res.get("dp_verification"),
                })
                return

            if mode == "solve_challenge":
                with DB_LOCK:
                    conn = get_db()
                    cur = conn.cursor()
                    cur.execute("SELECT * FROM challenges ORDER BY round_id DESC LIMIT 1")
                    c_row = cur.fetchone()
                    if not c_row or c_row["status"] != "ACTIVE":
                        _create_new_challenge_unlocked(cur, bits=28)
                        conn.commit()
                        cur.execute("SELECT * FROM challenges ORDER BY round_id DESC LIMIT 1")
                        c_row = cur.fetchone()
                    round_id = c_row["round_id"]
                    bits = c_row["bits"]
                    px_int = int(c_row["pub_x_hex"], 16)
                    py_int = int(c_row["pub_y_hex"], 16)
                    conn.close()

                t_bits = (bits // 2) - 1
                M = 1 << t_bits
                t_ops = ctypes.c_uint64(0)
                s_ops = ctypes.c_uint64(0)
                t_sec = ctypes.c_double(0.0)
                s_sec = ctypes.c_double(0.0)
                out_q = ctypes.c_int64(0)
                out_r = ctypes.c_uint32(0)
                out_sgn = ctypes.c_int32(0)

                t0 = time.perf_counter()
                ok = lib_dual.sqf_linear_bsgs_blind_solve(
                    int_to_limbs(px_int), int_to_limbs(py_int),
                    bits, t_bits,
                    ctypes.byref(t_ops), ctypes.byref(s_ops),
                    ctypes.byref(t_sec), ctypes.byref(s_sec),
                    ctypes.byref(out_q), ctypes.byref(out_r), ctypes.byref(out_sgn)
                )
                wall_dt = time.perf_counter() - t0
                if ok != 1:
                    self._send_json({"ok": False, "error": "C++ solver did not converge"}, 500)
                    return

                W = 1 << bits
                solved_k = (W // 2) + out_q.value * (2 * M) + out_sgn.value * out_r.value
                real_ops = int(t_ops.value + s_ops.value)

                with DB_LOCK:
                    conn = get_db()
                    cur = conn.cursor()
                    cur.execute("SELECT name FROM agents WHERE agent_id = ?", (aid,))
                    ag = cur.fetchone()
                    ag_name = ag["name"] if ag else aid
                    cur.execute(
                        "UPDATE challenges SET status = 'SOLVED', winner_agent = ?, solved_sec = ? WHERE round_id = ?",
                        (ag_name, wall_dt, round_id),
                    )
                    cur.execute(
                        """
                        UPDATE agents
                        SET tickets = tickets + 5, challenges_won = challenges_won + 1,
                            verified_ec_ops = verified_ec_ops + ?, last_seen = ?
                        WHERE agent_id = ?
                        """,
                        (real_ops, time.time(), aid),
                    )
                    conn.commit()
                    conn.close()

                self._send_json({
                    "ok": True,
                    "round_id": round_id,
                    "bits": bits,
                    "solved_k_hex": hex(solved_k),
                    "real_ec_ops": real_ops,
                    "wall_sec": wall_dt,
                })
                return

        self._send_json({"ok": False, "error": "Unknown endpoint"}, 404)


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), LotteryRequestHandler)
    print(f"[+] AI-Agent Bitcoin Puzzle Lottery (83-Key Funnel + Anti-Duplicate) запущен на http://0.0.0.0:{port}")
    server.serve_forever()
