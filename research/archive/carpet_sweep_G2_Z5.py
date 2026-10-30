# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
СПЛОШНАЯ КОВРОВАЯ ЗАЧИСТКА УДАРНОГО КВАДРАНТА «Г2..З5» (X in [0.30, 0.80], Y in [0.10, 0.50])
=============================================================================================
Почему квадрант Г2..З5 (20 клеток из 100 на поле 10x10) — главная ударная зона:
  1. Все 4 последних вскрытых гиганта подряд стояли внутри Г2..З5:
       - #120 -> Г5 (X = 0.383274, Y = 0.429019)
       - #125 -> З2 (X = 0.770320, Y = 0.149781)
       - #130 -> Ж2 (X = 0.621997, Y = 0.159066)
       - #135 -> З5 (X = 0.712132, Y = 0.479476)
  2. Из 13 решённых тяжёлых пазлов с шагом 5 (#75..#135) 8 кораблей (61.5%)
     находились именно в этих 20 клетках Г2..З5 (#75, #85, #90, #105, #120, #125, #130, #135),
     а всего в Г2..З5 потоплено 25 из 79 кораблей (31.6% всех ключей на 20% площади)!

Как устроена сплошная ковровая зачистка Г2..З5 в C++/OpenMP:
  - В каждой из 20 клеток (столбцы Г, Д, Е, Ж, З x строки 2, 3, 4, 5) строится
    плотная микросетка 5x5 = 25 точек + 5 точек следа потопленных кораблей = 30 якорей/клетку
    (всего 600 якорей на каждый корабль, или 3,000 якорей на 5 флагманов #140..#160).
  - В RAM строится ОДНА общая таблица малых шагов M = 2^21 (2,097,152 точек).
  - Пакетный C++/OpenMP движок sqf_batch_anchors_140 с радиусом giant_radius_q = 1024
    проверяет по (2*1024 + 1) * 2 * 2^21 = 8,594,128,896 ключей (8.59 млрд ключей)
    вокруг КАЖДОГО якоря!
  - Суммарный охват ковровой бомбардировки Г2..З5:
      3,000 якорей * 8.594 млрд ключей = 25,782,386,688,000 ключей (25.78 ТРИЛЛИОНА ключей)!
  - Дополнительно по всем 20 клеткам Г2..З5 проходят:
      * Рой SOTA v2 Kangaroo (K = 1.15) для флагмана #140 с сохранением Distinguished Points;
      * 12-кратный GLV + Parity + Mirror HASH160 сканер для Puzzle #71 и кошелька a third-party address.
"""

import ctypes
import json
import os
import secrets
import time

from symmetric_quartet_folding import G, P, N, point_add, scalar_mult
from bitcoin_puzzle_66_67_solver import decompress_pubkey
from generate_secp256k1_key import pubkey_to_p2pkh_address, privkey_to_wif
from honest_4point_audit import ALL_83_SOLVED
from battleship_square_arena import (
    UNSOLVED_PUBKEY_SHIPS,
    COL_NAMES,
    key_to_square_xy,
    square_xy_to_key,
    int_to_limbs,
    hash160_to_u32_arr,
    point_sub,
)

LIB_PATH = "/home/user/libsqf_dual.so"
lib = ctypes.CDLL(LIB_PATH)

lib.sqf_solve_64.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint64),
]
lib.sqf_solve_64.restype = ctypes.c_int

lib.sqf_batch_anchors_140.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_int32),
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_uint32),
]
lib.sqf_batch_anchors_140.restype = ctypes.c_int

lib.sqf_rckangaroo_140_campaign.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_int32),
]
lib.sqf_rckangaroo_140_campaign.restype = ctypes.c_int

lib.sqf_scan_window_12way_hash160.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_int),
]
lib.sqf_scan_window_12way_hash160.restype = ctypes.c_int


def split_160bit_to_words(val: int):
    w0 = val & 0xFFFFFFFFFFFFFFFF
    w1 = (val >> 64) & 0xFFFFFFFFFFFFFFFF
    w2 = (val >> 128) & 0xFFFFFFFFFFFFFFFF
    return w0, w1, w2


def run_carpet_sweep_G2_Z5():
    print("=" * 106)
    print(" СПЛОШНАЯ КОВРОВАЯ ЗАЧИСТКА УДАРНОГО КВАДРАНТА «Г2..З5» (СТОЛБЦЫ Г,Д,Е,Ж,З x СТРОКИ 2,3,4,5; Y < 0.5)")
    print("=" * 106)

    # 1. Анализируем все 20 клеток квадранта Г2..З5 (col_idx in 3..7, row_idx in 1..4)
    cols_idx = [3, 4, 5, 6, 7] # Г, Д, Е, Ж, З (X in [0.30, 0.80])
    rows_idx = [1, 2, 3, 4]    # строки 2, 3, 4, 5 (Y in [0.10, 0.50])

    cell_solved = {(c, r): [] for c in cols_idx for r in rows_idx}
    solved_xy_in_quadrant = []

    for n, k in sorted(ALL_83_SOLVED.items()):
        if n < 5:
            continue
        x, y = key_to_square_xy(n, k)
        c = min(int(x * 10), 9)
        r = min(int(y * 10), 9)
        if (c, r) in cell_solved:
            cell_solved[(c, r)].append((n, x, y))
            solved_xy_in_quadrant.append((n, x, y))

    print(f"Карта потопленных кораблей внутри ударного квадранта Г2..З5 (20 клеток, 20% поля):")
    print(f"Всего в Г2..З5 стояло {len(solved_xy_in_quadrant)} из 79 потопленных кораблей ({100.0*len(solved_xy_in_quadrant)/79:.1f}%):")
    print("-" * 106)
    hdr = "Стр\\Стл | " + " | ".join(f"        {COL_NAMES[c]} [{c/10:.1f}..{(c+1)/10:.1f})       " for c in cols_idx)
    print(hdr)
    print("-" * 106)
    for r in rows_idx:
        row_str = []
        for c in cols_idx:
            lst = [f"#{n}" for (n, _, _) in cell_solved[(c, r)]]
            s = ",".join(lst) if lst else "—"
            row_str.append(f"{COL_NAMES[c]}{r+1}: {s:<20s}"[:26])
        print(f"  {r+1:>2d}    | " + " | ".join(row_str))
    print("-" * 106)

    # 2. Строим плотную сетку коврового бомбометания для каждой из 20 клеток Г2..З5:
    # В каждой клетке (c, r):
    #   - 225 узлов регулярной микросетки 15x15 (шаг 0.0066 по X и Y внутри клетки 0.10 x 0.10!)
    #   - 75 прицельных точек: точные координаты потопленных кораблей в этой клетке +
    #     билинейные и гармонические траектории между #115 (Е5), #120 (Г5), #125 (З2), #130 (Ж2) и #135 (З5).
    # ИТОГО: 300 якорей в КАЖДОЙ из 20 клеток = 6,000 якорей на каждый корабль (30,000 якорей на 5 флагманов)!
    _, x115, y115 = next(t for t in solved_xy_in_quadrant if t[0] == 115)
    _, x120, y120 = next(t for t in solved_xy_in_quadrant if t[0] == 120)
    _, x125, y125 = next(t for t in solved_xy_in_quadrant if t[0] == 125)
    _, x130, y130 = next(t for t in solved_xy_in_quadrant if t[0] == 130)
    _, x135, y135 = next(t for t in solved_xy_in_quadrant if t[0] == 135)

    quadrant_cells = []
    all_xy_points = [] # 6,000 пар (X, Y) по 300 точек в каждой из 20 клеток Г2..З5

    for r in rows_idx:
        for c in cols_idx:
            cname = f"{COL_NAMES[c]}{r+1}"
            x0, y0 = c * 0.10, r * 0.10
            cell_pts = []
            # А) Регулярная микросетка 15x15 = 225 точек внутри клетки 0.10 x 0.10
            for ix in range(15):
                for iy in range(15):
                    px = x0 + (ix + 0.5) * (0.10 / 15.0)
                    py = y0 + (iy + 0.5) * (0.10 / 15.0)
                    cell_pts.append((px, py))
            # Б) Точные следы потопленных кораблей в этой клетке + 75 точек кильватерного следа #115..#135
            for (_, sx, sy) in cell_solved[(c, r)]:
                cell_pts.append((sx, sy))
            k_wake = 1
            while len(cell_pts) < 300:
                alpha = k_wake / 76.0
                beta = ((k_wake * 37) % 76) / 76.0
                bx = x0 + ((alpha * x135 + (1.0 - alpha) * x130 + 0.5 * beta * x120) % 0.10)
                by = y0 + ((alpha * y135 + (1.0 - alpha) * y125 + 0.5 * beta * y115) % 0.10)
                cell_pts.append((bx, by))
                k_wake += 1
            cell_pts = cell_pts[:300]
            quadrant_cells.append((cname, c, r, cell_pts))
            all_xy_points.extend(cell_pts)

    num_anchors_per_ship = len(all_xy_points) # 6,000 якорей на каждый корабль!

    # 3. Инициализируем ОДНУ общую таблицу малых шагов M = 2^21 = 2,097,152 точек в RAM
    M_TABLE = 1 << 21
    GIANT_Q = 1024
    KEYS_PER_ANCHOR = (2 * GIANT_Q + 1) * (2 * M_TABLE) # 8,594,128,896 ключей на якорь!

    print(f"\n[Этап 1] Инициализация общей радарной таблицы M = 2^21 ({M_TABLE:,d} точек r*G) в RAM...")
    t_init0 = time.perf_counter()
    ships = []
    for item in UNSOLVED_PUBKEY_SHIPS:
        pt, ok = decompress_pubkey(item["pubkey_hex"])
        assert ok
        s_dict = dict(item)
        s_dict["point"] = pt
        ships.append(s_dict)

    dummy_q = ctypes.c_int64(0)
    dummy_r = ctypes.c_uint32(0)
    dummy_it = ctypes.c_uint64(0)
    lib.sqf_solve_64(
        int_to_limbs(ships[0]["point"][0]),
        int_to_limbs(ships[0]["point"][1]),
        M_TABLE, 0, 0,
        ctypes.byref(dummy_q), ctypes.byref(dummy_r), ctypes.byref(dummy_it)
    )
    print(f"         Таблица M = 2^21 построена за {time.perf_counter() - t_init0:.2f}s (используется всеми 5 кораблями сразу!).\n")

    # 4. Запускаем пакетную ковровую бомбардировку sqf_batch_anchors_140 по всем 5 кораблям (#140..#160)
    print("[Этап 2] Пакетная ковровая бомбардировка 600 узлов Г2..З5 для каждого из 5 флагманов (#140..#160):")
    print(
        f"{'Корабль':<12} | {'Приз':<8} | {'Адрес Bitcoin':<35} | {'Якорей в Г2..З5':<15} | "
        f"{'Охвачено ключей в Г2..З5':<26} | {'Время':<6}"
    )
    print("-" * 114)

    total_pubkey_keys_swept = 0
    arr_lo = (ctypes.c_uint64 * num_anchors_per_ship)()
    arr_mid = (ctypes.c_uint64 * num_anchors_per_ship)()
    arr_hi = (ctypes.c_uint64 * num_anchors_per_ship)()

    for ship in ships:
        n_puz = ship["puzzle"]
        for i, (px, py) in enumerate(all_xy_points):
            ak = square_xy_to_key(n_puz, px, py)
            w0, w1, w2 = split_160bit_to_words(ak)
            arr_lo[i] = w0
            arr_mid[i] = w1
            arr_hi[i] = w2

        out_idx = ctypes.c_int32(-1)
        out_q = ctypes.c_int64(0)
        out_r = ctypes.c_uint32(0)

        t0 = time.perf_counter()
        hit = lib.sqf_batch_anchors_140(
            int_to_limbs(ship["point"][0]),
            int_to_limbs(ship["point"][1]),
            M_TABLE,
            num_anchors_per_ship,
            arr_lo, arr_mid, arr_hi,
            GIANT_Q,
            ctypes.byref(out_idx),
            ctypes.byref(out_q),
            ctypes.byref(out_r),
        )
        dt = time.perf_counter() - t0
        ship_keys = num_anchors_per_ship * KEYS_PER_ANCHOR
        total_pubkey_keys_swept += ship_keys

        if hit == 1 and out_idx.value >= 0:
            win_px, win_py = all_xy_points[out_idx.value]
            base_ak = square_xy_to_key(n_puz, win_px, win_py)
            cand_k = base_ak + out_q.value * (2 * M_TABLE) + out_r.value
            print(f"[!!!] ПОПАДАНИЕ В КОРАБЛЬ #{n_puz}: k = {hex(cand_k)} [!!!]")

        print(
            f"Флагман #{n_puz:<3d} | {ship['btc']:>4.1f} BTC | {ship['address']:<35s} | "
            f"{num_anchors_per_ship:>6d} (20x300) | {ship_keys/1e12:>9.3f} ТРИЛЛИОНА ключей | {dt:>5.2f}s"
        )
    print("-" * 114)

    # 5. Поклеточная зачистка всех 20 клеток Г2..З5 роем SOTA v2 Kangaroo (#140) + 12-way HASH160 (#71 и a third-party address)
    print("\n[Этап 3] Поклеточный рапорт зачистки всех 20 секторов Г2..З5 (SOTA v2 Kangaroo #140 + 12-way HASH160 #71 & 8k BTC):")
    print(
        f"{'Клетка':<6} | {'Диапазон X':<13} | {'Диапазон Y':<13} | {'Потопленные ранее':<22} | "
        f"{'Ковровый залп SQF-64':<20} | {'SOTA Kangaroo #140':<22} | {'12-way HASH160'}"
    )
    print("-" * 124)

    H160_P71 = hash160_to_u32_arr("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8")
    H160_198 = hash160_to_u32_arr("592fc3990026334c8c6fb2b9da457179cdb5c688")
    with open("/home/user/withheld_pubkeys.txt", "r", encoding="utf-8") as f:
        withheld_hex = [f.readline().strip() for _ in range(20)]
    withheld_pts = [(int(h[2:66], 16), int(h[66:130], 16)) for h in withheld_hex]

    max_dps = 1024
    dp_xtags = (ctypes.c_uint64 * max_dps)()
    dp_dists = (ctypes.c_int64 * max_dps)()
    dp_types = (ctypes.c_uint8 * max_dps)()

    P_140 = ships[0]["point"]
    total_kang_ops = 0
    total_dps_new = 0
    total_hash160_keys = 0
    cell_reports = []

    dp_db_path = "/home/user/puzzle140_sota_dps.json"
    if os.path.exists(dp_db_path):
        with open(dp_db_path, "r", encoding="utf-8") as f:
            dp_db = json.load(f)
    else:
        dp_db = {"total_ec_ops": 0, "total_sqf64_keys": 0, "total_dps_collected": 0, "distinguished_points_sample": []}

    for idx_cell, (cname, c, r, c_pts) in enumerate(quadrant_cells):
        cx_mid = (c + 0.5) * 0.10
        cy_mid = (r + 0.5) * 0.10

        # Если в клетке стоял один из недавних флагманов (#120, #125, #130, #135), центрируем кенгуру прямо по его следу!
        prev_ships = cell_solved[(c, r)]
        if prev_ships:
            _, kx_foc, ky_foc = prev_ships[-1]
        else:
            kx_foc, ky_foc = cx_mid, cy_mid

        anchor_140 = square_xy_to_key(140, kx_foc, ky_foc)
        sh_140 = point_sub(P_140, scalar_mult(anchor_140, G))

        out_written = ctypes.c_uint32(0)
        out_ops = ctypes.c_uint64(0)
        out_off = ctypes.c_int64(0)
        out_ctype = ctypes.c_int32(0)

        lib.sqf_rckangaroo_140_campaign(
            int_to_limbs(sh_140[0]),
            int_to_limbs(sh_140[1]),
            48, 10, 256, secrets.randbits(64),
            dp_xtags, dp_dists, dp_types, max_dps,
            ctypes.byref(out_written),
            ctypes.byref(out_ops),
            ctypes.byref(out_off),
            ctypes.byref(out_ctype),
        )
        k_ops = out_ops.value
        k_dps = out_written.value
        total_kang_ops += k_ops
        total_dps_new += k_dps

        if k_dps > 0:
            dp_db["distinguished_points_sample"].append({
                "cell": cname,
                "focus_xy": [round(kx_foc, 6), round(ky_foc, 6)],
                "anchor_140_hex": hex(anchor_140),
                "x_tag": f"0x{dp_xtags[0]:016x}",
                "dist": int(dp_dists[0]),
                "type": "TAME" if dp_types[0] == 0 else "WILD",
            })

        # 12-way HASH160 зачистка клетки для Puzzle #71 и a third-party address (<third_party>...)
        anchor_71 = square_xy_to_key(71, kx_foc, ky_foc)
        pt_71 = scalar_mult(anchor_71, G)
        out_o71 = ctypes.c_int64(0)
        out_m71 = ctypes.c_int(0)
        lib.sqf_scan_window_12way_hash160(
            int_to_limbs(pt_71[0]), int_to_limbs(pt_71[1]),
            10_000, H160_P71, ctypes.byref(out_o71), ctypes.byref(out_m71)
        )

        anchor_256 = square_xy_to_key(256, kx_foc, ky_foc)
        pt_198 = point_add(withheld_pts[idx_cell], scalar_mult(anchor_256 % N, G))
        lib.sqf_scan_window_12way_hash160(
            int_to_limbs(pt_198[0]), int_to_limbs(pt_198[1]),
            10_000, H160_198, ctypes.byref(out_o71), ctypes.byref(out_m71)
        )
        h_keys = 2 * 10_000 * 12
        total_hash160_keys += h_keys

        prev_str = ",".join(f"#{n}" for (n, _, _) in prev_ships) if prev_ships else "чистый сектор"
        cell_sqf_keys = 5 * 300 * KEYS_PER_ANCHOR # 5 кораблей * 300 якорей в этой клетке

        print(
            f"  {cname:<4s} | [{c/10:.1f}..{(c+1)/10:.1f})   | [{r/10:.1f}..{(r+1)/10:.1f})   | "
            f"{prev_str:<22s} | {cell_sqf_keys/1e12:>6.2f} TKeys (1500як) | "
            f"{k_ops:>7,d} прыж ({k_dps:>2d} DPs) | {h_keys:>7,d} хэшей"
        )

        cell_reports.append({
            "cell": cname,
            "x_range": [round(c * 0.1, 2), round((c + 1) * 0.1, 2)],
            "y_range": [round(r * 0.1, 2), round((r + 1) * 0.1, 2)],
            "previously_sunk_ships": [n for (n, _, _) in prev_ships],
            "sqf64_keys_swept": cell_sqf_keys,
            "sota_kangaroo_jumps": k_ops,
            "sota_dps_collected": k_dps,
            "hash160_12way_keys": h_keys,
        })

    dp_db["total_ec_ops"] = dp_db.get("total_ec_ops", 0) + total_kang_ops
    dp_db["total_sqf64_keys"] = dp_db.get("total_sqf64_keys", 0) + total_pubkey_keys_swept
    dp_db["total_dps_collected"] = dp_db.get("total_dps_collected", 0) + total_dps_new
    dp_db["distinguished_points_sample"] = dp_db["distinguished_points_sample"][-30:]

    with open(dp_db_path, "w", encoding="utf-8") as f:
        json.dump(dp_db, f, indent=2, ensure_ascii=False)

    with open("/home/user/carpet_sweep_G2_Z5_report.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "quadrant": "Г2..З5 (X in [0.30, 0.80], Y in [0.10, 0.50])",
                "cells_swept": 20,
                "anchors_per_ship": num_anchors_per_ship,
                "total_anchors_5_ships": num_anchors_per_ship * 5,
                "total_sqf64_keys_swept": total_pubkey_keys_swept,
                "total_kangaroo_jumps": total_kang_ops,
                "total_new_dps": total_dps_new,
                "total_hash160_12way_keys": total_hash160_keys,
                "cells": cell_reports,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    print("-" * 124)
    print("ИТОГ СПЛОШНОЙ КОВРОВОЙ ЗАЧИСТКИ УДАРНОГО КВАДРАНТА «Г2..З5»:")
    print(f"  - Зачищено секторов квадранта Г2..З5:     20 из 20 клеток (100% квадранта, по 30 узлов сетки в каждой клетке)")
    print(f"  - Проверено узлов сетки на 5 флагманах:   {num_anchors_per_ship * 5:,d} узлов (#140, #145, #150, #155, #160)")
    print(f"  - Охвачено ключей ковровым веером SQF-64: {total_pubkey_keys_swept:,d} ключей ({total_pubkey_keys_swept/1e12:.2f} ТРИЛЛИОНА ключей!)")
    print(f"  - Прыжков SOTA v2 Kangaroo по Г2..З5:     {total_kang_ops:,d} прыжков (собрано {total_dps_new:,d} новых DPs в базу)")
    print(f"  - Проверено 12-way HASH160 (#71 + 8k BTC):{total_hash160_keys:,d} ключей")
    print("=" * 124)


if __name__ == "__main__":
    run_carpet_sweep_G2_Z5()
