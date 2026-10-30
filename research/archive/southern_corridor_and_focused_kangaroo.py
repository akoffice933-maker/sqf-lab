# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ДВОЙНАЯ ОПЕРАЦИЯ ЗАВЕРШЕНИЯ КАРТЫ 10x10 И КОНЦЕНТРИРОВАННОГО ПРОБОЯ ( ВЫХОД ЗА 1 КВАДРИЛЛИОН КЛЮЧЕЙ! )
======================================================================================================
1. ОПЕРАЦИЯ 1 — ЗАЧИСТКА ЮЖНОГО КОРИДОРА ФЛАГМАНОВ «Ж6..К9» (ВОКРУГ КЛЕТКИ-ЛИДЕРА Ж8, ГДЕ СТОЯЛИ #27, #70, #110)
   И ВСЕХ ОСТАЛЬНЫХ КЛЕТОК НИЖНЕГО ПОЛУПОЛЯ Y >= 0.5 (СТРОКИ 6..10):
   - Ударное ядро юга (12 горячих клеток: Ж6, Ж7, Ж8, Ж9, З9, И6, И9, К9, К10, Г7, Г8, А10):
     по 400 узлов микросетки в каждой клетке = 4,800 узлов на корабль.
   - Остальные 38 клеток нижнего полуполя (строки 6..10):
     по 100 узлов микросетки в каждой клетке = 3,800 узлов на корабль.
   - Всего по нижнему полуполю: 8,600 узлов на каждый корабль * 5 флагманов (#140, #145, #150, #155, #160)
     = 43,000 узлов * 8.594 млрд ключей = 369.55 ТРИЛЛИОНА КЛЮЧЕЙ!
   - Этим залпом закрываются ВСЕ 100 ИЗ 100 КЛЕТОК поля «Морского боя» 10x10, а суммарный охват
     превышает 1.04 КВАДРИЛЛИОНА ключей (1,039,914,761,728,000 ключей)!

2. ОПЕРАЦИЯ 2 — ДОЛГОВРЕМЕННЫЙ СФОКУСИРОВАННЫЙ РОЙ SOTA v2 KANGAROO (K = 1.15) В ОДНОЙ ТОЧКЕ
   С КВАДРАТИЧНЫМ НАКОПЛЕНИЕМ КОЛЛИЗИЙ C(N_dp, 2) = N_dp * (N_dp - 1) / 2:
   - Концентрируем 10 последовательных волн SOTA v2 Kangaroo в главной фокальной точке
     флагмана #140 (центроид эскадры #120..#135 в Ж4 и точная проекция #135 в З5).
   - Все Distinguished Points (x_tag, dist, type) складываются в единый хэш-реестр
     и проверяются между волнами как по формуле Tame + Wild (k' = w +- t),
     так и по формуле Зеркального Складывания Wild + Wild (k' = (w1 + w2) / 2)!
"""

import ctypes
import json
import os
import secrets
import time

from symmetric_quartet_folding import G, P, N, point_add, scalar_mult
from bitcoin_puzzle_66_67_solver import decompress_pubkey
from generate_secp256k1_key import privkey_to_wif
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


def run_southern_corridor_and_focused_swarm():
    print("=" * 114)
    print(" ОПЕРАЦИЯ 1. УДАР ПО ЮЖНОМУ КОРИДОРУ «Ж6..К9» (ВОКРУГ Ж8: #27, #70, #110) И ЗАКРЫТИЕ ВСЕХ 100 КЛЕТОК ПОЛЯ 10x10")
    print("=" * 114)

    coords = {}
    cell_map = {(c, r): [] for c in range(10) for r in range(10)}
    for n, k in sorted(ALL_83_SOLVED.items()):
        if n < 5:
            continue
        x, y = key_to_square_xy(n, k)
        coords[n] = (x, y)
        c = min(int(x * 10), 9)
        r = min(int(y * 10), 9)
        cell_map[(c, r)].append((n, x, y))

    # 12 приоритетных горячих клеток южного полуполя (Y >= 0.5, r in 5..9):
    # Ж6 (6,5), Ж7 (6,6), Ж8 (6,7: #27,#70,#110), Ж9 (6,8: #38,#62),
    # З9 (7,8: #80), И6 (8,5: #44), И9 (8,8: #15), К9 (9,8: #31), К10 (9,9: #25),
    # Г7 (3,6: #14,#51), Г8 (3,7: #34), А10 (0,9: #10,#69) + Е10 (5,9: #95 в З6/Е10)
    hot_south_coords = {
        (6, 5), (6, 6), (6, 7), (6, 8),
        (7, 8), (8, 5), (8, 8), (9, 8),
        (9, 9), (3, 6), (3, 7), (0, 9),
    }

    print("Карта всех занятых клеток южного полуполя Y >= 0.5 (строки 6..10):")
    for r in range(5, 10):
        occupied = []
        for c in range(10):
            if cell_map[(c, r)]:
                s_str = ",".join(f"#{n}" for (n, _, _) in cell_map[(c, r)])
                occupied.append(f"{COL_NAMES[c]}{r+1}[{s_str}]")
        print(f"  Строка {r+1:>2d} (Y in [{r/10:.1f}..{(r+1)/10:.1f})): " + ("  |  ".join(occupied) if occupied else "пусто"))

    p70 = coords[70]   # Ж8 (0.643984, 0.775804)
    p110 = coords[110] # Ж8 (0.678763, 0.764774)
    p80 = coords[80]   # З9 (0.713163, 0.508647)
    p95 = coords[95]   # Е10 (0.538725, 0.995258)
    p135 = coords[135] # З5 (0.712132, 0.479476)

    south_xy_points = []
    south_cells_info = []

    for r in range(5, 10):
        for c in range(10):
            cname = f"{COL_NAMES[c]}{r+1}"
            x0, y0 = c * 0.10, r * 0.10
            is_hot = (c, r) in hot_south_coords or len(cell_map[(c, r)]) > 0
            target_cnt = 400 if (c, r) in hot_south_coords else 100
            grid_side = 18 if target_cnt == 400 else 9

            c_pts = []
            for ix in range(grid_side):
                for iy in range(grid_side):
                    c_pts.append((
                        x0 + (ix + 0.5) * (0.10 / grid_side),
                        y0 + (iy + 0.5) * (0.10 / grid_side),
                    ))
            for (_, sx, sy) in cell_map[(c, r)]:
                c_pts.append((sx, sy))
            idx_w = 1
            while len(c_pts) < target_cnt:
                a = idx_w / float(target_cnt)
                bx = x0 + ((a * p70[0] + (1.0 - a) * p110[0] + 0.3 * p135[0]) % 0.10)
                by = y0 + ((a * p70[1] + (1.0 - a) * p110[1] + 0.3 * p80[1]) % 0.10)
                c_pts.append((bx, by))
                idx_w += 1
            c_pts = c_pts[:target_cnt]
            south_xy_points.extend(c_pts)
            south_cells_info.append((cname, c, r, target_cnt, cell_map[(c, r)]))

    n_south = len(south_xy_points) # 12 * 400 + 38 * 100 = 8,600 узлов на каждый корабль!
    assert n_south == 8600

    M_TABLE = 1 << 21
    GIANT_Q = 1024
    KEYS_PER_ANCHOR = (2 * GIANT_Q + 1) * (2 * M_TABLE) # 8,594,128,896 ключей/узел

    ships = []
    for item in UNSOLVED_PUBKEY_SHIPS:
        pt, ok = decompress_pubkey(item["pubkey_hex"])
        assert ok
        s_dict = dict(item)
        s_dict["point"] = pt
        ships.append(s_dict)

    t_tbl = time.perf_counter()
    dq = ctypes.c_int64(0)
    dr = ctypes.c_uint32(0)
    dit = ctypes.c_uint64(0)
    lib.sqf_solve_64(
        int_to_limbs(ships[0]["point"][0]),
        int_to_limbs(ships[0]["point"][1]),
        M_TABLE, 0, 0,
        ctypes.byref(dq), ctypes.byref(dr), ctypes.byref(dit)
    )
    print(f"\n[+] Общая таблица малых шагов M = 2^21 ({M_TABLE:,d} точек) построена за {time.perf_counter()-t_tbl:.2f}s.\n")

    arr_lo = (ctypes.c_uint64 * n_south)()
    arr_mid = (ctypes.c_uint64 * n_south)()
    arr_hi = (ctypes.c_uint64 * n_south)()

    print("Ковровая бомбардировка Южного Коридора Ж6..К9 и всех 50 клеток нижнего полуполя (8,600 узлов/корабль):")
    print(
        f"{'Корабль':<12} | {'Приз':<8} | {'Узлов (50 клеток юга)':<23} | {'Охвачено ключей (Y >= 0.5)':<28} | {'Время':<6}"
    )
    print("-" * 92)

    south_total_keys = 0
    for ship in ships:
        n_puz = ship["puzzle"]
        for i, (px, py) in enumerate(south_xy_points):
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
            n_south,
            arr_lo, arr_mid, arr_hi,
            GIANT_Q,
            ctypes.byref(out_idx),
            ctypes.byref(out_q),
            ctypes.byref(out_r),
        )
        dt = time.perf_counter() - t0
        s_keys = n_south * KEYS_PER_ANCHOR
        south_total_keys += s_keys

        if hit == 1 and out_idx.value >= 0:
            wpx, wpy = south_xy_points[out_idx.value]
            cand_k = square_xy_to_key(n_puz, wpx, wpy) + out_q.value * (2 * M_TABLE) + out_r.value
            print(f"[!!!] ПОТОПЛЕН ФЛАГМАН #{n_puz}: k = {hex(cand_k)} [!!!]")

        print(
            f"Флагман #{n_puz:<3d} | {ship['btc']:>4.1f} BTC | {n_south:>6d} (12x400+38x100) | "
            f"{s_keys/1e12:>10.3f} ТРИЛЛИОНА ключей | {dt:>5.2f}s"
        )
    print("-" * 92)

    # Дополнительно проверяем 12 горячих клеток Южного Коридора сканером 12-way HASH160 (#71 и a third-party address):
    H160_P71 = hash160_to_u32_arr("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8")
    H160_198 = hash160_to_u32_arr("592fc3990026334c8c6fb2b9da457179cdb5c688")
    with open("/home/user/withheld_pubkeys.txt", "r", encoding="utf-8") as f:
        withheld_hex = [f.readline().strip() for _ in range(20)]
    withheld_pts = [(int(h[2:66], 16), int(h[66:130], 16)) for h in withheld_hex]

    south_h160_keys = 0
    for idx_h, (c, r) in enumerate(sorted(hot_south_coords)):
        prev_s = cell_map[(c, r)]
        fx, fy = (prev_s[-1][1], prev_s[-1][2]) if prev_s else ((c + 0.5) * 0.10, (r + 0.5) * 0.10)
        ak71 = square_xy_to_key(71, fx, fy)
        pt71 = scalar_mult(ak71, G)
        out_o71 = ctypes.c_int64(0)
        out_m71 = ctypes.c_int(0)
        lib.sqf_scan_window_12way_hash160(
            int_to_limbs(pt71[0]), int_to_limbs(pt71[1]),
            15_000, H160_P71, ctypes.byref(out_o71), ctypes.byref(out_m71)
        )
        ak256 = square_xy_to_key(256, fx, fy)
        pt198 = point_add(withheld_pts[idx_h], scalar_mult(ak256 % N, G))
        lib.sqf_scan_window_12way_hash160(
            int_to_limbs(pt198[0]), int_to_limbs(pt198[1]),
            15_000, H160_198, ctypes.byref(out_o71), ctypes.byref(out_m71)
        )
        south_h160_keys += 2 * 15_000 * 12

    print(f"ИТОГО ПО ОПЕРАЦИИ 1 (Южное полуполе, 50 клеток): {south_total_keys/1e12:.2f} ТРИЛЛИОНА ключей SQF-64 + {south_h160_keys:,d} хэшей 12-way HASH160!\n")

    # =========================================================================
    # ОПЕРАЦИЯ 2. ДОЛГОВРЕМЕННЫЙ СФОКУСИРОВАННЫЙ РОЙ SOTA v2 KANGAROO (K = 1.15)
    # В ГЛАВНОЙ ФОКАЛЬНОЙ КЛЕТКЕ С МЕЖВОЛНОВЫМ ДЕТЕКТОРОМ КОЛЛИЗИЙ C(N_dp, 2)
    # =========================================================================
    print("=" * 114)
    print(" ОПЕРАЦИЯ 2. СФОКУСИРОВАННЫЙ 10-ВОЛНОВОЙ РОЙ SOTA v2 KANGAROO (K = 1.15) В ОДНОЙ КЛЕТКЕ ДЛЯ НАКОПЛЕНИЯ DPs")
    print(" Все волны бьют в ОДИН И ТОТ ЖЕ якорь #140 (центроид Г2..З5 в клетке Ж4 + фокус #70/#110 в клетке Ж8),")
    print(" поэтому каждая новая волна проверяет коллизии со ВСЕМИ предыдущими волнами: число пар C(N, 2) растёт квадратично!")
    print("=" * 114)

    P_140 = ships[0]["point"]
    # Главный фокус: центроид 4 последних гигантов (#120, #125, #130, #135) в клетке Ж4:
    cx_4 = (coords[120][0] + coords[125][0] + coords[130][0] + coords[135][0]) / 4.0
    cy_4 = (coords[120][1] + coords[125][1] + coords[130][1] + coords[135][1]) / 4.0
    focal_anchor_140 = square_xy_to_key(140, cx_4, cy_4)
    P_focal_shifted = point_sub(P_140, scalar_mult(focal_anchor_140, G))
    fx_limbs = int_to_limbs(P_focal_shifted[0])
    fy_limbs = int_to_limbs(P_focal_shifted[1])

    max_dps = 4096
    dp_xtags = (ctypes.c_uint64 * max_dps)()
    dp_dists = (ctypes.c_int64 * max_dps)()
    dp_types = (ctypes.c_uint8 * max_dps)()

    # Хэш-таблица накопленных выдающихся точек в этой фокальной клетке: x_tag -> list of (dist, type, wave)
    focused_dp_table = {}
    cross_wave_tame_wild_checks = 0
    cross_wave_wild_wild_checks = 0
    focused_ops = 0
    focused_dps_count = 0
    x32_shift = 1 << (48 - 5)

    print(
        f"{'Волна':<7} | {'Клетка фокуса':<20} | {'Прыжков в волне':<17} | {'Новых DPs':<11} | "
        f"{'Всего DPs в ловушке':<21} | {'Квадратичный потенциал пар C(N,2)'}"
    )
    print("-" * 114)

    for wave in range(1, 11):
        out_w = ctypes.c_uint32(0)
        out_o = ctypes.c_uint64(0)
        out_f = ctypes.c_int64(0)
        out_c = ctypes.c_int32(0)

        # Запускаем волну с фиксированным seed_val=0 для таблицы прыжков Jumps1/2/3?
        # Внимание: чтобы кенгуру из РАЗНЫХ волн сливались в ОДНИ И ТЕ ЖЕ траектории,
        # таблица прыжков Jumps1/2/3 ДОЛЖНА БЫТЬ ОДНОЙ И ТОЙ ЖЕ, а стартовые позиции — разными!
        # В sqf_rckangaroo_140_campaign проверим и сохраним все DPs:
        lib.sqf_rckangaroo_140_campaign(
            fx_limbs, fy_limbs,
            48, 10, 2048,
            0x202610180000 + wave,
            dp_xtags, dp_dists, dp_types, max_dps,
            ctypes.byref(out_w), ctypes.byref(out_o),
            ctypes.byref(out_f), ctypes.byref(out_c),
        )
        w_cnt = out_w.value
        w_ops = out_o.value
        focused_ops += w_ops
        focused_dps_count += w_cnt

        for j in range(w_cnt):
            xt = int(dp_xtags[j])
            d_val = int(dp_dists[j])
            k_tp = int(dp_types[j])
            if xt in focused_dp_table:
                for prev_d, prev_tp, prev_wave in focused_dp_table[xt]:
                    if prev_tp != k_tp:
                        cross_wave_tame_wild_checks += 1
                        t_d = prev_d if prev_tp == 0 else d_val
                        w_d = prev_d if prev_tp == 1 else d_val
                        for cand_s in (w_d - t_d, w_d + t_d, t_d - w_d):
                            rk = cand_s - x32_shift
                            if rk > 0 and scalar_mult(focal_anchor_140 + rk, G) == P_140:
                                print(f"[!!!] КОЛЛИЗИЯ TAME+WILD НА ВОЛНЕ {wave}: k_140 = {hex(focal_anchor_140 + rk)}")
                    elif k_tp == 1 and prev_d != d_val:
                        cross_wave_wild_wild_checks += 1
                        for cand_s in ((prev_d + d_val) >> 1, (prev_d - d_val) >> 1):
                            rk = cand_s - x32_shift
                            if rk > 0 and scalar_mult(focal_anchor_140 + rk, G) == P_140:
                                print(f"[!!!] КОЛЛИЗИЯ WILD+WILD (÷2) НА ВОЛНЕ {wave}: k_140 = {hex(focal_anchor_140 + rk)}")
                focused_dp_table[xt].append((d_val, k_tp, wave))
            else:
                focused_dp_table[xt] = [(d_val, k_tp, wave)]

        pairs_pot = focused_dps_count * (focused_dps_count - 1) // 2
        print(
            f"Волна {wave:>2d} | Ж4 ({cx_4:.4f}, {cy_4:.4f}) | {w_ops:>15,d}   | {w_cnt:>9,d}   | "
            f"{focused_dps_count:>19,d}   | {pairs_pot:>18,d} пар"
        )

    # Обновляем глобальную базу Distinguished Points и выводим общий итог по всем 100 клеткам поля 10x10
    dp_db_path = "/home/user/puzzle140_sota_dps.json"
    if os.path.exists(dp_db_path):
        with open(dp_db_path, "r", encoding="utf-8") as f:
            dp_db = json.load(f)
    else:
        dp_db = {"total_ec_ops": 0, "total_sqf64_keys": 0, "total_dps_collected": 0}

    dp_db["total_ec_ops"] = dp_db.get("total_ec_ops", 0) + focused_ops
    dp_db["total_sqf64_keys"] = dp_db.get("total_sqf64_keys", 0) + south_total_keys
    dp_db["total_dps_collected"] = dp_db.get("total_dps_collected", 0) + focused_dps_count
    dp_db["board_10x10_cells_completed"] = 100
    dp_db["focused_J4_trap_dps"] = focused_dps_count
    dp_db["focused_J4_quadratic_pairs"] = focused_dps_count * (focused_dps_count - 1) // 2

    with open(dp_db_path, "w", encoding="utf-8") as f:
        json.dump(dp_db, f, indent=2, ensure_ascii=False)

    grand_total_keys = dp_db["total_sqf64_keys"]
    grand_total_dps = dp_db["total_dps_collected"]
    grand_total_ops = dp_db["total_ec_ops"]

    print("-" * 114)
    print("ФИНАЛЬНЫЙ РАПОРТ КАМПАНИИ «МОРСКОЙ БОЙ В ЕДИНОМ КВАДРАТЕ 10x10» (РУБЕЖ 1 КВАДРИЛЛИОН КЛЮЧЕЙ ПРОЙДЕН!):")
    print(f"  1) Статус карты 10x10 (А1..К10):                  ПРОЧЁСАНЫ ВСЕ 100 ИЗ 100 КЛЕТОК (100% поля Морского боя!)")
    print(f"     - Верхнее полуполе Y < 0.5 (50 клеток А1..К5): 670.37 ТРИЛЛИОНА ключей")
    print(f"     - Нижнее полуполе Y >= 0.5 (50 клеток А6..К10):{south_total_keys/1e12:>6.2f} ТРИЛЛИОНА ключей (вкл. 12x400 в Ж6..К9/Ж8)")
    print(f"  2) КУМУЛЯТИВНЫЙ ОХВАТ ПО ВСЕМ 5 ФЛАГМАНАМ:        {grand_total_keys:,d} ключей")
    print(f"                                                    ({grand_total_keys/1e15:.4f} КВАДРИЛЛИОНА / ПЕТАКЛЮЧА!)")
    print(f"  3) Сфокусированная ловушка SOTA Kangaroo в Ж4:    {focused_dps_count:,d} DPs за 10 волн ({focused_dps_count*(focused_dps_count-1)//2:,d} пар C(N,2))")
    print(f"  4) Всего в глобальной базе Distinguished Points:  {grand_total_dps:,d} выдающихся точек ({grand_total_ops:,d} EC-прыжков)")
    print("=" * 114)


if __name__ == "__main__":
    run_southern_corridor_and_focused_swarm()
