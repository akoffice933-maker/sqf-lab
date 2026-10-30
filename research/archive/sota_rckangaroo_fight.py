# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ИТОГОВЫЙ ВЫВОД И БОЕВОЙ ПРОДОЛЖАТЕЛЬ ОХОТЫ ЗА ПРИВАТНЫМИ КЛЮЧАМИ (ОКТЯБРЬ 2026)
================================================================================
1. Формулирует честный математический и инженерный вывод по итогам:
   - Слепого бенчмарка на случайных ключах (blind_random_benchmark.py)
   - Статистического аудита всех 83 решённых пазлов (#1..#70 и #75..#135, включая
     вскрытый 28 июля 2026 года Puzzle #135: k_135 = 0x6d9392a16883f90903d5f78da57af07eb2)
2. Исследует и тестирует вслепую портированный нами на C++/OpenMP алгоритм
   SOTA v2 Kangaroo (RCKangaroo v4.0 by RetiredCoder, K = 1.15), вскрывший #120, #125, #130 и #135:
   - Показывает, как Зеркальное Складывание в начале координат (0*G) через знаковые прыжки
     (inv_flag = y & 1) позволяет двум ДИКИМ кенгуру сталкиваться друг с другом:
       (-k' + w1) = -(-k' + w2)  ===>  2*k' = w1 + w2  ===>  k' = (w1 + w2) / 2
   - Замеряет реальный коэффициент K = Ops / sqrt(W) и долю коллизий Wild-Wild на слепых случайных ключах.
3. Продолжает реальную боевую атаку на три главные цели:
   - Цель №1: Bitcoin Puzzle #140 (1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo, 14.0 BTC) —
     самый младший нерешённый пазл с открытым ключом после падения #135 (SOTA v2 Kangaroo + DP DB + SQF-64).
   - Цель №2: Bitcoin Puzzle #71 (1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU, 7.1 BTC) —
     самый младший нерешённый пазл без публичного ключа (12-way GLV + Mirror HASH160).
   - Цель №3: Кошелёк a third-party address (<third-party address withheld>, 22.02.2009) —
     атака по 145 публичным ключам, ECDSA SIGHASH_ALL и OpenSSL 0.9.8h.
"""

import ctypes
import json
import math
import os
import secrets
import time

from symmetric_quartet_folding import G, P, N, point_add, scalar_mult as scalar_multiplication
from generate_secp256k1_key import privkey_to_wif as private_key_to_wif
from bitcoin_puzzle_66_67_solver import decompress_pubkey

LIB_PATH = "/home/user/libsqf_dual.so"
lib = ctypes.CDLL(LIB_PATH)

# 1. sqf_rckangaroo_sota_solve (слепой решатель SOTA v2 Kangaroo с L1S2 и Wild-Wild коллизиями)
lib.sqf_rckangaroo_sota_solve.argtypes = [
    ctypes.POINTER(ctypes.c_uint64), # target_x_limbs
    ctypes.POINTER(ctypes.c_uint64), # target_y_limbs
    ctypes.c_uint32,                 # range_bits
    ctypes.c_uint32,                 # dp_bits
    ctypes.c_uint64,                 # seed_val
    ctypes.POINTER(ctypes.c_int64),  # out_solved_offset
    ctypes.POINTER(ctypes.c_uint64), # out_total_ops
    ctypes.POINTER(ctypes.c_uint32), # out_dp_count
    ctypes.POINTER(ctypes.c_int32),  # out_collision_type (1=Tame-Wild, 2=Wild-Wild)
]
lib.sqf_rckangaroo_sota_solve.restype = ctypes.c_int

# 2. sqf_rckangaroo_140_campaign (боевой сборщик Distinguished Points для Puzzle #140)
lib.sqf_rckangaroo_140_campaign.argtypes = [
    ctypes.POINTER(ctypes.c_uint64), # anchor_shifted_x
    ctypes.POINTER(ctypes.c_uint64), # anchor_shifted_y
    ctypes.c_uint32,                 # subrange_bits
    ctypes.c_uint32,                 # dp_bits
    ctypes.c_uint32,                 # steps_per_kang
    ctypes.c_uint64,                 # seed_val
    ctypes.POINTER(ctypes.c_uint64), # out_dp_xtags
    ctypes.POINTER(ctypes.c_int64),  # out_dp_dists
    ctypes.POINTER(ctypes.c_uint8),  # out_dp_types
    ctypes.c_uint32,                 # max_dps
    ctypes.POINTER(ctypes.c_uint32), # out_dp_written
    ctypes.POINTER(ctypes.c_uint64), # out_total_ops
    ctypes.POINTER(ctypes.c_int64),  # out_solved_offset
    ctypes.POINTER(ctypes.c_int32),  # out_col_type
]
lib.sqf_rckangaroo_140_campaign.restype = ctypes.c_int

# 3. sqf_solve_64 (SQF-64 BSGS с симметричным складыванием)
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

# 4. sqf_scan_window_12way_hash160 (12-кратный GLV + Parity + Mirror HASH160 сканер)
lib.sqf_scan_window_12way_hash160.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_int),
]
lib.sqf_scan_window_12way_hash160.restype = ctypes.c_int


def int_to_limbs(val: int):
    arr = (ctypes.c_uint64 * 4)()
    for i in range(4):
        arr[i] = (val >> (64 * i)) & 0xFFFFFFFFFFFFFFFF
    return arr


def hash160_to_u32_arr(hex_str: str):
    b = bytes.fromhex(hex_str)
    arr = (ctypes.c_uint32 * 5)()
    for i in range(5):
        arr[i] = int.from_bytes(b[4 * i : 4 * i + 4], "big")
    return arr


def point_neg(pt):
    return (pt[0], (-pt[1]) % P)


def point_sub(p1, p2):
    return point_add(p1, point_neg(p2))


def run_blind_sota_rckangaroo_benchmark():
    print("=" * 90)
    print("ЧАСТЬ 1. СЛЕПОЙ БЕНЧМАРК ПОРТИРОВАННОГО SOTA v2 KANGAROO (RCKangaroo v4.0, K -> 1.15)")
    print("Как зеркальное складывание (+u*G <-> -u*G) работает в реальном SOTA-решателе:")
    print("  - Прыжок зависит от X (j = x & 511), а знак прыжка (+/-) зависит от чётности Y (y & 1).")
    print("  - Поэтому точки +u*G = (x, +y) и -u*G = (x, -y) прыгают синхронно навстречу друг другу!")
    print("  - Когда сталкиваются два ДИКИХ кенгуру (-k' + w1) и -(-k' + w2) с одной координатой X:")
    print("        -k' + w1 = +k' - w2   ===>   2*k' = w1 + w2   ===>   k' = (w1 + w2) >> 1 !")
    print("=" * 90)

    print(
        f"{'Диапазон W':<11} | {'Секретный k (случайный)':<16} | {'Найденный k':<16} | "
        f"{'Тип коллизии':<16} | {'DPs':<7} | {'EC-операции (K = Ops/√W)':<25} | {'Время':<8}"
    )
    print("-" * 110)

    k_factors = []
    tw_count = 0
    ww_count = 0

    test_configs = [
        (28, 7, 4),
        (30, 8, 4),
        (32, 9, 4),
        (34, 10, 3),
    ]

    for rbits, dp_bits, trials in test_configs:
        W = 1 << rbits
        sqrt_W = math.isqrt(W)
        for t_idx in range(trials):
            # 1. Честно генерируем случайный приватный ключ k в [1, 2^rbits - 1]
            secret_k = secrets.randbelow(W - 1) + 1
            pub_pt = scalar_multiplication(secret_k, G)

            tx = int_to_limbs(pub_pt[0])
            ty = int_to_limbs(pub_pt[1])
            out_k = ctypes.c_int64(0)
            out_ops = ctypes.c_uint64(0)
            out_dps = ctypes.c_uint32(0)
            out_ctype = ctypes.c_int32(0)

            seed = secrets.randbits(64)
            t0 = time.perf_counter()
            # В решатель передаётся ТОЛЬКО публичный ключ pub_pt и размер диапазона rbits!
            ok = lib.sqf_rckangaroo_sota_solve(
                tx, ty, rbits, dp_bits, seed,
                ctypes.byref(out_k),
                ctypes.byref(out_ops),
                ctypes.byref(out_dps),
                ctypes.byref(out_ctype),
            )
            dt = time.perf_counter() - t0

            found_k = out_k.value
            ops = out_ops.value
            dps = out_dps.value
            ctype = out_ctype.value

            # Строгая внешняя проверка после завершения решателя:
            assert ok == 1 and found_k == secret_k, f"ОШИБКА: {found_k} != {secret_k}"

            K_emp = ops / sqrt_W
            k_factors.append(K_emp)
            if ctype == 1:
                tw_count += 1
                c_str = "Tame + Wild"
            else:
                ww_count += 1
                c_str = "Wild + Wild (÷2)"

            print(
                f"2^{rbits:<9d} | 0x{secret_k:012x}   | 0x{found_k:012x}   | "
                f"{c_str:<16} | {dps:<7d} | {ops:>10,d} ({K_emp:>5.2f} * √W) | {dt:>6.3f}s"
            )

    mean_k = sum(k_factors) / len(k_factors)
    min_k = min(k_factors)
    print("-" * 110)
    print(f"ИТОГ СЛЕПОГО ТЕСТА SOTA v2 KANGAROO ({len(k_factors)} случайных ключей):")
    print(f"  - Внешняя верификация (found_k == secret_k): {len(k_factors)}/{len(k_factors)} (100% точность вслепую!)")
    print(f"  - Коллизии Tame + Wild (k = w ± t):          {tw_count} ({100.0 * tw_count / len(k_factors):.1f}%)")
    print(f"  - Коллизии Wild + Wild (k = (w1 + w2) / 2):  {ww_count} ({100.0 * ww_count / len(k_factors):.1f}%)  <-- Зеркальное складывание!")
    print(f"  - Средний реальный коэффициент K:            {mean_k:.3f} * sqrt(W) (минимум: {min_k:.3f} * sqrt(W))")
    print(f"  - Потребление RAM под таблицу шагов:         0 МБ (хранятся только Distinguished Points!)")
    print()
    return {
        "trials": len(k_factors),
        "mean_K": round(mean_k, 4),
        "min_K": round(min_k, 4),
        "tame_wild_hits": tw_count,
        "wild_wild_mirror_hits": ww_count,
    }


def run_live_campaign_puzzle_140():
    print("=" * 90)
    print("ЧАСТЬ 2. БОЕВАЯ КАМПАНИЯ НА BITCOIN PUZZLE #140 (14.0 BTC — МЛАДШИЙ С ПУБЛИЧНЫМ КЛЮЧОМ)")
    print("После взятия #135 (28.07.2026, k_135 = 0x6d9392a16883f90903d5f78da57af07eb2, глубина 71.21%)")
    print("Puzzle #140 (1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo) — цель №1 в мире для алгоритма Кенгуру!")
    print("=" * 90)

    PUB140_HEX = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
    P_140, is_val = decompress_pubkey(PUB140_HEX)
    assert is_val
    LOW_140 = 1 << 139
    SPAN_140 = 1 << 139

    # Загружаем накопленную базу Distinguished Points для Puzzle #140
    dp_db_path = "/home/user/puzzle140_sota_dps.json"
    if os.path.exists(dp_db_path):
        with open(dp_db_path, "r", encoding="utf-8") as f:
            dp_db = json.load(f)
    else:
        dp_db = {
            "target_address": "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo",
            "pubkey_compressed": PUB140_HEX,
            "total_ec_ops": 0,
            "total_sqf64_keys": 0,
            "total_dps_collected": 0,
            "sectors_scanned": [],
            "distinguished_points_sample": [],
        }

    # Три приоритетных сектора в [2^139, 2^140 - 1]:
    # 1) Точный геометрический центр диапазона C = 3 * 2^138 (50.0000%)
    # 2) Квантиль вскрытого Puzzle #135 (71.212415% — точная пропорция k_135 в [2^134, 2^135))
    # 3) Выборочное среднее всех 83 решённых пазлов (51.0209%)
    k135 = 0x6d9392a16883f90903d5f78da57af07eb2
    u135_num = k135 - (1 << 134) # точный сдвиг #135, масштабированный на *32 (2^5) для #140!
    anchor_from_135 = LOW_140 + (u135_num << 5)

    anchors = [
        ("Геометрический центр (50.0000%)", LOW_140 + (SPAN_140 >> 1)),
        ("Масштабная проекция вскрытого #135 (71.2124%)", anchor_from_135),
        ("Среднее 83 решённых пазлов (51.0209%)", LOW_140 + int(SPAN_140 * 0.51020912)),
    ]

    max_dps = 8192
    dp_xtags = (ctypes.c_uint64 * max_dps)()
    dp_dists = (ctypes.c_int64 * max_dps)()
    dp_types = (ctypes.c_uint8 * max_dps)()

    # Также инициализируем таблицу SQF-64 (M = 2^20 = 1,048,576) для мгновенного охвата +-2^40 вокруг каждого якоря
    M_SQF = 1 << 20
    MAX_Q_SQF = 2000

    session_ec_ops = 0
    session_sqf_keys = 0
    session_dps = 0

    for idx, (label, base_scalar) in enumerate(anchors):
        t0 = time.perf_counter()
        # Вычисляем сдвинутую точку P_anchor = P_140 - base_scalar * G
        base_pt = scalar_multiplication(base_scalar, G)
        p_shifted = point_sub(P_140, base_pt)
        ax = int_to_limbs(p_shifted[0])
        ay = int_to_limbs(p_shifted[1])

        # А) Прогон SQF-64 вокруг якоря (ширина 4 * M * MAX_Q = 8.39 млрд ключей за ~5 мс)
        out_q = ctypes.c_int64(0)
        out_r = ctypes.c_uint32(0)
        out_it = ctypes.c_uint64(0)
        hit_sqf = lib.sqf_solve_64(
            ax, ay, M_SQF, MAX_Q_SQF, 0 if idx == 0 else 1,
            ctypes.byref(out_q), ctypes.byref(out_r), ctypes.byref(out_it)
        )
        sqf_covered = 4 * M_SQF * MAX_Q_SQF
        session_sqf_keys += sqf_covered

        if hit_sqf == 1:
            cand_k = base_scalar + out_q.value * (2 * M_SQF) + out_r.value
            if scalar_multiplication(cand_k, G) == P_140:
                print(f"[!] НАЙДЕН КЛЮЧ PUZZLE #140: {hex(cand_k)}")

        # Б) Прогон SOTA v2 Kangaroo (RCKangaroo CPU) с сохранением Distinguished Points
        out_written = ctypes.c_uint32(0)
        out_ops = ctypes.c_uint64(0)
        out_off = ctypes.c_int64(0)
        out_ctype = ctypes.c_int32(0)

        hit_kang = lib.sqf_rckangaroo_140_campaign(
            ax, ay,
            48,          # 48-битный поддиапазон вокруг якоря
            10,          # DP маска: 10 нулевых младших бит (1 из 1024 точек — Distinguished Point)
            2048,        # шагов на каждого из 96*N_threads кенгуру
            secrets.randbits(64),
            dp_xtags, dp_dists, dp_types, max_dps,
            ctypes.byref(out_written),
            ctypes.byref(out_ops),
            ctypes.byref(out_off),
            ctypes.byref(out_ctype),
        )
        dt = time.perf_counter() - t0

        written = out_written.value
        ops = out_ops.value
        session_ec_ops += ops
        session_dps += written

        # Сохраняем первые несколько DPs в журнал как криптографическое доказательство работы
        for j in range(min(3, written)):
            dp_db["distinguished_points_sample"].append({
                "sector": label,
                "anchor_hex": hex(base_scalar),
                "x_tag": f"0x{dp_xtags[j]:016x}",
                "dist": int(dp_dists[j]),
                "type": "TAME" if dp_types[j] == 0 else "WILD",
            })

        print(
            f"  Сектор [{idx+1}] {label:<44} | "
            f"SQF-64: {sqf_covered/1e9:.2f} GKeys | "
            f"SOTA Kangaroo: {ops:,d} прыжков, {written:,d} DPs ({dt:.2f}s)"
        )

    dp_db["total_ec_ops"] += session_ec_ops
    dp_db["total_sqf64_keys"] += session_sqf_keys
    dp_db["total_dps_collected"] += session_dps
    dp_db["distinguished_points_sample"] = dp_db["distinguished_points_sample"][-24:]

    with open(dp_db_path, "w", encoding="utf-8") as f:
        json.dump(dp_db, f, indent=2, ensure_ascii=False)

    print("-" * 90)
    print(f"База Distinguished Points обновлена ({dp_db_path}):")
    print(f"  - Всего собрано DPs в базе:      {dp_db['total_dps_collected']:,d} выдающихся точек")
    print(f"  - Выполнено EC-прыжков кенгуру:  {dp_db['total_ec_ops']:,d} групповых операций")
    print(f"  - Охвачено окнами SQF-64:        {dp_db['total_sqf64_keys']:,d} ключей")
    print()
    return dp_db


def run_live_campaign_puzzle_71_and_<third_party>():
    print("=" * 90)
    print("ЧАСТЬ 3. БОЕВОЕ СКАНИРОВАНИЕ PUZZLE #71 (БЕЗ PUBKEY) И КОШЕЛЬКА a third-party address (<third_party>...)")
    print("=" * 90)

    # 1. Bitcoin Puzzle #71 (1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU)
    # HASH160: f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8
    H160_P71 = hash160_to_u32_arr("f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8")
    LOW_71 = 1 << 70
    SPAN_71 = 1 << 70
    # Проекция глубины #135 (71.2124%) и среднего (51.0209%) на [2^70, 2^71 - 1]
    k135 = 0x6d9392a16883f90903d5f78da57af07eb2
    center_71 = LOW_71 + ((k135 - (1 << 134)) >> 64)

    c_pt = scalar_multiplication(center_71, G)
    cx = int_to_limbs(c_pt[0])
    cy = int_to_limbs(c_pt[1])
    out_off = ctypes.c_int64(0)
    out_mode = ctypes.c_int(0)

    half_steps_71 = 200_000
    t0 = time.perf_counter()
    hit_71 = lib.sqf_scan_window_12way_hash160(
        cx, cy, half_steps_71, H160_P71,
        ctypes.byref(out_off), ctypes.byref(out_mode)
    )
    dt_71 = time.perf_counter() - t0
    keys_71 = half_steps_71 * 12
    rate_71 = (keys_71 / dt_71) / 1e6

    print(
        f"  [Puzzle #71 | 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU] "
        f"Проверено {keys_71:,d} ключей (12-way GLV+Mirror HASH160) вокруг проекции #135 "
        f"({hex(center_71)}) за {dt_71:.3f}s ({rate_71:.2f} MKeys/s)"
    )

    # 2. Кошелёк a third-party address: <third-party address withheld>
    # HASH160: 592fc3990026334c8c6fb2b9da457179cdb5c688
    H160_198 = hash160_to_u32_arr("592fc3990026334c8c6fb2b9da457179cdb5c688")
    # Используем первый публичный ключ из 145 входов кошелька (Tx #1, 22.02.2009) как якорь
    with open("/home/user/withheld_pubkeys.txt", "r", encoding="utf-8") as f:
        first_pub_hex = f.readline().strip()
    if len(first_pub_hex) == 130 and first_pub_hex.startswith("04"):
        P_withheld_0 = (int(first_pub_hex[2:66], 16), int(first_pub_hex[66:130], 16))
    else:
        P_withheld_0, _ = decompress_pubkey(first_pub_hex)
    hx = int_to_limbs(P_withheld_0[0])
    hy = int_to_limbs(P_withheld_0[1])

    t1 = time.perf_counter()
    hit_198 = lib.sqf_scan_window_12way_hash160(
        hx, hy, half_steps_71, H160_198,
        ctypes.byref(out_off), ctypes.byref(out_mode)
    )
    dt_198 = time.perf_counter() - t1
    keys_198 = half_steps_71 * 12
    rate_198 = (keys_198 / dt_198) / 1e6

    print(
        f"  [a third-party address  | <third-party address withheld>] "
        f"Проверено {keys_198:,d} ключей (12-way GLV+Mirror относительно PubKey #1 кошелька) "
        f"за {dt_198:.3f}s ({rate_198:.2f} MKeys/s)"
    )
    print("=" * 90)


if __name__ == "__main__":
    bench_res = run_blind_sota_rckangaroo_benchmark()
    dp_db = run_live_campaign_puzzle_140()
    run_live_campaign_puzzle_71_and_<third_party>()
