import ctypes
import hashlib
import hmac
import math
import time
from symmetric_quartet_folding import G, P, N, point_add, point_neg, scalar_mult
from generate_secp256k1_key import privkey_to_wif, pubkey_to_p2pkh_address
from bitcoin_puzzle_66_67_solver import decompress_pubkey
from sqf_dual_suite import lib_dual, int_to_limbs, solve_pubkey_window

# Настраиваем сигнатуры новых C++ функций в libsqf_dual.so
lib_dual.sqf_signed_bit_skeleton_140.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_int),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint64),
]
lib_dual.sqf_signed_bit_skeleton_140.restype = ctypes.c_int

lib_dual.sqf_check_point_in_table.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint32),
]
lib_dual.sqf_check_point_in_table.restype = ctypes.c_int

# =====================================================================
# БАЗА РЕАЛЬНЫХ РЕШЁННЫХ КЛЮЧЕЙ BITCOIN PUZZLE (#1..#70, #75, #80, #125, #130)
# =====================================================================
SOLVED_KEYS = {
    1: 0x1, 2: 0x3, 3: 0x7, 4: 0x8, 5: 0x15, 6: 0x31, 7: 0x4c, 8: 0xe0,
    9: 0x1d3, 10: 0x202, 11: 0x483, 12: 0xa7b, 13: 0x1460, 14: 0x2930,
    15: 0x68f3, 16: 0xc936, 17: 0x1764f, 18: 0x3080d, 19: 0x5749f, 20: 0xd2c55,
    21: 0x1ba534, 22: 0x2de40f, 23: 0x556e52, 24: 0xdc2a04, 25: 0x1fa5ee5,
    26: 0x340326e, 27: 0x6ac3875, 28: 0xd916ce8, 29: 0x17e2551e, 30: 0x3d94cd64,
    31: 0x7d4fe747, 32: 0xb862a62e, 33: 0x1a96ca8d8, 34: 0x34a65911d,
    35: 0x4aed21170, 36: 0x9de820a7c, 37: 0x1757756a93, 38: 0x22382facd0,
    39: 0x4b5f8303e9, 40: 0xe9ae4933d6, 41: 0x153869acc5b, 42: 0x2a221c58d8f,
    43: 0x6bd3b27c591, 44: 0xe02b35a358f, 45: 0x122fca143c05, 46: 0x2ec18388d544,
    47: 0x6cd610b53cba, 48: 0xade6d7ce3b9b, 49: 0x174176b015f4d, 50: 0x22bd43c2e9354,
    51: 0x75070a1a009d4, 52: 0xefae164cb9e3c, 53: 0x180788e47e326c, 54: 0x236fb6d5ad1f43,
    55: 0x6abe1f9b67e114, 56: 0x9d18b63ac4ffdf, 57: 0x1eb25c90795d61c, 58: 0x2c675b852189a21,
    59: 0x7496cbb87cab44f, 60: 0xfc07a1825367bbe, 61: 0x13c96a3742f64906, 62: 0x363d541eb611abee,
    63: 0x7cce5efdaccf6808, 64: 0xf7051f27b09112d4, 65: 0x1a838b13505b26867,
    66: 0x2832ed74f2b5e35ee, 67: 0x730fc235c1942c1ae, 68: 0xbebb3940cd0fc1491,
    69: 0x101d83275fb2bc7e0c, 70: 0x349b84b6431a6c4ef1,
    75: 0x4c5ce114686a1336e07, 80: 0xea1a5c66dcc11b5ad180,
    125: 0x1c533b6bb7f0804e09960225e44877ac,
    130: 0x33e7665705359f04f28b88cf897c603c9,
}

P140_PUB_HEX = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
P140_ADDR    = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
P140_START   = 1 << 139
P140_END     = (1 << 140) - 1
MASK_139     = (1 << 139) - 1
LAMBDA       = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72

def clamp_140(val: int) -> int:
    return P140_START | (val & MASK_139)

def generate_hypothesis_anchors():
    """
    Генерирует якоря A_i по всем простым математическим гипотезам в диапазоне [2^139, 2^140 - 1].
    Каждый якорь при проверке через таблицу автоматически покрывает [A_i - 8.38M, A_i + 8.38M]!
    """
    anchors = []

    # 1. Алгебраические комбинации решённых ключей (70+70=140, 65+75=140, 60+80=140, 15+125=140, 10+130=140)
    pairs_140 = [(70, 70), (65, 75), (60, 80), (15, 125), (10, 130)]
    for i, j in pairs_140:
        ki, kj = SOLVED_KEYS[i], SOLVED_KEYS[j]
        anchors.append((f"Произведение k_{i} * k_{j}", clamp_140(ki * kj)))
        anchors.append((f"Склейка (k_{j} << {i}) | k_{i}", clamp_140((kj << i) | ki)))
        anchors.append((f"Склейка (k_{j} << {i}) ^ k_{i}", clamp_140((kj << i) ^ ki)))
        anchors.append((f"Отношение k_{j}^2 // k_{i}", clamp_140((kj * kj) // max(1, ki))))

    # Сдвиги всех решённых ключей #1..#130 до 140 бит и повторение их паттернов
    for n, kn in SOLVED_KEYS.items():
        shift = 140 - n
        anchors.append((f"Сдвиг k_{n} << {shift}", clamp_140(kn << shift)))
        # Заполнение 140 бит повторяющимся ключом k_n
        rep = 0
        while rep.bit_length() < 140:
            rep = (rep << n) | kn
        anchors.append((f"Периодический повтор k_{n}", clamp_140(rep)))
        # Относительная позиция внутри диапазона n, перенесённая на 140 бит:
        low_n = kn - (1 << (n - 1))
        scaled_140 = P140_START + (low_n << (140 - n))
        anchors.append((f"Точная проекция позиции #{n}", clamp_140(scaled_140)))

    # 2. Простые детерминированные генераторы (SHA-256 / двойной SHA-256 / HMAC от базовых сидов)
    seeds = [
        b"", b"bitcoin", b"satoshi", b"saatoshi_rising", b"puzzle", b"140",
        b"Bitcoin Puzzle", b"secp256k1", b"1", b"0", b"key140", b"32BTC"
    ]
    for s in seeds:
        h1 = int.from_bytes(hashlib.sha256(s).digest(), "big")
        h2 = int.from_bytes(hashlib.sha256(hashlib.sha256(s).digest()).digest(), "big")
        h_idx = int.from_bytes(hashlib.sha256(s + b"140").digest(), "big")
        hm = int.from_bytes(hmac.new(s, (140).to_bytes(4, "big"), hashlib.sha512).digest()[:32], "big")
        anchors.append((f"SHA256({s.decode() or 'empty'})", clamp_140(h1)))
        anchors.append((f"SHA256d({s.decode() or 'empty'})", clamp_140(h2)))
        anchors.append((f"SHA256({s.decode()}+'140')", clamp_140(h_idx)))
        anchors.append((f"HMAC_SHA512({s.decode()}, 140)", clamp_140(hm)))

        # Цепочка из 140 итераций SHA256^140(seed)
        cur = s
        for _ in range(140):
            cur = hashlib.sha256(cur).digest()
        anchors.append((f"SHA256^140({s.decode() or 'empty'})", clamp_140(int.from_bytes(cur, "big"))))

    # 3. Фундаментальные математические константы и рациональная сетка (p/q) * 2^139
    # Считаем с точностью 160 бит через целочисленную арифметику:
    anchors.append(("Золотое сечение phi * 2^139", clamp_140((math.isqrt(5 << 280) - (1 << 140)) >> 1)))
    anchors.append(("Корень sqrt(2) * 2^139",      clamp_140(math.isqrt(2 << 278))))
    anchors.append(("Корень sqrt(3) * 2^139",      clamp_140(math.isqrt(3 << 278))))
    anchors.append(("Эндоморфизм LAMBDA mod 2^140", clamp_140(LAMBDA)))
    anchors.append(("Порядок кривой N mod 2^140",   clamp_140(N)))

    for q in range(2, 65):
        for p in range(1, q):
            if math.gcd(p, q) == 1:
                frac_val = P140_START + ((1 << 139) * p) // q
                anchors.append((f"Дробь {p}/{q} диапазона", clamp_140(frac_val)))

    # 4. Повторяющиеся байты (0x8888..., 0x9999..., 0xAAAA..., ..., 0xFFFF...) и палиндромы
    for byte_val in range(0x00, 0x100):
        pat = int.from_bytes(bytes([byte_val]) * 18, "big")
        anchors.append((f"Повтор байта 0x{byte_val:02x}", clamp_140(pat)))

    return anchors


if __name__ == "__main__":
    print("=" * 90)
    print(" ГИПОТЕЗА ПРОСТОТЫ: КОМПЛЕКСНЫЙ АНАЛИЗ И ШТУРМ BITCOIN PUZZLE #140")
    print("=" * 90)
    K140_pt, valid = decompress_pubkey(P140_PUB_HEX)
    assert valid

    # Шаг 0: Инициализируем в ОЗУ универсальную таблицу M = 8,388,608 (покрывает +/- 8.38 млн вокруг любой точки!)
    M_TABLE = 8_388_608
    print(f"[*] 1. Прогрев универсальной таблицы x(r*G) на M = {M_TABLE:,} точек (охват 16,77 млн ключей на 1 точку)...")
    _ = solve_pubkey_window(P140_PUB_HEX, P140_START, P140_START + (1 << 46), M=M_TABLE)

    # Шаг 1: Полный обход Знакового Битового Скелета 2^139 +/- 2^a +/- 2^b +/- 2^c +/- r по всем 140 битам!
    print(f"\n[*] 2. Проверка ГИПОТЕЗЫ БИТОВОЙ ПРОСТОТЫ (все k = 2^139 +/- 2^a +/- 2^b +/- 2^c +/- r)...")
    t0 = time.time()
    K_base = point_add(K140_pt, point_neg(scalar_mult(P140_START, G)))
    kb_x = int_to_limbs(K_base[0])
    kb_y = int_to_limbs(K_base[1])
    out_a, out_b, out_c = ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(0)
    out_r = ctypes.c_uint32(0)
    out_combos = ctypes.c_uint64(0)

    hit_skel = lib_dual.sqf_signed_bit_skeleton_140(
        kb_x, kb_y, ctypes.c_uint32(M_TABLE),
        ctypes.byref(out_a), ctypes.byref(out_b), ctypes.byref(out_c),
        ctypes.byref(out_r), ctypes.byref(out_combos)
    )
    t_skel = time.time() - t0
    effective_keys_skel = out_combos.value * (2 * M_TABLE)
    print(f"    Проверено 3-битовых скелетов : {out_combos.value:,} комбинаций по всем 140 битам")
    print(f"    Охвачено ключей с таблицей   : {effective_keys_skel:,} ({effective_keys_skel / 1e12:,.1f} ТРИЛЛИОНОВ ключей!)")
    print(f"    Время выполнения (OpenMP C++): {t_skel:.3f} сек ({(effective_keys_skel / 1e12) / t_skel:,.1f} Трлн кл/с)")
    print(f"    Результат в скелете 2^a±2^b±2^c: {bool(hit_skel)}")

    # Шаг 2: Проверка всех алгебраических, рекуррентных, SHA256/HMAC и рациональных якорей
    anchors = generate_hypothesis_anchors()
    print(f"\n[*] 3. Проверка {len(anchors):,} математических и криптографических гипотез (по +/- 8,38 млн вокруг каждой)...")
    t1 = time.time()
    out_r_anchor = ctypes.c_uint32(0)
    for name, a_val in anchors:
        # Вычисляем D = K_140 - a_val * G и проверяем её в таблице g_table (16.77 млн ключей за 1 проверку!)
        D_pt = point_add(K140_pt, point_neg(scalar_mult(a_val, G)))
        if D_pt is None:
            print(f"[!] НАЙДЕН КЛЮЧ НА ЯКОРЕ {name}: {hex(a_val)}")
            break
        dx = int_to_limbs(D_pt[0])
        if lib_dual.sqf_check_point_in_table(dx, ctypes.byref(out_r_anchor)):
            r_hit = out_r_anchor.value
            for sr in (1, -1):
                cand = a_val + sr * r_hit
                if scalar_mult(cand, G) == K140_pt:
                    print(f"[!] НАЙДЕН КЛЮЧ В ОКРЕСТНОСТИ ЯКОРЯ {name}: {hex(cand)}")
                    break
    t_anc = time.time() - t1
    print(f"    Проверено {len(anchors):,} якорей ({len(anchors) * 2 * M_TABLE:,} ключей) за {t_anc:.3f} сек.")

    # Шаг 3: Глубокое сканирование 50-битных окон (по 1,12 квадриллиона ключей!) вокруг главных алгебраических гипотез
    print(f"\n[*] 4. Глубокий прогон SQF-64 (по 1,12 КВАДРИЛЛИОНА ключей) вокруг 5 главных алгебраических гипотез:")
    deep_targets = [
        ("Квадрат ключа #70: k_70 * k_70",               clamp_140(SOLVED_KEYS[70] * SOLVED_KEYS[70])),
        ("Произведение #65 * #75: k_65 * k_75",          clamp_140(SOLVED_KEYS[65] * SOLVED_KEYS[75])),
        ("Произведение #10 * #130: k_10 * k_130",        clamp_140(SOLVED_KEYS[10] * SOLVED_KEYS[130])),
        ("Проекция ключа #130: k_130 << 10",             clamp_140(SOLVED_KEYS[130] << 10)),
        ("Золотое сечение диапазона #140 (phi)",         clamp_140((math.isqrt(5 << 280) - (1 << 140)) >> 1)),
    ]
    win_half = 1 << 49 # окно шириной 2^50 = 1.125 квадриллиона ключей вокруг гипотезы!
    for idx, (label, center_val) in enumerate(deep_targets, start=1):
        wa = max(P140_START, center_val - win_half)
        wb = min(P140_END, wa + (1 << 50) - 1)
        res = solve_pubkey_window(P140_PUB_HEX, wa, wb, M=M_TABLE)
        print(f"    [{idx}/5] {label:38s} | {res['elapsed']:.3f} сек | {res['tkeys_per_sec']:,.1f} Трлн кл/с | Найдено: {res['found']}")

    print("=" * 90)
