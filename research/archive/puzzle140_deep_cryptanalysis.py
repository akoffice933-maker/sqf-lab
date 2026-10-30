import ctypes
import hashlib
import hmac
import math
import time
from symmetric_quartet_folding import G, P, N, point_add, point_neg, scalar_mult
from generate_secp256k1_key import privkey_to_wif, pubkey_to_p2pkh_address
from bitcoin_puzzle_66_67_solver import decompress_pubkey
from sqf_dual_suite import lib_dual, int_to_limbs, solve_pubkey_window

# Настраиваем сигнатуру пакетного C++/OpenMP сканера якорей sqf_batch_anchors_140
lib_dual.sqf_batch_anchors_140.argtypes = [
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
lib_dual.sqf_batch_anchors_140.restype = ctypes.c_int

# =====================================================================
# ПОЛНАЯ БАЗА ВСЕХ 82 РАСКРЫТЫХ КЛЮЧЕЙ BITCOIN PUZZLE (#1..#70 и #75..#130)
# =====================================================================
ALL_82_SOLVED = {
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
    75: 0x4c5ce114686a1336e07,
    80: 0xea1a5c66dcc11b5ad180,
    85: 0x11720c4f018d51b8cebba8,
    90: 0x2ce00bb2136a445c71e85bf,
    95: 0x527a792b183c7f64a0e8b1f4,
    100: 0xaf55fc59c335c8ec67ed24826,
    105: 0x16f14fc2054cd87ee6396b33df3,
    110: 0x35c0d7234df7deb0f20cf7062444,
    115: 0x60f4d11574f5deee49961d9609ac6,
    120: 0xb10f22572c497a836ea187f2e1fc23,
    125: 0x1c533b6bb7f0804e09960225e44877ac,
    130: 0x33e7665705359f04f28b88cf897c603c9,
}

P140_PUB_HEX = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
P140_ADDR    = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
P140_START   = 1 << 139
P140_END     = (1 << 140) - 1
MASK_139     = (1 << 139) - 1

def clamp_140(val: int) -> int:
    return P140_START | (val & MASK_139)

# =====================================================================
# 1. АЛГОРИТМ БЕРЛЕКЭМПА — МЕССИ (LFSR СИНТЕЗ НАД GF(2) ПО 82 КЛЮЧАМ)
# =====================================================================
def berlekamp_massey_gf2(bits):
    """
    Находит минимальный линейный регистр сдвига с обратной связью (LFSR),
    генерирующий битовую последовательность bits над полем GF(2).
    """
    n = len(bits)
    C = [1] + [0] * n
    B = [1] + [0] * n
    L = 0
    m = -1
    for i in range(n):
        d = bits[i]
        for j in range(1, L + 1):
            d ^= (C[j] & bits[i - j])
        if d == 1:
            T = list(C)
            shift = i - m
            for j in range(n - shift + 1):
                C[j + shift] ^= B[j]
            if 2 * L <= i:
                L = i + 1 - L
                m = i
                B = T
    return C[:L + 1], L

def extrapolate_lfsr(bits, target_index):
    poly, L = berlekamp_massey_gf2(bits)
    seq = list(bits)
    while len(seq) <= target_index:
        nxt = 0
        for j in range(1, L + 1):
            nxt ^= (poly[j] & seq[-j])
        seq.append(nxt)
    return seq[target_index], L

def synthesize_140_by_lfsr():
    """
    Синтезирует 140-битный ключ Puzzle #140 побитово через LFSR Берлекэмпа — Месси:
    Вариант А: По последовательности всех ключей кратных 5 (#5, #10, ..., #130 -> #140)
    Вариант Б: По последовательности младших бит #1..#70 с продолжением до #140
    """
    step5_indices = [5 * m for m in range(1, 27)] # 5, 10, ..., 130 (26 точек)
    # Выравниваем каждый ключ к 139 битам (дробная часть внутри [2^(n-1), 2^n))
    normalized_step5 = []
    for idx in step5_indices:
        k = ALL_82_SOLVED[idx]
        frac_139 = (k - (1 << (idx - 1))) << (140 - idx)
        normalized_step5.append(frac_139)

    pred_step5 = 0
    for bit_pos in range(139):
        col = [(val >> bit_pos) & 1 for val in normalized_step5]
        # idx=130 это индекс 25, idx=135 это 26, idx=140 это 27!
        b140, _ = extrapolate_lfsr(col, 27)
        if b140:
            pred_step5 |= (1 << bit_pos)

    # Вариант Б: по непрерывной последовательности #1..#70 (выровненной по старшему биту)
    norm_1_70 = [((ALL_82_SOLVED[i] - (1 << (i - 1))) << (140 - i)) for i in range(1, 71)]
    pred_1_70 = 0
    for bit_pos in range(139):
        col = [(val >> bit_pos) & 1 for val in norm_1_70]
        b140, _ = extrapolate_lfsr(col, 139) # индекс 139 соответствует пазлу #140
        if b140:
            pred_1_70 |= (1 << bit_pos)

    return clamp_140(pred_step5), clamp_140(pred_1_70)

# =====================================================================
# 2. ГЕНЕРАЦИЯ ВСЕХ ПАРНЫХ И РЕКУРРЕНТНЫХ ЯКОРЕЙ ПО БАЗЕ 82 КЛЮЧЕЙ
# =====================================================================
def build_all_deep_anchors():
    anchors = []

    # А. Синтез Берлекэмпа — Месси (LFSR)
    lfsr_a, lfsr_b = synthesize_140_by_lfsr()
    anchors.append(("LFSR Берлекэмпа-Месси (шаг 5: #5..#130 -> #140)", lfsr_a))
    anchors.append(("LFSR Берлекэмпа-Месси (ряд #1..#70 -> #140)",     lfsr_b))

    # Б. ВСЕ 13 комплементарных пар (i + j == 140) из полного набора 82 решённых ключей!
    # (10,130), (15,125), (20,120), (25,115), (30,110), (35,105), (40,100), (45,95), (50,90), (55,85), (60,80), (65,75), (70,70)
    for i in sorted(ALL_82_SOLVED.keys()):
        j = 140 - i
        if j in ALL_82_SOLVED and i <= j:
            ki, kj = ALL_82_SOLVED[i], ALL_82_SOLVED[j]
            li = ki - (1 << (i - 1))
            lj = kj - (1 << (j - 1))
            anchors.append((f"Произведение k_{i}*k_{j}", clamp_140(ki * kj)))
            anchors.append((f"Произведение мантисс l_{i}*l_{j}", clamp_140(li * lj * 2)))
            anchors.append((f"Старшая склейка (k_{j}<<{i})|k_{i}", clamp_140((kj << i) | ki)))
            anchors.append((f"Обратная склейка (k_{i}<<{j})|k_{j}", clamp_140((ki << j) | kj)))
            anchors.append((f"XOR склейка (k_{j}<<{i})^k_{i}", clamp_140((kj << i) ^ ki)))
            anchors.append((f"Сумма проекций #{i} + #{j}", clamp_140((li << (140 - i)) + (lj << (140 - j)))))
            anchors.append((f"Разность проекций #{j} - #{i}", clamp_140((lj << (140 - j)) - (li << (140 - i)))))
            anchors.append((f"SHA256(k_{i} || k_{j})", clamp_140(int.from_bytes(hashlib.sha256(ki.to_bytes(18, 'big') + kj.to_bytes(18, 'big')).digest(), 'big'))))

    # В. Линейно-разностные и LCG экстраполяции по шагу 5 (#110, #115, #120, #125, #130 -> #140)
    u = {n: (ALL_82_SOLVED[n] - (1 << (n - 1))) << (140 - n) for n in ALL_82_SOLVED}
    # Линейная, квадратичная и кубическая конечные разности через #115, #120, #125, #130:
    anchors.append(("Линейная экстраполяция #120->#130->#140", clamp_140(2 * u[130] - u[120])))
    anchors.append(("Квадратичная разность #110,#120,#130->#140", clamp_140(3 * u[130] - 3 * u[120] + u[110])))
    anchors.append(("Кубическая разность #100..#130->#140", clamp_140(4 * u[130] - 6 * u[120] + 4 * u[110] - u[100])))
    anchors.append(("Шаг-5 экстраполяция 3*u130 - 2*u125", clamp_140(3 * u[130] - 2 * u[125])))

    # LCG множители между соседними 5-шаговыми ключами: k_{n+10} = (k_n * A) mod 2^139
    for n in [60, 65, 70, 75, 80, 85, 90, 95, 100, 105, 110, 115, 120]:
        if (n + 5) in ALL_82_SOLVED and (n + 10) in ALL_82_SOLVED:
            # Отношение k_{n+10} / k_n применённое к k_130
            ratio_pred = (ALL_82_SOLVED[130] * ALL_82_SOLVED[n + 10]) // ALL_82_SOLVED[n]
            anchors.append((f"Мультипликативный шаг ({n}->130->140)", clamp_140(ratio_pred)))

    # Г. Плотная рациональная и статистическая сетка (4000 узлов по всему диапазону #140)
    # В 82 решённых пазлах средняя позиция ключа внутри диапазона равна 50.24%, медиана 51.8%
    for permil in range(1, 3500):
        pos = P140_START + (MASK_139 * permil) // 3500
        anchors.append((f"Сетка {permil}/3500", clamp_140(pos)))

    return anchors


if __name__ == "__main__":
    print("=" * 92)
    print(" ГЛУБОКИЙ КРИПТОАНАЛИЗ 82 РЕШЁННЫХ КЛЮЧЕЙ И ПАКЕТНЫЙ ШТУРМ PUZZLE #140 (C++/OpenMP)")
    print("=" * 92)

    # Статистика по всем 82 решённым ключам
    fracs = [(ALL_82_SOLVED[n] - (1 << (n - 1))) / float(1 << (n - 1)) * 100.0 for n in ALL_82_SOLVED]
    hw_ratios = [bin(ALL_82_SOLVED[n]).count("1") / float(n) * 100.0 for n in ALL_82_SOLVED if n >= 20]
    print(f"[+] Загружено реальных решённых ключей : {len(ALL_82_SOLVED)} (#1..#70 и все кратные 5 до #130)")
    print(f"[+] Средняя позиция ключа в диапазоне  : {sum(fracs)/len(fracs):.2f}% (мин: {min(fracs):.2f}%, макс: {max(fracs):.2f}%)")
    print(f"[+] Средняя плотность единиц (Hamming) : {sum(hw_ratios)/len(hw_ratios):.2f}% бит равны 1 (ожидание для ГСЧ: 50.0%)\n")

    # Инициализируем таблицу M = 8,388,608 в C++ ОЗУ
    M_TABLE = 8_388_608
    K140_pt, _ = decompress_pubkey(P140_PUB_HEX)
    _ = solve_pubkey_window(P140_PUB_HEX, P140_START, P140_START + (1 << 46), M=M_TABLE)

    anchors = build_all_deep_anchors()
    num_anc = len(anchors)
    GIANT_Q = 256 # На каждый якорь проверяем (2*256 + 1) * 16.77M = 8,589,934,592 (8.59 МИЛЛИАРДА) ключей!

    print(f"[*] Сформировано {num_anc:,} криптоаналитических якорей (LFSR Берлекэмпа-Месси, все 13 пар i+j=140, LCG, сетка)")
    print(f"[*] Радиус захвата каждого якоря в C++ : +/- {GIANT_Q} гигантских шагов = {(2*GIANT_Q + 1) * 2 * M_TABLE:,} ключей (8,59 млрд ключей!)")
    total_keys_batch = num_anc * (2 * GIANT_Q + 1) * (2 * M_TABLE)
    print(f"[*] Суммарный охват пакета             : {total_keys_batch:,} ({total_keys_batch / 1e12:,.2f} ТРИЛЛИОНОВ ключей!)\n")

    lo_arr  = (ctypes.c_uint64 * num_anc)()
    mid_arr = (ctypes.c_uint64 * num_anc)()
    hi_arr  = (ctypes.c_uint64 * num_anc)()

    for idx, (_, val) in enumerate(anchors):
        lo_arr[idx]  = val & 0xFFFFFFFFFFFFFFFF
        mid_arr[idx] = (val >> 64) & 0xFFFFFFFFFFFFFFFF
        hi_arr[idx]  = (val >> 128) & 0xFFFFFFFFFFFFFFFF

    k140_x = int_to_limbs(K140_pt[0])
    k140_y = int_to_limbs(K140_pt[1])
    out_idx = ctypes.c_int32(-1)
    out_q   = ctypes.c_int64(0)
    out_r   = ctypes.c_uint32(0)

    t0 = time.time()
    hit = lib_dual.sqf_batch_anchors_140(
        k140_x, k140_y,
        ctypes.c_uint32(M_TABLE),
        ctypes.c_uint32(num_anc),
        lo_arr, mid_arr, hi_arr,
        ctypes.c_uint32(GIANT_Q),
        ctypes.byref(out_idx),
        ctypes.byref(out_q),
        ctypes.byref(out_r),
    )
    elapsed = time.time() - t0
    speed_tkeys = (total_keys_batch / 1e12) / elapsed

    print(f"[+] Пакетный C++/OpenMP прогон завершён за {elapsed:.3f} сек!")
    print(f"[+] Эффективная скорость по {num_anc:,} гипотезам : {speed_tkeys:,.2f} ТРЛН ключей/сек (TeraKeys/s)")

    # Также прогоним по 1,12 квадриллиона ключей (2^50) вокруг двух главных предсказаний LFSR Берлекэмпа-Месси
    lfsr_a, lfsr_b = synthesize_140_by_lfsr()
    print(f"\n[*] Глубокая проверка предсказаний LFSR Берлекэмпа — Месси (окна по 1,12 квадриллиона ключей):")
    print(f"    1) LFSR по 26 ключам кратным 5 (#5..#130) : {hex(lfsr_a)}")
    res_la = solve_pubkey_window(P140_PUB_HEX, lfsr_a - (1 << 49), lfsr_a + (1 << 49) - 1, M=M_TABLE)
    print(f"       Проверено 1,12 квадриллиона ключей за {res_la['elapsed']:.3f} сек ({res_la['tkeys_per_sec']:,.1f} Трлн кл/с) | Найдено: {res_la['found']}")

    print(f"    2) LFSR по 70 непрерывным ключам (#1..#70): {hex(lfsr_b)}")
    res_lb = solve_pubkey_window(P140_PUB_HEX, lfsr_b - (1 << 49), lfsr_b + (1 << 49) - 1, M=M_TABLE)
    print(f"       Проверено 1,12 квадриллиона ключей за {res_lb['elapsed']:.3f} сек ({res_lb['tkeys_per_sec']:,.1f} Трлн кл/с) | Найдено: {res_lb['found']}")
    print("=" * 92)
