# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
import ctypes
import hashlib
import hmac
import struct
import time
from symmetric_quartet_folding import G, P, N, scalar_mult
from bitcoin_puzzle_66_67_solver import decompress_pubkey
from sqf_dual_suite import lib_dual, int_to_limbs, solve_pubkey_window
from puzzle140_deep_cryptanalysis import ALL_82_SOLVED, P140_PUB_HEX, P140_ADDR, P140_START, P140_END, MASK_139, clamp_140, berlekamp_massey_gf2, extrapolate_lfsr

# =====================================================================
# 1. ТОЧНОЕ ОБРАЩЕНИЕ (UNTEMPERING) ВИХРЯ МЕРСЕННА MT19937 (32-bit и 64-bit)
# "Вся сложность в простоте": каждая из 4 битовых операций MT19937 обратима!
# =====================================================================
def temper32(y: int) -> int:
    y &= 0xFFFFFFFF
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= (y >> 18)
    return y & 0xFFFFFFFF

def untemper_right(y: int, shift: int) -> int:
    res = y
    for _ in range(32 // shift + 1):
        res = y ^ (res >> shift)
    return res & 0xFFFFFFFF

def untemper_left(y: int, shift: int, mask: int) -> int:
    res = y
    for _ in range(32 // shift + 1):
        res = y ^ ((res << shift) & mask)
    return res & 0xFFFFFFFF

def untemper32(y: int) -> int:
    """
    Точное математическое обращение выходного слова MT19937 в скрытое состояние state[i]:
    temper32(untemper32(y)) == y для любого 32-битного числа!
    """
    y &= 0xFFFFFFFF
    y = untemper_right(y, 18)
    y = untemper_left(y, 15, 0xEFC60000)
    y = untemper_left(y, 7, 0x9D2C5680)
    y = untemper_right(y, 11)
    return y & 0xFFFFFFFF

# 64-битный Вихрь Мерсенна (MT19937-64):
def temper64(y: int) -> int:
    y &= 0xFFFFFFFFFFFFFFFF
    y ^= (y >> 29) & 0x5555555555555555
    y ^= (y << 17) & 0x71D67FFFEDA60000
    y ^= (y << 37) & 0xFFF7EEE000000000
    y ^= (y >> 43)
    return y & 0xFFFFFFFFFFFFFFFF

def untemper64(y: int) -> int:
    y &= 0xFFFFFFFFFFFFFFFF
    # 1) Обращаем y ^= (y >> 43)
    y ^= (y >> 43)
    # 2) Обращаем y ^= (y << 37) & 0xFFF7EEE000000000
    y ^= (y << 37) & 0xFFF7EEE000000000
    # 3) Обращаем y ^= (y << 17) & 0x71D67FFFEDA60000 (4 итерации покрывают 64 бита)
    res = y
    for _ in range(4):
        res = y ^ ((res << 17) & 0x71D67FFFEDA60000)
    y = res & 0xFFFFFFFFFFFFFFFF
    # 4) Обращаем y ^= (y >> 29) & 0x5555555555555555
    res = y
    for _ in range(3):
        res = y ^ ((res >> 29) & 0x5555555555555555)
    return res & 0xFFFFFFFFFFFFFFFF

def reconstruct_mt19937_candidates_for_140():
    """
    Извлекает 32-битные и 64-битные слова из 82 известных ключей,
    обращает их через untemper32 / untemper64 в слова внутреннего состояния MT19937,
    восстанавливает линейную связь и скручивание (Twist) для шага #140,
    и применяет прямое темперирование temper32 / temper64!
    """
    candidates = []

    # 1. Извлекаем младшие и старшие 32-битные слова известных ключей #33..#70 и #75..#130
    keys_sorted = [ALL_82_SOLVED[n] for n in sorted(ALL_82_SOLVED.keys()) if n >= 33]
    untempered_low32  = [untemper32(k & 0xFFFFFFFF) for k in keys_sorted]
    untempered_high32 = [untemper32((k >> (k.bit_length() - 32)) & 0xFFFFFFFF) for k in keys_sorted]

    # Применяем шаг скручивания MT19937 (Twist: MATRIX_A = 0x9908B0DF) к парам внутренних состояний:
    def mt_twist_step(s0, s1, s_m):
        y = (s0 & 0x80000000) | (s1 & 0x7FFFFFFF)
        return s_m ^ (y >> 1) ^ (0x9908B0DF if (y & 1) else 0)

    # Генерируем 5-словные (160-битные) прогнозы состояния для #140 через untempered-слова:
    n_u = len(untempered_low32)
    for offset in range(1, n_u - 6):
        words_140 = []
        for w_idx in range(5):
            s0 = untempered_low32[(offset + w_idx) % n_u]
            s1 = untempered_low32[(offset + w_idx + 1) % n_u]
            sm = untempered_high32[(offset + w_idx + 3) % n_u]
            next_state = mt_twist_step(s0, s1, sm)
            words_140.append(temper32(next_state))
        val_140 = 0
        for w in words_140:
            val_140 = (val_140 << 32) | w
        candidates.append((f"MT19937-32 Twist (offset={offset})", clamp_140(val_140)))

    # 2. Побитовый синтез LFSR ПОСЛЕ снятия нелинейной маски темперирования (untemper64)!
    keys_64 = [ALL_82_SOLVED[n] for n in [65, 70, 75, 80, 85, 90, 95, 100, 105, 110, 115, 120, 125, 130]]
    # Выравниваем каждый ключ к 140 битам и разбиваем на три 64-битных слова, обращая каждое через untemper64:
    aligned_140 = [(k - (1 << (k.bit_length() - 1))) << (140 - k.bit_length()) for k in keys_64]
    u_words = [[untemper64((v >> (64 * w)) & 0xFFFFFFFFFFFFFFFF) for v in aligned_140] for w in range(3)]

    reconstructed_val = 0
    for w in range(3):
        pred_state_64 = 0
        for b in range(64):
            bits = [(x >> b) & 1 for x in u_words[w]]
            # Индекс 130 — это 13-й элемент, 135 — 14-й, 140 — 15-й!
            bit_140, _ = extrapolate_lfsr(bits, 15)
            if bit_140:
                pred_state_64 |= (1 << b)
        # Применяем прямое 64-битное темперирование MT19937-64!
        out_word_64 = temper64(pred_state_64)
        reconstructed_val |= (out_word_64 << (64 * w))

    candidates.append(("MT19937-64 Untemper + LFSR + Temper", clamp_140(reconstructed_val)))
    return candidates


# =====================================================================
# 2. ВОССТАНОВЛЕНИЕ МОДУЛЬНЫХ ГСЧ (LCG / Xorshift128+ / Аффинные генераторы в Z/N)
# =====================================================================
def reconstruct_lcg_and_affine_candidates():
    """
    Восстанавливает параметры аффинного генератора k_{n+1} = (A * k_n + B) mod M
    и разностных цепочек по известным ключам #1..#70 и #65..#130.
    """
    candidates = []

    # 1. Точное решение линейного генератора в поле скаляров кривой Z/N:
    # По трём последовательным 5-шаговым ключам (например, #120, #125, #130):
    # k_125 = A * k_120 + B (mod N)
    # k_130 = A * k_125 + B (mod N)
    # => A = (k_130 - k_125) * (k_125 - k_120)^(-1) mod N,  B = (k_125 - A * k_120) mod N
    step5 = [65, 70, 75, 80, 85, 90, 95, 100, 105, 110, 115, 120, 125, 130]
    for i in range(len(step5) - 2):
        n1, n2, n3 = step5[i], step5[i + 1], step5[i + 2]
        k1, k2, k3 = ALL_82_SOLVED[n1], ALL_82_SOLVED[n2], ALL_82_SOLVED[n3]
        A_modN = ((k3 - k2) * pow(k2 - k1, -1, N)) % N
        B_modN = (k2 - A_modN * k1) % N
        # Прокручиваем от k_130 на 2 шага по 5 бит (130 -> 135 -> 140):
        k135_cand = (A_modN * ALL_82_SOLVED[130] + B_modN) % N
        k140_cand = (A_modN * k135_cand + B_modN) % N
        candidates.append((f"Аффинный ГСЧ mod N по (#{n1},#{n2},#{n3})", clamp_140(k140_cand)))

    # 2. Точное решение LCG для нормализованных мантисс m_n = (k_n - 2^(n-1)) << (140 - n) по модулю 2^139:
    MOD139 = 1 << 139
    for n1 in range(40, 69):
        k1, k2, k3 = ALL_82_SOLVED[n1], ALL_82_SOLVED[n1 + 1], ALL_82_SOLVED[n1 + 2]
        diff1 = k2 - k1
        diff2 = k3 - k2
        # Убираем общую степень двойки из diff1 для обратимости по mod 2^139
        tz = (diff1 & -diff1).bit_length() - 1
        d1_odd = diff1 >> tz
        d2_shr = diff2 >> tz
        A_2 = (d2_shr * pow(d1_odd, -1, MOD139)) % MOD139
        B_2 = (k2 - A_2 * k1) % MOD139
        # Экстраполируем от k_130 за 10 шагов (130 -> 140)
        cur = ALL_82_SOLVED[130]
        for _ in range(10):
            cur = (A_2 * cur + B_2) % MOD139
        candidates.append((f"2-адический LCG mod 2^139 (#{n1}..#{n1+2})", clamp_140(cur)))

    # 3. Xorshift128+ рекуррентность между парами ключей:
    for i in range(len(step5) - 1):
        x = ALL_82_SOLVED[step5[i]]
        y = ALL_82_SOLVED[step5[i + 1]]
        # Шаг Xorshift128+:
        s1 = x ^ ((x << 23) & MASK_139)
        s0 = y
        s_next = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5)
        candidates.append((f"Xorshift128+ шаг (#{step5[i]},#{step5[i+1]})", clamp_140(s_next + s0)))

    return candidates


# =====================================================================
# 3. BIP32 HMAC-SHA512 / OpenSSL PRNG (SHA-1/SHA-256 Mixing от известных ключей)
# =====================================================================
def reconstruct_bip32_and_openssl_candidates():
    """
    Проверяет гипотезу детерминированной деривации BIP32 (HMAC-SHA512) и OpenSSL RAND_bytes,
    где предыдущие ключи (#70, #130 или кортеж #1..#70) выступают родительским ключом / состоянием пула энтропии!
    """
    candidates = []

    # 1. BIP32 CKDpriv: HMAC-SHA512(key=chain_code, data=0x00 || parent_priv_32bytes || index_4bytes)
    chain_codes = [
        b"Bitcoin seed",
        b"",
        hashlib.sha256(b"Bitcoin seed").digest(),
        hashlib.sha256(b"saatoshi_rising").digest(),
        ALL_82_SOLVED[130].to_bytes(32, "big"),
        ALL_82_SOLVED[70].to_bytes(32, "big"),
    ]
    parent_keys = [1, 65, 70, 75, 80, 85, 90, 95, 100, 105, 110, 115, 120, 125, 130]

    for cc in chain_codes:
        for pk_idx in parent_keys:
            pk_bytes = ALL_82_SOLVED[pk_idx].to_bytes(32, "big")
            for idx_val in [140, 139, 140 | 0x80000000, (140 - pk_idx)]:
                data = b"\x00" + pk_bytes + struct.pack(">I", idx_val & 0xFFFFFFFF)
                I = hmac.new(cc, data, hashlib.sha512).digest()
                IL = int.from_bytes(I[:32], "big")
                child_raw = (IL + ALL_82_SOLVED[pk_idx]) % N
                candidates.append((f"BIP32 CKDpriv (p=#{pk_idx}, i={idx_val})", clamp_140(child_raw)))
                candidates.append((f"BIP32 Raw IL (p=#{pk_idx}, i={idx_val})", clamp_140(IL)))

    # 2. OpenSSL SSLeay RAND_bytes (пул энтропии на базе SHA-1 / SHA-256 с инкрементным счётчиком MD):
    # В OpenSSL 1.0.1 (январь 2015 года!) RAND_bytes смешивал 20-байтные блоки SHA-1(md || state || counter)
    for pk_idx in parent_keys:
        st = ALL_82_SOLVED[pk_idx].to_bytes(32, "big")
        # Собираем 140 бит из 8 последовательных блоков SHA-1 (по 20 байт):
        sha1_stream = b""
        md = hashlib.sha1(st).digest()
        for cnt in range(8):
            md = hashlib.sha1(md + st + struct.pack("<I", 140 + cnt)).digest()
            sha1_stream += md[:10]
        val_ssl = int.from_bytes(sha1_stream[:18], "big")
        candidates.append((f"OpenSSL SSLeay SHA1-PRNG (from #{pk_idx})", clamp_140(val_ssl)))

    # 3. Хэш-аккумулятор от полной конкатенации всех известных ключей #1..#70:
    concat_1_70 = b"".join(ALL_82_SOLVED[i].to_bytes(9, "big") for i in range(1, 71))
    h_acc = int.from_bytes(hashlib.sha512(concat_1_70 + b"\x8c").digest()[:18], "big")
    candidates.append(("SHA512 аккумулятор всех ключей #1..#70", clamp_140(h_acc)))

    return candidates


if __name__ == "__main__":
    print("=" * 94)
    print(" ВОССТАНОВЛЕНИЕ СОСТОЯНИЯ ГСЧ (MT19937 / OpenSSL PRNG / BIP32 / LCG) ПО 82 КЛЮЧАМ")
    print("=" * 94)

    # 1. Проверяем математическую точность нашего untemper32 и untemper64:
    test_w32 = 0x730fc235
    test_w64 = 0x730fc235c1942c1a
    assert temper32(untemper32(test_w32)) == test_w32, "Ошибка untemper32!"
    assert temper64(untemper64(test_w64)) == test_w64, "Ошибка untemper64!"
    print(f"[+] Проверка обратимости Вихря Мерсенна:")
    print(f"    temper32(untemper32({hex(test_w32)})) == {hex(temper32(untemper32(test_w32)))} (100% точное обращение!)")
    print(f"    temper64(untemper64({hex(test_w64)})) == {hex(temper64(untemper64(test_w64)))} (100% точное обращение!)\n")

    mt_cands   = reconstruct_mt19937_candidates_for_140()
    lcg_cands  = reconstruct_lcg_and_affine_candidates()
    bip_cands  = reconstruct_bip32_and_openssl_candidates()
    all_cands  = mt_cands + lcg_cands + bip_cands

    print(f"[+] Сконструировано восстановленных состояний ГСЧ для шага #140:")
    print(f"    - Вихрь Мерсенна (MT19937-32 Twist & MT19937-64 Untemper+LFSR) : {len(mt_cands)} состояний")
    print(f"    - Модульные LCG (mod N, 2-адический LCG mod 2^139, Xorshift128+): {len(lcg_cands)} состояний")
    print(f"    - Деривация BIP32 (HMAC-SHA512 CKDpriv) и OpenSSL SHA1-PRNG    : {len(bip_cands)} состояний")
    print(f"    ВСЕГО кандидатов состояния ГСЧ                                  : {len(all_cands)}\n")

    # Инициализируем таблицу M = 8,388,608 в ОЗУ C++
    M_TABLE = 8_388_608
    K140_pt, _ = decompress_pubkey(P140_PUB_HEX)
    _ = solve_pubkey_window(P140_PUB_HEX, P140_START, P140_START + (1 << 46), M=M_TABLE)

    # Проверяем все восстановленные состояния ГСЧ в C++/OpenMP с радиусом GIANT_Q = 1024
    # (каждое состояние проверяет (2*1024 + 1) * 16,777,216 = 34,376,515,584 (34.38 МИЛЛИАРДА) ключей!)
    GIANT_Q = 1024
    num_c = len(all_cands)
    keys_per_cand = (2 * GIANT_Q + 1) * (2 * M_TABLE)
    total_keys_prng = num_c * keys_per_cand

    lo_arr  = (ctypes.c_uint64 * num_c)()
    mid_arr = (ctypes.c_uint64 * num_c)()
    hi_arr  = (ctypes.c_uint64 * num_c)()
    for idx, (_, val) in enumerate(all_cands):
        lo_arr[idx]  = val & 0xFFFFFFFFFFFFFFFF
        mid_arr[idx] = (val >> 64) & 0xFFFFFFFFFFFFFFFF
        hi_arr[idx]  = (val >> 128) & 0xFFFFFFFFFFFFFFFF

    k140_x = int_to_limbs(K140_pt[0])
    k140_y = int_to_limbs(K140_pt[1])
    out_idx = ctypes.c_int32(-1)
    out_q   = ctypes.c_int64(0)
    out_r   = ctypes.c_uint32(0)

    print(f"[*] Запуск пакетного C++/OpenMP анализатора по всем {num_c} состояниям ГСЧ")
    print(f"    (захват {keys_per_cand:,} ключей на каждое состояние = {total_keys_prng / 1e12:,.2f} ТРИЛЛИОНОВ ключей)...")
    t0 = time.time()
    hit = lib_dual.sqf_batch_anchors_140(
        k140_x, k140_y,
        ctypes.c_uint32(M_TABLE),
        ctypes.c_uint32(num_c),
        lo_arr, mid_arr, hi_arr,
        ctypes.c_uint32(GIANT_Q),
        ctypes.byref(out_idx),
        ctypes.byref(out_q),
        ctypes.byref(out_r),
    )
    el = time.time() - t0
    print(f"[+] Все {num_c} состояний ГСЧ ({total_keys_prng / 1e12:,.2f} трлн ключей) проверены за {el:.3f} сек ({(total_keys_prng/1e12)/el:,.1f} Трлн кл/с)!\n")

    # И выполняем глубокий прогон SQF-64 (по 1,12 квадриллиона ключей!) вокруг 4 главных реконструкций ГСЧ:
    top_prng_targets = [
        mt_cands[-1],   # MT19937-64 Untemper + LFSR + Temper
        lcg_cands[11],  # Аффинный ГСЧ mod N по (#120, #125, #130) -> #140
        bip_cands[14],  # BIP32 CKDpriv от #130 с ключом "Bitcoin seed"
        bip_cands[-2],  # OpenSSL SSLeay SHA1-PRNG от #130
    ]
    print("[*] Глубокое сканирование SQF-64 (окна по 1,12 КВАДРИЛЛИОНА ключей) вокруг 4 главных реконструкций ГСЧ:")
    for idx, (label, c_val) in enumerate(top_prng_targets, start=1):
        wa = max(P140_START, c_val - (1 << 49))
        wb = min(P140_END, wa + (1 << 50) - 1)
        res = solve_pubkey_window(P140_PUB_HEX, wa, wb, M=M_TABLE)
        print(f"    [{idx}/4] {label:48s}")
        print(f"          Центр: {hex(c_val)} | {res['elapsed']:.3f} сек | {res['tkeys_per_sec']:,.1f} Трлн кл/с | Найдено: {res['found']}")

    print("=" * 94)
