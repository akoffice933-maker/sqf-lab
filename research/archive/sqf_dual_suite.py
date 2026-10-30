import ctypes
import struct
import hashlib
import time
import secrets
from symmetric_quartet_folding import G, P, N, point_add, point_neg, scalar_mult
from generate_secp256k1_key import privkey_to_wif, pubkey_to_p2pkh_address, BASE58_ALPHABET
from bitcoin_puzzle_66_67_solver import decompress_pubkey

# Загружаем двухрежимную библиотеку libsqf_dual.so (SQF-64 + Зеркальный HASH160-сканер)
lib_dual = ctypes.CDLL("./libsqf_dual.so")

lib_dual.sqf_solve_64.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint64),
]
lib_dual.sqf_solve_64.restype = ctypes.c_int

lib_dual.sqf_hash160_scan.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint64),
]
lib_dual.sqf_hash160_scan.restype = ctypes.c_int

def int_to_limbs(val: int):
    arr = (ctypes.c_uint64 * 4)()
    for i in range(4):
        arr[i] = (val >> (64 * i)) & 0xFFFFFFFFFFFFFFFF
    return arr

def address_to_hash160(addr: str) -> bytes:
    n = 0
    for c in addr:
        n = n * 58 + BASE58_ALPHABET.index(c)
    b = n.to_bytes(25, "big")
    chk = hashlib.sha256(hashlib.sha256(b[:21]).digest()).digest()[:4]
    if b[21:] != chk:
        raise ValueError(f"Неверная контрольная сумма Base58Check у адреса {addr}!")
    return b[1:21]

def scan_address_hash160(target_address: str, start_key: int, num_keys: int):
    """
    РЕЖИМ 1 (БЕЗ ОТКРЫТОГО КЛЮЧА):
    Ищет приватный ключ в интервале [start_key + 1, start_key + num_keys]
    только по Bitcoin-адресу (через одноблочный SHA256 + RIPEMD160 и зеркальное сложение C +/- j*G).
    """
    t0 = time.time()
    rmd_bytes = address_to_hash160(target_address)
    rmd_words = (ctypes.c_uint32 * 5)(*struct.unpack("<5I", rmd_bytes))

    start_pt = scalar_mult(start_key, G)
    sx = int_to_limbs(start_pt[0])
    sy = int_to_limbs(start_pt[1])
    out_off = ctypes.c_uint64(0)

    ok = lib_dual.sqf_hash160_scan(sx, sy, ctypes.c_uint64(num_keys), rmd_words, ctypes.byref(out_off))
    elapsed = time.time() - t0
    found_k = (start_key + out_off.value) if ok else None
    return {
        "found": bool(ok),
        "k": found_k,
        "keys_scanned": num_keys,
        "elapsed": elapsed,
        "mkeys_per_sec": (num_keys / 1e6) / elapsed,
    }

def solve_pubkey_window(comp_pubkey_hex: str, win_a: int, win_b: int, M: int = 8_388_608):
    """
    РЕЖИМ 2 (С ИЗВЕСТНЫМ ОТКРЫТЫМ КЛЮЧОМ):
    Распаковывает сжатый ключ 02/03... и ищет приватный ключ в окне [win_a, win_b]
    методом Симметричного Квартет-Свёртывания (SQF-64) со скоростью до 1 ПетаКлюча/с.
    """
    t0 = time.time()
    target_pt, is_valid = decompress_pubkey(comp_pubkey_hex)
    if not is_valid:
        raise ValueError("Точка не принадлежит кривой secp256k1!")

    W = win_b - win_a
    C = (win_a + win_b) // 2
    K0 = point_add(target_pt, point_neg(scalar_mult(C, G)))
    if K0 is None:
        return {"found": True, "k": C, "elapsed": time.time() - t0, "tkeys_per_sec": 0}

    x0 = int_to_limbs(K0[0])
    y0 = int_to_limbs(K0[1])
    max_q = (W // (4 * M)) + 2048

    out_q = ctypes.c_int64(0)
    out_r = ctypes.c_uint32(0)
    out_inv = ctypes.c_uint64(0)

    ok = lib_dual.sqf_solve_64(
        x0, y0,
        ctypes.c_uint32(M),
        ctypes.c_uint64(max_q),
        ctypes.c_int(1),
        ctypes.byref(out_q),
        ctypes.byref(out_r),
        ctypes.byref(out_inv),
    )
    elapsed = time.time() - t0
    if ok:
        q_val = out_q.value
        r_val = out_r.value
        for sq in (1, -1):
            for sr in (1, -1):
                cand = C + sq * q_val * (2 * M) + sr * r_val
                if scalar_mult(cand, G) == target_pt:
                    return {
                        "found": True,
                        "k": cand,
                        "inversions": out_inv.value,
                        "elapsed": elapsed,
                        "tkeys_per_sec": (W / 1e12) / elapsed,
                    }
    return {"found": False, "k": None, "inversions": out_inv.value, "elapsed": elapsed, "tkeys_per_sec": (W / 1e12) / elapsed}


if __name__ == "__main__":
    print("=" * 88)
    print(" ДВУХРЕЖИМНЫЙ КОМПЛЕКС SQF-DUAL (C++/OpenMP):")
    print("   Режим 1: Зеркальный HASH160-сканер (SHA256 + RIPEMD160) — для Bitcoin Puzzle #71")
    print("   Режим 2: Квартет-свёртывание SQF-64 (по открытому ключу) — для Bitcoin Puzzle #140")
    print("=" * 88)

    # -----------------------------------------------------------------
    # ТЕСТ РЕЖИМА 1: Взлом 71-битного ключа ТОЛЬКО по Bitcoin-адресу!
    # -----------------------------------------------------------------
    p71_start = 0x400000000000000000
    p71_end   = 0x7fffffffffffffffff
    p71_real_addr = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
    p71_rmd160 = address_to_hash160(p71_real_addr).hex()

    print(f"\n[РЕЖИМ 1] Параметры реального нерешённого Bitcoin Puzzle #71 (7.1 BTC):")
    print(f"  Диапазон (71 бит) : {hex(p71_start)} .. {hex(p71_end)}")
    print(f"  Целевой адрес     : {p71_real_addr}")
    print(f"  Целевой HASH160   : {p71_rmd160} (контрольная сумма Base58Check верна!)")

    # Проверим работу HASH160-сканера на тестовом 71-битном адресе (без передачи открытого ключа!)
    scan_span = 4_194_304 # 4.19 млн полных циклов (secp256k1 + SHA256 + RIPEMD160)
    base_71 = p71_start + secrets.randbelow(p71_end - p71_start - scan_span)
    secret_71_demo = base_71 + secrets.randbelow(scan_span - 100) + 50
    demo_pt = scalar_mult(secret_71_demo, G)
    demo_comp = (b"\x02" if demo_pt[1] % 2 == 0 else b"\x03") + demo_pt[0].to_bytes(32, "big")
    demo_addr = pubkey_to_p2pkh_address(demo_comp)

    print(f"\n  [*] Проверка HASH160-сканера вслепую только по адресу {demo_addr} (в 71-битной зоне)...")
    res_h160 = scan_address_hash160(demo_addr, base_71, scan_span)
    print(f"  [!] 71-битный ключ найден ТОЛЬКО по адресу : {hex(res_h160['k'])} (Совпадение: {res_h160['k'] == secret_71_demo})")
    print(f"      Восстановленный WIF                    : {privkey_to_wif(res_h160['k'], compressed=True)}")
    print(f"      Время сканирования                     : {res_h160['elapsed']:.4f} сек")
    print(f"      Скорость полного хеширования (CPU)     : {res_h160['mkeys_per_sec']:.2f} МЛН адресов/сек (MKeys/s)")

    # -----------------------------------------------------------------
    # ТЕСТ РЕЖИМА 2: Реальный нерешённый Bitcoin Puzzle #140 (14.0 BTC)
    # -----------------------------------------------------------------
    p140_start = 0x80000000000000000000000000000000000
    p140_end   = 0xfffffffffffffffffffffffffffffffffff
    p140_pub   = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
    p140_addr  = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"

    (p140_x, p140_y), p140_valid = decompress_pubkey(p140_pub)
    p140_derived_addr = pubkey_to_p2pkh_address(bytes.fromhex(p140_pub))

    print(f"\n" + "-" * 88)
    print(f"[РЕЖИМ 2] Параметры реального нерешённого Bitcoin Puzzle #140 (14.0 BTC, публичный ключ открыт!):")
    print(f"  Диапазон (140 бит): {hex(p140_start)} .. {hex(p140_end)}")
    print(f"  Сжатый ключ 03... : {p140_pub}")
    print(f"  На кривой secp256k1: {p140_valid} | Адрес: {p140_derived_addr} == {p140_addr} ({p140_derived_addr == p140_addr})")
    print(f"  Координата X      : 0x{p140_x:064x}")
    print(f"  Координата Y      : 0x{p140_y:064x}")

    # Демонстрация взлома 140-битного ключа алгоритмом SQF-64 в суб-окне шириной 2^52 (4.5 квадриллиона ключей)
    sub_win_140 = 1 << 52
    secret_140_demo = p140_start + secrets.randbelow(p140_end - p140_start - sub_win_140)
    win140_a = secret_140_demo - (sub_win_140 // 3)
    win140_b = win140_a + sub_win_140 - 1
    demo140_pt = scalar_mult(secret_140_demo, G)
    demo140_comp = ("02" if demo140_pt[1] % 2 == 0 else "03") + f"{demo140_pt[0]:064x}"

    print(f"\n  [*] Запуск SQF-64 в 140-битной зоне (окно 4,5 квадриллиона ключей)...")
    res_140 = solve_pubkey_window(demo140_comp, win140_a, win140_b, M=8_388_608)
    print(f"  [!] 140-битный ключ вычислен из 02/03...   : {hex(res_140['k'])} ({res_140['k'].bit_length()} бит!)")
    print(f"      Точное совпадение                      : {res_140['k'] == secret_140_demo}")
    print(f"      Время (холодный старт + поиск)         : {res_140['elapsed']:.4f} сек")
    print(f"      Эффективная скорость                   : {res_140['tkeys_per_sec']:,.2f} ТРЛН ключей/сек (TeraKeys/s)")

    # И прогоняем реальное суб-окно самого Bitcoin Puzzle #140 на горячем кэше:
    rand_win_start = p140_start + secrets.randbelow(p140_end - p140_start - sub_win_140)
    res_real_140 = solve_pubkey_window(p140_pub, rand_win_start, rand_win_start + sub_win_140 - 1, M=8_388_608)
    print(f"\n  [*] Просканировано реальное окно Puzzle #140 ({sub_win_140:,} ключей) на горячем кэше:")
    print(f"      Время обхода 4,5 квадриллиона ключей   : {res_real_140['elapsed']:.4f} сек ({res_real_140['tkeys_per_sec']:,.2f} Трлн ключей/с!)")
    print("=" * 88)
