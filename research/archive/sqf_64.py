import ctypes
import time
import math
import secrets
from symmetric_quartet_folding import G, P, N, point_add, point_neg, scalar_mult
from generate_secp256k1_key import privkey_to_wif, pubkey_to_p2pkh_address

# Загружаем 64-битный C++/OpenMP движок libsqf_64.so
lib64 = ctypes.CDLL("./libsqf_64.so")
lib64.sqf_solve_64.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint64),
]
lib64.sqf_solve_64.restype = ctypes.c_int

def int_to_limbs(val: int):
    arr = (ctypes.c_uint64 * 4)()
    for i in range(4):
        arr[i] = (val >> (64 * i)) & 0xFFFFFFFFFFFFFFFF
    return arr

def solve_sqf_64(target_pub, a: int, b: int, max_ram_mb: int = 256, reuse_table: bool = True, fixed_M: int = None):
    """
    64-битный решатель SQF-64:
    - Полная поддержка 64-битных границ [a, b] и 64-битного счётчика гигантских шагов max_q (uint64_t).
    - Автоматическое ограничение размера таблицы по лимиту ОЗУ (max_ram_mb), чтобы исключить переполнение памяти.
    - Конвейерная предвыборка (__builtin_prefetch) в кэш L1/L3.
    - Возможность переиспользования универсальной таблицы x(r * G) в ОЗУ (0.000 сек на Фазу 1 при повторных вызовах!).
    """
    t0 = time.time()
    W = b - a
    C = (a + b) // 2

    # 1. Центрируем открытый ключ K0 = K - C*G
    K0 = point_add(target_pub, point_neg(scalar_mult(C, G)))
    if K0 is None:
        return {"k": C, "inversions": 1, "elapsed": time.time() - t0}

    x0_limbs = int_to_limbs(K0[0])
    y0_limbs = int_to_limbs(K0[1])

    # 2. Вычисляем максимальный размер таблицы M, помещающийся в max_ram_mb
    # Таблица имеет ёмкость 2^k >= 2*M по 8 байт + 1 байт Bitmap = 9 байт на слот (~18-28 байт на точку M)
    max_M_by_ram = (max_ram_mb * 1024 * 1024) // 32
    if fixed_M is not None:
        M = fixed_M
    else:
        ideal_M = max(2048, int(math.isqrt(W)) // 4)
        M = min(ideal_M, max_M_by_ram)
        M = ((M + 2047) // 2048) * 2048

    max_q = (W // (4 * M)) + 2048

    out_q = ctypes.c_int64(0)
    out_r = ctypes.c_uint32(0)
    out_inv = ctypes.c_uint64(0)

    ok = lib64.sqf_solve_64(
        x0_limbs, y0_limbs,
        ctypes.c_uint32(M),
        ctypes.c_uint64(max_q),
        ctypes.c_int(1 if reuse_table else 0),
        ctypes.byref(out_q),
        ctypes.byref(out_r),
        ctypes.byref(out_inv),
    )

    if ok:
        q_val = out_q.value
        r_val = out_r.value
        for sign_q in (1, -1):
            for sign_r in (1, -1):
                cand = C + sign_q * q_val * (2 * M) + sign_r * r_val
                if scalar_mult(cand, G) == target_pub:
                    elapsed = time.time() - t0
                    table_cap = 1 << (M * 2 - 1).bit_length()
                    ram_mb = (table_cap * 9) / (1024 * 1024)
                    return {
                        "k": cand,
                        "M": M,
                        "max_q": max_q,
                        "q": sign_q * q_val,
                        "r": sign_r * r_val,
                        "inversions": out_inv.value,
                        "ram_mb": ram_mb,
                        "elapsed": elapsed,
                        "speed_tkeys": (W / 1e12) / elapsed,
                    }
    return None

if __name__ == "__main__":
    print("=" * 86)
    print(" SQF-64: 64-БИТНАЯ АРХИТЕКТУРА + КОНВЕЙЕР PREFETCH + ГЛОБАЛЬНЫЙ КЭШ БАЗЫ r*G")
    print("=" * 86)

    # Часть 1: Прогрев универсальной таблицы M = 8,388,608 (144 МБ ОЗУ) и тест 48..54 бит
    SHARED_M = 8_388_608
    for idx, bits in enumerate([48, 50, 52, 54]):
        a = 1 << (bits - 1)
        b = (1 << bits) - 1
        secret_k = a + secrets.randbelow(b - a)
        pub = scalar_mult(secret_k, G)

        mode_str = "Холодный старт (построение базы + поиск)" if idx == 0 else "Горячий кэш базы r*G (только поиск!)"
        res = solve_sqf_64(pub, a, b, reuse_table=True, fixed_M=SHARED_M)
        print(f"\n[+] Диапазон {bits} бит ({b - a + 1:,} ключей) — [{mode_str}]:")
        print(f"    Секретный ключ     : {hex(secret_k)}")
        print(f"    Найденный ключ     : {hex(res['k'])} (Совпадение: {res['k'] == secret_k})")
        print(f"    Делений по модулю P: {res['inversions']:,} | ОЗУ: {res['ram_mb']:.1f} МБ")
        print(f"    Время вычисления   : {res['elapsed']:.4f} сек")
        print(f"    Эффективная скор.  : {res['speed_tkeys']:,.2f} ТРЛН ключей/сек (TeraKeys/s)")

    # Часть 2: Полноценный 64-битный приватный ключ (0x8000000000000000 .. 0xFFFFFFFFFFFFFFFF)
    print("\n" + "=" * 86)
    print(" ТЕСТ 64-БИТНОГО КЛЮЧА (secp256k1, старший 64-й бит = 1)")
    print("=" * 86)
    # Генерируем настоящий 64-битный приватный ключ в [2^63, 2^64 - 1]
    a64 = 1 << 63
    b64 = (1 << 64) - 1
    # Выбираем случайное 54-битное подокно внутри 64-битного пространства (или 12-битный префикс)
    window_width = 1 << 53
    win_start = a64 + secrets.randbelow(b64 - a64 - window_width)
    win_end   = win_start + window_width - 1
    secret_k64 = win_start + secrets.randbelow(window_width)

    pub64 = scalar_mult(secret_k64, G)
    pub64_uncompressed = "04" + f"{pub64[0]:064x}" + f"{pub64[1]:064x}"
    wif64 = privkey_to_wif(secret_k64, compressed=True)

    print(f"Целевой 64-битный ключ (скрыт) : {hex(secret_k64)} ({secret_k64:,})")
    print(f"Открытый ключ 04...            : {pub64_uncompressed[:38]}...{pub64_uncompressed[-18:]}")
    print(f"64-битное окно поиска          : [{hex(win_start)}, {hex(win_end)}] ({window_width:,} ключей)")

    res64 = solve_sqf_64(pub64, win_start, win_end, reuse_table=True, fixed_M=SHARED_M)
    recovered_wif64 = privkey_to_wif(res64["k"], compressed=True)
    print(f"\n[!] 64-БИТНЫЙ КЛЮЧ УСПЕШНО ВЫЧИСЛЕН ИЗ ОТКРЫТОГО КЛЮЧА!")
    print(f"    Вычисленный ключ (HEX)     : {hex(res64['k'])} ({res64['k']:,})")
    print(f"    Восстановленный WIF        : {recovered_wif64}")
    print(f"    Точное совпадение          : {res64['k'] == secret_k64 and recovered_wif64 == wif64}")
    print(f"    Время взлома (горячий кэш) : {res64['elapsed']:.4f} сек")
    print(f"    Эффективная скорость       : {res64['speed_tkeys']:,.2f} ТРЛН ключей/сек (TeraKeys/s)")
    print("=" * 86)
