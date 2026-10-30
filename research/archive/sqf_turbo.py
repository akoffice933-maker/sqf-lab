# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
import ctypes
import time
import math
import secrets
from symmetric_quartet_folding import G, P, N, point_add, point_neg, scalar_mult

# Загружаем скомпилированный C++ ускоритель libsqf.so
lib = ctypes.CDLL("./libsqf.so")
lib.sqf_solve_native.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32),
]
lib.sqf_solve_native.restype = ctypes.c_int

def int_to_limbs(val: int):
    arr = (ctypes.c_uint64 * 4)()
    for i in range(4):
        arr[i] = (val >> (64 * i)) & 0xFFFFFFFFFFFFFFFF
    return arr

def solve_sqf_turbo(target_pub, a: int, b: int):
    t0 = time.time()
    W = b - a
    C = (a + b) // 2

    # 1. Центрируем открытый ключ K0 = K - C*G
    K0 = point_add(target_pub, point_neg(scalar_mult(C, G)))
    if K0 is None:
        return {"k": C, "inversions": 1, "elapsed": time.time() - t0}

    x0_limbs = int_to_limbs(K0[0])
    y0_limbs = int_to_limbs(K0[1])

    # 2. Выбираем оптимальный радиус M = sqrt(W) // 2
    M = max(1024, int(math.isqrt(W)) // 2)
    # Округляем M до кратного 2048 для идеального выравнивания пакетов
    M = ((M + 2047) // 2048) * 2048
    max_q = (W // (4 * M)) + 1024

    out_q = ctypes.c_int64(0)
    out_r = ctypes.c_uint32(0)
    out_inv = ctypes.c_uint32(0)

    ok = lib.sqf_solve_native(
        x0_limbs, y0_limbs,
        ctypes.c_uint32(M),
        ctypes.c_uint32(max_q),
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
                    return {
                        "k": cand,
                        "M": M,
                        "q": sign_q * q_val,
                        "r": sign_r * r_val,
                        "inversions": out_inv.value,
                        "elapsed": elapsed,
                        "speed_gkeys": (W / 1e9) / elapsed,
                    }
    return None

if __name__ == "__main__":
    print("=" * 80)
    print(" SQF-TURBO (C++ Native + __uint128_t Field Mul + Moving-Center Quartet Folding)")
    print("=" * 80)

    for bits in [30, 38, 42, 46, 48]:
        a = 1 << (bits - 1)
        b = (1 << bits) - 1
        secret_k = 0x31ee951c if bits == 30 else (a + secrets.randbelow(b - a))
        pub = scalar_mult(secret_k, G)

        res = solve_sqf_turbo(pub, a, b)
        print(f"\n[+] Диапазон {bits} бит ({b - a + 1:,} ключей):")
        print(f"    Секретный ключ     : {hex(secret_k)}")
        print(f"    Найденный ключ     : {hex(res['k'])} (Совпадение: {res['k'] == secret_k})")
        print(f"    Делений по модулю P: {res['inversions']:,}")
        print(f"    Время вычисления   : {res['elapsed']:.4f} сек")
        print(f"    Эффективная скор.  : {res['speed_gkeys']:.2f} МЛРД ключей/сек (GKeys/s) на 1 ядре CPU!")
    print("\n" + "=" * 80)
