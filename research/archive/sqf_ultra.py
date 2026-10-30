import ctypes
import time
import math
import secrets
from symmetric_quartet_folding import G, P, N, point_add, point_neg, scalar_mult

# Загружаем многопоточный C++/OpenMP ускоритель libsqf_ultra.so
lib_ultra = ctypes.CDLL("./libsqf_ultra.so")
lib_ultra.sqf_solve_ultra.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_int64),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32),
]
lib_ultra.sqf_solve_ultra.restype = ctypes.c_int

def int_to_limbs(val: int):
    arr = (ctypes.c_uint64 * 4)()
    for i in range(4):
        arr[i] = (val >> (64 * i)) & 0xFFFFFFFFFFFFFFFF
    return arr

def solve_sqf_ultra(target_pub, a: int, b: int):
    t0 = time.time()
    W = b - a
    C = (a + b) // 2

    # 1. Центрируем открытый ключ K0 = K - C*G
    K0 = point_add(target_pub, point_neg(scalar_mult(C, G)))
    if K0 is None:
        return {"k": C, "inversions": 1, "elapsed": time.time() - t0}

    x0_limbs = int_to_limbs(K0[0])
    y0_limbs = int_to_limbs(K0[1])

    # 2. Асимметричный баланс M vs Q_max:
    # Фаза поиска с кэш-битовой маской (Bitmap) и остановкой в среднем на полпути
    # работает в ~4 раза быстрее на точку, чем построение таблицы.
    # Поэтому оптимальный радиус таблицы M = sqrt(W) // 4 (в 2 раза меньше ОЗУ и в ~1.7 раза быстрее!)
    M = max(2048, int(math.isqrt(W)) // 4)
    M = ((M + 2047) // 2048) * 2048
    max_q = (W // (4 * M)) + 2048

    out_q = ctypes.c_int64(0)
    out_r = ctypes.c_uint32(0)
    out_inv = ctypes.c_uint32(0)

    ok = lib_ultra.sqf_solve_ultra(
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
                    ram_mb = (M * 2 * 8) / (1024 * 1024)
                    return {
                        "k": cand,
                        "M": M,
                        "q": sign_q * q_val,
                        "r": sign_r * r_val,
                        "inversions": out_inv.value,
                        "ram_mb": ram_mb,
                        "elapsed": elapsed,
                        "speed_gkeys": (W / 1e9) / elapsed,
                    }
    return None

if __name__ == "__main__":
    print("=" * 84)
    print(" SQF-ULTRA: OpenMP Multi-Core + L3 Bitmap Filter + 8-Byte Compact Table + 2-Level Batch")
    print("=" * 84)

    for bits in [30, 38, 42, 46, 48, 50, 52]:
        a = 1 << (bits - 1)
        b = (1 << bits) - 1
        secret_k = 0x31ee951c if bits == 30 else (a + secrets.randbelow(b - a))
        pub = scalar_mult(secret_k, G)

        res = solve_sqf_ultra(pub, a, b)
        print(f"\n[+] Диапазон {bits} бит ({b - a + 1:,} ключей):")
        print(f"    Секретный ключ     : {hex(secret_k)}")
        print(f"    Найденный ключ     : {hex(res['k'])} (Совпадение: {res['k'] == secret_k})")
        print(f"    Делений по модулю P: {res['inversions']:,} | Память таблицы: {res['ram_mb']:.2f} МБ")
        print(f"    Время вычисления   : {res['elapsed']:.4f} сек")
        print(f"    Эффективная скор.  : {res['speed_gkeys']:,.1f} МЛРД ключей/сек (GKeys/s)")
    print("\n" + "=" * 84)
