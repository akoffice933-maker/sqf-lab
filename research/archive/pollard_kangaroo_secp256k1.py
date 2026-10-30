import hashlib
import time
import random

# =====================================================================
# 1. Параметры эллиптической кривой secp256k1
# Уравнение: y^2 = x^3 + 7 (mod p)
# =====================================================================
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

# Арифметика точек на кривой secp256k1 (в аффинных координатах)
def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return None  # Точка в бесконечности

    if x1 == x2:
        # Удвоение точки: s = (3 * x1^2) / (2 * y1) mod P
        s = (3 * x1 * x1 * pow(2 * y1, -1, P)) % P
    else:
        # Сложение разных точек: s = (y2 - y1) / (x2 - x1) mod P
        s = ((y2 - y1) * pow(x2 - x1, -1, P)) % P

    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, point):
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

# =====================================================================
# 2. Алгоритм кенгуру Полларда (Pollard's Kangaroo / Lambda Method)
# с использованием Distinguished Points (особых точек)
# =====================================================================
def pollard_kangaroo(target_pubkey, a, b):
    """
    Ищет закрытый ключ k в известном диапазоне [a, b],
    такой что k * G = target_pubkey.
    """
    range_width = b - a
    # Оптимальный средний размер прыжка ~ sqrt(b - a) / 2
    # Выбираем количество размеров прыжков (степени двойки: 2^0, 2^1, ..., 2^(m-1))
    import math
    mean_jump = max(1, int(math.isqrt(range_width)) // 2)
    num_jumps = max(8, int(math.log2(mean_jump)) + 2)

    # Таблица размеров прыжков s_i и предвычисленных точек s_i * G
    jumps_scalar = [1 << i for i in range(num_jumps)]
    jumps_point = [scalar_mult(s, G) for s in jumps_scalar]

    # Маска для "особых точек" (Distinguished Points - DP):
    # Сохраняем в таблицу только те точки, у которых младшие dp_bits бит координаты X равны 0.
    # Это экономит память и ускоряет проверку пересечения путей.
    dp_bits = max(0, int(math.log2(mean_jump)) - 4)
    dp_mask = (1 << dp_bits) - 1

    print(f"[*] Диапазон поиска: [{ hex(a) }, { hex(b) }] (ширина: 2^{int(math.log2(range_width))} ключей)")
    print(f"[*] Ожидаемая сложность: ~ {int(2 * math.isqrt(range_width)):,} операций (вместо {range_width:,} при полном переборе)")
    print(f"[*] Критерий особой точки (DP): младшие {dp_bits} бит X равны 0\n")

    # Словари для хранения особых точек (Distinguished Points):
    # X-координата -> пройденная дистанция
    tame_dp = {}  # Ручной кенгуру (знаем точный скаляр от 0)
    wild_dp = {}  # Дикий кенгуру (знаем смещение относительно неизвестного ключа k)

    # 1. Стартовая позиция "Ручного кенгуру" (Tame): середина диапазона (a + b) // 2
    tame_dist = (a + b) // 2
    tame_point = scalar_mult(tame_dist, G)

    # 2. Стартовая позиция "Дикого кенгуру" (Wild): сам целевой публичный ключ K = k * G
    wild_dist = 0
    wild_point = target_pubkey

    total_steps = 0
    start_time = time.time()

    while True:
        # --- Шаг Ручного кенгуру (Tame) ---
        if (tame_point[0] & dp_mask) == 0:
            tame_dp[tame_point[0]] = tame_dist
            if tame_point[0] in wild_dp:
                # ПЕРЕСЕЧЕНИЕ ПУТЕЙ НАЙДЕНО!
                # tame_dist * G == (k + wild_dist) * G  =>  k = tame_dist - wild_dp[x]
                found_k = (tame_dist - wild_dp[tame_point[0]]) % N
                elapsed = time.time() - start_time
                return found_k, total_steps, elapsed

        jump_idx_t = tame_point[0] % num_jumps
        tame_dist += jumps_scalar[jump_idx_t]
        tame_point = point_add(tame_point, jumps_point[jump_idx_t])
        total_steps += 1

        # --- Шаг Дикого кенгуру (Wild) ---
        if (wild_point[0] & dp_mask) == 0:
            wild_dp[wild_point[0]] = wild_dist
            if wild_point[0] in tame_dp:
                # ПЕРЕСЕЧЕНИЕ ПУТЕЙ НАЙДЕНО!
                found_k = (tame_dp[wild_point[0]] - wild_dist) % N
                elapsed = time.time() - start_time
                return found_k, total_steps, elapsed

        jump_idx_w = wild_point[0] % num_jumps
        wild_dist += jumps_scalar[jump_idx_w]
        wild_point = point_add(wild_point, jumps_point[jump_idx_w])
        total_steps += 1


if __name__ == "__main__":
    # Пример: загадаем секретный ключ в 28-битном диапазоне [2^27, 2^28 - 1]
    # Полный перебор занял бы до 134 217 728 операций умножения/сложения.
    # Алгоритм кенгуру Полларда найдёт его примерно за ~20 000 шагов!
    a = 1 << 27
    b = (1 << 28) - 1

    secret_k = 0x0B8F3A2D  # Секретный закрытый ключ (193 935 917)
    print(f"[+] Скрытый закрытый ключ (для проверки): {hex(secret_k)} ({secret_k})")

    # Вычисляем открытый ключ K = secret_k * G
    pubkey = scalar_mult(secret_k, G)
    print(f"[+] Известный открытый ключ K:")
    print(f"    X = {hex(pubkey[0])}")
    print(f"    Y = {hex(pubkey[1])}\n")

    # Запускаем поиск закрытого ключа ТОЛЬКО по открытому ключу и диапазону [a, b]
    found_k, steps, elapsed = pollard_kangaroo(pubkey, a, b)

    print(f"[!] УСПЕХ! Закрытый ключ вычислен из открытого!")
    print(f"    Найденный ключ : {hex(found_k)} ({found_k})")
    print(f"    Совпадение     : {found_k == secret_k}")
    print(f"    Сделано шагов  : {steps:,} (ускорение в {(secret_k - a) / steps:.1f} раз относительно перебора от начала)")
    print(f"    Затрачено время: {elapsed:.3f} сек")
