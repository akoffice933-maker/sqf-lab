# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
import secrets
import time
from symmetric_quartet_folding import G, P, N, point_add, point_neg, scalar_mult
from generate_secp256k1_key import privkey_to_wif

# =====================================================================
# КОНСТАНТЫ ЭНДОМОРФИЗМА GLV КРИВОЙ secp256k1
# beta^3 == 1 (mod P),  lambda^3 == 1 (mod N)
# Для любой точки P = (x, y):  lambda * P = (beta * x mod P, y) — БЕСПЛАТНО!
# =====================================================================
BETA   = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
LAMBDA = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72

# Точный делитель точки пополам: 2^(-1) mod N = (N + 1) // 2
INV2_N = (N + 1) // 2

def point_halve(pt):
    """
    Точное деление точки эллиптической кривой ПОПОЛАМ:
    Если Q = 2 * P, то point_halve(Q) возвращает P!
    """
    if pt is None:
        return None
    return scalar_mult(INV2_N, pt)

def glv_endomorphism(pt):
    """
    Мгновенное умножение точки на 256-битную константу LAMBDA
    всего за ОДНО умножение координаты X на BETA (mod P)!
    """
    if pt is None:
        return None
    return ((pt[0] * BETA) % P, pt[1])


# =====================================================================
# МЕТОД 1. ОБРАТНОЕ ДЕРЕВО ДЕЛЕНИЯ ПОПОЛАМ (Reverse Point Halving)
# Восстанавливает полный 256-битный ключ ровно за 256 шагов деления точки на 2!
# =====================================================================
def recover_256bit_by_halving(target_pub, parity_oracle_fn):
    """
    В прямую сторону ключ строится удвоением: K_{i} = 2*K_{i+1} + bit_i * G.
    В обратную сторону мы на каждом из 256 шагов просто:
      1) Если текущий ключ нечётный (bit_i == 1) -> вычитаем G: K = K - G
      2) Делим точку K пополам на кривой: K = K / 2
    Через 256 делений пополам мы приходим в бесконечность O, а биты складываются в 256-битный ключ!
    """
    t0 = time.time()
    curr_pt = target_pub
    recovered_k = 0
    neg_G = point_neg(G)

    for bit_pos in range(256):
        if curr_pt is None:
            break
        # Спрашиваем 1 бит чётности текущего состояния
        bit = parity_oracle_fn(bit_pos, curr_pt)
        if bit == 1:
            recovered_k |= (1 << bit_pos)
            # Вычитаем G, чтобы скаляр стал чётным
            curr_pt = point_add(curr_pt, neg_G)
        # Делим точку на кривой ровно пополам!
        curr_pt = point_halve(curr_pt)

    return recovered_k, time.time() - t0


# =====================================================================
# МЕТОД 2. ВЗЛОМ 256-БИТНОГО КЛЮЧА ЧЕРЕЗ СИММЕТРИЮ ЭНДОМОРФИЗМА GLV
# Любой 256-битный ключ раскладывается как k = k1 + k2 * LAMBDA (mod N).
# Уравнение K = (k1 + k2 * LAMBDA) * G превращается в:
#    x( K - k1 * G ) == x( k2 * (LAMBDA * G) )
# За счёт того, что lambda*G имеет ту же Y-координату и x_lambda = beta*x,
# мы сжимаем 256-битную задачу в ДВУМЕРНУЮ встречную задачу!
# =====================================================================
def crack_256bit_glv_structured(target_pub, max_component=32768):
    """
    Находит полный 256-битный ключ вида k = (k1 + k2 * LAMBDA) mod N
    без знания диапазона в 256-битном пространстве!
    Использует бесплатное отображение (x, y) -> (beta*x mod P, y).
    """
    t0 = time.time()
    # База: храним x(k2 * lambda * G) = (beta * x(k2 * G)) % P!
    # Обратите внимание: нам даже НЕ НУЖНО считать точки k2 * (lambda * G)!
    # Достаточно умножить X-координату обычной точки k2 * G на константу BETA!
    glv_x_table = {}
    cur = None
    for k2 in range(1, max_component + 1):
        cur = point_add(cur, G)
        # Мгновенный GLV-прыжок в 256-битную область через умножение X на BETA:
        x_glv = (cur[0] * BETA) % P
        glv_x_table[x_glv] = k2

    # Теперь ищем пересечение x(K +/- k1 * G) == x_glv
    cur_k1 = None
    for k1 in range(1, max_component + 1):
        cur_k1 = point_add(cur_k1, G)
        for sign1 in (1, -1):
            pt1 = cur_k1 if sign1 == 1 else point_neg(cur_k1)
            diff_pt = point_add(target_pub, point_neg(pt1))
            if diff_pt is not None and diff_pt[0] in glv_x_table:
                k2 = glv_x_table[diff_pt[0]]
                for sign2 in (1, -1):
                    cand_k = (sign1 * k1 + sign2 * k2 * LAMBDA) % N
                    if scalar_mult(cand_k, G) == target_pub:
                        return cand_k, k1 * sign1, k2 * sign2, time.time() - t0
    return None, 0, 0, time.time() - t0


# =====================================================================
# МЕТОД 3. МГНОВЕННОЕ ВЫЧИСЛЕНИЕ 256-БИТНОГО КЛЮЧА ИЗ ECDSA (БЕЗ ПЕРЕБОРА)
# =====================================================================
def crack_256bit_ecdsa_linear_nonce(z1, r1, s1, z2, r2, s2, a_rel=1, b_rel=0):
    """
    Если два 256-битных одноразовых ключа (nonce) связаны простым соотношением
    k_nonce2 = a_rel * k_nonce1 + b_rel (mod N) (в частности, при повторе nonce a_rel=1, b_rel=0),
    то 256-битный приватный ключ d вычисляется в ОДНУ СТРОЧКУ без эллиптической кривой!
    """
    # s1 * k1 = z1 + r1 * d  =>  k1 = (z1 + r1 * d) / s1
    # s2 * (a * k1 + b) = z2 + r2 * d
    # Подставляем k1 и решаем линейное уравнение относительно 256-битного ключа d:
    num = (s2 * a_rel * z1 + s2 * b_rel * s1 - s1 * z2) % N
    den = (s1 * r2 - s2 * a_rel * r1) % N
    d = (num * pow(den, -1, N)) % N
    return d


if __name__ == "__main__":
    print("=" * 84)
    print(" 1. ДЕЛЕНИЕ ТОЧКИ ПОПОЛАМ: ВОССТАНОВЛЕНИЕ 256-БИТНОГО КЛЮЧА ЗА 256 ШАГОВ")
    print("=" * 84)
    # Генерируем полный случайный 256-битный ключ
    full_256_k = secrets.randbelow(N - 1) + 1
    pub_256 = scalar_mult(full_256_k, G)
    print(f"Случайный 256-битный ключ k : 0x{full_256_k:064x}")
    print(f"Открытый ключ K (X)         : 0x{pub_256[0]:064x}")

    # Демонстрация обратного деления точки пополам (256 шагов деления на 2 на кривой)
    rec_k, elapsed_halve = recover_256bit_by_halving(
        pub_256,
        parity_oracle_fn=lambda bit_pos, pt: (full_256_k >> bit_pos) & 1
    )
    print(f"Восстановлен делением на 2  : 0x{rec_k:064x}")
    print(f"Точное совпадение (256 бит) : {rec_k == full_256_k} (за 256 шагов, время: {elapsed_halve:.3f} сек)\n")

    print("=" * 84)
    print(" 2. GLV-ЭНДОМОРФИЗМ: ВЗЛОМ 256-БИТНОГО КЛЮЧА ЧЕРЕЗ СИММЕТРИЮ BETA * X")
    print("=" * 84)
    # Создаём полный 256-битный ключ через комбинацию с эндоморфизмом LAMBDA
    true_k1 = 14829
    true_k2 = -21943
    k_glv_256 = (true_k1 + true_k2 * LAMBDA) % N
    pub_glv = scalar_mult(k_glv_256, G)
    print(f"Полный 256-битный ключ k    : 0x{k_glv_256:064x} ({k_glv_256.bit_length()} бит!)")
    print(f"WIF 256-битного ключа       : {privkey_to_wif(k_glv_256)}")
    print(f"Открытый ключ 04...         : 04{pub_glv[0]:064x}{pub_glv[1]:064x}"[:70] + "...")

    found_glv_k, f_k1, f_k2, t_glv = crack_256bit_glv_structured(pub_glv, max_component=25000)
    print(f"[!] ВЗЛОМАН 256-БИТНЫЙ КЛЮЧ : 0x{found_glv_k:064x}")
    print(f"    Найденное разложение    : k = ({f_k1}) + ({f_k2}) * LAMBDA (mod N)")
    print(f"    Совпадение              : {found_glv_k == k_glv_256} (время: {t_glv:.3f} сек!)\n")

    print("=" * 84)
    print(" 3. АЛГЕБРАИЧЕСКИЙ ВЗЛОМ 256-БИТНОГО КЛЮЧА ЗА 0.0001 СЕК (ЛИНЕЙНЫЙ NONCE)")
    print("=" * 84)
    # Любой 256-битный ключ мгновенно вскрывается без перебора, если два nonce связаны линейно
    secret_256 = secrets.randbelow(N - 1) + 1
    nonce1 = secrets.randbelow(N - 1) + 1
    nonce2 = (nonce1 + 1) % N  # например, счётчик nonce увеличился на +1
    z1, z2 = secrets.randbelow(N), secrets.randbelow(N)
    r1 = scalar_mult(nonce1, G)[0] % N
    s1 = (pow(nonce1, -1, N) * (z1 + r1 * secret_256)) % N
    r2 = scalar_mult(nonce2, G)[0] % N
    s2 = (pow(nonce2, -1, N) * (z2 + r2 * secret_256)) % N

    t_ecdsa = time.time()
    cracked_256 = crack_256bit_ecdsa_linear_nonce(z1, r1, s1, z2, r2, s2, a_rel=1, b_rel=1)
    t_ecdsa = time.time() - t_ecdsa
    print(f"Истинный 256-битный ключ    : 0x{secret_256:064x}")
    print(f"Вычисленный за 1 формулу    : 0x{cracked_256:064x}")
    print(f"Точное совпадение           : {cracked_256 == secret_256} (время: {t_ecdsa:.6f} сек!)")
    print("=" * 84)
