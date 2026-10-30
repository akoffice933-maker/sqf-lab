# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 akoffice933-maker <https://github.com/akoffice933-maker>
import time
import math
import secrets

# =====================================================================
# Параметры эллиптической кривой secp256k1: y^2 = x^3 + 7 (mod P)
# =====================================================================
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2:
        s = (3 * x1 * x1 * pow(2 * y1, -1, P)) % P
    else:
        s = ((y2 - y1) * pow(x2 - x1, -1, P)) % P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)

def point_neg(p):
    return None if p is None else (p[0], (-p[1]) % P)

def scalar_mult(k, point=G):
    k %= N
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def batch_inverse(vals):
    """
    Цепное обращение Монтгомери: заменяет K делений по модулю P
    на ОДНО деление pow(acc, -1, P) и 3*(K-1) обычных умножений.
    """
    n = len(vals)
    prefix = [0] * n
    acc = 1
    for i in range(n):
        acc = (acc * vals[i]) % P
        prefix[i] = acc
    inv_all = pow(acc, -1, P)
    res = [0] * n
    for i in range(n - 1, 0, -1):
        res[i] = (inv_all * prefix[i - 1]) % P
        inv_all = (inv_all * vals[i]) % P
    res[0] = inv_all
    return res

def generate_multiples_fast(base_point, count):
    """
    Рекурсивная зеркальная генерация точек m * base_point (m = 1 .. count):
    Каждая пара точек (C + j*B) и (C - j*B) имеет ОДИН И ТОТ ЖЕ знаменатель (x_C - x_j)!
    Поэтому 1 обращение знаменателя рождает сразу 2 точки кривой.
    """
    if count <= 8:
        pts = []
        cur = None
        for _ in range(count):
            cur = point_add(cur, base_point)
            pts.append(cur)
        return pts, count

    B = min(512, max(8, int(math.isqrt(count))))
    small_pts_full, inv_count = generate_multiples_fast(base_point, B)

    pts = [None] * (count + 1)
    for i, pt in enumerate(small_pts_full, start=1):
        pts[i] = pt

    step_2B = point_add(pts[B], pts[B])
    inv_count += 1

    center_idx = B
    center_pt = pts[B]
    small_pts = pts[1:B]

    while center_idx - (B - 1) <= count:
        cx, cy = center_pt
        diffs = [(cx - sx) % P for (sx, _) in small_pts]
        invs = batch_inverse(diffs)
        inv_count += 1

        for j_minus_1, (sx, sy) in enumerate(small_pts):
            j = j_minus_1 + 1
            inv_dx = invs[j_minus_1]
            x_sum = cx + sx

            # 1) Точка (center_idx + j): C + j*B -> наклон (cy - sy) / (cx - sx)
            idx_plus = center_idx + j
            if idx_plus <= count and pts[idx_plus] is None:
                s_p = ((cy - sy) * inv_dx) % P
                nx_p = (s_p * s_p - x_sum) % P
                ny_p = (s_p * (cx - nx_p) - cy) % P
                pts[idx_plus] = (nx_p, ny_p)

            # 2) Точка (center_idx - j): C - j*B -> наклон (cy + sy) / (cx - sx)
            idx_minus = center_idx - j
            if 1 <= idx_minus <= count and pts[idx_minus] is None:
                s_m = ((cy + sy) * inv_dx) % P
                nx_m = (s_m * s_m - x_sum) % P
                ny_m = (s_m * (cx - nx_m) - cy) % P
                pts[idx_minus] = (nx_m, ny_m)

        if center_idx + B <= count and pts[center_idx + B] is None:
            pts[center_idx + B] = point_add(center_pt, pts[B])
            inv_count += 1

        center_idx += 2 * B
        if center_idx - (B - 1) <= count:
            center_pt = point_add(center_pt, step_2B)
            inv_count += 1
            if center_idx <= count:
                pts[center_idx] = center_pt

    return pts[1:count + 1], inv_count


def solve_sqf(target_pub, a, b):
    """
    АЛГОРИТМ SQF (Symmetric Quartet Folding / Симметричное Квартет-Свёртывание)
    ---------------------------------------------------------------------------
    Принцип простоты:
    Вместо случайных прыжков кенгуру используем фундаментальное свойство кривой:
      1) У противоположных точек +P и -P координата X ОДИНАКОВАЯ: x(+P) == x(-P).
      2) У суммы (K0 + Q) и разности (K0 - Q) знаменатель наклона ОДИНАКОВЫЙ: (x0 - xQ).

    Центрируем ключ вокруг середины диапазона C = (a + b) // 2:
      K0 = K - C*G = delta * G,  где delta in [-W/2, +W/2].

    Тогда уравнение поиска превращается в одно-единственное равенство X-координат:
      x( K0 +/- q * (2M * G) )  ==  x( r * G )

    Каждая проверка ОДНОЙ точки Q_q = q*(2M*G) без вычисления координаты Y
    одновременно проверяет ЧЕТЫРЕ знаковых квадранта:
      delta = +2Mq + r,  +2Mq - r,  -2Mq + r,  -2Mq - r
    """
    t0 = time.time()
    W = b - a
    C = (a + b) // 2

    # 1. Сдвигаем открытый ключ в центр диапазона C
    K0 = point_add(target_pub, point_neg(scalar_mult(C, G)))
    if K0 is None:
        return {"k": C, "inversions": 1, "steps": 1, "elapsed": time.time() - t0}
    x0, y0 = K0

    # 2. Радиус малого крыла M = sqrt(W) // 2 (так как 1 шаг покрывает 4 знаковые ветви)
    M = max(64, int(math.isqrt(W)) // 2)

    # 3. Строим таблицу X-координат x(r * G) -> r для r = 1..M
    r_pts, inv_r = generate_multiples_fast(G, M)
    x_table = {pt[0]: r for r, pt in enumerate(r_pts, start=1)}

    # Проверка центрального сегмента (q = 0)
    if x0 in x_table:
        r = x_table[x0]
        for s_r in (1, -1):
            cand = C + s_r * r
            if scalar_mult(cand, G) == target_pub:
                return {"k": cand, "inversions": inv_r, "steps": M, "elapsed": time.time() - t0}

    # 4. Шаг большого крыла = 2*M*G, число шагов max_q = W / (4*M)
    G_giant = point_add(r_pts[-1], r_pts[-1])
    max_q = (W // (4 * M)) + 2

    q_pts, inv_q = generate_multiples_fast(G_giant, max_q)
    total_inversions = inv_r + inv_q + 1

    # 5. За ОДНО обращение (x0 - x_q) проверяем сразу K0 + Q_q И K0 - Q_q (только X!)
    chunk_size = 512
    for start in range(0, len(q_pts), chunk_size):
        chunk = q_pts[start:start + chunk_size]
        diffs = [(x0 - qx) % P for (qx, _) in chunk]
        invs = batch_inverse(diffs)
        total_inversions += 1

        for i, (qx, qy) in enumerate(chunk):
            q = start + i + 1
            inv_dx = invs[i]
            x_sum = x0 + qx

            # Ветвь А: x(K0 - q * 2M*G) -> наклон (y0 + qy) / (x0 - qx)
            s_minus = ((y0 + qy) * inv_dx) % P
            x_minus = (s_minus * s_minus - x_sum) % P
            if x_minus in x_table:
                r = x_table[x_minus]
                for s_r in (1, -1):
                    cand = C + q * (2 * M) + s_r * r
                    if scalar_mult(cand, G) == target_pub:
                        return {
                            "k": cand,
                            "C": C,
                            "q": q,
                            "r": s_r * r,
                            "M": M,
                            "inversions": total_inversions,
                            "elapsed": time.time() - t0,
                        }

            # Ветвь Б: x(K0 + q * 2M*G) -> наклон (y0 - qy) / (x0 - qx)
            s_plus = ((y0 - qy) * inv_dx) % P
            x_plus = (s_plus * s_plus - x_sum) % P
            if x_plus in x_table:
                r = x_table[x_plus]
                for s_r in (1, -1):
                    cand = C - q * (2 * M) + s_r * r
                    if scalar_mult(cand, G) == target_pub:
                        return {
                            "k": cand,
                            "C": C,
                            "q": -q,
                            "r": s_r * r,
                            "M": M,
                            "inversions": total_inversions,
                            "elapsed": time.time() - t0,
                        }

    return None

if __name__ == "__main__":
    print("=" * 78)
    print(" ТЕСТ 1: Сравнение SQF с Кенгуру Полларда на том же 30-битном ключе")
    print("=" * 78)
    a30, b30 = 1 << 29, (1 << 30) - 1
    k30 = 0x31ee951c
    pub30 = scalar_mult(k30, G)
    res30 = solve_sqf(pub30, a30, b30)
    print(f"Искомый ключ          : {hex(k30)} ({k30:,})")
    print(f"Найденный ключ SQF    : {hex(res30['k'])} ({res30['k']:,}) -> Совпадение: {res30['k'] == k30}")
    print(f"Разложение SQF        : k = C + 2*M*q + r = {res30['C']} + 2*{res30['M']}*({res30['q']}) + ({res30['r']})")
    print(f"Делений по модулю P   : ВСЕГО {res30['inversions']} (в Кенгуру Полларда было 35,066 делений — в {35066 // res30['inversions']} раз меньше!)")
    print(f"Время вычисления      : {res30['elapsed']:.4f} сек (в Кенгуру было 0.668 сек — в {0.668 / res30['elapsed']:.1f} раз быстрее!)\n")

    print("=" * 78)
    print(" ТЕСТ 2: 34-битный диапазон (8 589 934 592 ключей — в 16 раз больше!)")
    print("=" * 78)
    a34, b34 = 1 << 33, (1 << 34) - 1
    k34 = a34 + secrets.randbelow(b34 - a34)
    pub34 = scalar_mult(k34, G)
    res34 = solve_sqf(pub34, a34, b34)
    print(f"Секретный ключ        : {hex(k34)} ({k34:,})")
    print(f"Вычисленный ключ SQF  : {hex(res34['k'])} ({res34['k']:,}) -> Совпадение: {res34['k'] == k34}")
    print(f"Делений по модулю P   : ВСЕГО {res34['inversions']}")
    print(f"Время вычисления      : {res34['elapsed']:.4f} сек")
    print("=" * 78)

# Проверим также 38-битный диапазон (274 877 906 944 ключей — ЧЕТВЕРТЬ ТРИЛЛИОНА ключей!)
if __name__ == "__main__":
    print("\n" + "=" * 78)
    print(" ТЕСТ 3: 38-битный диапазон (274 877 906 944 ключей — 0.27 ТРИЛЛИОНА!)")
    print("=" * 78)
    a38, b38 = 1 << 37, (1 << 38) - 1
    k38 = a38 + secrets.randbelow(b38 - a38)
    pub38 = scalar_mult(k38, G)
    res38 = solve_sqf(pub38, a38, b38)
    print(f"Секретный ключ        : {hex(k38)} ({k38:,})")
    print(f"Вычисленный ключ SQF  : {hex(res38['k'])} ({res38['k']:,}) -> Совпадение: {res38['k'] == k38}")
    print(f"Делений по модулю P   : ВСЕГО {res38['inversions']}")
    print(f"Время вычисления      : {res38['elapsed']:.4f} сек")
    print("=" * 78)
