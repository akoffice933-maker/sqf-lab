import ctypes
import math
import secrets
import time
from symmetric_quartet_folding import G, P, N, point_add, point_neg, scalar_mult
from sqf_dual_suite import lib_dual, int_to_limbs
from recursive_center_folding_solver import (
    precompute_folding_centers,
    reconstruct_key_from_folding_signs,
)

# Регистрируем честный C++ солвер с аппаратными счётчиками операций внутри циклов
lib_dual.sqf_honest_blind_solve.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_double),
    ctypes.POINTER(ctypes.c_double),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint32),
]
lib_dual.sqf_honest_blind_solve.restype = ctypes.c_int


def test_predicates_on_10000_random_steps():
    """
    ЭКСПЕРИМЕНТ 1: Проверка локальных координатных предикатов на 10,000 случайных шагах
    (200 криптографически случайных 64-битных ключей x 50 шагов складывания на каждый).
    Стандартное отклонение на 10,000 испытаний: sigma = 0.5 / sqrt(10000) = 0.50%.
    """
    print("=" * 106)
    print(" ЭКСПЕРИМЕНТ 1: ТЕСТ КООРДИНАТНЫХ ПРЕДИКАТОВ НА 10,000 СЛУЧАЙНЫХ ШАГАХ (200 СЛУЧАЙНЫХ КЛЮЧЕЙ)")
    print("=" * 106)

    bit_width = 64
    steps_per_key = 50
    num_keys = 200
    total_steps = num_keys * steps_per_key

    centers_s, centers_pt = precompute_folding_centers(bit_width, steps_per_key + 1, 1 << 64)

    hits = {
        "y(Q_j) > y(C_j*G)": 0,
        "Legendre(y_Q) == +1": 0,
        "x(Q_+) < x(Q_-)": 0,
        "y(Q_j) чётный": 0,
        "y(Q_j) < P / 2": 0,
        "x(Q_j) > x(C_j*G)": 0,
        "Инерция +Q (b_j == b_{j-1})": 0,
    }

    t0 = time.time()
    for _ in range(num_keys):
        k_rand = (1 << 64) + secrets.randbelow(1 << 64)
        P_rand = scalar_mult(k_rand, G)
        Q_curr = point_add(P_rand, point_neg(centers_pt[0]))
        cur_dist = k_rand - centers_s[0]

        for j in range(1, steps_per_key + 1):
            true_s = 1 if cur_dist >= 0 else -1
            C_pt = centers_pt[j]
            Q_plus = point_add(Q_curr, point_neg(C_pt))
            Q_minus = point_add(point_neg(Q_curr), point_neg(C_pt))

            xQ, yQ = Q_curr
            xC, yC = C_pt
            xp, _ = Q_plus
            xm, _ = Q_minus

            if (1 if yQ > yC else -1) == true_s:
                hits["y(Q_j) > y(C_j*G)"] += 1
            if (1 if pow(yQ, (P - 1) // 2, P) == 1 else -1) == true_s:
                hits["Legendre(y_Q) == +1"] += 1
            if (1 if xp < xm else -1) == true_s:
                hits["x(Q_+) < x(Q_-)"] += 1
            if (1 if (yQ & 1) == 0 else -1) == true_s:
                hits["y(Q_j) чётный"] += 1
            if (1 if yQ < (P >> 1) else -1) == true_s:
                hits["y(Q_j) < P / 2"] += 1
            if (1 if xQ > xC else -1) == true_s:
                hits["x(Q_j) > x(C_j*G)"] += 1
            if true_s == 1:
                hits["Инерция +Q (b_j == b_{j-1})"] += 1

            D_pos = Q_curr if true_s == 1 else point_neg(Q_curr)
            Q_curr = point_add(D_pos, point_neg(C_pt))
            cur_dist = abs(cur_dist) - centers_s[j]

    el = time.time() - t0
    sigma = 0.5 / math.sqrt(total_steps) * 100.0
    print(f"[+] Проверено {total_steps:,} независимых шагов складывания за {el:.2f} с (1 sigma = {sigma:.2f}%):")
    print("-" * 106)
    print(f" {'Предикат выбора ветви (+Q vs -Q)':34s} | {'Угадано из 10,000':>18s} | {'Точность (%)':>14s} | {'Отклонение (в σ)':>18s}")
    print("-" * 106)
    for name, h in hits.items():
        pct = (h / total_steps) * 100.0
        z_score = (pct - 50.0) / sigma
        print(f" {name:34s} | {h:18,d} | {pct:13.2f}% | {z_score:+17.2f}σ")
    print("-" * 106)


def blind_solve_single_run(pub_pt, range_start: int, range_bits: int, table_bits: int):
    """
    ЧЕСТНЫЙ СЛЕПОЙ РЕШАТЕЛЬ:
    1) Получает на вход ТОЛЬКО pub_pt = (X, Y), range_start, range_bits и table_bits.
       Секретный ключ secret_k сюда НЕ передаётся вообще.
    2) Внутри C++ функции sqf_honest_blind_solve:
       - Таблица размера M = 2^table_bits строится С НУЛЯ (free + init_global_table(M)),
         время построения записывается в out_table_sec, а число точек — в out_table_ec_ops.
       - Дерево глубины D = range_bits - (table_bits + 1) обходится с инкрементом атомарного
         счётчика local_ops++ на каждом вычислении точки в цикле и останавливается при попадании.
    3) Возвращает кандидата recovered_k (для внешней сверки с secret_k) и реальные замеры.
    """
    tree_depth = range_bits - (table_bits + 1)
    centers_s, centers_pt = precompute_folding_centers(range_bits, tree_depth + 1, range_start)

    Q1 = point_add(pub_pt, point_neg(centers_pt[0]))
    q1x = int_to_limbs(Q1[0])
    q1y = int_to_limbs(Q1[1])

    cx_arr = (ctypes.c_uint64 * (4 * tree_depth))()
    cy_arr = (ctypes.c_uint64 * (4 * tree_depth))()
    for j in range(tree_depth):
        pt_x, pt_y = centers_pt[j + 1]
        for l in range(4):
            cx_arr[4 * j + l] = (pt_x >> (64 * l)) & 0xFFFFFFFFFFFFFFFF
            cy_arr[4 * j + l] = (pt_y >> (64 * l)) & 0xFFFFFFFFFFFFFFFF

    out_tbl_ops  = ctypes.c_uint64(0)
    out_srch_ops = ctypes.c_uint64(0)
    out_tbl_sec  = ctypes.c_double(0.0)
    out_srch_sec = ctypes.c_double(0.0)
    out_mask     = ctypes.c_uint64(0)
    out_r        = ctypes.c_uint32(0)

    hit = lib_dual.sqf_honest_blind_solve(
        q1x, q1y,
        ctypes.c_uint32(tree_depth),
        ctypes.c_uint32(table_bits),
        cx_arr, cy_arr,
        ctypes.byref(out_tbl_ops),
        ctypes.byref(out_srch_ops),
        ctypes.byref(out_tbl_sec),
        ctypes.byref(out_srch_sec),
        ctypes.byref(out_mask),
        ctypes.byref(out_r),
    )
    if hit != 1:
        return None, 0, 0, 0.0, 0.0

    mask_val = out_mask.value
    r_val = out_r.value
    signs = [1 if ((mask_val >> (tree_depth - 1 - b)) & 1) == 0 else -1 for b in range(tree_depth)]

    # Выбираем из двух знаков (+r_val и -r_val) тот, который даёт публичный ключ pub_pt
    recovered_k = None
    for final_s in (+1, -1):
        cand = reconstruct_key_from_folding_signs(centers_s, signs, r_val, final_s)
        if scalar_mult(cand, G) == pub_pt:
            recovered_k = cand
            break

    return (
        recovered_k,
        out_tbl_ops.value,
        out_srch_ops.value,
        out_tbl_sec.value,
        out_srch_sec.value,
    )


def test_honest_blind_benchmark():
    """
    ЭКСПЕРИМЕНТ 2 (ИСПРАВЛЕННЫЙ):
    Проверяем все 3 пункта ревью:
      1) Время построения таблицы M = 2^((n-2)//2) замеряется С НУЛЯ на каждом запуске (t_tbl).
      2) Счётчик групповых операций (srch_ops) реально инкрементируется внутри цикла C++ (local_ops++)
         с ранним выходом на уровне листьев, поэтому он меняется от запуска к запуску в зависимости
         от случайной позиции ключа k!
      3) Сверка found_k == secret_k выполняется СТРОГО СНАРУЖИ после завершения решателя.
    """
    print("\n" + "=" * 106)
    print(" ЭКСПЕРИМЕНТ 2 (ЧЕСТНЫЙ ЗАМЕР): ТАБЛИЦА С НУЛЯ + СЧЁТЧИК В ЦИКЛЕ C++ + ВНЕШНЯЯ СВЕРКА КЛЮЧА")
    print("=" * 106)
    print(
        f" {'W':5s} | {'sqrt(W)':>10s} | {'Табл. M':>10s} | {'Поиск (реал.)':>14s} | "
        f"{'Всего EC оп.':>14s} | {'Отнош. к √W':>11s} | {'t_табл':>8s} | {'t_поиск':>8s} | {'t_всего':>8s}"
    )
    print("-" * 106)

    for range_bits in (32, 34, 36, 38, 40):
        W = 1 << range_bits
        sqrt_W = math.isqrt(W)
        # Оптимальный баланс таблицы M = 2^((range_bits - 2) // 2) = 0.5 * sqrt(W)
        table_bits = (range_bits - 2) // 2

        # Проводим по 3 независимых слепых запуска со случайными ключами для каждого размера W,
        # чтобы показать реальный разброс счётчика операций и времени поиска!
        for trial in range(1, 4):
            range_start = secrets.randbits(160)
            secret_k = range_start + secrets.randbelow(W)
            pub_P = scalar_mult(secret_k, G)

            # Вызываем слепой решатель (secret_k внутрь НЕ передаётся!)
            found_k, tbl_ops, srch_ops, t_tbl, t_srch = blind_solve_single_run(
                pub_P, range_start, range_bits, table_bits
            )

            # Строгая внешняя проверка после завершения решателя:
            assert found_k == secret_k, f"Mismatch on W=2^{range_bits}, trial={trial}!"

            total_ops = tbl_ops + srch_ops
            ratio = total_ops / float(sqrt_W)
            t_tot = t_tbl + t_srch

            lbl = f"2^{range_bits}" if trial == 1 else f"  #{trial}"
            print(
                f" {lbl:5s} | {sqrt_W:10,d} | {tbl_ops:10,d} | {srch_ops:14,d} | "
                f"{total_ops:14,d} | {ratio:9.3f}√W | {t_tbl:7.4f}s | {t_srch:7.4f}s | {t_tot:7.4f}s"
            )
        print("-" * 106)


if __name__ == "__main__":
    test_predicates_on_10000_random_steps()
    test_honest_blind_benchmark()
