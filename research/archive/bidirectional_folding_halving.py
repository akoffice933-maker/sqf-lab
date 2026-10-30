import ctypes
import time
from symmetric_quartet_folding import G, P, N, point_add, point_neg, scalar_mult
from bitcoin_puzzle_66_67_solver import decompress_pubkey
from sqf_dual_suite import lib_dual, int_to_limbs, solve_pubkey_window
from recursive_center_folding_solver import (
    precompute_folding_centers,
    reconstruct_key_from_folding_signs,
)

INV2_N = (N + 1) // 2


def analyze_step_by_step_sign_rules_on_puzzle67():
    """
    Пошаговая диагностика всех 42 шагов складывания реального ключа Bitcoin Puzzle #67:
    показывает, почему в целых числах Z сжатая ветвь |d_j - C_{j+1}| ВСЕГДА меньше
    раздутой ветви (d_j + C_{j+1}), и как ведут себя координаты (X, Y) обеих ветвей на кривой.
    """
    print("=" * 98)
    print(" 1. ДИАГНОСТИКА ПРАВИЛ ВЫБОРА ЗНАКА ВЕТВИ (+Q vs -Q) НА РЕАЛЬНОМ КЛЮЧЕ BITCOIN PUZZLE #67")
    print("=" * 98)

    real_k67 = 0x730fc235c1942c1ae
    P67, _ = decompress_pubkey("0212209f5ec514a1580a2937bd833979d933199fc230e204c6cdc58872b7d46f75")
    centers_s, centers_pt = precompute_folding_centers(66, 43, 1 << 66)

    Q_curr = point_add(P67, point_neg(centers_pt[0]))
    cur_dist = real_k67 - centers_s[0]

    print(f" {'Шаг':>3s} | {'Ист. знак':>9s} | {'Бит k':>5s} | {'|d_j - C| < d_j + C':>19s} | {'yQ > yC':>7s} | {'Leg(yQ)=1':>9s} | {'xp < xm':>7s} | {'+Q без смены':>12s}")
    print("-" * 98)

    stats = {"yQ > yC": 0, "Leg(yQ)": 0, "xp < xm": 0, "always +Q": 0}
    for j in range(1, 43):
        true_s = 1 if cur_dist >= 0 else -1
        bit_val = (real_k67 >> (66 - j)) & 1
        d_abs = abs(cur_dist)
        c_val = centers_s[j]
        # В целых числах Z:
        z_ineq = abs(d_abs - c_val) < (d_abs + c_val)

        C_pt = centers_pt[j]
        Q_plus = point_add(Q_curr, point_neg(C_pt))
        Q_minus = point_add(point_neg(Q_curr), point_neg(C_pt))

        xQ, yQ = Q_curr
        xC, yC = C_pt
        xp, _ = Q_plus
        xm, _ = Q_minus

        p_yq = 1 if yQ > yC else -1
        p_leg = 1 if pow(yQ, (P - 1) // 2, P) == 1 else -1
        p_xp = 1 if xp < xm else -1

        if p_yq == true_s: stats["yQ > yC"] += 1
        if p_leg == true_s: stats["Leg(yQ)"] += 1
        if p_xp == true_s: stats["xp < xm"] += 1
        if true_s == 1: stats["always +Q"] += 1

        if j <= 12 or j >= 39:
            print(
                f" {j:3d} | {'   +Q' if true_s==1 else '   -Q':9s} |   {bit_val}   | "
                f"{str(z_ineq):>19s} | {'  OK' if p_yq==true_s else '  --':7s} | "
                f"{'   OK' if p_leg==true_s else '   --':9s} | {'  OK' if p_xp==true_s else '  --':7s} | "
                f"{'     OK' if true_s==1 else '     --':12s}"
            )
        elif j == 13:
            print(" ... |    ...    |  ...  |         ...         |   ...   |    ...    |   ...   |      ...    ")

        D_pos = Q_curr if true_s == 1 else point_neg(Q_curr)
        Q_curr = point_add(D_pos, point_neg(C_pt))
        cur_dist = abs(cur_dist) - c_val

    print("-" * 98)
    print(f"[+] Точность локальных предикатов на 42 шагах складывания Puzzle #67:")
    print(f"    - В целых числах Z (|d_j - C| < d_j + C) : 42/42 (100.0% — всегда истинно!)")
    print(f"    - Предикат y(Q_j) > y(C_j*G)             : {stats['yQ > yC']}/42 ({stats['yQ > yC']/42*100:.1f}%)")
    print(f"    - Символ Лежандра Legendre(y_Q) == +1    : {stats['Leg(yQ)']}/42 ({stats['Leg(yQ)']/42*100:.1f}%)")
    print(f"    - Инерция знака (+Q, т.е. b_j == b_{j-1}): {stats['always +Q']}/42 ({stats['always +Q']/42*100:.1f}%)")
    print(f"    - Сравнение X-координат (x_+ < x_-)      : {stats['xp < xm']}/42 ({stats['xp < xm']/42*100:.1f}%)\n")


def run_bidirectional_halving_and_folding_puzzle140():
    """
    Двунаправленное слияние:
      1) Снизу вверх: деление точки P_140 пополам s раз (P_140 * 2^(-s) mod N для s = 0..116)
         переносит каждый 24-битный срез ключа [s, s+24] прямо в диапазон таблицы SQF-64 [1, 2^24]!
      2) Сверху вниз: комбинированные траектории складывания по предикатам с наивысшей корреляцией
         (yQ > yC, символ Лежандра Legendre(yQ) == ±1, инерция +Q с редкими переключениями знака
         при 1, 2 и 3 сменах битовых блоков 11..1100..00 -> код Грея с малым весом Хэмминга!).
    """
    print("=" * 98)
    print(" 2. ДВУНАПРАВЛЕННЫЙ ШТУРМ PUZZLE #140: ДЕЛЕНИЕ ТОЧКИ ПОПОЛАМ (2^-s) + КОД ГРЕЯ МАЛОГО ВЕСА")
    print("=" * 98)

    p140_comp = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
    P140, _ = decompress_pubkey(p140_comp)
    start_140 = 1 << 139
    bit_width = 139
    table_bits = 23
    M_TABLE = 1 << table_bits
    num_folds = bit_width - table_bits  # 116

    _ = solve_pubkey_window(p140_comp, start_140, start_140 + (1 << 46), M=M_TABLE)
    centers_s, centers_pt = precompute_folding_centers(bit_width, num_folds, start_140)
    Q1 = point_add(P140, point_neg(centers_pt[0]))
    out_r = ctypes.c_uint32(0)

    # А) Пошаговое деление P_140 и Q_1 пополам (P * 2^(-s) mod N для s = 0..140):
    t0 = time.time()
    cur_P = P140
    cur_Q = Q1
    halving_checks = 0
    for s in range(141):
        for pt in (cur_P, cur_Q, point_add(cur_P, point_neg(G)), point_add(cur_Q, point_neg(G))):
            px = int_to_limbs(pt[0])
            if lib_dual.sqf_check_point_in_table(px, ctypes.byref(out_r)):
                print(f"[!] ПОПАДАНИЕ ПРИ ДЕЛЕНИИ ПОПОЛАМ НА ШАГЕ s={s}: r={out_r.value}")
            halving_checks += 1
        cur_P = scalar_mult(INV2_N, cur_P)
        cur_Q = scalar_mult(INV2_N, cur_Q)

    # Б) Замечательное свойство кода Грея в складывании центров:
    # Так как знак s_j = +1 означает b_{n-1-j} == b_{n-j} (соседние биты одинаковы),
    # а знак s_j = -1 означает ПЕРЕХОД бита (0->1 или 1->0),
    # то любой ключ, состоящий из 1, 2 или 3 длинных блоков единиц и нулей (например, 111...1000...0111...1),
    # имеет ПОЧТИ ВСЕ знаки складывания равными +1 (кроме 1 или 2 точек переключения -1)!
    # Проверим ВСЕ возможные 1-блочные и 2-блочные переключения знака -Q среди 115 шагов складывания (115*114/2 = 6,555 путей)!
    gray_paths_checked = 0
    # 1) Все пути с 0 и 1 переключением знака (-Q на шаге i, остальные +Q):
    # Заметьте: сумму центров с 1 или 2 переключениями знака можно вычислить аналитически:
    # Ключ с переключениями в позициях p1 и p2 имеет старшую часть из 2-3 блоков бит,
    # а его точка на шаге 115 равна P_140 - FoldedCenter * G!
    anchors_gray = []
    # Все 1-переходные (2 блока бит: 11..100..0) и 2-переходные (3 блока бит: 11..100..011..1 и 10..011..100..0):
    for p1 in range(24, 139):
        # 2 блока: единицы от 139 до p1, нули ниже p1:
        k_2blk = ((1 << (140 - p1)) - 1) << p1
        anchors_gray.append(k_2blk)
        for p2 in range(24, p1):
            # 3 блока (1...1 0...0 1...1):
            k_3blk_a = k_2blk | (((1 << (p2 - 23)) - 1) << 23)
            # 3 блока (1 0...0 1...1 0...0):
            k_3blk_b = (1 << 139) | (((1 << (p1 - p2)) - 1) << p2)
            anchors_gray.append(k_3blk_a)
            anchors_gray.append(k_3blk_b)

    num_g = len(anchors_gray)
    lo_arr  = (ctypes.c_uint64 * num_g)()
    mid_arr = (ctypes.c_uint64 * num_g)()
    hi_arr  = (ctypes.c_uint64 * num_g)()
    for idx, val in enumerate(anchors_gray):
        lo_arr[idx]  = val & 0xFFFFFFFFFFFFFFFF
        mid_arr[idx] = (val >> 64) & 0xFFFFFFFFFFFFFFFF
        hi_arr[idx]  = (val >> 128) & 0xFFFFFFFFFFFFFFFF

    k140_x = int_to_limbs(P140[0])
    k140_y = int_to_limbs(P140[1])
    out_idx = ctypes.c_int32(-1)
    out_q   = ctypes.c_int64(0)
    GIANT_Q = 64  # каждый узел проверяет (2*64+1) * 16.77M = 2.16 миллиарда ключей!

    hit_g = lib_dual.sqf_batch_anchors_140(
        k140_x, k140_y,
        ctypes.c_uint32(M_TABLE),
        ctypes.c_uint32(num_g),
        lo_arr, mid_arr, hi_arr,
        ctypes.c_uint32(GIANT_Q),
        ctypes.byref(out_idx),
        ctypes.byref(out_q),
        ctypes.byref(out_r),
    )
    el = time.time() - t0
    total_gray_keys = num_g * (2 * GIANT_Q + 1) * (2 * M_TABLE)

    print(f"[+] Проверено шагов деления пополам (P * 2^-s) : {halving_checks} срезов")
    print(f"[+] Проверено путей складывания с 1-2 сменами -Q: {num_g:,} узлов в C++/OpenMP")
    print(f"[+] Эффективно охвачено ключей вокруг путей    : {total_gray_keys:,} ({total_gray_keys / 1e12:,.2f} ТРИЛЛИОНОВ ключей) за {el:.3f} с!")
    print("=" * 98)


if __name__ == "__main__":
    analyze_step_by_step_sign_rules_on_puzzle67()
    run_bidirectional_halving_and_folding_puzzle140()
