from symmetric_quartet_folding import G, P, N, point_add, point_neg, scalar_mult

# Константы кривой secp256k1
INV2_N = (N + 1) // 2
BETA   = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
LAMBDA = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72

# Знаменитый открытый ключ Сатоши Накамото из Генезис-блока (который вы прислали ранее)
SATOSHI_HEX = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
K_SATOSHI = (int(SATOSHI_HEX[2:66], 16), int(SATOSHI_HEX[66:], 16))

print("=" * 86)
print(" ДОКАЗАТЕЛЬСТВО ТЕОРЕМЫ 1: ТОЧНОЕ ДЕЛЕНИЕ ТОЧКИ ПОПОЛАМ (НА КЛЮЧЕ САТОШИ 04678afd...)")
print("=" * 86)
# 1) Проверяем тождество (2 * INV2_N) mod N == 1
print(f"1. Проверка в кольце скаляров: (2 * INV2_N) mod N == {(2 * INV2_N) % N}")

# 2) Делим открытый ключ Сатоши K_SATOSHI пополам: H = INV2_N * K_SATOSHI
H_satoshi = scalar_mult(INV2_N, K_SATOSHI)
print(f"2. Половина открытого ключа Сатоши (H = K_Satoshi / 2):")
print(f"   H.x = 0x{H_satoshi[0]:064x}")
print(f"   H.y = 0x{H_satoshi[1]:064x}")
print(f"   Лежит ли H на кривой secp256k1? {(H_satoshi[1]**2 - H_satoshi[0]**3 - 7) % P == 0}")

# 3) Удваиваем половину H + H и сравниваем с исходным ключом Сатоши
reconstructed_satoshi = point_add(H_satoshi, H_satoshi)
print(f"3. Проверка H + H == K_Satoshi : {reconstructed_satoshi == K_SATOSHI} (совпадение бит в бит!)\n")


print("=" * 86)
print(" ДОКАЗАТЕЛЬСТВО ТЕОРЕМЫ 2: ПАРАДОКС ЧЁТНОСТИ (k и k + N ДАЮТ ОДНУ ТОЧКУ (X, Y))")
print("=" * 86)
# Возьмём конкретный ЧЁТНЫЙ 256-битный ключ k_even
k_even = 0x64a8f2c19b3e7004d12a88c055e91b3477a109c288f1e4d033b2a19088c4e210
# А теперь прибавим к нему порядок кривой N: k_odd = k_even + N
k_odd = k_even + N

print(f"1. Чётность k_even      : k_even mod 2 = {k_even % 2} (ЧЁТНОЕ число)")
print(f"2. Чётность k_odd=k+N   : k_odd  mod 2 = {k_odd % 2}  (НЕЧЁТНОЕ число, т.к. N нечётное!)")

# Вычислим точки на кривой без предварительного взятия mod N (через прямое двоичное умножение)
def raw_scalar_mult_no_mod(k_raw, pt):
    res = None
    addend = pt
    while k_raw > 0:
        if k_raw & 1:
            res = point_add(res, addend)
        addend = point_add(addend, addend)
        k_raw >>= 1
    return res

P_from_even = raw_scalar_mult_no_mod(k_even, G)
P_from_odd  = raw_scalar_mult_no_mod(k_odd, G)

print(f"3. Точка от чётного  k  : X = 0x{P_from_even[0]:064x}")
print(f"4. Точка от нечётного k+N: X = 0x{P_from_odd[0]:064x}")
print(f"5. Тождественное равенство точек (P_even == P_odd): {P_from_even == P_from_odd}")
print("   ВЫВОД: Координаты (X, Y) физически не содержат бита чётности скаляра,\n"
      "   потому что одна и та же точка одновременно порождается и чётным k, и нечётным k+N!\n")


print("=" * 86)
print(" ДОКАЗАТЕЛЬСТВО ТЕОРЕМЫ 3: 256 ДЕЛЕНИЙ ПОПОЛАМ ПРИВОДЯТ ЛЮБОЙ КЛЮЧ РОВНО В НОЛЬ (O)")
print("=" * 86)
curr = P_from_even
steps_taken = 0
for i in range(256):
    bit = (k_even >> i) & 1
    if bit == 1:
        curr = point_add(curr, point_neg(G))
    curr = scalar_mult(INV2_N, curr)
    steps_taken += 1

print(f"После {steps_taken} шагов вида K_{{i+1}} = (K_i - b_i*G) / 2:")
print(f"Финальная точка K_256 == {curr} (Точка в бесконечности / Ноль группы!)\n")


print("=" * 86)
print(" ДОКАЗАТЕЛЬСТВО ТЕОРЕМЫ 4: КУБИЧЕСКАЯ СИММЕТРИЯ (BETA^3 == 1 mod P, LAMBDA^3 == 1 mod N)")
print("=" * 86)
print(f"1. Проверка BETA^3 mod P == 1                 : {pow(BETA, 3, P) == 1}")
print(f"2. Проверка LAMBDA^3 mod N == 1               : {pow(LAMBDA, 3, N) == 1}")
print(f"3. Проверка 1 + LAMBDA + LAMBDA^2 mod N == 0  : {(1 + LAMBDA + LAMBDA**2) % N == 0}")

# Применим быстрое умножение X * BETA к открытому ключу Сатоши K_SATOSHI:
fast_glv_satoshi = ((K_SATOSHI[0] * BETA) % P, K_SATOSHI[1])
# И сравним с полным 256-битным умножением точки Сатоши на скаляр LAMBDA:
full_mult_satoshi = scalar_mult(LAMBDA, K_SATOSHI)

print(f"4. 1 умножение (BETA * X_Satoshi mod P, Y)    : X = 0x{fast_glv_satoshi[0]:064x}")
print(f"5. 256-битное умножение LAMBDA * K_Satoshi    : X = 0x{full_mult_satoshi[0]:064x}")
print(f"6. Полное совпадение (fast_glv == LAMBDA * K) : {fast_glv_satoshi == full_mult_satoshi}")

# И проверим фундаментальное тождество: K + LAMBDA*K + LAMBDA^2*K == O (ноль!) для ключа Сатоши:
fast_glv2_satoshi = ((fast_glv_satoshi[0] * BETA) % P, fast_glv_satoshi[1])
sum_three = point_add(point_add(K_SATOSHI, fast_glv_satoshi), fast_glv2_satoshi)
print(f"7. Сумма трёх симметричных точек K + phi(K) + phi^2(K) == {sum_three} (НОЛЬ ГРУППЫ!)")
print("=" * 86)
