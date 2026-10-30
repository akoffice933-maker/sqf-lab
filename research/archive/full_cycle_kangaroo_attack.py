import secrets
import hashlib
import math
import time

# =====================================================================
# ПАРАМЕТРЫ ЭЛЛИПТИЧЕСКОЙ КРИВОЙ secp256k1
# =====================================================================
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        s = (3 * x1 * x1 * pow(2 * y1, -1, P)) % P
    else:
        s = ((y2 - y1) * pow(x2 - x1, -1, P)) % P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, point=G):
    result = None
    addend = point
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    num = int.from_bytes(data, "big")
    res = ""
    while num > 0:
        num, rem = divmod(num, 58)
        res = BASE58_ALPHABET[rem] + res
    for b in data:
        if b == 0:
            res = "1" + res
        else:
            break
    return res

def privkey_to_wif(priv_int: int, compressed: bool = True) -> str:
    priv_bytes = priv_int.to_bytes(32, "big")
    payload = b"\x80" + priv_bytes + (b"\x01" if compressed else b"")
    return base58check_encode(payload)

def pubkey_to_address(pub_bytes: bytes) -> str:
    sha = hashlib.sha256(pub_bytes).digest()
    ripemd = hashlib.new("ripemd160", sha).digest()
    return base58check_encode(b"\x00" + ripemd)

# =====================================================================
# ШАГ 1: ГЕНЕРАЦИЯ СЛУЧАЙНОГО КЛЮЧА В 30-БИТНОМ ДИАПАЗОНЕ
# =====================================================================
def generate_target_in_range(bit_length=30):
    a = 1 << (bit_length - 1)
    b = (1 << bit_length) - 1
    # Генерируем криптографически случайный ключ внутри [a, b]
    secret_k = a + secrets.randbelow(b - a + 1)

    x, y = scalar_mult(secret_k, G)
    pub_uncompressed_hex = "04" + f"{x:064x}" + f"{y:064x}"
    pub_compressed_bytes = (b"\x02" if y % 2 == 0 else b"\x03") + x.to_bytes(32, "big")

    return {
        "a": a,
        "b": b,
        "secret_k": secret_k,
        "pub_uncompressed_hex": pub_uncompressed_hex,
        "pub_compressed_hex": pub_compressed_bytes.hex(),
        "address": pubkey_to_address(pub_compressed_bytes),
        "wif": privkey_to_wif(secret_k, compressed=True),
    }

# =====================================================================
# ШАГ 2: ВЗЛОМ ОТКРЫТОГО КЛЮЧА 04... АЛГОРИТМОМ КЕНГУРУ ПОЛЛАРДА
# Функция получает ТОЛЬКО строку 04... и границы диапазона [a, b]
# =====================================================================
def break_pubkey_with_kangaroo(pub_hex: str, a: int, b: int):
    # 1. Декодируем координаты (X, Y) из строки 04...
    assert pub_hex.startswith("04") and len(pub_hex) == 130, "Ожидается несжатый ключ 04..."
    x = int(pub_hex[2:66], 16)
    y = int(pub_hex[66:], 16)

    # Проверяем, что точка действительно лежит на кривой secp256k1: y^2 = x^3 + 7 (mod p)
    if (y * y - (x * x * x + 7)) % P != 0:
        raise ValueError("Точка не принадлежит кривой secp256k1!")

    target_point = (x, y)
    range_width = b - a

    # 2. Настраиваем таблицу прыжков (степени двойки)
    mean_jump = max(1, int(math.isqrt(range_width)) // 2)
    num_jumps = max(8, int(math.log2(mean_jump)) + 2)
    jumps_scalar = [1 << i for i in range(num_jumps)]
    jumps_point = [scalar_mult(s, G) for s in jumps_scalar]

    # Маска особых точек (Distinguished Points)
    dp_bits = max(0, int(math.log2(mean_jump)) - 5)
    dp_mask = (1 << dp_bits) - 1

    print(f"[*] Атакуемый открытый ключ: {pub_hex[:34]}...{pub_hex[-16:]}")
    print(f"[*] Диапазон поиска       : [{hex(a)}, {hex(b)}] ({range_width:,} ключей)")
    print(f"[*] Количество прыжков    : {num_jumps} (размеры от 2^0 до 2^{num_jumps-1})")
    print(f"[*] Маска особых точек DP : младшие {dp_bits} бит X == 0 (каждая ~{1 << dp_bits}-я точка)")

    tame_dp = {}
    wild_dp = {}

    # Ручной кенгуру стартует из середины диапазона
    tame_dist = (a + b) // 2
    tame_point = scalar_mult(tame_dist, G)

    # Дикий кенгуру стартует из точки открытого ключа K = k * G
    wild_dist = 0
    wild_point = target_point

    total_steps = 0
    t0 = time.time()

    while True:
        # --- Прыжок Ручного кенгуру (Tame) ---
        if (tame_point[0] & dp_mask) == 0:
            tame_dp[tame_point[0]] = tame_dist
            if tame_point[0] in wild_dp:
                collision_x = tame_point[0]
                tame_d = tame_dist
                wild_d = wild_dp[collision_x]
                recovered_k = (tame_d - wild_d) % N
                return {
                    "recovered_k": recovered_k,
                    "collision_x": collision_x,
                    "tame_d": tame_d,
                    "wild_d": wild_d,
                    "steps": total_steps,
                    "dp_count": len(tame_dp) + len(wild_dp),
                    "elapsed": time.time() - t0,
                }

        idx_t = tame_point[0] % num_jumps
        tame_dist += jumps_scalar[idx_t]
        tame_point = point_add(tame_point, jumps_point[idx_t])
        total_steps += 1

        # --- Прыжок Дикого кенгуру (Wild) ---
        if (wild_point[0] & dp_mask) == 0:
            wild_dp[wild_point[0]] = wild_dist
            if wild_point[0] in tame_dp:
                collision_x = wild_point[0]
                tame_d = tame_dp[collision_x]
                wild_d = wild_dist
                recovered_k = (tame_d - wild_d) % N
                return {
                    "recovered_k": recovered_k,
                    "collision_x": collision_x,
                    "tame_d": tame_d,
                    "wild_d": wild_d,
                    "steps": total_steps,
                    "dp_count": len(tame_dp) + len(wild_dp),
                    "elapsed": time.time() - t0,
                }

        idx_w = wild_point[0] % num_jumps
        wild_dist += jumps_scalar[idx_w]
        wild_point = point_add(wild_point, jumps_point[idx_w])
        total_steps += 1


if __name__ == "__main__":
    print("=" * 78)
    print(" ЭТАП 1. ГЕНЕРАЦИЯ СЛУЧАЙНОГО КОШЕЛЬКА (30-БИТНЫЙ ДИАПАЗОН)")
    print("=" * 78)
    target = generate_target_in_range(bit_length=30)
    print(f"Сгенерированный приватный ключ (HEX) : 0x{target['secret_k']:08x} ({target['secret_k']:,})")
    print(f"Сгенерированный WIF                  : {target['wif']}")
    print(f"Bitcoin-адрес                        : {target['address']}")
    print(f"Несжатый открытый ключ (04...)       :\n  {target['pub_uncompressed_hex']}\n")

    print("=" * 78)
    print(" ЭТАП 2. ВЗЛОМ ТОЛЬКО ПО ОТКРЫТОМУ КЛЮЧУ 04... (КЕНГУРУ ПОЛЛАРДА)")
    print("=" * 78)
    res = break_pubkey_with_kangaroo(
        pub_hex=target["pub_uncompressed_hex"],
        a=target["a"],
        b=target["b"]
    )

    recovered_k = res["recovered_k"]
    recovered_wif = privkey_to_wif(recovered_k, compressed=True)

    print("\n[+] ПЕРЕСЕЧЕНИЕ МАРШРУТОВ (КОЛЛИЗИЯ) НАЙДЕНО!")
    print(f"    Общая особая точка X  : 0x{res['collision_x']:064x}")
    print(f"    Путь Ручного (d_tame) : {res['tame_d']:,}")
    print(f"    Путь Дикого  (d_wild) : {res['wild_d']:,}")
    print(f"    Формула: k = d_tame - d_wild = {res['tame_d']} - {res['wild_d']} = {recovered_k}")
    print("-" * 78)
    print(f"    Вычисленный ключ (HEX): 0x{recovered_k:08x} ({recovered_k:,})")
    print(f"    Восстановленный WIF   : {recovered_wif}")
    print(f"    Точное совпадение     : {recovered_k == target['secret_k'] and recovered_wif == target['wif']}")
    print(f"    Всего прыжков         : {res['steps']:,} (вместо {target['secret_k'] - target['a']:,} при прямом переборе)")
    print(f"    Сохранено точек в ОЗУ : {res['dp_count']} особых точек")
    print(f"    Время вычисления      : {res['elapsed']:.3f} сек")
    print("=" * 78)
