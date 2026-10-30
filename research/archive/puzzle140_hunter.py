import os
import json
import time
import secrets
from symmetric_quartet_folding import G, P, N, scalar_mult
from generate_secp256k1_key import privkey_to_wif, pubkey_to_p2pkh_address
from bitcoin_puzzle_66_67_solver import decompress_pubkey
from sqf_dual_suite import solve_pubkey_window

# =====================================================================
# ОФИЦИАЛЬНЫЕ ПАРАМЕТРЫ НЕРЕШЁННОГО BITCOIN PUZZLE #140 (14.0 BTC)
# =====================================================================
P140_PUBKEY_COMP = "031f6a332d3c5c4f2de2378c012f429cd109ba07d69690c6c701b6bb87860d6640"
P140_ADDRESS     = "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"
P140_START       = 0x80000000000000000000000000000000000
P140_END         = 0xfffffffffffffffffffffffffffffffffff
P140_WIDTH       = P140_END - P140_START + 1

PROGRESS_FILE    = "puzzle140_progress.json"
FOUND_FILE       = "FOUND_PUZZLE_140.txt"

def load_progress():
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, "r") as f:
            return json.load(f)
    return {
        "puzzle": 140,
        "address": P140_ADDRESS,
        "pubkey": P140_PUBKEY_COMP,
        "windows_scanned": 0,
        "total_keys_covered": 0,
        "history": []
    }

def save_progress(state):
    with open(PROGRESS_FILE, "w") as f:
        json.dump(state, f, indent=2)

def build_strategic_windows(window_size: int):
    """
    Формирует приоритетные окна внутри 140-битного диапазона:
    1) Самое начало диапазона (0.00% — по аналогии с Puzzle #69, найденным в начале диапазона)
    2) Ровно середина диапазона (50.00%)
    3) Самый конец диапазона (100.00%)
    4) Позиция 0.72% (точная относительная точка, где лежал ключ Puzzle #69)
    5) Случайные непересекающиеся окна внутри 140-битного пространства
    """
    pos_072 = P140_START + (P140_WIDTH * 72) // 10000
    mid     = (P140_START + P140_END) // 2

    windows = [
        ("Начало диапазона (0.00%)", P140_START, P140_START + window_size - 1),
        ("Точка 0.72% (зона #69)",   pos_072,    pos_072 + window_size - 1),
        ("Центр диапазона (50.0%)",  mid,        mid + window_size - 1),
        ("Конец диапазона (100%)",   P140_END - window_size + 1, P140_END),
    ]
    # Добавим 2 случайных окна в глубине 140-битного пространства
    for i in range(1, 3):
        r_start = P140_START + secrets.randbelow(P140_WIDTH - window_size)
        pct = float(r_start - P140_START) / float(P140_WIDTH) * 100.0
        windows.append((f"Случайный сектор #{i} ({pct:.2f}%)", r_start, r_start + window_size - 1))
    return windows

def run_puzzle140_hunter(window_bits: int = 50, table_M: int = 4_194_304):
    (tx, ty), valid = decompress_pubkey(P140_PUBKEY_COMP)
    addr_check = pubkey_to_p2pkh_address(bytes.fromhex(P140_PUBKEY_COMP))
    assert valid and addr_check == P140_ADDRESS, "Ошибка верификации ключа Puzzle #140!"

    print("=" * 90)
    print(" ОХОТНИК НА BITCOIN PUZZLE #140 (SQF-64 NATIVE C++/OpenMP)")
    print("=" * 90)
    print(f" Целевой адрес     : {P140_ADDRESS} (Награда: 14.0 BTC)")
    print(f" Сжатый ключ 03... : {P140_PUBKEY_COMP}")
    print(f" Полный диапазон   : {hex(P140_START)} .. {hex(P140_END)} (2^139 ключей)")
    print(f" Размер 1 окна     : 2^{window_bits} = {1 << window_bits:,} ключей | Таблица M = {table_M:,} точек")
    print("=" * 90)

    state = load_progress()
    window_size = 1 << window_bits
    windows = build_strategic_windows(window_size)

    t_start_all = time.time()

    for idx, (label, w_a, w_b) in enumerate(windows, start=1):
        res = solve_pubkey_window(P140_PUBKEY_COMP, w_a, w_b, M=table_M)
        state["windows_scanned"] += 1
        state["total_keys_covered"] += window_size
        state["history"].append({
            "label": label,
            "start": hex(w_a),
            "end": hex(w_b),
            "elapsed_sec": round(res["elapsed"], 4),
            "speed_tkeys_s": round(res["tkeys_per_sec"], 2),
        })
        save_progress(state)

        print(f"[{idx}/{len(windows)}] {label:28s} | [{hex(w_a)[:16]}..{hex(w_b)[-8:]}] "
              f"| {res['elapsed']:.3f} сек | {res['tkeys_per_sec']:,.1f} Трлн кл/с | Найдено: {res['found']}")

        if res["found"]:
            k_found = res["k"]
            wif = privkey_to_wif(k_found, compressed=True)
            msg = (
                f"BITCOIN PUZZLE #140 SOLVED!\n"
                f"Address     : {P140_ADDRESS}\n"
                f"Private HEX : {hex(k_found)}\n"
                f"Private WIF : {wif}\n"
            )
            with open(FOUND_FILE, "w") as ff:
                ff.write(msg)
            print("\n" + "!" * 90)
            print(msg)
            print("!" * 90)
            return

    total_el = time.time() - t_start_all
    print("-" * 90)
    print(f"[*] Сессия завершена за {total_el:.2f} сек.")
    print(f"[*] Всего проверено ключей в Puzzle #140 : {state['total_keys_covered']:,} ({state['total_keys_covered'] / 1e15:.2f} квадриллионов ключей!)")
    print(f"[*] Чекпоинт сохранён в файл             : {PROGRESS_FILE}")
    print("=" * 90)

if __name__ == "__main__":
    run_puzzle140_hunter(window_bits=50, table_M=4_194_304)
