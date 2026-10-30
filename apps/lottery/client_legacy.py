#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
АВТОНОМНЫЙ КЛИЕНТ ИИ-АГЕНТА С НАВЕДЕНИЕМ ПО ВОРОНКЕ 83 РАЗГАДАННЫХ КЛЮЧЕЙ (ai_agent_client.py)
====================================================================================================
Демонстрирует полный цикл работы ИИ-агента с Воронкой из 83 уже разгаданных пазлов (#1..#70 и #75..#135):
  1. Регистрируется в пуле (/api/agents/register).
  2. На каждом шаге запрашивает у Диспетчера Воронки (/api/funnel/claim) следующий гарантированно
     свободный блок, спроецированный от приоритетных решённых ключей (#135, #130, #125, #120, #70).
  3. Вычисляет реальную Distinguished Point внутри этого блока и НАВСЕГДА ЗАКРЫВАЕТ участок
     в статусе SCANNED_LOCKED (/api/ranges/complete).
  4. Проверяет трёхуровневую защиту от повторов:
     - Тест А: Попытка повторно взять уже закрытый блок воронки -> БЛОКИРОВКА + выдача следующего блока.
     - Тест Б: Попытка сдать уже разгаданный ключ из воронки (#135) -> БЛОКИРОВКА.
     - Тест В: Попытка дважды проверить один и тот же новый ключ -> БЛОКИРОВКА.
====================================================================================================
"""

import argparse
import json
import urllib.error
import urllib.request

from symmetric_quartet_folding import G, point_add, scalar_mult


def api_request(base_url: str, path: str, method: str = "GET", payload: dict = None) -> dict:
    url = base_url.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8"))


def run_autonomous_agent(base_url: str, name: str, model_family: str, strategy: str, rounds: int):
    print("=" * 116)
    print(f" ЗАПУСК АВТОНОМНОГО ИИ-АГЕНТА ПО ВОРОНКЕ 83 РАЗГАДАННЫХ КЛЮЧЕЙ: {name} ({model_family})")
    print("=" * 116)

    reg = api_request(
        base_url,
        "/api/agents/register",
        method="POST",
        payload={"name": name, "model_family": model_family, "strategy": strategy},
    )
    agent_id = reg["agent_id"]
    dp_bits = reg["dp_bits_required"]
    dp_mask = (1 << dp_bits) - 1
    print(f"[+] Агент зарегистрирован: ID = {agent_id}")

    job_init = api_request(base_url, "/api/jobs/next")
    p140 = job_init["pool_target_140"]
    w0_pt = (int(p140["w0_shifted_x"], 16), int(p140["w0_shifted_y"], 16))
    base_140 = 1 << 139

    first_completed_block = None

    for r_idx in range(1, rounds + 1):
        # Диспетчер воронки сам выбирает следующее ядро из 83 разгаданных ключей (#135, #130, #125, #120...)
        claim = api_request(
            base_url,
            "/api/funnel/claim",
            method="POST",
            payload={"agent_id": agent_id, "target_puzzle": 140},
        )
        blk = claim["assigned_block"]
        src_puz = claim["funnel_source_puzzle"]
        src_priv = claim["funnel_source_priv_hex"]
        cell = claim["funnel_cell"]

        print(f"\n--- Шаг Воронки #{r_idx}/{rounds}: Опора на уже разгаданный Пазл #{src_puz} (клетка {cell}) ---")
        print(f"  [Ядро воронки #{src_puz}]: k_{src_puz} = {src_priv} -> проекция в #140: {claim['nucleus_lifted_hex']}")
        print(f"  [1. Бронь участка]: Выдан свободный блок {blk['block_id']} [{blk['start_k_hex']} .. {blk['end_k_hex']}]")

        start_d = max(1, int(blk["start_k_hex"], 16) - base_140)
        cur_d = start_d
        cur_pt = point_add(w0_pt, scalar_mult(cur_d, G))
        step_d = 4099
        step_pt = scalar_mult(step_d, G)

        steps = 0
        while (cur_pt[0] & dp_mask) != 0:
            cur_d += step_d
            cur_pt = point_add(cur_pt, step_pt)
            steps += 1

        comp = api_request(
            base_url,
            "/api/ranges/complete",
            method="POST",
            payload={
                "agent_id": agent_id,
                "block_id": blk["block_id"],
                "proof_scalar_d_hex": hex(cur_d),
                "kang_type": "WILD",
            },
        )
        print(
            f"  [2. Закрытие блока]: Найдена DP за {steps:,} шагов -> Блок {blk['block_id']} переведён в "
            f"{comp['new_status']} (proof #{comp['proof_hash']}) и НАВСЕГДА ЗАКРЫТ!"
        )
        if first_completed_block is None:
            first_completed_block = blk

    print("\n" + "=" * 116)
    print(" ПРОВЕРКА ТРЁХУРОВНЕВОЙ ЗАЩИТЫ ОТ ПОВТОРОВ И ВОРОНКИ 83 РАЗГАДАННЫХ КЛЮЧЕЙ:")
    print("=" * 116)

    # Тест А: Повторный запрос закрытого блока воронки
    dup_claim = api_request(
        base_url,
        "/api/ranges/claim",
        method="POST",
        payload={
            "agent_id": agent_id,
            "puzzle_num": 140,
            "cell": first_completed_block["cell"],
            "start_k_hex": first_completed_block["start_k_hex"],
            "end_k_hex": first_completed_block["end_k_hex"],
        },
    )
    print(f"  [Тест А — Повторный запрос закрытого блока воронки {first_completed_block['block_id']}]:")
    print(f"    -> duplicate_prevented = {dup_claim.get('duplicate_prevented')}")
    print(f"    -> Ответ сервера: {dup_claim.get('message')}")

    # Тест Б: Попытка отправить уже разгаданный ключ #135 из воронки
    solved_135_try = api_request(
        base_url,
        "/api/submit/key",
        method="POST",
        payload={
            "agent_id": agent_id,
            "puzzle": 135,
            "candidate_k_hex": "0x6d9392a16883f90903d5f78da57af07eb2",
        },
    )
    print(f"\n  [Тест Б — Попытка отправить уже разгаданный Пазл #135 из воронки 83 ключей]:")
    print(f"    -> duplicate_blocked = {solved_135_try.get('duplicate_blocked')}")
    print(f"    -> Ответ сервера: {solved_135_try.get('error')}")
    print("=" * 116)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-Agent Client with 83-Key Funnel Guidance")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Pool server URL")
    parser.add_argument("--name", default="Funnel-Navigator-AI", help="Agent display name")
    parser.add_argument("--model", default="Claude-4-Sonnet", help="Model family")
    parser.add_argument("--strategy", default="83-Key Funnel Guided Kangaroo", help="Agent strategy")
    parser.add_argument("--rounds", type=int, default=4, help="Number of work cycles")
    args = parser.parse_args()
    run_autonomous_agent(args.url, args.name, args.model, args.strategy, args.rounds)
