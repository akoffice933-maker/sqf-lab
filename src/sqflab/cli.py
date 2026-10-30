"""Command line interface: ``python -m sqflab <command>``."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from . import __version__
from .battleship import cell_bounds, cell_label, key_to_square_xy, square_xy_to_key, unsolved_ships
from .bsgs import sqf_solve
from .curve import decompress, p2pkh_address, pubkey_from_private, wif
from .kangaroo import kangaroo_solve
from .p2g import (
    CLUE2_PLAINTEXT,
    clue8_rule_a,
    clue8_rule_b,
    clue8_rule_c,
    decode_clue2,
    segment_ledger,
    walk_wasd,
)
from .registry import Registry


def _cmd_addr(args: argparse.Namespace) -> int:
    if args.priv:
        k = int(args.priv, 16)
        pub = pubkey_from_private(k, compressed=not args.uncompressed)
        print(f"private  : 0x{k:064x}")
        print(f"public   : {pub.hex()}")
        print(f"address  : {p2pkh_address(pub)}")
        print(f"wif      : {wif(k, compressed=not args.uncompressed)}")
        return 0
    if not args.pub:
        print("error: pass --priv or --pub", file=sys.stderr)
        return 2
    pub = decompress(bytes.fromhex(args.pub))
    print(f"public   : {args.pub}")
    print(f"address  : {p2pkh_address(bytes.fromhex(args.pub))}")
    print(f"x,y      : 0x{pub[0]:064x} 0x{pub[1]:064x}")
    return 0


def _cmd_solve(args: argparse.Namespace) -> int:
    pub = decompress(bytes.fromhex(args.pub))
    if args.start is not None and args.end is not None:
        a, b = int(args.start, 16), int(args.end, 16)
    else:
        if args.bits is None:
            print("error: pass --bits or --start/--end", file=sys.stderr)
            return 2
        a, b = 1 << (args.bits - 1), (1 << args.bits) - 1
    if args.engine == "kangaroo":
        res = kangaroo_solve(pub, a, b, max_ops=args.max_ops)
        print(f"k        : {hex(res.k) if res.k else None}")
        print(f"ops      : {res.ops:,}  ({res.ops_over_sqrt:.3f} * sqrt(W))")
        print(f"seconds  : {res.seconds:.3f}")
        print(f"verified : {res.verified}")
        return 0 if res.verified else 1

    res = sqf_solve(pub, a, b, table_size=args.table_size, max_table=args.max_table)
    print(f"k            : {hex(res.k) if res.k else None}")
    print(f"table        : {res.table_size:,} entries, {res.memory_bytes / 1e6:.1f} MB")
    print(f"ops          : {res.ops:,} ({res.ops_over_sqrt:.3f} * sqrt(W))")
    print(f"inversions   : {res.inversions:,}")
    print(f"seconds      : {res.seconds:.3f}")
    print(f"verified     : {res.verified}")
    return 0 if res.verified else 1


def _cmd_bench(args: argparse.Namespace) -> int:
    from .bench import run_suite, write_report

    payload = run_suite(args.solvers, args.bits, trials=args.trials, seed=args.seed)
    if args.out:
        write_report(payload, args.out)
        print(f"report written to {args.out}")
    for key, stats in payload["summary"].items():
        print(f"{key:16s} runs={stats['runs']} verified={stats['verified']} "
              f"ops/sqrt={stats['ops_over_sqrt_mean']:.3f} t={stats['seconds_mean']:.3f}s")
    return 0


def _cmd_registry(args: argparse.Namespace) -> int:
    with Registry(args.db) as reg:
        if args.action == "init":
            print(json.dumps(reg.stats(), indent=2))
        elif args.action == "claim":
            agent = reg.register_agent(args.agent or "cli") if args.agent else None
            print(json.dumps(reg.claim(args.label, agent_id=agent, bits=args.bits,
                                       span=args.span, start=_hex(args.start),
                                       end=_hex(args.end)), indent=2))
        elif args.action == "complete":
            print(json.dumps(reg.complete(args.block, ops=args.ops), indent=2))
        elif args.action == "submit":
            k = int(args.priv, 16)
            inserted = reg.submit_key(k, bits=k.bit_length(), source="cli")
            print(json.dumps({"duplicate": not inserted, "fingerprint": k % 10_000}, indent=2))
        elif args.action == "stats":
            print(json.dumps(reg.stats(args.label), indent=2))
    return 0


def _hex(value: Optional[str]) -> Optional[int]:
    return int(value, 16) if value else None


def _cmd_p2g(args: argparse.Namespace) -> int:
    if args.action == "ledger":
        print(json.dumps(segment_ledger(), indent=2, default=str))
    elif args.action == "clue2":
        print(decode_clue2())
        print(f"(expected: {CLUE2_PLAINTEXT})")
    elif args.action == "clue8":
        print("rule A:", clue8_rule_a())
        print("rule B:", clue8_rule_b())
        print("rule C:", json.dumps(clue8_rule_c(), indent=2))
    elif args.action == "walk":
        for col, row, cell in walk_wasd():
            print(f"  col={col} row={row} cell={cell}")
    return 0


def _cmd_battleship(args: argparse.Namespace) -> int:
    if args.action == "ships":
        print(json.dumps(unsolved_ships(), indent=2))
        return 0
    if args.action == "cell":
        start, end = cell_bounds(args.bits, args.col, args.row)
        print(json.dumps({
            "cell": f"{'ABCDEFGHIJ'[args.col]}{args.row + 1}",
            "bits": args.bits,
            "start_k": hex(start),
            "end_k": hex(end),
            "width": end - start + 1,
        }, indent=2))
        return 0
    secret = int(args.priv, 16)
    x, y = key_to_square_xy(args.bits, secret)
    print(json.dumps({
        "k": hex(secret),
        "x": round(x, 6),
        "y": round(y, 6),
        "cell": cell_label(x, y),
        "roundtrip_ok": square_xy_to_key(args.bits, x, y) == secret,
    }, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqflab",
        description="Symmetric Quartet Folding laboratory: solvers, honest benchmarks, "
                    "anti-duplicate registry, P2G reconstruction and the battleship model.",
    )
    parser.add_argument("--version", action="version", version=f"sqflab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    addr = sub.add_parser("addr", help="address / WIF helpers")
    addr.add_argument("--priv", help="private key in hex")
    addr.add_argument("--pub", help="SEC1 public key in hex")
    addr.add_argument("--uncompressed", action="store_true")
    addr.set_defaults(func=_cmd_addr)

    solve = sub.add_parser("solve", help="SQF-BSGS or kangaroo solve")
    solve.add_argument("--pub", required=True, help="SEC1 compressed/uncompressed public key")
    solve.add_argument("--bits", type=int, help="puzzle width, window [2^(bits-1), 2^bits)")
    solve.add_argument("--start", help="explicit lower bound (hex)")
    solve.add_argument("--end", help="explicit upper bound (hex)")
    solve.add_argument("--engine", choices=["sqf", "kangaroo"], default="sqf")
    solve.add_argument("--table-size", type=int, default=None)
    solve.add_argument("--max-table", type=int, default=1 << 21)
    solve.add_argument("--max-ops", type=int, default=5_000_000)
    solve.set_defaults(func=_cmd_solve)

    bench = sub.add_parser("bench", help="blind benchmark suite")
    bench.add_argument("--solvers", nargs="+", default=["sqf"], choices=["sqf", "kangaroo"])
    bench.add_argument("--bits", nargs="+", type=int, default=[16, 18, 20])
    bench.add_argument("--trials", type=int, default=3)
    bench.add_argument("--seed", type=int, default=None)
    bench.add_argument("--out", help="JSON report path")
    bench.set_defaults(func=_cmd_bench)

    registry = sub.add_parser("registry", help="anti-duplicate scan registry")
    registry.add_argument("--db", default="registry.sqlite3")
    registry.add_argument("action", choices=["init", "claim", "complete", "submit", "stats"])
    registry.add_argument("--label", default="puzzle-140")
    registry.add_argument("--bits", type=int, default=140)
    registry.add_argument("--span", type=int, default=None)
    registry.add_argument("--start")
    registry.add_argument("--end")
    registry.add_argument("--agent")
    registry.add_argument("--block")
    registry.add_argument("--ops", type=int, default=0)
    registry.add_argument("--priv")
    registry.set_defaults(func=_cmd_registry)

    p2g = sub.add_parser("p2g", help="path-to-greatness-3ltc decoders")
    p2g.add_argument("action", choices=["ledger", "clue2", "clue8", "walk"])
    p2g.set_defaults(func=_cmd_p2g)

    ship = sub.add_parser("battleship", help="single-square scheduling model")
    ship.add_argument("action", choices=["ships", "cell", "map"])
    ship.add_argument("--bits", type=int, default=140)
    ship.add_argument("--col", type=int, default=0)
    ship.add_argument("--row", type=int, default=0)
    ship.add_argument("--priv", default=hex(1 << 139 | 0x1234))
    ship.set_defaults(func=_cmd_battleship)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
