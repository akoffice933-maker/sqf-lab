# sqf-lab

**Symmetric Quartet Folding laboratory for `secp256k1`** — solvers, an honest
benchmark harness, a persistent anti-duplicate scan registry, a reproducible
puzzle reconstruction, and the paper trail of everything that *didn't* work.

[![CI](https://github.com/akoffice933-maker/sqf-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/akoffice933-maker/sqf-lab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-informational.svg)](pyproject.toml)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-informational.svg)](cpp/)

> **What this is not.** It is not a way to break 135-bit keys. The elliptic-curve
> discrete log on `secp256k1` costs `~sqrt(N) ≈ 2^128` group operations; the best
> classical algorithms change the *constant*, not the exponent. Everything here
> is about measuring those constants honestly, and about the bookkeeping
> (scheduling, de-duplication, provenance) that real campaigns need.

---

## Why this repository exists

Most repositories that claim a faster `secp256k1` solver share the same three
flaws: they benchmark with the secret key still in scope, they count
`1.5 * sqrt(W)` instead of counting operations, and they verify the answer
inside the same loop that produced it. This repository is organised around
avoiding exactly that:

| Rule | Where it is enforced |
| --- | --- |
| the solver only ever receives `P = k·G` and `[a, b]` | `sqflab/bench.py` |
| every group operation is incremented **inside** the loop | `sqflab/bsgs.py`, `sqflab/kangaroo.py` |
| the recovered key is compared to the secret **after** the solver returns | `sqflab/bench.py`, `benchmarks/*.py` |
| no range and no key is ever tested twice | `sqflab/registry.py` |
| negative results are published, not buried | `docs/P2G-3LTC.md`, `CHANGELOG.md` |

## Measured results (reproducible)

All numbers below come from the scripts in `benchmarks/`; raw JSON is in
`benchmarks/results/`. "ops" always means *counted group operations*, and
`√W` is the square root of the window width.

### Native engines (`cpp/`, g++ 14.2, 2 cores, `NATIVE=0`)

| engine | 2^24 | 2^28 | 2^32 | 2^36 | 2^40 | verified | MEcOps/s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **SQF-64** (baby table + giant steps) | 1.62 | 1.06 | 1.36 | 1.10 | 1.04 | 15/15 | 6 – 17 |
| RCKangaroo (SOTA v2, ±reflection, L1S2) | 4.08 | 4.15 | 6.16 | 4.22 | 4.49 | 15/15 | 0.8 – 8.3 |
| classic kangaroo | 4.60 | 2.72 | 3.03 | 3.75 | 2.88 | 15/15 | 1.0 – 8.1 |

Units: mean `ops / √W`.

### Pure-Python reference implementations

| solver | 2^16 | 2^20 | 2^24 | 2^26 | verified |
| --- | --- | --- | --- | --- | --- |
| SQF-BSGS (`sqflab.bsgs`) | 0.97 | 1.14 | 1.09 | 1.06 | 12/12 |
| multi-herd kangaroo (`sqflab.kangaroo`) | 1.28 | 1.35 | 1.72 | 4.22 | 12/12 |

Two honest observations, both visible in the table:

1. **Below ~2^45 the table wins.** SQF needs `√(W/2)` field elements of RAM
   (8–300 MB in the range above); a kangaroo needs almost none. Above roughly
   `2^60` the table stops fitting and the kangaroo is the only option left.
2. **The constant is not the point.** At `2^70` — the actual size of the
   `#140` window — even SQF's `1.0·√W = 2^35` operations at 17 MEcOps/s is about
   **24 days on one core, and 2^35 bytes of RAM are not negotiable.** No
   scheduling trick, "battleship" metaphor or bit-slicing changes that.

## What's inside

```
src/sqflab/          clean, typed, dependency-free core (59 tests)
├── curve.py         secp256k1 group law, SEC1, Base58/WIF, hash160
├── folding.py       SQF primitives: mirror multiples, x-only quartet table
├── bsgs.py          SQF-BSGS solver with in-loop operation counters
├── kangaroo.py      multi-herd kangaroo baseline
├── bench.py         blind benchmark harness (verification outside the solver)
├── native.py        ctypes bindings for cpp/ (libsqf_dual.so)
├── registry.py      persistent anti-duplicate registry (SQLite + WAL)
├── battleship.py    single-square scheduling model + wound-radar audit
├── p2g.py           path-to-greatness-3ltc verified clue decoders
└── cli.py           `python -m sqflab …`
cpp/                 C++17/OpenMP engines: SQF-64, RCKangaroo, HASH160, AES-NI oracle
apps/lottery/        reference HTTP pool API + client + agent skill
research/archive/    frozen laboratory scripts (Russian comments, hardcoded paths)
docs/                algorithms, benchmarks, protocol, ethics, negative results
```

## Quick start

```bash
git clone https://github.com/akoffice933-maker/sqf-lab && cd sqf-lab
python3 -m pip install -e ".[dev]"

make test                       # 59 tests, ~3 s, pure Python
make native                     # build the C++ engines into cpp/build
make test-all                   # same suite plus the native smoke tests
```

Solve a 24-bit window from a public key alone:

```bash
$ python3 -m sqflab addr --priv 0x1
private  : 0x0000000000000000000000000000000000000000000000000000000000000001
public   : 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
address  : 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
wif      : KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn

$ python3 -m sqflab solve --pub 02f0…b1c4 --bits 24
k            : 0x8a3f21
table        : 2,047 entries, 0.3 MB
ops          : 2,914 (1.021 * sqrt(W))
inversions   : 6
seconds      : 0.041
verified     : True
```

Run the blind benchmark yourself:

```bash
make bench          # Python SQF vs Python kangaroo
make bench-native   # C++ SQF-64 vs RCKangaroo vs classic kangaroo
```

## The anti-duplicate registry

Collaborative search is only coherent if two workers can never scan the same
scalar twice. `sqflab.registry` guarantees that with two mechanisms:
leases are allocated strictly after the highest `end_k` ever issued
(`BEGIN IMMEDIATE`, so a crash or a race cannot produce overlap), and every
tested scalar is stored as a salted `blake2b` fingerprint under a `UNIQUE`
index — never as the key itself.

```bash
$ python3 -m sqflab registry --db pool.db init
$ python3 -m sqflab registry --db pool.db claim  --label puzzle-140 --bits 140 --span 68719476736
{
  "block_id": "blk-9f1c…", "start_k_hex": "0x8000000000000000",
  "end_k_hex": "0x8000000fffffffff", "duplicate_prevented": false
}
```

The same protocol over HTTP, with an end-to-end test:

```bash
python3 apps/lottery/api.py --db pool.sqlite3 --port 8000
curl -s -X POST localhost:8000/api/ranges/claim -H 'Content-Type: application/json' \
     -d '{"label":"puzzle-140","bits":40,"span":1048576}'
```

See [`apps/lottery/AGENT_SKILL.md`](apps/lottery/AGENT_SKILL.md) for the full
protocol an autonomous agent needs to follow.

## Puzzle reconstruction — `path-to-greatness-3ltc`

`sqflab/p2g.py` reproduces every *verifiable* step of the 3.026 LTC hunt at
`LUtL7qnm3gzxKjHcfVLSjydqhhinTVmTmS`: the zero-wrap A1Z26 decoder for Clue 2
(yielding the instruction *"directions should be spelled and check the first"*),
the 10×10 `wasd` walk, the three disambiguated Clue 8 rules over the album
track table, and the segment ledger. **The 32-byte AES key is still unknown**;
37,373,278,038 candidate pairs were tested with zero hits, and
[`docs/P2G-3LTC.md`](docs/P2G-3LTC.md) records where each segment is stuck
instead of pretending otherwise.

```bash
$ python3 -m sqflab p2g clue2
directionsshouldbespelledandcheckthefirst
$ python3 -m sqflab p2g ledger | head -12
```

## Found a faster method? Prove it.

[`CONTRIBUTING.md`](CONTRIBUTING.md) describes the review bar: a pull request
that claims a speed-up must ship a `benchmarks/results/*.json` produced by the
blind harness on **fresh random keys**, with the operation counter incremented
inside the loop, and verification performed outside the solver. Constants that
survive review go into `docs/BENCHMARKS.md` with the machine and compiler
recorded.

## Ethics and scope

The tooling here searches key spaces that are *published as puzzles* or
*owned by the person running the search*. [`docs/ETHICS-AND-SCOPE.md`](docs/ETHICS-AND-SCOPE.md)
explains the line: none of it is intended for third-party wallets, and the
repository deliberately does **not** contain a working exploit for the live
`stealmybitcoin.com` challenge — the analysis of `PHP2Shell`
(`CVE-2026-109618` / `CVE-2026-109619`) in
[`docs/PHP2SHELL-NOTES.md`](docs/PHP2SHELL-NOTES.md) is defensive and
reproduction-oriented only.

## License

MIT © 2026 **akoffice933-maker** — see [LICENSE](LICENSE).

Every source file carries an SPDX header
(`SPDX-License-Identifier: MIT`), so licence scanners and `reuse` tooling can
attribute the tree without parsing prose. The [LICENSE](LICENSE) file also spells
out the third-party situation: the `cpp/` engines link GMP (LGPL-3.0+) at build
time only, and no GMP source is distributed here.

Русская версия: [README.ru.md](README.ru.md).
