# Reference pool: anti-duplicate collaborative search

| file | what it is |
| --- | --- |
| `api.py` | **current**: ~200 lines of stdlib HTTP over `sqflab.registry`; tested end-to-end |
| `AGENT_SKILL.md` | the protocol an autonomous agent must follow (RU, the original spec) |
| `server_legacy.py` | the original 2k-line monolith: 83-key funnel, dashboard, in-process C++ bursts |
| `client_legacy.py` | client SDK for the legacy server |

## Run the current API

```bash
python3 apps/lottery/api.py --host 0.0.0.0 --port 8000 --db pool.sqlite3
# or, from the repo root:
make test   # includes tests/test_lottery_api.py (real HTTP, real SQLite)
```

```bash
curl -s -X POST localhost:8000/api/agents/register \
     -H 'Content-Type: application/json' -d '{"name":"my-hunter"}'

curl -s -X POST localhost:8000/api/ranges/claim \
     -H 'Content-Type: application/json' \
     -d '{"agent_id":"agent-…","label":"puzzle-140","bits":40,"span":1048576}'

curl -s localhost:8000/api/state
```

## Guarantees

* blocks are allocated strictly after the highest `end_k` for their label, under
  `BEGIN IMMEDIATE` → no overlap, ever;
* an explicit range that intersects an existing block is rejected with
  `duplicate_prevented: true` **and** redirected to a free block;
* tested scalars are stored as salted `blake2b` fingerprints under a `UNIQUE`
  index → replay is a no-op;
* SQLite runs in WAL mode with `synchronous=FULL`; a crash cannot erase a lease.

## Legacy server

```bash
make -C cpp                    # it needs libsqf_dual.so
SQF_LAB_LIB=$PWD/cpp/build/libsqf_dual.so \
  python3 apps/lottery/server_legacy.py       # http://0.0.0.0:8000
```

It imports six frozen modules from `research/archive/` (see the shim at the top of
the file) and stores its database in `var/`. It is preserved for provenance: the
83-key funnel logic and the dashboard live there, not in `api.py`.
