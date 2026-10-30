# Anti-duplicate pool protocol

The pool exists to make one promise: **no scalar is ever tested twice, by
anybody.** Two mechanisms implement it — interval leases and key fingerprints —
and both are crash-safe.

## Guarantees

| Guarantee | Mechanism | Test |
| --- | --- | --- |
| leases never overlap | next block starts at `max(end_k) + 1` under `BEGIN IMMEDIATE` | `test_blocks_never_overlap` |
| a duplicate request is redirected, not served | explicit-range validation against existing blocks | `test_duplicate_range_is_rejected_and_redirected` |
| a key is only ever recorded once | `UNIQUE` index on a salted `blake2b` fingerprint | `test_keys_are_deduplicated` |
| a crash cannot lose a lease | WAL + synchronous writes, block written before work starts | `test_persistence_across_reopen` |
| the server is only bookkeeping | all crypto stays in the worker | `apps/lottery/api.py` has no `curve` import |

Keys are **never** stored in plaintext by the registry; only
`blake2b(salt ‖ decimal(k), digest_size=16)`. That is enough to answer "was this
scalar already tested?" without turning the database into a key store.

## HTTP API (`apps/lottery/api.py`)

| method | path | body | returns |
| --- | --- | --- | --- |
| `POST` | `/api/agents/register` | `{name, model_family, strategy}` | `{agent_id, ok}` |
| `POST` | `/api/ranges/claim` | `{agent_id, label, bits, span}` or explicit `{start_k_hex, end_k_hex}` | block + `duplicate_prevented` |
| `POST` | `/api/ranges/complete` | `{block_id, ops}` | block with `status: SCANNED_LOCKED` |
| `POST` | `/api/submit/key` | `{k_hex, agent_id, source}` | `{stored, duplicate}` |
| `POST` | `/api/submit/dp` | `{label, tag, herd, distance, x_tag}` | `{stored}` |
| `GET` | `/api/state` | – | totals by status, unique keys, DP count |
| `GET` | `/` | – | minimal dashboard |

Errors: `409` with `{ok: false, error}` when a label is exhausted or a range is
invalid; `404` for unknown block ids.

## Client loop

```python
claim → run the solver on [start_k, end_k] → submit every tested DP →
complete(block_id, ops) → claim again
```

If the client dies mid-block, the lease stays `LEASED`; the next claimant of that
label still receives a block *after* it, so no work is duplicated. Re-issuing the
same `block_id` to `/api/ranges/complete` is idempotent.

## Relationship to the legacy monolith

`apps/lottery/server_legacy.py` is the original single-file service (83-key
funnel, browser dashboard, in-process C++ bursts). It is kept for provenance and
depends on `research/archive/`. New deployments should use `api.py` +
`sqflab.registry`.
