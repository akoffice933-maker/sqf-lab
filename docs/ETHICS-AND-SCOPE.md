# Ethics and scope

## The line

This repository is for:

* **published puzzles** whose author intends them to be solved (Bitcoin puzzle
  transactions, treasure hunts, CTF-style challenges you are invited to);
* **key spaces you own** — your own wallets, your own audit engagements, your own
  research corpora;
* **measurement** — benchmarks, constants, memory models, bookkeeping.

It is not for third-party wallets, live services belonging to someone else, or
"recovering" keys from addresses you do not control. Two concrete consequences in
this codebase:

1. **No live exploitation tooling.** The `PHP2Shell` material
   (`docs/PHP2SHELL-NOTES.md`) is defensive analysis. There is no exploit, no
   target list and no scanner for `stealmybitcoin.com` here, even though the
   challenge invites attempts — the honest unit of work there is *mitigation*,
   not a bounty.
2. **No plaintext key storage in shared infrastructure.** The pool registry stores
   only salted `blake2b` fingerprints (`registry.py`), so a compromise of the
   coordination database does not leak anyone's partial results.

## What we deliberately do not publish

Some material was written during the research phase and stays out of the public
release, even though it is technically interesting:

* scripts aimed at a specific third-party address holding a large balance from 2009
  (not a puzzle; not ours) and the datasets they read — the code exists locally
  but is not in this repository or its history;
* any working exploit against a live service, including the public
  `PHP2Shell` challenge — the repository ships analysis, never a payload.

The rule is simple: if publishing it would let a stranger take someone else's
money, it does not ship.

## Known limits, stated up front

* **Nothing here breaks a 135-bit key.** `√(2^135) = 2^67.5` operations; at the
  measured 17 MEcOps/s that is ~10^5 years on one core, and the SQF table alone
  would need `2^66` bytes. Any claim to the contrary is wrong, including claims
  made by earlier versions of these scripts.
* **Bitcoin puzzle addresses with unrevealed public keys** cannot be attacked
  faster than brute force over `2^(n−1)`; only the ones that have spent coins
  (revealing `P`) are amenable to kangaroo/BSGS at all.
* **Negative results are results.** 37 billion tested pairs with zero hits
  (`docs/P2G-3LTC.md`) is a publishable fact about the puzzle, not a failure to
  hide.

## Responsible disclosure

Found something real in software you don't own? Report it to the vendor, wait for
a patch, then publish. Security contact for this repository: see
[`SECURITY.md`](../SECURITY.md).

## Use of AI assistance

Parts of this codebase were written with AI assistance, and the benchmark harness
exists partly because AI-generated "optimisations" are very good at producing
plausible constants. The countermeasures are mechanical: blind inputs, in-loop
counters, external verification, committed raw JSON.
