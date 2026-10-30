# Security policy

## What belongs here

This repository contains cryptanalytic search tooling, not a network service.
Two things are still worth reporting:

1. **A bug in the code** — wrong curve arithmetic, a registry race that allows
   duplicate leases, a path traversal in `apps/lottery/api.py`, a crash on
   adversarial input.
2. **A documentation problem with security impact** — a claim that could lead
   someone to deploy the pool API on the open internet without knowing it has no
   authentication.

## Reporting

Open a private security advisory on GitHub, or email the maintainers listed in
`pyproject.toml`. Please include a minimal reproducer and the exact commit.
Expect an acknowledgement within a few days.

## Explicit non-goals

* The reference pool API has **no authentication and no rate limiting**. It is a
  reference implementation for a trusted network. Put it behind a reverse proxy
  with auth if you expose it.
* SQLite files (`pool.sqlite3`, `var/`) are local state; do not commit them and
  do not serve them.
* The registry stores only salted `blake2b` fingerprints of tested scalars, which
  is intentional: a stolen database must not leak partial progress as usable keys.

## Supported versions

`main` only, at this stage.
