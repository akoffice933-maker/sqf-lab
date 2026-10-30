# `PHP2Shell` (`CVE-2026-109618` / `CVE-2026-109619`) — defensive notes

> **Scope.** This note exists so that operators can recognise and mitigate the
> bug class, and so that anyone reading the hype can see which parts are real.
> It deliberately contains **no working exploit** and no target-specific
> offsets, and the repository does not ship tooling against live third-party
> services — including `stealmybitcoin.com`, which is analysed here only as a
> public experiment.

## What was disclosed

Wiz Research disclosed two CVEs on 2026-10-21, patched in PHP `8.2.35`,
`8.3.36`, `8.4.27`, `8.5.12`. Four distinct primitives fold under them, all of
them cross-request memory-safety bugs in the Zend engine:

| # | Primitive | Global left dangling | Effect |
| --- | --- | --- | --- |
| 1 | upload-progress unserialiser UAF | `BG(unserialize)` | attacker-reclaimed memory used as live bookkeeping → controlled corruption |
| 2 | remote process-memory disclosure | `PS(id)` | a later multipart request URL-encodes reclaimed heap into a `PHPSESSID` cookie → ASLR defeat, works even without `session_start()` |
| 3 | fatal-error backtrace UAF | `EG(last_fatal_error_backtrace)` | diagnostic path walks freed memory |
| 4 | OPcache type confusion | `CG(map_ptr_last)` | partially persisted objects in shared memory get reused as the wrong type |

Common precondition: an **out-of-memory bailout** (`zend_bailout`/`longjmp`)
destroying the request heap while a global still points into it.

## Why the public experiment has not been "won"

The `stealmybitcoin.com` deployment (PHP 8.4.26 behind nginx) blocks the stock
PoCs for ordinary, boring reasons:

1. **Static phase.** For its first ~18 hours the site served only `index.html`;
   no PHP script executed, so no reachable SAPI path existed.
2. **`nginx` request buffering and `client_max_body_size`.** The PoCs assume the
   attacker controls the body size that reaches the `rfc1867` parser. A proxy in
   front caps it, so the OOM has to be produced by amplification *inside* PHP
   rather than by request size.
3. **`cli-server`, not `mod_php`/FPM.** Single-worker, restarts on fault, fresh
   ASLR base each time — a cross-request primitive needs the *same* worker to
   survive to the next request.
4. **Heap noise.** Every concurrent scanner perturbs the freelist between the
   two requests the primitive needs.

None of this makes the bug less severe; it makes *this* target a bad fit for
copy-pasted exploits. That distinction is the useful takeaway.

## Detection and mitigation

* Patch: `8.2.35 / 8.3.36 / 8.4.27 / 8.5.12` or later. There is no configuration
  workaround that is equivalent.
* Hunt for: multipart requests followed by memory-limit errors or repeated
  HTTP 500, oversized/malformed `PHPSESSID` response cookies, unexplained PHP
  worker churn.
* If you cannot patch immediately: terminate at the edge (WAF rules for the
  multipart patterns), cap `memory_limit` conservatively, and monitor
  `OOM`-driven worker restarts.

## Reproducing safely

Any reproduction belongs in a disposable container
(`docker run --rm --network none php:8.4.26-apache`), with ASLR variability and
memory limits under your control. Never point this class of primitive at a host
you do not own — which is exactly why this repository stops at analysis.
