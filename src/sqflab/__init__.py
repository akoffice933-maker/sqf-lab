"""sqf-lab: Symmetric Quartet Folding laboratory for ``secp256k1``.

Public surface
--------------
``sqflab.curve``       field / group arithmetic, SEC1, addresses, WIF
``sqflab.folding``     SQF primitives (mirror multiples, x-only quartet table)
``sqflab.bsgs``        SQF-BSGS solver with honest operation counters
``sqflab.kangaroo``    classical Pollard kangaroo baseline
``sqflab.bench``       blind, verification-outside-the-solver benchmark harness
``sqflab.registry``    persistent anti-duplicate scan registry (SQLite)
``sqflab.battleship``  single-square scheduling model + wound radar audit
``sqflab.p2g``         path-to-greatness-3ltc verified clue decoders

Nothing here pretends that 135+ bit ECDLP is reachable; the benchmarks exist to
measure constants, not to move the exponent.
"""

__version__ = "0.1.0"
__all__ = [
    "__version__",
    "curve",
    "folding",
    "bsgs",
    "kangaroo",
    "bench",
    "registry",
    "battleship",
    "p2g",
]
