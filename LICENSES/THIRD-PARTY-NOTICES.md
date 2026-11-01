# Third-party material and notices

The project itself is MIT-licensed. The canonical MIT text is
[`LICENSE`](../LICENSE) and [`LICENSES/MIT.txt`](MIT.txt). This file records
everything that is *not* part of that grant, so `LICENSE` can stay
byte-for-byte the standard MIT template that GitHub, REUSE and SPDX tooling
recognise.

## In-tree code

The `research/archive/` directory contains exploration scripts written for this
project during its research phase; they are covered by the same MIT terms.

The `cpp/src/` engine sources were written for this project and are likewise
covered by the same MIT terms.

## GMP (LGPL-3.0-or-later, build time only)

The `cpp/` engines link against the GNU MP library (LGPL-3.0 or later) at build
time only. No GMP source is distributed here, so the resulting shared objects
remain under the MIT terms above, subject to GMP's LGPL obligations for the GMP
library itself.

## On-chain facts

Bitcoin puzzle keys, addresses and transaction data referenced in `docs/` and
`research/archive/` are public blockchain facts, not licensed content.
