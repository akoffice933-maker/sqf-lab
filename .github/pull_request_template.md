## What this changes

<!-- one paragraph, please -->

## Type

- [ ] bug fix
- [ ] new algorithm / optimisation (**attach benchmark JSON**)
- [ ] tests
- [ ] documentation
- [ ] packaging / CI

## Methodology checklist (required for performance claims)

- [ ] blind run: harness generated the key, solver saw only `P` and `[a, b]`
- [ ] counters incremented at the operation site
- [ ] verification performed outside the solver
- [ ] `benchmarks/results/*.json` committed
- [ ] baseline re-run on the same machine, same commit, same seed policy

## Tests

```
make test          # 58 passed
make test-all      # with cpp/build/libsqf_dual.so
```

## Scope

- [ ] this does not target third-party wallets or live third-party services
      (see `docs/ETHICS-AND-SCOPE.md`)
