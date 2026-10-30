# Publishing this repository

The repository is built, committed and tagged locally (`v0.1.0`). The GitHub
connector is not available in this session, so the push is a two-minute manual
step. Shell commands are for `bash`.

## 0. Sanity check

```bash
cd /home/user/sqf-lab
make test                 # 58 passed
git log --oneline         # 6 commits + tag
git tag -l                # v0.1.0
```

Nothing sensitive is tracked: `*.sqlite3`, `cpp/build/`, `var/`, `__pycache__`
are in `.gitignore`, and the registry never stores private keys in the first
place (only salted `blake2b` fingerprints).

## 1. Create the remote and push (GitHub CLI — recommended)

```bash
gh auth login                     # once per machine, scope: repo
cd /home/user/sqf-lab
gh repo create sqf-lab --public --source=. --remote=origin --push
git push origin --tags
```

## 2. Create the remote and push (plain git)

```bash
# create an empty repo at https://github.com/new (no README, no .gitignore)
cd /home/user/sqf-lab
git remote add origin git@github.com:<your-account>/sqf-lab.git
git branch -M main
git push -u origin main
git push origin --tags
```

## 3. Repository settings worth setting once

| setting | value |
| --- | --- |
| description | `Symmetric Quartet Folding laboratory for secp256k1: honest solvers, blind benchmarks, anti-duplicate scan registry` |
| topics | `secp256k1`, `ecdlp`, `pollard-kangaroo`, `bsgs`, `bitcoin-puzzles`, `cryptanalysis`, `reproducible-research` |
| website | link to `docs/BENCHMARKS.md` or the project page |
| features | Wiki off, Projects off, Discussions on |
| branch protection (main) | require PR + CI (`python`, `native`, `cli`) to pass |
| security | enable Dependabot alerts and private vulnerability reporting |

## 4. Update the placeholder URLs (optional, 1 minute)

`README.md`, `README.ru.md`, `CITATION.cff`, `pyproject.toml`, the CI badge and
the issue-template `config.yml` contain `your-org`. Replace after the first push:

```bash
grep -rl "your-org" . --exclude-dir=.git | xargs sed -i 's/your-org/<your-account>/g'
git commit -am "docs: point links at the real repository" && git push
```

## 5. Release

```bash
git tag -a v0.1.0 -m "sqf-lab 0.1.0 — reference solvers, blind benchmarks, registry"
git push origin v0.1.0
gh release create v0.1.0 --notes-file CHANGELOG.md --title "sqf-lab 0.1.0"
```

Attach the two benchmark JSONs to the release so the numbers travel with the tag:

```bash
gh release upload v0.1.0 benchmarks/results/*.json
```

## 6. Reproducing the numbers on a new machine

```bash
sudo apt-get install -y build-essential libgmp-dev   # or: brew install gmp
python3 -m pip install -e ".[dev]"
make native NATIVE=0
make bench-native                                    # writes benchmarks/results/native_suite.json
```

Compare against `docs/BENCHMARKS.md`. Different CPU → different `MEcOps/s`;
`ops / √W` should stay within the published spread, because it is a property of
the algorithm rather than the hardware. If it does not, that is a bug report
worth opening (see `.github/ISSUE_TEMPLATE/benchmark_claim.yml`).
