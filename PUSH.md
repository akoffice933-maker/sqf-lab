# Publishing this repository

Everything is built, committed and tagged locally (`v0.1.0`), and every URL in
the repository already points at **`akoffice933-maker/sqf-lab`**. The GitHub
connector is not available in this session, so the push is a two-minute manual
step. Shell commands are for `bash`.

## 0. Sanity check

```bash
cd /home/user/sqf-lab
make test                 # 58 passed
git log --oneline         # 7 commits + tag
git tag -l                # v0.1.0
git remote -v             # prints nothing yet
```

Nothing sensitive is tracked: `*.sqlite3`, `cpp/build/`, `var/`, `__pycache__`
are in `.gitignore`, and the registry never stores private keys in the first
place (only salted `blake2b` fingerprints).

## 1. Create the remote and push (GitHub CLI — recommended)

```bash
gh auth login                      # once per machine, scope: repo
cd /home/user/sqf-lab
gh repo create sqf-lab --public --source=. --remote=origin --push
git push origin --tags
```

## 2. Create the remote and push (plain git)

```bash
# open https://github.com/new?owner=akoffice933-maker and create an EMPTY repo
# named `sqf-lab` (no README, no .gitignore, no license — this tree has them)
cd /home/user/sqf-lab
git remote add origin git@github.com:akoffice933-maker/sqf-lab.git
git branch -M main
git push -u origin main
git push origin --tags
```

If you prefer HTTPS with a token:

```bash
git remote add origin https://github.com/akoffice933-maker/sqf-lab.git
```

## 3. Commits are already attributed to you

The local repository is configured as:

```
user.name  = akoffice933-maker
user.email = 253819023+akoffice933-maker@users.noreply.github.com
```

That is GitHub's `ID+username` no-reply address, so commits link to the account
without exposing a personal mailbox. Check with `git log -1 --format='%an <%ae>'`.
To change it before pushing:

```bash
git config user.email "<your-email@example.com>"    # or your preferred address
```

The seven commits are thematic, so a reviewer can read the history in order:
scaffold → core → native engines → apps → tests/benchmarks → docs → URL fix.

## 4. Repository settings worth setting once

| setting | value |
| --- | --- |
| description | `Symmetric Quartet Folding laboratory for secp256k1: honest solvers, blind benchmarks, anti-duplicate scan registry` |
| topics | `secp256k1`, `ecdlp`, `pollard-kangaroo`, `bsgs`, `bitcoin-puzzles`, `cryptanalysis`, `reproducible-research` |
| website | — (or link to `docs/BENCHMARKS.md`) |
| features | Wiki off, Projects off, Discussions on |
| branch protection (main) | require PR + CI (`python`, `native`, `cli`) to pass |
| security | enable Dependabot alerts and private vulnerability reporting |

## 5. Release

```bash
git tag -a v0.1.0 -m "sqf-lab 0.1.0 — reference solvers, blind benchmarks, registry"
git push origin v0.1.0
gh release create v0.1.0 --notes-file CHANGELOG.md --title "sqf-lab 0.1.0"
gh release upload v0.1.0 benchmarks/results/*.json
```

Attaching the two benchmark JSONs makes the numbers travel with the tag, which is
the whole point of `docs/BENCHMARKS.md`.

## 6. Reproducing the numbers on a new machine

```bash
sudo apt-get install -y build-essential libgmp-dev   # or: brew install gmp
python3 -m pip install -e ".[dev]"
make native NATIVE=0
make bench-native                                    # writes benchmarks/results/native_suite.json
```

Compare against `docs/BENCHMARKS.md`. A different CPU changes `MEcOps/s`, but
`ops / √W` should stay inside the published spread — it is a property of the
algorithm, not of the hardware. If it does not, open a
`.github/ISSUE_TEMPLATE/benchmark_claim.yml` issue with the JSON.

## 7. CI badge

The badge in `README.md` / `README.ru.md` is

```
https://github.com/akoffice933-maker/sqf-lab/actions/workflows/ci.yml/badge.svg
```

It renders as "failing" until the first workflow run finishes on `main`; that is
expected and not a broken link.
