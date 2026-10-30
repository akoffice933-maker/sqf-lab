#!/usr/bin/env bash
# publish.sh — create the GitHub repository and push this tree in one step.
#
#   ./publish.sh --dry-run                 # show what would happen, touch nothing
#   GH_TOKEN=ghp_… ./publish.sh            # create repo + push main + tags
#   ./publish.sh --private                 # same, but a private repository
#   ./publish.sh --ssh                     # push over SSH instead of HTTPS
#
# Token scopes: classic token needs `repo`; a fine-grained token needs
# "Administration: read & write" (to create the repository) and
# "Contents: read & write" (to push). Nothing else.
#
# The token is only ever used inside a single `git push` invocation and in API
# calls; it is never written to .git/config, the shell history or any file.

set -euo pipefail

OWNER="akoffice933-maker"
REPO="sqf-lab"
DESCRIPTION="Symmetric Quartet Folding laboratory for secp256k1: honest solvers, blind benchmarks, anti-duplicate scan registry"
HOMEPAGE=""
TOPICS='["secp256k1","ecdlp","pollard-kangaroo","bsgs","bitcoin-puzzles","cryptanalysis","reproducible-research"]'

PRIVATE=false
DRY_RUN=false
USE_SSH=false
TAG="v0.1.0"

while [ $# -gt 0 ]; do
  case "$1" in
    --private)  PRIVATE=true ;;
    --dry-run)  DRY_RUN=true ;;
    --ssh)      USE_SSH=true ;;
    --tag)      TAG="${2:?--tag needs a value}"; shift ;;
    -h|--help)  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)          echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  !\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m  ✗\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- preconditions
cd "$(dirname "$0")"

[ -d .git ] || die "not a git repository: run this from the sqf-lab checkout"
git rev-parse --verify HEAD >/dev/null 2>&1 || die "no commits yet"

say "Checking the tree before publishing"
[ -z "$(git status --porcelain)" ] || die "working tree is dirty — commit or stash first"
ok "working tree clean ($(git rev-list --count HEAD) commits, $(git ls-files | wc -l | tr -d ' ') files)"
git rev-parse --verify "refs/tags/${TAG}" >/dev/null 2>&1 || die "tag ${TAG} is missing"
ok "tag ${TAG} -> $(git rev-parse --short "${TAG}^{commit}")"
if git remote get-url origin >/dev/null 2>&1; then
  warn "remote 'origin' already exists: $(git remote get-url origin)"
  warn "it will be re-pointed at https://github.com/${OWNER}/${REPO}.git"
fi

# ---------------------------------------------------------------- token lookup
TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-${GITHUB_PAT:-}}}"
if [ -z "$TOKEN" ] && command -v gh >/dev/null 2>&1; then
  TOKEN="$(gh auth token 2>/dev/null || true)"
  [ -n "$TOKEN" ] && ok "using the token stored by gh CLI"
fi
if [ -z "$TOKEN" ] && ! $DRY_RUN; then
  printf 'GitHub token (input hidden, classic scope "repo"): '
  read -rs TOKEN; echo
fi
if [ -z "$TOKEN" ] && ! $DRY_RUN; then
  die "no token: export GH_TOKEN=… or install/authorise gh CLI"
fi

API="https://api.github.com"
auth_header() { printf 'Authorization: Bearer %s' "$1"; }

repo_exists() {
  [ "$(curl -sS -o /dev/null -w '%{http_code}' -H "$(auth_header "$1")" "$API/repos/${OWNER}/${REPO}")" = "200" ]
}

# ---------------------------------------------------------------- create repo
say "Repository https://github.com/${OWNER}/${REPO}"
if $DRY_RUN; then
  warn "dry run: would POST ${API}/user/repos {name: ${REPO}, private: ${PRIVATE}}"
  warn "dry run: would PUT  ${API}/repos/${OWNER}/${REPO}/topics"
  warn "dry run: would git push origin main + ${TAG}"
  exit 0
fi

repo_exists "$TOKEN" && ok "repository already exists — reusing it" || {
  body=$(python3 - "$REPO" "$DESCRIPTION" "$PRIVATE" "$HOMEPAGE" <<'PY'
import json, sys
name, description, private, homepage = sys.argv[1:5]
print(json.dumps({
    "name": name,
    "description": description,
    "private": private == "true",
    "has_issues": True,
    "has_wiki": False,
    "has_projects": False,
    "has_discussions": True,
    "homepage": homepage or None,
}, ensure_ascii=False))
PY
)
  status=$(curl -sS -o /tmp/sqf_publish_repo.json -w '%{http_code}' \
    -X POST -H "$(auth_header "$TOKEN")" -H 'Accept: application/vnd.github+json' \
    -d "$body" "$API/user/repos")
  if [ "$status" = "201" ]; then
    ok "created repository"
  elif grep -q 'already exists' /tmp/sqf_publish_repo.json 2>/dev/null; then
    ok "repository already exists — reusing it"
  else
    echo; sed -n '1,20p' /tmp/sqf_publish_repo.json; die "repository creation failed (HTTP $status)"
  fi
}

curl -sS -o /dev/null -X PUT \
  -H "$(auth_header "$TOKEN")" -H 'Accept: application/vnd.github+json' \
  -d "{\"names\": ${TOPICS}}" \
  "$API/repos/${OWNER}/${REPO}/topics" && ok "topics set: $(echo "$TOPICS" | tr -d '[]"' )"

# ---------------------------------------------------------------- push
say "Pushing main and ${TAG}"
if $USE_SSH; then
  REMOTE="git@github.com:${OWNER}/${REPO}.git"
  git remote remove origin 2>/dev/null || true
  git remote add origin "$REMOTE"
  git push -u origin HEAD:main
  git push origin "$TAG"
else
  # Tokenised URL used only for this invocation: never stored in .git/config.
  PUSH_URL="https://x-access-token:${TOKEN}@github.com/${OWNER}/${REPO}.git"
  git push --quiet "$PUSH_URL" HEAD:refs/heads/main
  git push --quiet "$PUSH_URL" "refs/tags/${TAG}:refs/tags/${TAG}"
  git remote remove origin 2>/dev/null || true
  git remote add origin "https://github.com/${OWNER}/${REPO}.git"
  ok "origin -> https://github.com/${OWNER}/${REPO}.git (no token stored)"
fi

# ---------------------------------------------------------------- verify
say "Verifying through the API"
curl -sS -o /dev/null -X PATCH \
  -H "$(auth_header "$TOKEN")" -H 'Accept: application/vnd.github+json' \
  -d '{"default_branch":"main"}' "$API/repos/${OWNER}/${REPO}"

head_sha_local=$(git rev-parse "refs/heads/main" 2>/dev/null || git rev-parse HEAD)
head_sha_remote=$(curl -sS -H "$(auth_header "$TOKEN")" "$API/repos/${OWNER}/${REPO}/commits/main" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')
[ "$head_sha_local" = "$head_sha_remote" ] && ok "main on GitHub matches local HEAD (${head_sha_local:0:7})" \
  || die "HEAD mismatch: local ${head_sha_local:0:7} vs remote ${head_sha_remote:0:7}"

tag_sha=$(curl -sS -H "$(auth_header "$TOKEN")" "$API/repos/${OWNER}/${REPO}/git/ref/tags/${TAG}" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("object",{}).get("sha","")[:7])' 2>/dev/null || true)
[ -n "$tag_sha" ] && ok "tag ${TAG} present (${tag_sha})" || warn "tag ${TAG} not visible yet"

echo
ok "published: https://github.com/${OWNER}/${REPO}"
echo "   next: create the release and attach the benchmark JSONs"
echo "   gh release create ${TAG} --notes-file CHANGELOG.md --title \"sqf-lab ${TAG#v}\" \\"
echo "     benchmarks/results/native_suite.json benchmarks/results/blind_suite_python.json"
