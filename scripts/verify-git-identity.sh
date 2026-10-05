#!/usr/bin/env bash
set -euo pipefail

expected_name="Joao Meneses"
expected_email="meneses-joao@hotmail.com"
expected_remote="git@github-pessoal:meneeses/cloudthreat-atlas.git"

actual_name="$(git config --local --get user.name || true)"
actual_email="$(git config --local --get user.email || true)"
actual_remote="$(git remote get-url origin 2>/dev/null || true)"
author_identity="$(git var GIT_AUTHOR_IDENT 2>/dev/null || true)"
committer_identity="$(git var GIT_COMMITTER_IDENT 2>/dev/null || true)"

fail() {
  printf 'Git identity check failed: %s\n' "$1" >&2
  exit 1
}

[[ "$actual_name" == "$expected_name" ]] || fail "local user.name is '$actual_name'"
[[ "$actual_email" == "$expected_email" ]] || fail "local user.email is '$actual_email'"
[[ "$actual_remote" == "$expected_remote" ]] || fail "origin is '$actual_remote'"
[[ "$author_identity" == "$expected_name <$expected_email>"* ]] || fail "author identity is '$author_identity'"
[[ "$committer_identity" == "$expected_name <$expected_email>"* ]] || fail "committer identity is '$committer_identity'"

printf 'Git identity verified: %s <%s> via %s\n' "$expected_name" "$expected_email" "$expected_remote"
