#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
guard_test_dir="$(mktemp -d /tmp/cloudthreat-git-guard.XXXXXX)"
trap 'rm -rf "$guard_test_dir"' EXIT

git -C "$guard_test_dir" init -q -b main
git -C "$guard_test_dir" config user.name 'Joao Meneses'
git -C "$guard_test_dir" config user.email 'meneses-joao@hotmail.com'
git -C "$guard_test_dir" remote add origin git@github-pessoal:meneeses/cloudthreat-atlas.git

(
  cd "$guard_test_dir"
  "$repo_root/scripts/verify-git-identity.sh"
)

git -C "$guard_test_dir" config user.name 'ICone Academy'
git -C "$guard_test_dir" config user.email 'dev@icone.academy'

if (
  cd "$guard_test_dir"
  "$repo_root/scripts/verify-git-identity.sh" >/dev/null 2>&1
); then
  printf 'Expected the personal identity guard to reject a company identity.\n' >&2
  exit 1
fi

git -C "$guard_test_dir" commit --allow-empty -qm 'test: forbidden identity'

if (
  cd "$guard_test_dir"
  "$repo_root/scripts/check-forbidden-identity.sh" --all >/dev/null 2>&1
); then
  printf 'Expected the history guard to find the forbidden identity.\n' >&2
  exit 1
fi

printf 'Git identity guard tests passed.\n'
