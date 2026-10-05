#!/usr/bin/env bash
set -euo pipefail

revision="${1:---all}"
forbidden_pattern='ICone Academy|dev@icone\.academy'

if git log "$revision" --format='%H %an <%ae> / %cn <%ce>' | grep -Eiq "$forbidden_pattern"; then
  printf 'Forbidden company identity found in Git history (%s):\n' "$revision" >&2
  git log "$revision" --format='%H %an <%ae> / %cn <%ce>' | grep -Ei "$forbidden_pattern" >&2
  exit 1
fi

printf 'No forbidden company identity found in %s.\n' "$revision"
