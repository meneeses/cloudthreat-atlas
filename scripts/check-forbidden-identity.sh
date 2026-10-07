#!/usr/bin/env bash
set -euo pipefail

revision="${1:---all}"
forbidden_pattern='ICone Academy|dev@icone\.academy'

history=""
if ! history="$(git log "$revision" --format='%H %an <%ae> / %cn <%ce>' 2>&1)"; then
  printf 'Forbidden identity check failed: cannot inspect %s.\n%s\n' "$revision" "$history" >&2
  exit 1
fi

if grep -Eiq "$forbidden_pattern" <<<"$history"; then
  printf 'Forbidden company identity found in Git history (%s):\n' "$revision" >&2
  grep -Ei "$forbidden_pattern" <<<"$history" >&2
  exit 1
fi

printf 'No forbidden company identity found in %s.\n' "$revision"
