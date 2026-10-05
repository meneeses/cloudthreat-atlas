#!/usr/bin/env bash
set -euo pipefail

changes="$(git status --porcelain --untracked-files=all -- internal/server/webdist)"
if [[ -n "$changes" ]]; then
  printf 'Embedded dashboard assets are stale. Run `cd web && npm run build:embed` and commit the result:\n%s\n' "$changes" >&2
  exit 1
fi

printf 'Embedded dashboard assets are current.\n'
