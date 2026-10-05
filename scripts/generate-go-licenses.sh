#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
output="${1:-$repo_root/demo/GO_THIRD_PARTY_LICENSES.txt}"
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT

{
  printf 'CloudThreat Atlas — Go third-party licenses\n'
  printf 'Generated from modules linked into ./cmd/atlas on Linux, macOS, and Windows. Do not edit manually.\n'

  while IFS='|' read -r module version module_dir; do
    [[ -n "$module" ]] || continue

    license_file=""
    for candidate in LICENSE LICENSE.txt LICENSE.md COPYING COPYING.txt; do
      if [[ -f "$module_dir/$candidate" ]]; then
        license_file="$module_dir/$candidate"
        break
      fi
    done
    if [[ -z "$license_file" ]]; then
      printf 'No license file found for %s %s\n' "$module" "$version" >&2
      exit 1
    fi

    printf '\n================================================================================\n'
    printf '%s %s\n' "$module" "$version"
    printf 'Source: https://%s\n' "$module"
    printf '================================================================================\n\n'
    sed -e 's/\r$//' "$license_file"
  done < <(
    cd "$repo_root"
    for target_os in linux darwin windows; do
      GOOS="$target_os" GOARCH=amd64 CGO_ENABLED=0 \
        go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}{{end}}' ./cmd/atlas
    done | sort -u
  )
} > "$temporary"

mkdir -p "$(dirname "$output")"
mv "$temporary" "$output"
trap - EXIT
