#!/usr/bin/env bash
set -euo pipefail

dist_dir="${1:-web/dist}"

if [[ ! -d "$dist_dir/assets" ]]; then
  echo "error: build output not found at $dist_dir/assets" >&2
  exit 1
fi

gzip_size() {
  gzip -c -9 "$1" | wc -c | tr -d ' '
}

assert_budget() {
  local label="$1"
  local file="$2"
  local limit="$3"
  local size
  size="$(gzip_size "$file")"
  printf '%-20s %8d bytes gzip (budget %d)\n' "$label" "$size" "$limit"
  if (( size > limit )); then
    echo "error: $label exceeds its gzip budget" >&2
    exit 1
  fi
}

main_js="$(find "$dist_dir/assets" -maxdepth 1 -type f -name 'index-*.js' -print -quit)"
graph_js="$(find "$dist_dir/assets" -maxdepth 1 -type f -name 'GraphView-*.js' -print -quit)"
main_css="$(find "$dist_dir/assets" -maxdepth 1 -type f -name 'index-*.css' -print -quit)"

for required in "$main_js" "$graph_js" "$main_css"; do
  if [[ -z "$required" ]]; then
    echo "error: expected Vite asset was not generated" >&2
    exit 1
  fi
done

assert_budget "initial JavaScript" "$main_js" $((105 * 1024))
assert_budget "React Flow chunk" "$graph_js" $((75 * 1024))
assert_budget "application CSS" "$main_css" $((15 * 1024))
