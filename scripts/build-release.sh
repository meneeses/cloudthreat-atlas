#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: build-release.sh VERSION OUTPUT_DIRECTORY}"
output_dir="${2:?usage: build-release.sh VERSION OUTPUT_DIRECTORY}"

if [[ ! "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: version must be a stable semantic version such as v0.2.0: $version" >&2
  exit 1
fi

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd -P)"
if find "$output_dir" -mindepth 1 -print -quit | grep -q .; then
  echo "error: output directory must be empty: $output_dir" >&2
  exit 1
fi

staging_dir="$(mktemp -d)"
trap 'rm -rf "$staging_dir"' EXIT

targets=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
)

for target in "${targets[@]}"; do
  read -r target_os target_arch <<<"$target"
  archive_name="cloudthreat-atlas_${version}_${target_os}_${target_arch}"
  package_dir="$staging_dir/$archive_name"
  mkdir -p "$package_dir"

  binary_name="atlas"
  if [[ "$target_os" == "windows" ]]; then
    binary_name="atlas.exe"
  fi

  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
    go build -trimpath -ldflags="-s -w" -o "$package_dir/$binary_name" ./cmd/atlas
  cp LICENSE NOTICE README.md SECURITY.md THIRD_PARTY_NOTICES.md "$package_dir/"
  cp demo/GO_THIRD_PARTY_LICENSES.txt "$package_dir/GO_THIRD_PARTY_LICENSES.txt"
  cp internal/server/webdist/THIRD_PARTY_LICENSES.md "$package_dir/WEB_THIRD_PARTY_LICENSES.md"

  if [[ "$target_os" == "windows" ]]; then
    (
      cd "$staging_dir"
      zip -q -r "$output_dir/$archive_name.zip" "$archive_name"
    )
  else
    tar -C "$staging_dir" -czf "$output_dir/$archive_name.tar.gz" "$archive_name"
  fi
done

(
  cd "$output_dir"
  sha256sum ./*.tar.gz ./*.zip > SHA256SUMS
)
