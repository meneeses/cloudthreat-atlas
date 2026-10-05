#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: smoke-standalone.sh /path/to/atlas}"
temporary="$(mktemp -d)"
address="127.0.0.1:18091"
log="$temporary/atlas.log"

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$temporary"
}
trap cleanup EXIT

(
  cd "$temporary"
  "$binary" demo --addr "$address" >"$log" 2>&1
) &
server_pid=$!

for _ in {1..50}; do
  if curl --fail --silent "http://$address/healthz" > "$temporary/health.json"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    sed -n '1,120p' "$log" >&2
    exit 1
  fi
  sleep 0.1
done

curl --fail --silent "http://$address/" > "$temporary/index.html"
curl --fail --silent "http://$address/cloudthreat-atlas/" > "$temporary/prefixed-index.html"
cmp "$temporary/index.html" "$temporary/prefixed-index.html"
grep -q 'CloudThreat Atlas' "$temporary/index.html"
grep -q 'contoso-health-demo' "$temporary/health.json"

main_asset="$(sed -n 's|.*src="\(/cloudthreat-atlas/assets/[^"]*\.js\)".*|\1|p' "$temporary/index.html" | head -n 1)"
style_asset="$(sed -n 's|.*href="\(/cloudthreat-atlas/assets/[^"]*\.css\)".*|\1|p' "$temporary/index.html" | head -n 1)"
[[ -n "$main_asset" && -n "$style_asset" ]]

curl --fail --silent "http://$address$main_asset" > "$temporary/app.js"
curl --fail --silent "http://$address$style_asset" > "$temporary/app.css"
lazy_asset="$(grep -o 'GraphView-[A-Za-z0-9_-]*\.js' "$temporary/app.js" | head -n 1)"
[[ -n "$lazy_asset" ]]
curl --fail --silent "http://$address/cloudthreat-atlas/assets/$lazy_asset" > "$temporary/graph.js"

curl --fail --silent "http://$address/cloudthreat-atlas/THIRD_PARTY_LICENSES.md" > "$temporary/web-licenses.md"
curl --fail --silent "http://$address/cloudthreat-atlas/GO_THIRD_PARTY_LICENSES.txt" > "$temporary/go-licenses.txt"
grep -q '@xyflow/react' "$temporary/web-licenses.md"
grep -q 'github.com/Azure/azure-sdk-for-go/sdk/azcore' "$temporary/go-licenses.txt"

curl --fail --silent \
  --header 'Content-Type: application/json' \
  --data '{"snapshotId":"contoso-health-demo","changes":[{"type":"remove-edge","targetId":"rel-identity-vault"}]}' \
  "http://$address/api/v1/simulations" > "$temporary/simulation.json"
grep -q 'path-internet-public-app' "$temporary/simulation.json"

status="$(curl --silent --output /dev/null --write-out '%{http_code}' "http://$address/cloudthreat-atlas/assets/app.js.map")"
[[ "$status" == "404" ]]

printf 'Standalone embedded demo smoke test passed.\n'
