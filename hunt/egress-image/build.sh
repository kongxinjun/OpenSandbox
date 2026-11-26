#!/bin/sh
# Build osb-hunt/egress:dev from this checkout: cross-compile on the host, then
# a debian-slim runtime with iptables/nftables (no mitmproxy).
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-/tmp/osb-hunt/egress-img}
ARCH=${ARCH:-$(go env GOARCH)}
mkdir -p "$OUT"
cd "$ROOT/components/egress"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "$OUT/egress" .
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "$OUT/egress-trace" ./tools/egress-trace
(cd ../internal && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "$OUT/supervisor" ./cmd/supervisor)
cp scripts/cleanup.sh "$OUT/"
cp "$ROOT/hunt/egress-image/Dockerfile" "$OUT/"
docker build -q -t osb-hunt/egress:dev "$OUT"
