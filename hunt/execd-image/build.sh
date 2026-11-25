#!/bin/sh
# Build a minimal execd image from the current checkout (no bwrap / session
# gate / launcher / ebpf variant): cross-compile on the host, copy onto busybox.
# The official Dockerfile needs BuildKit and a golang base image; this avoids both.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-/tmp/osb-hunt/execd-img}
ARCH=${ARCH:-$(go env GOARCH)}
mkdir -p "$OUT"
(cd "$ROOT/components/execd" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "$OUT/execd" ./main.go)
(cd "$ROOT/components/internal" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "$OUT/opensandbox-supervisor" ./cmd/supervisor)
cp "$ROOT/components/execd/bootstrap.sh" "$OUT/"
cp "$(dirname "$0")/Dockerfile" "$OUT/"
docker build -q -t osb-hunt/execd:dev "$OUT"
