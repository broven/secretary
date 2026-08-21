#!/bin/sh
set -eu
cd "$(dirname "$0")"
bun test
# SECRETARY_VERSION is set by the release workflow from the git tag; a local
# build leaves it unset and the binary reports "dev".
VERSION=${SECRETARY_VERSION:-dev}
OUT=${SECRETARY_OUTFILE:-bin/secretary-core}
TARGET_FLAG=""
[ -n "${SECRETARY_TARGET:-}" ] && TARGET_FLAG="--target=$SECRETARY_TARGET"

# shellcheck disable=SC2086
bun build --compile $TARGET_FLAG \
  --define SECRETARY_BUILD_VERSION="\"$VERSION\"" \
  src/secretary.ts --outfile "$OUT"
chmod 755 "$OUT"
echo "built: $OUT ($VERSION)"
