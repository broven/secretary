#!/bin/sh
set -eu
cd "$(dirname "$0")"
bun test
bun build --compile src/secretary.ts --outfile bin/secretary-core
chmod 755 bin/secretary-core
