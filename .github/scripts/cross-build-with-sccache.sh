#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: cross-build-with-sccache.sh TARGET}"
client="$(realpath -- "${SCCACHE_BIN:?canonical sccache action must run first}")"
if [[ ! -x "$client" ]]; then
    echo "canonical sccache client is not executable: $client" >&2
    exit 2
fi
if [[ "$client" == *[[:space:]]* ]]; then
    echo "sccache client path cannot be used in CROSS_CONTAINER_OPTS: $client" >&2
    exit 2
fi
if [[ -n "${SCCACHE_SERVER_UDS:-}" ]]; then
    echo "cross cache bridge requires the canonical host TCP endpoint, not a Unix socket" >&2
    exit 2
fi

# cross runs rustc in a Docker container. The existing sccache daemon stays on
# the CI host, while this client runs the compiler locally inside the container
# and forwards only cache I/O over host networking. Never start another daemon.
export CROSS_CONTAINER_OPTS="--network=host --mount type=bind,src=$client,dst=/usr/local/bin/sccache,readonly"
export RUSTC_WRAPPER=/usr/local/bin/sccache
export CMAKE_C_COMPILER_LAUNCHER=/usr/local/bin/sccache
export CMAKE_CXX_COMPILER_LAUNCHER=/usr/local/bin/sccache
export SCCACHE_CLIENT_SIDE=1
export SCCACHE_START_SERVER=0
export SCCACHE_NO_AUTO_START_SERVER=1
cross build --release --target "$target"
