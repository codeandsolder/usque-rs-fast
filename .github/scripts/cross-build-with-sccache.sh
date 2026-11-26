#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: cross-build-with-sccache.sh TARGET}"
# The shared CI action installs the ordinary server inside each disposable
# cross container. The host never starts a daemon or runs the container's
# compiler. Cache objects persist through the canonical Actions cache.
if [[ "${CODEANDSOLDER_SCCACHE_EXECUTION:-}" != cross ||
      ! -d "${CODEANDSOLDER_CROSS_CACHE_CONTROL:-}" ||
      "${CROSS_CONTAINER_OPTS:-}" != *"--entrypoint /ci-sccache/run"* ]]; then
    echo "canonical cross-container sccache setup must run first" >&2
    exit 2
fi

# The cross x86_64-musl image's old GCC crashes in expand_debug_locations
# when compiling BoringSSL's vectorized Keccak. Disable GCC's optional
# debug-variable tracking only; code generation and vectorization remain
# fully optimized, and the other target compilers are untouched.
if [[ "$target" == "x86_64-unknown-linux-musl" ]]; then
    export CXXFLAGS="${CXXFLAGS:+$CXXFLAGS }-fno-var-tracking-assignments"
fi
# An explicit feature set is useful when staging a full proxy release.
# Default release behavior remains unchanged when unset.
build_args=(--release --locked --target "$target")
if [[ -n "${USQUE_BUILD_FEATURES:-}" ]]; then
    build_args+=(--features "$USQUE_BUILD_FEATURES")
fi
cross build "${build_args[@]}"
