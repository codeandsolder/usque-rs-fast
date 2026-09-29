#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${USQUE_BIN:-$repo_root/target/debug/usque-rs}"
config="${1:-${USQUE_CONFIG:-/etc/usque/config.json}}"
socks_port="${SOCKS_PORT:-19080}"
http_port="${HTTP_PORT:-19081}"
proxy_user="${PROXY_SMOKE_USER:-usque-smoke}"
proxy_password="${PROXY_SMOKE_PASSWORD:-usque-smoke-$$}"
transport_args=()
if [[ "${PROXY_SMOKE_IPV6:-0}" == "1" ]]; then
    transport_args+=(--ipv6)
fi
workdir="$(mktemp -d "${TMPDIR:-/tmp}/usque-proxy-smoke.XXXXXX")"
proxy_pid=""

cleanup() {
    if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
        kill "$proxy_pid" 2>/dev/null || true
        wait "$proxy_pid" 2>/dev/null || true
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

fail() {
    printf 'proxy smoke: %s\n' "$*" >&2
    exit 1
}

command -v curl >/dev/null || fail "curl is required"
command -v rg >/dev/null || fail "ripgrep is required"
[[ -x "$binary" ]] || fail "binary is not executable: $binary"
[[ -r "$config" ]] || fail "config is not readable: $config"

wait_for_listener() {
    local log_file=$1
    local label=$2
    local attempt

    for attempt in {1..100}; do
        if ! kill -0 "$proxy_pid" 2>/dev/null; then
            cat "$log_file" >&2 || true
            fail "$label exited before listening"
        fi
        if rg -q 'proxy listening on' "$log_file"; then
            return 0
        fi
        sleep 0.1
    done

    cat "$log_file" >&2 || true
    fail "$label did not start listening"
}

stop_proxy() {
    if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
        kill "$proxy_pid"
        wait "$proxy_pid" 2>/dev/null || true
    fi
    proxy_pid=""
}

start_socks() {
    local log_file="$workdir/socks.log"
    RUST_LOG=info "$binary" -c "$config" socks \
        --bind 127.0.0.1 \
        --port "$socks_port" \
        --username "$proxy_user" \
        --password "$proxy_password" \
        "${transport_args[@]}" \
        >"$log_file" 2>&1 &
    proxy_pid=$!
    wait_for_listener "$log_file" "SOCKS proxy"
}

start_http() {
    local log_file="$workdir/http.log"
    RUST_LOG=info "$binary" -c "$config" http-proxy \
        --bind 127.0.0.1 \
        --port "$http_port" \
        --username "$proxy_user" \
        --password "$proxy_password" \
        "${transport_args[@]}" \
        >"$log_file" 2>&1 &
    proxy_pid=$!
    wait_for_listener "$log_file" "HTTP proxy"
}

curl_common=(
    --fail
    --silent
    --show-error
    --connect-timeout 10
    --max-time 30
    --noproxy ""
    --output /dev/null
)

printf '%s\n' 'proxy smoke: SOCKS5 with client-side DNS'
start_socks
curl "${curl_common[@]}" \
    --proxy-user "$proxy_user:$proxy_password" \
    --socks5 "127.0.0.1:$socks_port" \
    https://example.com/

printf '%s\n' 'proxy smoke: SOCKS5h with WARP-side DNS'
curl "${curl_common[@]}" \
    --proxy-user "$proxy_user:$proxy_password" \
    --socks5-hostname "127.0.0.1:$socks_port" \
    https://example.com/

printf '%s\n' 'proxy smoke: SOCKS authentication is required'
if curl "${curl_common[@]}" \
    --socks5-hostname "127.0.0.1:$socks_port" \
    https://example.com/ 2>/dev/null; then
    fail "SOCKS request unexpectedly succeeded without credentials"
fi
stop_proxy

printf '%s\n' 'proxy smoke: HTTP forward proxy'
start_http
curl "${curl_common[@]}" \
    --proxy-user "$proxy_user:$proxy_password" \
    --proxy "http://127.0.0.1:$http_port" \
    http://example.com/

printf '%s\n' 'proxy smoke: HTTPS CONNECT'
curl "${curl_common[@]}" \
    --proxy-user "$proxy_user:$proxy_password" \
    --proxy "http://127.0.0.1:$http_port" \
    https://example.com/

printf '%s\n' 'proxy smoke: HTTP proxy authentication is required'
if curl "${curl_common[@]}" \
    --proxy "http://127.0.0.1:$http_port" \
    https://example.com/ 2>/dev/null; then
    fail "HTTP proxy request unexpectedly succeeded without credentials"
fi
stop_proxy

printf '%s\n' 'proxy smoke: all checks passed'
