#!/usr/bin/env bash
set -euo pipefail

# Document the public benchmark identity and host endpoint settings.
usage() {
    cat <<'EOF'
Usage: scripts/run-server.sh [--build-dir PATH] [--state-dir PATH] [--] [server arguments...]

Run the Linux server using the repository's build/ and .winlin-local/ directories.
HTTP control listens on 0.0.0.0:38443 unless --bind/--port overrides it.
Clients select per-run server workers, TLS on/off/kTLS, and cipher.
The implementation connection ceiling is 65536 per endpoint; it is not configurable.
Workload data defaults to HTTP port 38444 or HTTPS port 38445; host overrides:
--http-port PORT and --https-port PORT. No server restart is needed between modes.
Default workload TLS identity: deliberately PUBLIC certs/benchmark/server.pem and server.key.
An existing server.pem/server.key in the state directory takes precedence.
Native --cert/--key override TLS defaults.
Place launcher options first. Relative overrides use the caller's working directory.
Use -- --help for the native server's help, without requiring state files.

Examples:
  scripts/run-server.sh
  scripts/run-server.sh --bind 10.0.0.4 --workers 8
  scripts/run-server.sh --state-dir /private/endpoint --http-port 39000 --https-port 39001

The bundled identity provides no trustworthy server authentication.
This script never overwrites existing certificates/keys or builds.
Runtime launches require a soft file-descriptor limit of at least 524288.
The launcher raises only its own soft limit; the hard limit must allow this.
EOF
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="$repo_root/build"
state_dir="$repo_root/.winlin-local"

while (( $# )); do
    case "$1" in
        --build-dir|--state-dir)
            if (( $# < 2 )) || [[ -z "$2" || "$2" == -* ]]; then
                printf 'winlin server launcher: FATAL: %s requires a path.\n' "$1" >&2
                exit 2
            fi
            if [[ "$1" == --build-dir ]]; then
                build_dir="$2"
            else
                state_dir="$2"
            fi
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            break
            ;;
    esac
done

if [[ "$(uname -s)" != Linux ]]; then
    echo 'winlin server launcher: FATAL: use scripts/run-server.ps1 on Windows.' >&2
    exit 1
fi

executable="$build_dir/winlin-server"
if [[ ! -f "$executable" || ! -x "$executable" ]]; then
    printf 'winlin server launcher: FATAL: executable not found: %s\nRun scripts/build.sh server first.\n' \
        "$executable" >&2
    exit 1
fi

if (( $# == 1 )) && [[ "$1" == --help ]]; then
    exec "$executable" --help
fi
if (( $# % 2 )); then
    echo 'winlin server launcher: FATAL: server arguments must be --option value pairs.' >&2
    exit 2
fi

certificate="$repo_root/certs/benchmark/server.pem"
private_key="$repo_root/certs/benchmark/server.key"
# Preserve existing installations, including partial custom state: missing custom files are errors,
# not a reason to silently replace a configured identity with the public test fixture.
if [[ -e "$state_dir/server.pem" || -L "$state_dir/server.pem" ||
      -e "$state_dir/server.key" || -L "$state_dir/server.key" ]]; then
    certificate="$state_dir/server.pem"
    private_key="$state_dir/server.key"
fi
has_certificate=false
has_private_key=false
server_arguments=("$@")

# Inspect option positions only, not values. Add defaults only when the caller did not provide them;
# duplicate native options are deliberately left for the server's strict parser to reject.
for (( index = 0; index < ${#server_arguments[@]}; index += 2 )); do
    case "${server_arguments[index]}" in
        --cert)
            certificate="${server_arguments[index + 1]}"
            has_certificate=true
            ;;
        --key)
            private_key="${server_arguments[index + 1]}"
            has_private_key=true
            ;;
    esac
done

for path in "$certificate" "$private_key"; do
    if [[ ! -f "$path" || ! -r "$path" ]]; then
        printf 'winlin server launcher: FATAL: state file is missing or unreadable: %s\nSee docs/https.md for setup.\n' \
            "$path" >&2
        exit 1
    fi
done

defaults=()
if ! "$has_certificate"; then
    defaults+=(--cert "$certificate")
fi
if ! "$has_private_key"; then
    defaults+=(--key "$private_key")
fi

# Change only the launched process's soft limit, preserving higher limits and the hard ceiling.
# Abort before readiness rather than starting a benchmark with an unexpectedly small allowance.
minimum_fd_limit=524288
soft_fd_limit="$(ulimit -Sn)"
if [[ "$soft_fd_limit" != unlimited ]] && (( soft_fd_limit < minimum_fd_limit )); then
    if ! ulimit -Sn "$minimum_fd_limit"; then
        printf 'winlin server launcher: FATAL: need at least %s file descriptors; soft=%s, hard=%s.\nRaise the hard nofile limit for this login/service, then retry.\n' \
            "$minimum_fd_limit" "$soft_fd_limit" "$(ulimit -Hn)" >&2
        exit 1
    fi
fi

if [[ "$certificate" == "$repo_root/certs/benchmark/server.pem" ]]; then
    echo 'winlin server launcher: WARNING: using the PUBLIC benchmark certificate/key; no trustworthy server identity.' >&2
fi

# Keep native stdout (including the readiness JSON), signals, and exit codes unchanged.
exec "$executable" "${defaults[@]}" "${server_arguments[@]}"
