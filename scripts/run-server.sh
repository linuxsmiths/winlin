#!/usr/bin/env bash
set -euo pipefail

# Document safe local defaults; provisioning remains an explicit, separate operation.
usage() {
    cat <<'EOF'
Usage: scripts/run-server.sh [--build-dir PATH] [--state-dir PATH] [--] [server arguments...]

Run the Linux server using the repository's build/ and .winlin-local/ directories.
Default state files: server.pem, server.key, pairing-token.
Native --cert, --key, and --token-file arguments override individual defaults.
Place launcher options first. Relative overrides use the caller's working directory.
Use -- --help for the native server's help, without requiring state files.

Examples:
  scripts/run-server.sh
  scripts/run-server.sh --bind 10.0.0.4 --workers 8
  scripts/run-server.sh --state-dir /private/endpoint --backend ktls

Create the certificate and private token as described in docs/https.md first.
This script never creates credentials, resets pairing, builds, or tunes the host.
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

certificate="$state_dir/server.pem"
private_key="$state_dir/server.key"
token_file="$state_dir/pairing-token"
has_certificate=false
has_private_key=false
has_token_file=false
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
        --token-file)
            token_file="${server_arguments[index + 1]}"
            has_token_file=true
            ;;
    esac
done

for path in "$certificate" "$private_key" "$token_file"; do
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
if ! "$has_token_file"; then
    defaults+=(--token-file "$token_file")
fi

# Keep native stdout (including the readiness JSON), signals, and exit codes unchanged.
exec "$executable" "${defaults[@]}" "${server_arguments[@]}"
