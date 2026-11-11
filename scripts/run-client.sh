#!/usr/bin/env bash
set -euo pipefail

# Explain launcher options without requiring an existing build or changing client state.
usage() {
    cat <<'EOF'
Usage: scripts/run-client.sh [--build-dir PATH] [--] [client arguments...]

Run the Linux client from the repository's build/ directory by default.
With no client arguments, start the interactive console.
Place launcher options before client arguments. Relative paths use the caller's
working directory. Use -- --help to display the client's own help.

Examples:
  scripts/run-client.sh
  scripts/run-client.sh inspect --target .winlin-local/local.json
  scripts/run-client.sh --build-dir build-client run --target target.json

This script does not build, pair targets, or change credentials.
EOF
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="$repo_root/build"

# Stop at the first application argument; all remaining values must retain their exact boundaries.
while (( $# )); do
    case "$1" in
        --build-dir)
            if (( $# < 2 )) || [[ -z "$2" || "$2" == -* ]]; then
                echo 'winlin client launcher: FATAL: --build-dir requires a path.' >&2
                exit 2
            fi
            build_dir="$2"
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
    echo 'winlin client launcher: FATAL: the client runs on Linux only.' >&2
    exit 1
fi

executable="$build_dir/winlin"
if [[ ! -f "$executable" || ! -x "$executable" ]]; then
    printf 'winlin client launcher: FATAL: executable not found: %s\nRun scripts/build.sh client first.\n' \
        "$executable" >&2
    exit 1
fi

# Replace the wrapper so stdin, signals, and the application's exit status are not intercepted.
exec "$executable" "$@"
