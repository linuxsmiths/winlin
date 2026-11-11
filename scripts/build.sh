#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/build.sh [client|server|all] [--jobs N] [--build-dir PATH]

Build Release binaries and their available tests. Default: all, 2 build jobs.
Run scripts/prep.sh first on Ubuntu. No root privileges are needed to build.
Relative --build-dir paths are resolved from the caller's working directory.
The default build directory is the repository's build/ directory.
EOF
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
component=all
jobs="${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
build_dir="$repo_root/build"
if (( $# )) && [[ "$1" != -* ]]; then
    component="$1"
    shift
fi
case "$component" in
    client) client=ON; server=OFF ;;
    server) client=OFF; server=ON ;;
    all) client=ON; server=ON ;;
    *) usage >&2; exit 2 ;;
esac
while (( $# )); do
    case "$1" in
        --jobs|--build-dir)
            if (( $# < 2 )) || [[ -z "$2" || "$2" == -* ]]; then
                echo "Missing value for $1." >&2
                exit 2
            fi
            if [[ "$1" == --jobs ]]; then jobs="$2"; else build_dir="$2"; fi
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]]; then
    echo "--jobs (or CMAKE_BUILD_PARALLEL_LEVEL) must be a positive integer." >&2
    exit 2
fi
if [[ "$(uname -s)" != Linux ]]; then
    echo "This script builds Linux targets; use scripts/build.ps1 on Windows." >&2
    exit 1
fi
if ! command -v cmake >/dev/null 2>&1; then
    echo "CMake is missing; run scripts/prep.sh first." >&2
    exit 1
fi

cmake -S "$repo_root" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=ON \
    "-DWINLIN_BUILD_CLIENT=$client" \
    "-DWINLIN_BUILD_SERVER=$server"
cmake --build "$build_dir" --parallel "$jobs"

if [[ "$client" == ON ]]; then printf 'Client: %s/winlin\n' "$build_dir"; fi
if [[ "$server" == ON ]]; then printf 'Server: %s/winlin-server\n' "$build_dir"; fi
printf 'Run tests: ctest --test-dir "%s" --output-on-failure\n' "$build_dir"
