#!/usr/bin/env bash
set -euo pipefail

# Surface native-tool failures even when a tool exits without printing its own diagnostic.
report_failure() {
    local status="$1"
    local line="$2"
    printf 'winlin prep: FATAL: command failed at line %s (exit %s).\n' "$line" "$status" >&2
    exit "$status"
}
trap 'report_failure "$?" "$LINENO"' ERR

usage() {
    cat <<'EOF'
Usage: scripts/prep.sh [--check]

Install the shared build/runtime dependencies for Ubuntu 24.04 or newer.
--check verifies prerequisites without installing packages or using sudo.

This does not configure certificates, firewall rules, kTLS, or host tuning.
EOF
}

check_only=false
case "${1:-}" in
    "") ;;
    --check) check_only=true ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
if (( $# > 1 )); then
    usage >&2
    exit 2
fi

if [[ ! -r /etc/os-release ]]; then
    echo "Cannot identify this OS; Ubuntu 24.04 or newer is required." >&2
    exit 1
fi
# shellcheck source=/dev/null
source /etc/os-release
if [[ "${ID:-}" != ubuntu ]] || ! dpkg --compare-versions "${VERSION_ID:-0}" ge 24.04; then
    echo "Ubuntu 24.04 or newer is required; found ${PRETTY_NAME:-unknown OS}." >&2
    exit 1
fi

packages=(
    build-essential
    ca-certificates
    cmake
    libgoogle-perftools-dev
    libssl-dev
    nlohmann-json3-dev
    openssl
    python3
)
missing=()
# dpkg-query status 1 means an absent package; other failures must not look like missing dependencies.
for package in "${packages[@]}"; do
    if package_status="$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>&1)"; then
        if [[ "$package_status" != installed ]]; then
            missing+=("$package")
        fi
    else
        status="$?"
        if (( status != 1 )); then
            printf 'winlin prep: FATAL: cannot inspect package %s (exit %s): %s\n' \
                "$package" "$status" "$package_status" >&2
            exit "$status"
        fi
        missing+=("$package")
    fi
done

if (( ${#missing[@]} )); then
    printf 'Missing packages: %s\n' "${missing[*]}" >&2
    if "$check_only"; then
        echo "Run scripts/prep.sh to install them." >&2
        exit 1
    fi
    as_root=()
    if (( EUID != 0 )); then
        if ! command -v sudo >/dev/null 2>&1; then
            echo "Install sudo or run this script as root to install packages." >&2
            exit 1
        fi
        as_root=(sudo)
    fi
    "${as_root[@]}" apt-get update
    "${as_root[@]}" apt-get install -y --no-install-recommends "${missing[@]}"
fi

for tool in g++ make cmake openssl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool is not on PATH: $tool" >&2
        exit 1
    fi
done
compiler_version="$(g++ -dumpfullversion -dumpversion)"
cmake_version="$(cmake --version)"
cmake_version="${cmake_version%%$'\n'*}"
cmake_version="${cmake_version##* }"
read -r _ openssl_version _ <<<"$(openssl version)"
json_version="$(dpkg-query -W -f='${Version}' nlohmann-json3-dev)"
if ! dpkg --compare-versions "$compiler_version" ge 13 ||
   ! dpkg --compare-versions "$cmake_version" ge 3.24 ||
   ! dpkg --compare-versions "$openssl_version" ge 3.0 ||
   ! dpkg --compare-versions "$json_version" ge 3.11; then
    echo "Need GCC >=13, CMake >=3.24, OpenSSL >=3.0, and nlohmann/json >=3.11." >&2
    echo "Check PATH and package versions; no third-party toolchain repositories are added automatically." >&2
    exit 1
fi

printf 'Ready: Ubuntu %s, GCC %s, CMake %s, OpenSSL %s.\n' \
    "$VERSION_ID" "$compiler_version" "$cmake_version" "$openssl_version"
echo "Build with scripts/build.sh client, server, or all."
echo "For large connection counts, check the calling shell's file descriptor limit (ulimit -n)."
