#!/usr/bin/env bash
set -euo pipefail

# Explain the fixed workload matrix and options without starting any benchmark.
usage() {
    cat <<'EOF'
Usage: scripts/sweep-https.sh --linux-target FILE --windows-target FILE
       [--repetitions N] [--duration SECONDS] [--build-dir PATH]

Sweep 256B, 512B, 1KiB, 4KiB, 8KiB, 16KiB, 64KiB, 256KiB, 1MiB, 4MiB.
For each size: GET then PUT. For each method:
  Linux baseline, Windows baseline, Linux load, Windows load.

Baselines: 1 connection, 1 client worker.
Load: 1024 connections, 32 client workers.
All runs: HTTPS, 32 server workers, GET copy mode, AES-128-GCM TLS 1.3.
Defaults: 3 repetitions, 30 seconds per repetition, repository build/ directory.
Each invocation also performs the client's fixed two-second warmup.

Baseline latency and requests/s describe one closed-loop connection; they are
not predictions of linear scaling to 1024 connections.
Results appear on the console. No JSON reports are created. The sweep stops
on any failed/interrupted invocation; earlier console results remain available.
Target/build paths are relative to the caller. Servers must already be running.
This script never builds, restarts servers, or changes machine-wide settings.
EOF
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
linux_target=
windows_target=
repetitions=3
duration=30
build_dir="$repo_root/build"

# Parse options before executing anything, preserving spaces in all caller-supplied paths.
while (( $# )); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --linux-target|--windows-target|--repetitions|--duration|--build-dir)
            if (( $# < 2 )) || [[ -z "$2" || "$2" == -* ]]; then
                printf 'winlin sweep: FATAL: missing value for %s.\n' "$1" >&2
                exit 2
            fi
            case "$1" in
                --linux-target) linux_target="$2" ;;
                --windows-target) windows_target="$2" ;;
                --repetitions) repetitions="$2" ;;
                --duration) duration="$2" ;;
                --build-dir) build_dir="$2" ;;
            esac
            shift 2
            ;;
        *) printf 'winlin sweep: FATAL: unknown option %s.\n' "$1" >&2; exit 2 ;;
    esac
done

# Reject incomplete inputs before generating a partial matrix. The native client validates
# target contents and endpoint capabilities when each workload starts.
if [[ ! "$repetitions" =~ ^[1-9][0-9]*$ || ! "$duration" =~ ^[1-9][0-9]*$ ]]; then
    echo 'winlin sweep: FATAL: repetitions and duration must be positive integers.' >&2
    exit 2
fi
for target in "$linux_target" "$windows_target"; do
    if [[ -z "$target" || ! -f "$target" || ! -r "$target" ]]; then
        printf 'winlin sweep: FATAL: provide readable --linux-target and --windows-target files: %s\n' \
            "$target" >&2
        exit 2
    fi
done
if [[ ! -x "$build_dir/winlin" ]]; then
    printf 'winlin sweep: FATAL: client executable not found: %s/winlin\n' "$build_dir" >&2
    exit 1
fi

# Execute one labeled block. Preserve the native status (including cancellation), and never
# continue with another server after a failed or incomplete benchmark.
run_block() {
    local os="$1" target="$2" size="$3" method="$4" phase="$5"
    local connections="$6" workers="$7" status
    printf '\n======================================================================\n'
    printf '%s | %s | size=%s | %s | connections=%s | client workers=%s\n' \
        "$os" "${method^^}" "$size" "$phase" "$connections" "$workers"
    printf 'server workers=32 | TLS=on | GET data=copy | repetitions=%s | duration=%ss\n' \
        "$repetitions" "$duration"
    printf '======================================================================\n'
    if bash "$repo_root/scripts/run-client.sh" --build-dir "$build_dir" run \
        --target "$target" --tls on --cipher TLS_AES_128_GCM_SHA256 \
        --server-workers 32 --workers "$workers" --connections "$connections" \
        --method "$method" --get-response-data copy --get-size "$size" --put-size "$size" \
        --duration "$duration" --requests 0 --repetitions "$repetitions" --timeout 10; then
        return 0
    else
        status=$?
        printf 'winlin sweep: FATAL: %s %s %s %s failed (exit %s); sweep incomplete.\n' \
            "$os" "$method" "$size" "$phase" "$status" >&2
        exit "$status"
    fi
}

# Keep both single-connection baselines ahead of the high-concurrency runs for every workload.
for size in 256B 512B 1KiB 4KiB 8KiB 16KiB 64KiB 256KiB 1MiB 4MiB; do
    for method in get put; do
        run_block Linux "$linux_target" "$size" "$method" baseline 1 1
        run_block Windows "$windows_target" "$size" "$method" baseline 1 1
        run_block Linux "$linux_target" "$size" "$method" load 1024 32
        run_block Windows "$windows_target" "$size" "$method" load 1024 32
    done
done
