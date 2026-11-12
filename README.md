# winlin

Winlin is a benchmark suite for comparing Linux and Windows performance in
workloads where the operating system and its native software stack make a
difference.

The goal is not just to show which system is faster, but to help explain **why**:
how much work each system completes, the latency it introduces, and the CPU,
memory, networking, and kernel activity behind those results.

## Project status

Winlin has native HTTPS server implementations for Linux (OpenSSL and kTLS) and
Windows (HTTP.sys/Schannel), with an interactive/noninteractive Linux client,
pairing and discovery, GET/PUT workloads, process telemetry, and JSON results.
Both servers share agent routing, authentication, capabilities, and workload
semantics. The kTLS backend verifies activation per direction and refuses
userspace fallback.

**Paced load, handshake benchmarks, and hardware profiling are not implemented
yet.** The broader architecture and benchmark areas below describe
the intended suite, not a completed feature list. This first implementation is
not yet a validated 100 Gbps or cross-OS performance comparison tool.

## Building and trying it

The Linux targets require a C++23 compiler, CMake 3.24 or newer, and OpenSSL 3
development files. Linux tests also require Python 3 and the
`openssl` command. CMake downloads a pinned, hash-verified nlohmann/json release
if a compatible system package is unavailable.

On **Ubuntu 24.04 or newer**, use the helper scripts:

```sh
./scripts/prep.sh                 # Install missing prerequisites; uses sudo if needed
./scripts/prep.sh --check         # Verify only; makes no system changes
./scripts/build.sh all            # Build client, server, and tests
# Or: ./scripts/build.sh client
# Or: ./scripts/build.sh server
ctest --test-dir build --output-on-failure
```

Both scripts work from any working directory. Builds default to Release, two
parallel jobs, and the repository's `build/` directory. Override these paths and
parallelism with `--build-dir PATH` and `--jobs N`; `CMAKE_BUILD_PARALLEL_LEVEL`
also sets the default job count. Selecting a component reconfigures that build
directory; use separate build directories to retain independent client/server
configurations. HTTPS integration tests are included only when both are enabled.

Prep installs compiler/build tools, OpenSSL development/runtime packages,
nlohmann/json, Python, and CA certificates. It does not configure TLS identities,
firewalls, kernel modules, persistent file descriptor limits, or benchmark tuning;
see the HTTPS guide for runtime setup. It adds no third-party package repositories.

For manual builds on Linux:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

See [the HTTPS quickstart](docs/https.md) for certificate setup, pairing, workloads,
results, and current limitations. A deliberately public certificate/key is
included for convenience; no manual certificate setup is needed for Linux.
Use the foreground launchers:

```sh
./scripts/run-server.sh           # Linux server; defaults to .winlin-local/ state
./scripts/run-client.sh           # Interactive Linux client (in another terminal)
./scripts/run-client.sh inspect --target .winlin-local/local.json
```

The Linux HTTPS server listens on `0.0.0.0:8443` by default, accepting remote IPv4
clients. Use `--bind 127.0.0.1` if you want loopback-only operation.

Both use the repository's `build/` directory; `--build-dir PATH` overrides it.
The server also accepts `--state-dir PATH`. Put launcher options before native
arguments, optionally separated by `--`. Use `--help` for launcher help or
`-- --help` for native help. The server creates a private local pairing token on
first use and preserves existing credentials/pairing. Launchers never build.

**The bundled TLS identity is public and provides no trustworthy server
authentication.** It is for isolated synthetic benchmarks only. The client
recognizes it automatically; custom certificates/pins remain supported. See
[the fixture documentation](certs/benchmark/README.md). Actual pairing tokens
and saved controller credentials are not bundled or checked into Git.

Linux runtime launches ensure a soft file-descriptor limit of at least **524,288**,
preserving higher limits. If the inherited hard limit is too low, startup fails
with instructions to raise it for the login/service. Only the launched process
is affected; no system-wide settings or hard limits are changed.

On **Windows Server 2022 or Windows 11, x86_64**, use PowerShell:

```powershell
.\scripts\prep.ps1                # Install missing VS 2022 C++ tools and CMake
.\scripts\prep.ps1 -Check         # Verify only
.\scripts\build.ps1 server        # Native HTTP.sys/Schannel server and unit tests
ctest --test-dir build -C Release --output-on-failure
```

Installation requires elevation; building does not. Windows uses native OS
libraries, not OpenSSL, and the client remains Linux-only. See the
[Windows server guide](docs/windows.md) for certificate bindings, URL ACLs,
Linux-client pairing, and optional privileged HTTPS tests.

After provisioning, start the Windows server in the foreground with
`.\scripts\run-server.ps1 -BindAddress 10.0.0.4 -Port 8443`. It defaults to
`build\Release\winlin-server.exe` and `.winlin-local\pairing-token`; use
`-BuildDirectory`, `-Configuration`, `-StateDirectory`, or `-ServerExe` to
override discovery. Run with `-Help` for all supported options.

Only **one server per machine** is supported, even on different HTTPS ports.
Both native servers reserve `127.0.0.1:8444` exclusively until shutdown; this port
is not used for communication. Stop any existing server before starting another
or running server integration tests. Windows does not need the Linux FD-limit setting.

## Goals

- Compare the practical performance of native Linux and Windows stacks, with
  configuration and implementation differences clearly documented.
- Make benchmarks easy to discover, configure, run, and compare from a single
  Linux client.
- Collect both headline performance metrics and detailed server-side telemetry
  to support analysis.
- Keep runs reproducible by saving workload parameters, environment details,
  backend capabilities, and raw results.
- Use a shared cross-platform server codebase while retaining platform-specific
  implementations where needed.

## Architecture

Winlin uses a client/server model:

```text
Linux client
  Interactive console / noninteractive commands
  Benchmark orchestration and load generation
  Result collection and comparison
       |
       +---- Windows server agent ---- Native Windows benchmark backends
       |
       +---- Linux server agent ------ Native Linux benchmark backends
```

### Linux client

The client is the user's entry point. It will discover an already-running Winlin
server agent at a supplied IP address, report its capabilities, and allow the
user to register it as a benchmark target. Onboarding will use a known agent
port, one-time pairing, and server identity confirmation.

An interactive, menu-driven console will let users select targets and benchmarks,
configure workloads, run tests, and inspect results or comparisons.
Noninteractive commands will use the same run configuration for automation.

For network-driven benchmarks, the client also generates load. The initial
design uses one Linux client host; coordinated load generation from multiple
hosts is a future extension.

### Windows and Linux servers

The server is the system under test. Its agent will expose supported benchmarks,
execute the server-side workload, collect telemetry and profiling data, and
return results to the client.

The server will build for Windows and Linux from the same source tree, with
native backends for each platform. Shared workload definitions and result formats
will provide consistency without requiring both operating systems to use an
identical implementation.

### Deployment and implementation

The client and servers are intended to run on the same virtual network or a
comparable low-latency network. Both virtual machines and bare-metal systems are
in scope, including high-core-count hosts and high-speed networking.

The implementation uses **C++23 and CMake**. The client will build only on
Linux; the server will build on both Linux and Windows.

## Benchmark scope

The suite is intended to grow across several areas:

| Area | Examples of questions to investigate |
| --- | --- |
| Networking | Packet-processing efficiency, packets per second, throughput, and request latency |
| TLS and HTTPS | Request handling, encryption overhead, handshake performance, and native TLS/offload paths |
| I/O | IOPS, completion latency, and CPU cost per operation |
| Scheduling | Context-switch efficiency and latency under different workloads |
| System calls | Call overhead, latency, and scaling with concurrency |
| Memory and CPU efficiency | Memory bandwidth, cache behavior, and cycles or instructions per unit of work |

These are areas of interest, not a list of implemented benchmarks. Some tests
will use client-generated traffic; others will execute locally on the server
under the client's control.

The first benchmark is HTTPS performance, intended to compare Windows
HTTP.sys/Schannel with Linux userspace OpenSSL and OpenSSL with kTLS. It will use
synthetic GET and PUT workloads without persistent storage I/O. Benchmark-specific
configuration, methodology, and current limitations are documented in the
[HTTPS guide](docs/https.md).

## Results and observability

Each benchmark should report the measurements relevant to its workload:

- **Performance:** completed operations or requests per second, useful data
  throughput, latency distributions and percentiles, errors, and timeouts.
- **Resource use:** CPU utilization, memory use, network activity, and context
  switches.
- **Efficiency and profiling:** cycles and instructions per operation, cache-miss
  rates, memory bandwidth, and execution profiles where supported.
- **Run context:** workload settings, OS and hardware details, selected backend,
  effective configuration, and available profiling or offload capabilities.

Client-side resource measurements are also important: a saturated load generator
must not be mistaken for a server performance limit.

Metric availability depends on the OS, hardware, virtualization environment, and
permissions. Unsupported or unavailable measurements will be identified
explicitly rather than reported as zero or silently omitted. Deeper collection
may require administrator or root privileges.

Initial output will focus on console summaries, side-by-side comparisons, and
saved raw JSON results. Graphs and richer reports can build on that foundation.

## Measurement principles

- **Compare clearly defined configurations.** Native-stack results are not
  automatically isolated measurements of the kernel or a single subsystem.
  Relevant differences must accompany the comparison.
- **Report what actually ran.** Verify effective settings and offload usage;
  never silently substitute an unsupported backend or configuration.
- **Separate workload types.** For example, steady-state request handling and
  connection establishment answer different performance questions.
- **Account for measurement overhead.** Use separate profiling runs where
  practical, and distinguish them from headline performance runs.
- **Make variability visible.** Support warmup, repeated measurements, and
  configurable run limits rather than relying on a single peak result.
- **Preserve enough context to reproduce results.** Hardware, VM placement,
  network limits, and system tuning can materially affect a comparison.

Benchmarks deliberately stress their targets. Run them on authorized test
systems with appropriate network isolation, not against production services.
