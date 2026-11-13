# HTTP/HTTPS benchmark

This is a working starting point, not a fully tuned cross-OS benchmark.
For Windows server provisioning, see the [Windows guide](windows.md).

## Supported today

- Linux OpenSSL userspace and explicitly requested OpenSSL+kTLS server backends.
- Windows HTTP.sys/Schannel with the same control and workload API.
- HTTP/1.1 over TLS 1.3, with one explicitly selected TLS cipher suite.
- Plain HTTP control on both platforms, independent of workload HTTP/HTTPS selection.
- Client-controlled server worker count, TLS/kTLS mode, and cipher.
- Persistent GET, PUT, or mixed workloads with configurable object sizes,
  connections, worker threads, warmup, duration, request limit, and repetitions.
- Interactive target selection and benchmark configuration, or noninteractive
  `add`, `inspect`, and `run` commands.
- Client/server process CPU time, peak resident memory, available context switches, server
  operation counters, latency histograms, throughput, estimated reference cycles per I/O,
  and saved JSON results.

The Linux server and client multiplex nonblocking TCP/TLS connections using epoll.
Connections are distributed across a configurable number of worker threads,
rather than creating one thread per connection. The server uses SO_REUSEPORT
listeners. Windows uses HTTP.sys, Schannel and IOCP for asynchronous HTTP
processing. Shared agent logic and shared HTTP/TLS contract tests keep
discovery, run leases, object semantics, and result fields aligned.
Both implementations still need tuning and validation on large machines.

The workload client reads responses directly into reusable storage. Its allocation-free
header parser borrows framing fields without building a header map, and delimiter searches
resume at newly received bytes with overlap for split headers. This retains ordinary
HTTP/1.1 framing and validation without assuming fixed Linux or HTTP.sys header lengths.
Control traffic and server requests retain the general-purpose parser.

## Local quickstart

Build the project using the commands in the [README](../README.md).

No manual certificate setup is needed. In one terminal, start the server:

```sh
./scripts/run-server.sh
```

The launcher uses `build/winlin-server`, the **deliberately public** certificate/key
in `certs/benchmark/`.
The bundled identity provides **no trustworthy server authentication**: anyone
can impersonate it. Use only on isolated synthetic benchmark networks.

Existing `server.pem`/`server.key` files in the state directory retain precedence;
a partial custom pair is an error, not a reason to fall back to the public pair.
Override directories with
`--build-dir PATH` and `--state-dir PATH` before native server options.
Individual `--cert` and `--key` options override the TLS defaults.
For example:

```sh
./scripts/run-server.sh --build-dir build-server --state-dir /private/winlin \
  --bind 10.0.0.4 --workers 8
```

Default directories are repository-relative; supplied relative paths use your
current directory. No launcher overwrites certificates/keys, builds, or changes
system-wide host settings. Direct executable invocations remain supported.

Both Linux launchers raise their process's soft file-descriptor limit to at least
524,288 (512K), leaving higher limits and the hard limit unchanged. A lower hard
limit causes a fatal startup error: raise the login/service's hard `nofile` limit
and start a new session or restart the service before retrying. Native executable
invocations bypass this launcher check; descriptor exhaustion remains fatal.

Only one Winlin server may run per machine, regardless of control bind address or
port. Both OS implementations hold an exclusive listener on `127.0.0.1:8444`
without accepting connections. This guard is released automatically on exit,
including crashes; an occupied guard port prevents startup with a clear error.
Linux HTTPS workers retain their independent `SO_REUSEPORT` listeners.

The Linux HTTP control listener defaults to `0.0.0.0:38443` (all IPv4 interfaces), so a
separate client machine can connect without an extra server argument. Use
`--bind 127.0.0.1` for loopback-only testing, or specify an individual test-network
IPv4 address. The instance guard remains loopback-only. Restrict access using
the host firewall and VNet rules. Never expose a benchmark agent to the internet.

The control channel always uses plain HTTP: no control TLS, certificate handshake,
pinning, or cipher configuration. Commands, telemetry, and run IDs are unencrypted
and vulnerable to on-path modification, so restrict these ports to a trusted,
isolated benchmark network. Before each benchmark the client starts a separate data endpoint:
port **38444 for HTTP**, or **38445 for HTTPS/OpenSSL/kTLS**. The server advertises
the effective port and settings; no client connection-transport option is needed.
Only the selected workload endpoint is active during a run. Native server
`--http-port` and `--https-port` override host-selected data ports, which must be
distinct from control. Allow all three ports from the benchmark client only.

One exclusive, automatically issued run lease owns the workload. Concurrent start
requests receive HTTP 409. The client stops the workload after completion or a
caught failure; an abandoned workload expires after its bounded lease. Run IDs
are managed automatically and omitted from results. Plain HTTP
provides no data confidentiality; use synthetic traffic on an isolated network.
Server startup `--workers` configures control workers only; workload workers and
cipher are selected separately by the client. There is no control cipher option.

After upgrading from TLS control, rebuild and restart both client and server.
Port 38443 is unchanged; old target files remain readable and their obsolete
control-cipher value is ignored. Windows needs an HTTP control URL reservation
instead of the old HTTPS reservation/binding; see the Windows migration instructions.
Update firewall/VNet rules as needed. A less common port does not replace isolation.

The client already knows the bundled workload certificate, so no fingerprint entry is needed:

```sh
./scripts/run-client.sh add \
  --host 127.0.0.1 \
  --target .winlin-local/local.json

./scripts/run-client.sh inspect --target .winlin-local/local.json
```

Remote testing uses the same command with the server's IP; no files need copying.
Any reachable client can run benchmarks. Use only an isolated
test network and restrict the port with firewall/VNet rules. Custom workload identities
require `--fingerprint SHA256`; their fingerprint
must be verified independently. This implementation uses exact certificate
pinning, not CA-chain or certificate-expiry validation. Pins are checked when
connecting to an HTTPS workload, not during HTTP registration/inspection; an
unexpected workload certificate is rejected even when no `--fingerprint` was provided.

Registration stores only the endpoint and expected workload certificate pin locally.
Saved targets remain usable across server restarts; existing target files also
remain readable. Files must be owned by the current user with private permissions
(mode `0600`). Client authentication is not supported; TLS server-certificate
verification and automatic benchmark run leases are separate mechanisms.

Alternatively, run `./scripts/run-client.sh` and select **Add server**. It prompts
only for the IP address and port, using the bundled workload certificate pin.
Register a custom workload pin with CLI `add --fingerprint SHA256`; such targets
also appear in the interactive menu when saved in its state directory.
Interactive targets are saved under `$XDG_STATE_HOME/winlin`, or
`~/.local/state/winlin` when that variable is unset. Targets registered with an
explicit `--target` path are usable through the CLI; the interactive menu lists
targets in the state directory.

The client launcher forwards arguments and interactive input unchanged. To use
a separate client build, run `./scripts/run-client.sh --build-dir build-client`
followed by any client command. `--help` shows launcher help; `-- --help` shows
the executable's own help. These help conventions also apply to the Linux server.

### Custom certificates

For a non-public identity, create your own certificate/key outside the fixtures:

```sh
umask 077
mkdir -p .winlin-local
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj '/CN=winlin-test' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout .winlin-local/server.key -out .winlin-local/server.pem
```

The launcher prefers this pair on subsequent starts. Obtain its fingerprint with
`openssl x509 -in .winlin-local/server.pem -outform DER | openssl dgst -sha256`
and pass the 64 hexadecimal digits as `--fingerprint SHA256` when adding a server.
Do not replace an existing endpoint identity unintentionally: saved client pins
will correctly reject a different certificate.

## Running workloads

```sh
./scripts/run-client.sh run --target .winlin-local/local.json \
  --method get --get-size 4KiB \
  --connections 256 --warmup 10 --duration 30 --repetitions 3

./scripts/run-client.sh run --target .winlin-local/local.json \
  --method put --put-size 64KiB \
  --connections 256 --duration 30

./scripts/run-client.sh run --target .winlin-local/local.json \
  --method mixed --get-percent 70 --get-size 4KiB --put-size 16KiB \
  --connections 256 --requests 100000 --duration 30 \
  --output results/mixed.json

# Change server tuning and disable workload TLS without restarting the server:
./scripts/run-client.sh run --target .winlin-local/local.json \
  --tls off --server-workers 32 \
  --workers 16 --connections 1024 --method get --get-size 4KiB
```

Workload TLS defaults to `--tls on` (Linux userspace OpenSSL or Windows Schannel).
`--tls off` selects plain HTTP; `--tls ktls` requests Linux kTLS. These are run
settings sent over HTTP control, not client connection options. Unsupported modes
are rejected, never silently substituted. Server workers default to 8, configurable
from 1 to 256. The server implementation has a fixed ceiling of 65,536 connections
per endpoint, advertised in `limits.max_connections`; it is not a run setting.
Client `--connections` still selects offered load concurrency (up to 16,384).
OS resources may impose a lower practical capacity; the ceiling is not a throughput
or resource-availability guarantee.
The interactive benchmark menu exposes these same settings.

`--get-percent` specifies the GET share by **issued request count**, not bytes.
Mixed requests are interleaved deterministically and the ratio is exact for each
complete group of 100 issued requests. Short or failed runs can have a different
completed-request ratio.

Sizes accept bytes or binary `KiB`/`MiB` suffixes, including custom values up to
64 MiB. The interactive menu advertises 256 B, 512 B, 1, 4, 8, 16, 64, 256 KiB,
1 MiB, and 4 MiB presets; zero-byte objects are also accepted.

The default is 256 connections, 10 seconds of warmup, 30 seconds of measurement,
and 3 repetitions. `--workers` defaults to the smaller of 8, available logical
CPUs, and connection count. Connections are configurable from 1 to 16,384,
subject to file descriptor, memory, server, and other host limits.
`--timeout` bounds connection setup and individual requests (default 10 seconds).

`--requests 0` means duration-only. A nonzero request limit is shared across all
workers and stops new issuance when reached, or when the duration expires,
whichever comes first. In-flight requests are drained, subject to the request
timeout. Reported elapsed time includes that drain; it can exceed the requested
duration. Errors are counted without automatically reconnecting or retrying.
Warmup requests do not consume the measured request limit.

Each repetition establishes its connections before warmup and measurement, then
reuses them throughout both phases. TLS handshakes are excluded from request
latencies and throughput. There is one outstanding request per connection:
HTTP pipelining, HTTP/2, and paced/open-loop arrivals are not implemented.

GET returns bytes from a pre-generated, reusable server buffer. PUT is
acknowledged only after its complete body has been consumed and discarded.
Payload generation happens outside the measured workload. There is no storage
I/O, but encryption, buffering, memory copies, HTTP parsing, and run-ID checks
remain part of the measured stack. An automatically supplied per-run lease is
checked on each request in both HTTP and HTTPS modes. Control and workload traffic
use different listeners in the same process, so telemetry still includes control
overhead.

### Cipher selection and kTLS

TLS workloads default to `TLS_AES_128_GCM_SHA256`. Client `run --cipher`
selects the workload cipher on both ends. Control has no TLS context or cipher;
startup server `--cipher` and client `add --cipher` are not accepted.
Cipher/TLS fields are `null` for plain HTTP workloads. Unsupported selections fail;
there is no silent cipher substitution.

The Windows backend supports the Schannel TLS 1.3 AES-128-GCM/SHA-256 and
AES-256-GCM/SHA-384 suites. It verifies negotiated protocol/algorithm/key size and
rejects requests that do not match `--cipher`. Schannel negotiation itself is
controlled by OS policy, not an OpenSSL-style per-process cipher list. The Linux
client offers exactly its selected suite; setup never rewrites machine-wide
Schannel cipher policy.

Select client `run --tls ktls` or the interactive menu to request kTLS without a
server restart. Discovery advertises kTLS as conditional on kernel/OpenSSL support.
The server verifies the relevant direction on each workload connection; activation
counts are returned through HTTP control telemetry. GET
requires active kTLS TX; PUT requires active kTLS RX. Missing activation causes
explicit rejection, not a userspace run mislabeled as kTLS.

Activation depends on the kernel, OpenSSL build, cipher, and TLS version.
In particular, TX and RX support can differ. The application does not load kernel
modules, tune the host, or configure NIC offload automatically. Socket kTLS
activation is **not** evidence of NIC cryptographic offload.

## Results and limitations

The console shows a compact per-run table of throughput, p50/p99 latency, errors,
and estimated reference cycles per I/O (`Ref CPIO`). Decimal table values use two decimal places;
JSON retains measurement precision. The console also shows run-specific warnings,
such as load-generator CPU saturation or failed requests. General methodology
caveats and backend measurement limitations appear once in the JSON report's
top-level `notes` array, not in the console or each repetition's `warnings`.
Detailed client/server telemetry, CPU utilization percentages, and raw server
counters stay in the JSON file, not the terminal. Report schema version 5
saves supported choices in `server_capabilities`, the HTTP start response's
configuration in `server_run`, and the selected workload endpoint.
Discovery is queried once per run through HTTP control; starting a run returns
its selected settings without a second capability query. Workload endpoints serve
only object GET/PUT, never metadata. Actual TLS/cipher and certificate checks occur
on the load connections, and kTLS is checked by the server per I/O direction.
Connection-specific `tls_version` and `ktls_tx`/`ktls_rx` fields are no longer
reported in `server_run`; kTLS activation counts remain in control telemetry.
Control-channel configuration is not exposed as benchmark capabilities.

CPU utilization uses **100% per logical CPU**, so multi-core utilization can exceed
100%. Each repetition's `server_host` contains OS-visible whole-server busy CPU time
and utilization, separately from application-only `server_process` telemetry.
Linux sums aggregate `/proc/stat` user, nice, system, IRQ and softirq time, excluding
idle, I/O wait and stolen VM time; guest time is not counted twice. Windows uses
`GetSystemTimes`, subtracting idle and covering **every processor group**, including
HTTP.sys/Schannel work charged to System.

On x86_64, a shared implementation calibrates an invariant TSC against
`std::chrono::steady_clock` once before serving requests. RDTSCP reads are fenced;
migrated calibration samples are discarded and at least three samples must agree
within 1% of the median. Calibration frequency, source, sample count and duration
are recorded in `reference_clock`. No frequency files or perf permissions are needed
for this clock calibration.

`server_reference_cycles_per_io` is whole-server busy CPU seconds multiplied by
calibrated TSC frequency, divided by successful completed I/Os. It is an **estimate
in fixed reference-clock units, not measured core-clock cycles**; turbo/throttling
do not change that fixed unit. Different TSC reference rates change the scale, so
compare frequencies alongside CPIO across hosts. A VM clock change requires
restarting the server to recalibrate.

This attributes **all server CPU work** to the benchmark. Use an otherwise idle
server: an exclusive Winlin lease does not exclude other applications. CPU accounting
granularity and sample/control overhead can dominate very short trials; use sustained
runs. Failed requests retain explicit warnings and are not included in the denominator.
Unsupported/unstable TSCs or unavailable CPU accounting leave reference CPIO `null`
in JSON and `N/A` in the table, with a reason printed once. ARM reference clocks
are not implemented yet; host CPU utilization remains available.

Optional raw process-cycle samples remain separate detailed telemetry:
Linux attempts inherited `perf_event_open` hardware cycles; Windows uses
`QueryProcessCycleTime`, excluding work charged to System. Permission/PMU failures
or multiplexing can leave these raw samples unavailable **without preventing
reference CPIO**. Winlin does not change host security policy automatically.
Cache misses, instructions, memory bandwidth and CPU profiling are not collected yet.
JSON output defaults to a uniquely named file under `results/`; `--output`
selects another path. Existing output files are not overwritten on startup.
Completed repetitions are saved as the run progresses, and a caught run failure
is recorded with `status: failed`. Abrupt termination may leave `status: running`.
Target files contain server addresses and certificate pins; results omit run IDs.

Server details put `environment` first, with OS, kernel, architecture and CPU
count, OS-visible total RAM, machine information, and effective process FD limits
before library/build metadata. Linux FD limits include soft/hard values (`"unlimited"`
when applicable); Windows reports these as not applicable.

Machine information uses SMBIOS manufacturer/model evidence, with an explicit
best-effort detection source. Missing or unrecognized firmware is `unknown`, not
assumed bare metal. AWS instance types are taken from firmware when exposed.
Microsoft virtual machines attempt a bounded, proxy-free lookup of only Azure's
link-local IMDS `vmSize` field, cached before measurement; other instance metadata
is never requested. If the SKU cannot be obtained, it remains `null` with a reason.
Other providers' SKUs are currently unavailable unless exposed in supported firmware.

Discovery then lists supported backends (mapped to transport/TLS mode), transports,
TLS versions, cipher choices, HTTP versions, methods, load modes, server worker
range, and immutable limits. kTLS support is conditional, never proof of activation.
Cipher choices describe implementation support; platform/provider policy can still
prevent negotiation, which is checked for each run. Current TLS/cipher/worker/offload
values appear only in the workload's `run` block and benchmark results, not inspection.
JSON output preserves this order rather than sorting keys alphabetically.

Results contain the effective workload and cipher, client/server environment and
build details, backend/offload capabilities, process telemetry snapshots and
deltas, operation counts, object goodput, and overall/per-method latency
histograms. Latency uses monotonic time from request issuance through receipt of
the full response. Percentile estimates use bounded-memory logarithmic buckets
with approximately 1.56% relative bucket width. Latency samples describe
successful requests only; inspect errors and timeouts separately.

Important limitations:

- This is a closed-loop generator. It does not measure latency under a fixed
  external arrival rate and must not be used to claim a latency SLA.
- Server telemetry is process-wide; the server enforces one active benchmark
  lease. Unrelated control requests can still add overhead. Sampling uses the control channel, so CPU and
  counter boundaries slightly exceed the client load interval.
- CPU utilization is reported as core equivalents, not a percentage of the entire
  machine. Peak RSS is the process-lifetime high-water mark, not a run-local peak.
  Load-generator CPU saturation is flagged heuristically, not conclusively ruled
  out.
- Windows process CPU excludes HTTP.sys/Schannel work charged to System. It is
  not total OS CPU cost and must not be used as an apples-to-apples TLS efficiency
  comparison. Results include this scope and a report-level note. Windows context-switch
  and raw connection/handshake counters are currently unavailable and remain
  `null`, rather than zero.
- NUMA placement, affinity, NIC/VM information, network counters,
  instructions, cache misses, memory bandwidth, and kernel profiles are not
  collected yet. Unavailable metrics are listed in capabilities.
- This version supports numeric IPv4 addresses only.
- TLS 1.2, handshake tests, paced load, automated comparative
  reports, and distributed load generators remain future work.

Do not interpret initial loopback results as an OS comparison or evidence that a
100 Gbps server is saturated. Validate client capacity, network limits, workload
correctness, and repeatability on the intended machines before drawing conclusions.
