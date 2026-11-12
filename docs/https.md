# HTTPS benchmark

This is a working starting point, not a fully tuned cross-OS benchmark.
For Windows server provisioning, see the [Windows guide](windows.md).

## Supported today

- Linux OpenSSL userspace and explicitly requested OpenSSL+kTLS server backends.
- Windows HTTP.sys/Schannel with the same control and workload API.
- HTTP/1.1 over TLS 1.3, with one explicitly selected TLS cipher suite.
- Persistent GET, PUT, or mixed workloads with configurable object sizes,
  connections, worker threads, warmup, duration, request limit, and repetitions.
- Interactive target selection and benchmark configuration, or noninteractive
  `pair`, `inspect`, and `run` commands.
- Client/server process CPU time, peak resident memory, available context switches, server
  operation counters, latency histograms, throughput, and saved JSON results.

The Linux server and client multiplex nonblocking TLS connections using epoll.
Connections are distributed across a configurable number of worker threads,
rather than creating one thread per connection. The server uses SO_REUSEPORT
listeners. Windows uses HTTP.sys, Schannel and IOCP for asynchronous HTTP
processing. Shared agent logic and a shared HTTPS contract test keep
authentication, discovery, object semantics, and result fields aligned.
Both implementations still need tuning and validation on large machines.

## Local quickstart

Build the project using the commands in the [README](../README.md).

No manual certificate setup is needed. In one terminal, start the server:

```sh
./scripts/run-server.sh
```

The launcher uses `build/winlin-server`, the **deliberately public** certificate/key
in `certs/benchmark/`. Authentication is disabled by default on both OSes:
no token files, credential transfer, or authentication prompts are needed.
The bundled identity provides **no trustworthy server authentication**: anyone
can impersonate it. Use only on isolated synthetic benchmark networks.

Existing `server.pem`/`server.key` files in the state directory retain precedence;
a partial custom pair is an error, not a reason to fall back to the public pair.
Override directories with
`--build-dir PATH` and `--state-dir PATH` before native server options.
Individual `--cert` and `--key` options override the TLS defaults.
Explicit `--token-file FILE` enables optional authentication; existing token and
session files are otherwise ignored, not deleted.
For example:

```sh
./scripts/run-server.sh --build-dir build-server --state-dir /private/winlin \
  --bind 10.0.0.4 --workers 8
```

Default directories are repository-relative; supplied relative paths use your
current directory. No launcher resets pairing, overwrites existing credentials,
builds, or changes system-wide host settings. An explicit missing `--token-file`
remains an error. Direct executable invocations remain supported.

Both Linux launchers raise their process's soft file-descriptor limit to at least
524,288 (512K), leaving higher limits and the hard limit unchanged. A lower hard
limit causes a fatal startup error: raise the login/service's hard `nofile` limit
and start a new session or restart the service before retrying. Native executable
invocations bypass this launcher check; descriptor exhaustion remains fatal.

Only one Winlin server may run per machine, regardless of HTTPS bind address or
port. Both OS implementations hold an exclusive listener on `127.0.0.1:8444`
without accepting connections. This guard is released automatically on exit,
including crashes; an occupied guard port prevents startup with a clear error.
Linux HTTPS workers retain their independent `SO_REUSEPORT` listeners.

The Linux HTTPS listener defaults to `0.0.0.0:8443` (all IPv4 interfaces), so a
separate client machine can connect without an extra server argument. Use
`--bind 127.0.0.1` for loopback-only testing, or specify an individual test-network
IPv4 address. The instance guard remains loopback-only. Restrict access using
the host firewall and VNet rules. Never expose a benchmark agent to the internet.

The client already knows the bundled certificate, so no fingerprint entry is needed:

```sh
./scripts/run-client.sh pair \
  --host 127.0.0.1 \
  --target .winlin-local/local.json

./scripts/run-client.sh inspect --target .winlin-local/local.json
```

Remote testing uses the same command with the server's IP; no files need copying.
Any reachable client can run benchmarks in this default mode. Use only an isolated
test network and restrict the port with firewall/VNet rules. Custom identities
require `--fingerprint SHA256`; their fingerprint
must be verified independently. This implementation uses exact certificate
pinning, not CA-chain or certificate-expiry validation; a different certificate
is rejected, even when no `--fingerprint` was provided.

Default registration is repeatable and stores the endpoint, certificate pin, and
cipher locally, without an access credential. Existing unauthenticated targets
remain usable across server restarts.

For optional authenticated mode, create a private token with
`(umask 077; openssl rand -hex 32 > /path/to/new-pairing-token)` at a new path and
start the server with `--token-file /path/to/new-pairing-token`. Transfer that file
privately to the client and pass `--token-file FILE` to CLI `pair`. The client checks
the pin before sending credentials, but the public fixture still cannot establish
a trustworthy identity. Use a custom identity when authentication matters.
Explicit token pairing consumes the bootstrap credential and exchanges it
for a persistent access credential. The server saves this in
`PAIRING-TOKEN-FILE.session` by default; `--session-file` overrides the location.
The client saves its credential and certificate pin in the target JSON file.
Linux files must remain private to their owner (mode `0600`); Windows credentials
require an owner-only DACL that may also grant SYSTEM and Administrators access.
Restarting the
server preserves the pairing. Currently one controller credential is supported;
additional independent controller identities and credential rotation are future
work.

To deliberately reset pairing, stop the server, remove its specific session
credential file and the corresponding client target file, generate a fresh
bootstrap credential, and restart. Do not delete these files during a run.

Alternatively, run `./scripts/run-client.sh` and select **Add server**. It prompts
only for the IP address, port, and cipher. The bundled certificate
is accepted automatically with a warning; custom certificates still require
fingerprint confirmation.
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
and pass the 64 hexadecimal digits as `--fingerprint SHA256` when pairing.
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
```

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
I/O, but encryption, buffering, memory copies, HTTP parsing, and authentication
remain part of the measured stack. Credentials are checked on each request;
control and workload endpoints currently share the HTTPS listener.

### Cipher selection and kTLS

Both processes default to `TLS_AES_128_GCM_SHA256`. Start the server with
`--cipher SUITE` and pair the client with the same option to choose a different
OpenSSL-supported TLS 1.3 cipher. A run can override the saved client selection
with `--cipher`, but must match the server's configured suite. Unsupported
selections fail; there is no silent cipher substitution.

The Windows backend supports the Schannel TLS 1.3 AES-128-GCM/SHA-256 and
AES-256-GCM/SHA-384 suites. It verifies negotiated protocol/algorithm/key size and
rejects requests that do not match `--cipher`. Schannel negotiation itself is
controlled by OS policy, not an OpenSSL-style per-process cipher list. The Linux
client offers exactly its selected suite; setup never rewrites machine-wide
Schannel cipher policy.

Start a separate server with `--backend ktls` to request kTLS. Server capabilities
report actual transmit and receive activation on the discovery connection, and
the server verifies the relevant direction on each workload connection. GET
requires active kTLS TX; PUT requires active kTLS RX. Missing activation causes
explicit rejection, not a userspace run mislabeled as kTLS.

Activation depends on the kernel, OpenSSL build, cipher, and TLS version.
In particular, TX and RX support can differ. The application does not load kernel
modules, tune the host, or configure NIC offload automatically. Socket kTLS
activation is **not** evidence of NIC cryptographic offload.

## Results and limitations

The console shows throughput, p50/p99 latency, errors, and measurement warnings.
JSON output defaults to a uniquely named file under `results/`; `--output`
selects another path. Existing output files are not overwritten on startup.
Completed repetitions are saved as the run progresses, and a caught run failure
is recorded with `status: failed`. Abrupt termination may leave `status: running`.
Treat target files as secrets; result files deliberately omit access credentials.

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
- Server telemetry is process-wide. Use one controller/run per server; exclusive
  run leasing is not implemented. Sampling uses the control channel, so CPU and
  counter boundaries slightly exceed the client load interval.
- CPU utilization is reported as core equivalents, not a percentage of the entire
  machine. Peak RSS is the process-lifetime high-water mark, not a run-local peak.
  Load-generator CPU saturation is flagged heuristically, not conclusively ruled
  out.
- Windows process CPU excludes HTTP.sys/Schannel work charged to System. It is
  not total OS CPU cost and must not be used as an apples-to-apples TLS efficiency
  comparison. Results include this scope and a warning. Windows context-switch
  and raw connection/handshake counters are currently unavailable and remain
  `null`, rather than zero.
- NUMA placement, affinity, NIC/VM information, network counters, hardware cycles,
  instructions, cache misses, memory bandwidth, and kernel profiles are not
  collected yet. Unavailable metrics are listed in capabilities.
- This version supports numeric IPv4 addresses only. The server defaults to
  eight workers or the available logical CPU count, whichever is smaller.
- TLS 1.2, handshake tests, paced load, automated comparative
  reports, and distributed load generators remain future work.

Do not interpret initial loopback results as an OS comparison or evidence that a
100 Gbps server is saturated. Validate client capacity, network limits, workload
correctness, and repeatability on the intended machines before drawing conclusions.
