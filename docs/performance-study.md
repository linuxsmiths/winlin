# Linux and Windows Performance for XStore-Relevant Workloads

**Review draft, 15 November 2026.** This document describes the study rationale,
benchmark design, and results framework. Environment details and baseline
measurements will be added as they are supplied and reviewed. No final cross-OS
performance conclusions are presented yet.

## 1. Motivation and scope

The purpose of this study is to compare Linux and Windows across operating-system
and native-stack performance dimensions that can affect XStore application
performance. These include network request processing, TLS, memory management,
thread scheduling, synchronization, thread creation, and system-call overhead.

The objective is not to declare one operating system universally faster. It is
to identify the conditions under which each platform uses resources more
efficiently, characterize the latency and throughput consequences, and explain
the mechanisms behind material differences.

Winlin, the benchmark suite used in this study, combines network-driven tests
with server-local microbenchmarks. HTTPS is the main application-facing workload:
it exercises several relevant layers together. The local tests provide narrower
measurements that can help investigate those results.

**This is not an end-to-end XStore benchmark.** It does not execute the XStore
application, reproduce its complete workload, or predict its production
performance. In particular, the current object workload performs no persistent
storage I/O, replication, or durability processing. Any connection between these
measurements and application performance requires application-level validation.

The central questions are:

- How much completed work does each native stack deliver at a given concurrency,
  object size, and latency?
- What server CPU cost accompanies that work, including work outside the server
  process?
- How much load-generator CPU is required, and can it constrain the comparison?
- Which differences come from native stack behavior, configuration, workload
  implementation, or the execution environment?

## 2. Benchmark setup

### 2.1. Roles and topology

A Linux client controls one target server at a time. Linux and Windows servers
are reached over the benchmark virtual network. The client generates GET/PUT
traffic for network tests; for local tests, it only configures the server-side
workload and collects its results.

```text
                         Linux client
                  Control and result collection
                  HTTP/HTTPS load generation
                               |
                    Benchmark virtual network
                               |
                 +-------------+-------------+
                 |                           |
           Linux server                Windows server
       epoll / TCP / OpenSSL        HTTP.sys / Schannel
       Optional verified kTLS       Asynchronous IOCP
                 |                           |
           Shared benchmark settings, object semantics,
                 run ownership, and telemetry schemas
```

The control plane uses a separate plain-HTTP endpoint. The workload plane uses
the explicitly selected HTTP or HTTPS backend. Control traffic is not part of
the request-latency measurement, but its CPU and interface traffic can contribute
to host-wide telemetry.

One exclusive Winlin lease owns the workload on a server. This prevents
overlapping Winlin runs; it does not prevent unrelated machine activity.
Control access must be restricted to the trusted benchmark network.

### 2.2. Environment record

The following inventory must accompany the final results. A matching VM SKU
alone is insufficient evidence of identical processors, topology, or networking.

| Item | Linux client | Linux server | Windows server |
|---|---|---|---|
| VM SKU or physical machine configuration | Pending | Pending | Pending |
| Processor model and logical CPU count | Pending | Pending | Pending |
| SMT, NUMA, affinity, and processor-group layout | Pending | Pending | Pending |
| Memory capacity | Pending | Pending | Pending |
| OS release, kernel/build, and relevant updates | Pending | Pending | Pending |
| NIC, driver, acceleration, and offload configuration | Pending | Pending | Pending |
| MTU, negotiated MSS, and network placement | Pending | Pending | Pending |
| Power policy and relevant resource limits | Pending | Pending | Pending |
| Compiler, optimization settings, and Winlin revision | Pending | Pending | Pending |
| Allocator and TLS library/provider version | Pending | Pending | Pending |
| TCP tuning and temporary experimental rules | Pending | Pending | Pending |
| Calibrated reference-clock frequency | Pending | Pending | Pending |

These are publication requirements, not assumptions about the existing machines.
Missing information is not replaced with the build defaults.

## 3. Design rationale

### 3.1. Native stacks, shared workload semantics

The study compares practical native implementations, rather than forcing both
operating systems to run one portability layer.

Linux uses an epoll-based nonblocking server with OpenSSL. Its optional kTLS
configuration is a distinct backend. Windows uses native HTTP.sys and Schannel,
with asynchronous completion handling through IOCP.

The servers share workload configuration, application-level object semantics,
control routing, and telemetry definitions. Native HTTP parsing, TLS processing,
buffering, scheduling, and transport behavior remain platform-specific.

Consequently, a result compares the reported **application implementation,
runtime, native stack, and OS configuration together**. It does not isolate a
kernel-only effect. For example, HTTP.sys can perform work outside the server
process, and Windows and Linux do not receive identical application-level send
submissions.

Linux builds default to `tcmalloc_minimal`; Windows uses its system runtime
allocator. The allocator must be reported, and allocator-sensitive results must
not be presented as a pure OS comparison.

### 3.2. Remove storage to study request processing

GET returns synthetic, pre-generated object bytes. PUT consumes and discards the
complete request body before acknowledging it. Neither operation accesses
persistent storage.

This removes disk service time and durability work so that HTTP/TLS processing,
networking, memory copies, and CPU costs are easier to observe. It does not remove
memory or runtime costs: large objects still require buffering and data movement.

The default GET mode copies each response from a pre-populated 1 GiB source pool
into reusable private storage. A separate shared-buffer mode provides a hot-data
comparison. Shared versus copy mode changes cache behavior and, on Linux TLS,
application submission layout as well as copying; it is not an isolated
`memcpy` experiment.

Payload generation is outside request processing. Reused storage avoids
unnecessary steady-state allocation, while initial allocation and growth can
still occur during warmup or first use.

### 3.3. Keep the client visible in the analysis

The client is a specialized load generator, not the system whose implementation
we intend to rank. It uses persistent nonblocking connections, reusable buffers,
and bounded-memory latency histograms.

Client CPU is nevertheless a first-class result. A busy client, saturated client
core, NIC limit, or receive-path bottleneck can constrain offered load and make
the server appear to have reached its capacity. Low aggregate client CPU alone
does not rule out a single-thread bottleneck.

Where possible, investigate a suspected client limit by varying client workers
and connections, examining per-core activity, and checking whether throughput
changes. A throughput plateau is not automatically a server limit.

## 4. HTTPS benchmark methodology

### 4.1. Workload contract

The workload uses HTTP/1.1 over persistent connections. HTTPS uses TLS 1.3 and an
explicitly selected cipher; the initial comparison uses
`TLS_AES_128_GCM_SHA256`.

There is one outstanding request per connection. A new request is issued after
the previous response has been fully consumed. HTTP pipelining, HTTP/2,
open-loop arrival pacing, and TLS-handshake benchmarking are not implemented.

Connections are established before a fixed two-second warmup. The same
connections, workers, and buffers are reused across measured repetitions.
Handshake time is excluded from request latency and throughput. In-flight work
is drained subject to timeouts, so measured elapsed time can exceed the requested
load duration.

This is a closed-loop workload. Its latency percentiles describe that workload,
not the queueing behavior of an independently paced production arrival stream.
Failed requests and timeouts must be reported separately from successful-request
latency.

Linux userspace OpenSSL, Linux kTLS, and Windows Schannel are separate result
series. For kTLS, the server verifies the direction relevant to the operation:
TX for GET and RX for PUT. Unsupported activation fails rather than falling back
silently. Socket kTLS activation does not establish NIC cryptographic offload.

### 4.2. Comparison matrix

The final study should vary one major factor at a time before combining factors.
The following is the proposed results matrix, not a claim that every cell has
already been measured.

| Factor | Comparison |
|---|---|
| Method | GET and PUT separately, followed by explicitly defined mixtures |
| Object size | Small-request cases such as 4 KiB, intermediate sizes, and 1 MiB |
| Concurrency | One connection, then a sweep toward the observed capacity plateau |
| Client/server workers | Record both; sweep independently where needed |
| Transport | Plain HTTP control comparison, HTTPS, and verified Linux kTLS |
| GET payload handling | Copy baseline; shared-buffer results labeled separately |
| Duration and repetition | Sustained runs with repeated trials; retain every repetition |

One connection exposes serial request/response behavior; it is not a capacity
test. Higher concurrency explores parallelism, queueing, batching, memory
footprint, and potential client/network limits.

A plain-HTTP comparison is useful context, but subtracting its CPU cost from
HTTPS does not isolate cryptography: buffering, packetization, and scheduling
can also change.

### 4.3. Metrics and their scope

| Metric | Definition and interpretation |
|---|---|
| Completed requests/s | Successful completed operations divided by measured client elapsed time |
| Object goodput | Successfully transferred object bytes per second; excludes protocol overhead |
| Request latency | Request issuance through receipt of the complete response, including PUT-body transmission where applicable |
| p50/p90/p99 | Successful-request percentile estimates from bounded logarithmic histograms, with approximately 1.56% relative bucket width |
| Client CPU | Client-process CPU usage; 100% represents one logical CPU |
| Server CPU | Whole-server busy CPU usage; includes native stack work charged outside the server process and unrelated host activity |
| Server process CPU | Additional process-scoped telemetry; not a substitute for whole-server cost |
| Reference cycles/I/O | Whole-server busy CPU seconds multiplied by calibrated invariant-TSC frequency, divided by successful completed operations |
| Network Gbps | Selected server-interface RX plus TX byte deltas over the server sampling interval; not object goodput or a wire capture |
| Errors and completion state | Required context for every result; an incomplete run is not a successful low-throughput observation |

Reference cycles are **estimated fixed-reference-clock units, not hardware
core-clock cycles**. They do not measure instructions, cache misses, or cycles
spent exclusively in the benchmark thread. Different reference frequencies
change the unit scale and must be considered when comparing hosts.

Host and interface telemetry include activity outside the measured request
loop. Use otherwise idle machines and retain the sampling intervals. Unavailable
measurements remain unavailable rather than becoming zero.

### 4.4. Reproducibility and comparison controls

Baseline comparisons require recorded hardware/topology, software revisions,
effective TLS configuration, offloads, allocator, and workload settings.
Temporary packet edits, corking, custom transport experiments, and buffer tuning
must be absent from the native baseline or explicitly labeled as separate
configurations.

Use the same object sizes, cipher, payload mode, load model, and declared worker
settings for paired runs. Equal worker counts do not imply identical native
stack parallelism, especially with HTTP.sys kernel processing.

Alternate or otherwise balance Linux/Windows run order, repeat complete
invocations, and preserve raw results. Three repetitions in one invocation are
an initial observation, not a confidence interval or proof of significance.
Do not average percentile values and describe the result as a pooled percentile.

Detailed JSON reports require `--output FILE`; console-only invocations do not
save them. Preserve complete and incomplete runs, warnings, and effective
settings. Treat external profiler runs as diagnostic runs because tracing adds
overhead.

## 5. HTTPS results

### 5.1. Result organization

Results will be added incrementally as measurements are supplied for each I/O
size and workload. Earlier diagnostic runs are not automatically promoted into
the comparison baseline. A result becomes part of the study only when its
configuration, measurement scope, and relevant experimental conditions are clear.

Each comparison should identify method, object size, connection count,
client/server workers, backend, cipher, GET payload mode, duration, repetitions,
and source/build revision. Retain the individual repetitions and link to the
supporting report or explicitly identify transcribed console data.

Organize results by method and object size, with one-connection behavior and
concurrency scaling shown separately. Keep native baselines, kTLS comparisons,
and tuning experiments in distinct series.

### 5.2. GET results

**Awaiting measurements.** Add a subsection for each supplied object size. For
each configuration, present successful requests/s, object goodput, per-run
p50/p90/p99 latency, errors, client CPU, whole-server CPU, and reference cost.
Report interface throughput separately from object goodput.

The accompanying analysis should distinguish serial request/response behavior
from capacity, note variability, and identify any demonstrated client, server,
or network constraint. A lower reference cost and a higher throughput are
different findings; neither alone describes the full result.

### 5.3. PUT results

**Awaiting measurements.** Use the same organization as GET, while emphasizing
that a successful operation requires the server to consume the entire body
before acknowledging it. Native TLS receive processing and client transmit
cost are part of the comparison.

### 5.4. Backend comparisons and mixed workloads

**Awaiting measurements.** Introduce HTTP, userspace HTTPS, and verified kTLS
comparisons only when otherwise matched runs are available. For mixtures,
state the GET share by issued request count, both object sizes, and the achieved
completed-request and byte mix.

Separate experimental transport changes from these baseline results. Include a
causal explanation only where supporting measurements establish it; otherwise
label the explanation as a hypothesis.

### 5.5. Figures and interpretation

Planned figures are throughput versus connections, reference cost versus object
size, client CPU versus delivered goodput, and tail latency versus offered
concurrency. Each figure must identify configuration, units, repetition
variability, and its raw-data source.

## 6. Supporting server-local benchmarks

These tests run on the selected server, not on the client. They investigate
narrower costs relevant to request-serving software; they do not prove which
mechanism limits HTTPS or which primitives XStore uses.

| Benchmark | Operation | Relevance and principal limitation |
|---|---|---|
| Same-CPU handoff | Condition-variable token ring pinned to one logical CPU | Scheduling and synchronization interaction; handoffs are not substituted for measured context switches |
| Cross-CPU handoff | Two pinned participants exchange the token | Synchronization and communication across selected CPU relationships; native spinning can avoid actual sleeps |
| Syscall | Linux `gettid` syscall or Windows `NtQueryInformationThread` | Small native kernel queries; the two APIs perform different work |
| Allocation | Live batches of `malloc`/`free`, optionally touching pages | Allocator/runtime and memory behavior; default allocators differ |
| Page fault | First byte write to each base page of a fresh region | First-touch provisioning; reservation/commit/release excluded, physical-page pool warmth uncontrolled |
| Thread creation | Sequential child creation, entry, exit, and join | Runtime plus OS lifecycle cost; stack/TLS caching remains enabled |
| Lock contention | Shared `std::mutex` protecting one counter increment | Contention, native spinning/parking, and fairness; acquisition latency is periodically sampled |

Local results will be added as measurements and native environment details are
supplied, recording measurement boundaries for each workload. Large handoff differences must not
be labeled scheduler-switch latency without evidence of actual descheduling.
Distinct CPU numbers do not establish separate physical cores or NUMA nodes.
Likewise, observed process page faults are not interchangeable with pages touched.

See [the local benchmark definitions](local-benchmarks.md) for precise operation
units, native APIs, affinity rules, and sampling limitations.

## 7. Conclusions and publication requirements

The framework provides a way to compare native request-serving stacks while
retaining the measurements needed to investigate differences. Its main value
is the combination of application-facing HTTPS results and narrower local
measurements, not a composite OS score.

The draft is a methodology and results framework. Before making externally shareable
performance claims, complete the environment record, freeze the source/build
and native baseline settings, archive repeated paired runs, resolve material
measurement questions, and distinguish observed effects from causal explanations.

Document any client, server, or network capacity limit. Separate stock/native
baselines from tuning experiments. Verify Windows behavior through native
execution rather than treating a Linux cross-build as runtime validation.

The final narrative should state where a finding is relevant to an XStore
engineering decision, and where an application-level experiment is still needed.
It should not extrapolate these synthetic tests into an end-to-end XStore
throughput or cost claim.

## Appendix A. Reproducing the HTTPS configuration

After registering targets and establishing the native baseline, this example
saves a new report for a one-connection, 1 MiB GET workload:

```sh
./build/winlin run --target linux.json \
  --benchmark https --tls on \
  --method get --get-response-data copy --get-size 1MiB \
  --connections 1 --workers 1 --server-workers 16 \
  --duration 30 --requests 0 --repetitions 3 --timeout 10 \
  --cipher TLS_AES_128_GCM_SHA256 \
  --output results/linux-https-get-1mib-c1.json
```

Repeat with the Windows target and a distinct output path. Use fresh output
paths for later trials. This command records workload settings; it does not
establish or reconstruct the machine and network configuration by itself.

Operational details are in the [HTTPS guide](https.md) and
[Windows setup guide](windows.md).

## Appendix B. Document source and publication format

Markdown is the editable, version-controlled source. It supports embedded images,
captions, tables, links, and code blocks. High-quality diagrams and charts are
separate versioned assets; Markdown does not restrict their visual quality.
Prefer PNG for predictable image embedding across GitHub and Word. Keep vector
originals where useful and export publication-sized images from them.

Word is a publication artifact, not a second independently edited source.
Pandoc can convert this document and its images to `.docx`; a reference Word
document can supply fonts, heading styles, and page layout later.

From the repository root, with Pandoc installed:

```sh
pandoc docs/performance-study.md \
  --from=markdown --standalone --toc --resource-path=docs \
  --output=/tmp/winlin-performance-study.docx
```

The export has not been generated or visually validated for this draft. Before
distribution, check table widths, figure resolution, captions, pagination, and
the table of contents in Word. Resolve the draft markers and pending evidence,
and remove or revise these editorial instructions for the final audience.
