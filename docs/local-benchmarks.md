# Server-local benchmarks

The Linux client controls these tests through the ordinary HTTP control endpoint.
The selected Linux or Windows server runs the operation loop locally; the client
does not generate network load. Local and network workloads share the exclusive
run lease, including abandonment expiry and explicit stop/join cleanup.

```sh
winlin run --target linux.json --benchmark context-switch \
  --server-cpu 2 --duration 30 --repetitions 3

winlin run --target windows.json --benchmark context-switch \
  --threads 1024 --server-cpu 2 --duration 30 --repetitions 3

winlin run --target windows.json --benchmark thread-create \
  --duration 10 --repetitions 3

winlin run --target linux.json --benchmark lock-contention \
  --server-workers 8 --latency-sample-every 1024 --duration 30 --repetitions 3

winlin run --target windows.json --benchmark syscall \
  --operation minimal-query --server-cpu 2 --duration 30 --repetitions 3

winlin run --target linux.json --benchmark allocation \
  --allocation-size 4KiB --live-allocations 16 --memory-touch none \
  --server-workers 1 --duration 30 --repetitions 3

winlin run --target linux.json --benchmark page-fault \
  --region-size 64MiB --server-cpu 2 --repetitions 3
```

Use `--output FILE` for a detailed JSON report; otherwise only console output is
created. The menu's **Run server-local benchmark** entry exposes the same options.
Existing network commands still default to `--benchmark https`; `--tls off`
continues to select their HTTP workload. Local benchmarks reject network-only
options, including TLS, connections, client workers, and GET/PUT sizes.
Telemetry and stop replies contain the full completed repetition history.
The client accepts control response bodies up to 16 MiB, covering the supported
1000 repetitions; HTTP headers remain limited to 16 KiB.

## Workload definitions

**Page-fault:** one fresh anonymous/private region per repetition, sized by
`--region-size` (default 64 MiB, maximum 1024 MiB). Region size must be a multiple
of the native base page size. A single pinned worker writes one volatile byte
per page exactly once. One operation means one first-touch base page, not one
inferred OS fault. This is a fixed-work pass and rejects `--duration`.

Reservation and access enablement/commit finish before both CPU and wall-time
boundaries. Workers park after touching, counters are sampled, and only then is
the region released. One untimed warmup region precedes the repetitions; every
measured repetition still uses a fresh region. No revisit or allocation/free
work is included in cycles/page.

Linux uses private anonymous `mmap`, `mprotect`, and `MADV_NOHUGEPAGE` on this
mapping only; there is no global THP change or eager page population. Windows
uses ordinary-page `VirtualAlloc` reservation and commit. Linux access enablement
is not equivalent to Windows commit charging, but neither setup is measured.
First touch includes demand-zero handling, page-table work, and a byte store.
The native page size and backend are reported; large/huge pages are not used.

Observed fault deltas cover the server process, including control and sampling
activity. Linux distinguishes minor/major faults; Windows provides a total with
minor/major unavailable. Page writes and observed faults need not match one for
one. Reference cycles use whole-server CPU samples and include boundary sampling
and background work. Short passes can be dominated by CPU-counter granularity;
prefer larger regions on otherwise idle, comparable hosts.

**Context-switch:** `--threads` selects 2–1024 participants (default two), all
pinned to the same logical CPU. A shared mutex protects a token; each participant
has its own condition variable and wakes only its successor, with the last waking
the first. There is no userspace spin loop or wake-all on steady-state handoffs.
Thread zero checks the deadline between complete laps and counts one directed
handoff per participant per lap. A final lap may extend beyond the duration.
Clock/check overhead is amortized once per lap, so it contributes less per
handoff as participant count increases.
Mean handoff latency is amortized lap time divided by participant count, not a
directly timed one-way latency. Two participants retain the round-trip fields
and console label; larger rings report mean lap time separately.

This stresses a larger thread/synchronization/cache footprint, not a run queue
of 1024 runnable tasks: normally only the current participant and its successor
are runnable. Compare 2, 8, 32, 128, and 1024 threads on an otherwise idle CPU.
Metadata identifies `blocking-cv-ring-v1`. Even the two-thread case now uses
dedicated signals, so rerun the baseline when comparing against the older
single-condition-variable implementation. Shutdown/failure wakes all blocked
participants; normal final wakeups remain inside the sampling interval.
Thread creation, joins, and stack release remain outside measurement.
Native thread/resource failures fail the run rather than reducing thread count.

Handoffs are not substituted for actual scheduler context switches.
Native mutex/wait implementations differ across platforms and are part of the
measurement. Scheduler counters, when available, cover the entire server
process, including HTTP control threads; Windows currently reports them as
unavailable. The JSON includes their rate, completed ring laps, and mean lap time.

**Syscall:** Linux calls `syscall(SYS_gettid)` explicitly; Windows calls
`NtQueryInformationThread(ThreadBasicInformation)` on the current thread. These
enter the kernel rather than reading a cached userspace thread ID. They do
different amounts of kernel work, so this is a labeled minimal-query comparison,
not a measurement of pure CPU privilege-transition cost. Timing and cancellation
checks occur between batches of 256 queries. Loop, checked API call, and shared
dispatch overhead remain included.

**Thread-create:** one creator repeatedly constructs a `std::thread`, waits for
it to exit using `join`, and only then starts another. The child's only body
records its entry timestamp and returns. Neither creator nor child receives an
explicit affinity setting; inherited process/CPU restrictions still apply.
`--server-cpu`, `--threads`, and `--server-workers` are rejected.

Startup latency spans the timestamp before construction to the child's entry
stamp, including runtime startup and scheduling. Lifecycle latency spans that
same initial timestamp to the return from `join`, including exit and cleanup.
The console reports mean/p50/p99 startup and lifecycle times in microseconds,
completed lifecycles/s, whole-server CPU, and reference cycles/lifecycle.
The JSON also retains amortized `mean_operation_ns` for the entire creator loop,
which includes bookkeeping and is distinct from the timed lifecycle mean.
Bounded logarithmic histograms produce percentile upper bounds within 1.5625%;
only summaries are sent, not individual samples or bucket dumps.

Child creation, exit, and join are inside measurement; outer creator setup and
teardown are outside it. Per-operation timestamps and histogram bookkeeping
add instrumentation overhead. Timestamp cost is included in lifecycle timing;
throughput and CPU cost also include recording the histogram samples.
This compares C++ runtime plus OS lifecycle cost, not a bare kernel thread API.
Runtime stack/TLS caching and the reported build allocator remain enabled, so
the ordinary two-second warmup does not represent cold thread startup.
Native deferred cleanup may continue after join; this measures the join-visible
lifecycle, not complete global resource reclamation.
Cancellation joins the current child before stopping; creation failures
propagate to the coordinator and preserve earlier completed repetitions.

**Allocation:** each worker allocates `live-allocations` blocks of the selected
size and then frees the entire batch. One operation is a complete allocation/free
pair. `--memory-touch none` adds no application writes to block contents;
`pages` writes at native page-size intervals and at the block's final byte.
Page sizes are platform-dependent. The existing build allocator is reported in
environment metadata: Linux's default tcmalloc versus Windows's runtime
allocator is an allocator-plus-platform comparison, not OS overhead alone.
The live allocation-size/count/worker product is capped at 1 GiB; allocator
metadata and overhead are additional. Blocks and pointer storage are worker-owned.
Clock/cancellation checks are amortized across repeated small batches (at most
256 pairs and 64 KiB of requested allocation work between checks, unless one
live batch itself exceeds those bounds).

**Lock-contention:** 1–256 unpinned workers (default eight) compete for one shared
`std::mutex`. Each operation locks it, increments one protected 64-bit counter,
and unlocks it. There is no I/O, artificial delay, or configurable critical-section
work in this version. One worker provides an uncontended baseline. All workers
finish setup before sampling and park after their operation loops; mutex and
counter state are fresh for each stage.

Report completed operations/s, amortized mean operation time, whole-server CPU,
and reference cycles/operation. Per-worker completed counts are retained in JSON;
the console shows their minimum and maximum. The protected counter must equal
the sum of completed operations, otherwise the run fails. Zero progress from an
individual worker is reported honestly, not converted into an unavailable value.
Uneven progress can reflect mutex behavior, scheduling, and initial wake delays;
it is not by itself proof of a particular fairness policy.

Acquisition latency spans immediately before locking to immediately after
successful acquisition, excluding the protected increment and unlock. Each
worker samples its first operation and then every `--latency-sample-every`
operations (default 1024, range 1–1048576). Mean/p50/p99 in microseconds and the
sample count are reported separately from amortized whole-operation timing.
Worker-local bounded histograms are merged only after CPU sampling.

Sampled acquisitions include clock overhead; their second timestamp extends
the critical section. Histogram recording is outside the lock but still costs
CPU and reduces throughput. Periodic sampling can miss or correlate with
scheduler events, so these are sampled observations, not a complete latency
distribution. Deadline checks happen every 256 operations per worker; stop and
failure flags are checked before each acquisition. An in-flight acquisition
finishes before exit, so duration and cancellation can overshoot while waiting.
No worker parks or joins while holding the benchmark mutex.

This measures C++ runtime plus OS synchronization, including native internal
spinning/parking, scheduling, and cache-coherence effects. It does not substitute
an application spinlock. Inherited affinity, SMT/NUMA layout, background load,
and worker count affect results; explicit CPU pinning is not offered in this
version. Compare equivalent CPU availability and topology on both servers.

## Affinity, accounting, and limitations

Omitting `--server-cpu` selects an allowed Linux CPU or Windows CPU zero.
An explicit CPU is validated; failure to pin any participant fails the run.
Windows CPU indices are flattened across processor groups; Linux indices use
native logical CPU numbering. The actual selected CPU is reported. Allocation
workers are not pinned in this first version.
Thread-create's creator and children are also not explicitly pinned.
Lock-contention workers are not explicitly pinned either; those two benchmarks
reject `--server-cpu`.

A fixed two-second warmup precedes repetitions, except for page-fault's single
untimed region. Workers are created for each
stage outside sampling, so per-thread allocator caches can be cold even after
global warmup. Outer worker setup/joins and partial-allocation cleanup are outside
measurement boundaries; workers park while final CPU counters are captured.
Thread-create's child creation and joins are deliberately inside those boundaries.

The console reports operations/s, **amortized mean** nanoseconds/operation,
whole-server average CPU usage, and reference cycles/operation. The mean is not
a latency percentile; for multiple allocation workers it uses the sum of their
elapsed operation-loop times divided by total pairs. Batch completion can extend
a run beyond its requested duration.

Reference cycles use whole-server busy CPU time times calibrated invariant-TSC
frequency, divided by completed operations, just like network reference CPIO.
Use an otherwise idle host: control sampling, unrelated processes, and OS
background activity contribute. Unavailable cycles/counters are null or `N/A`,
never zero. Reports retain completed repetitions if a later worker fails; the
run is marked failed/incomplete and the client exits nonzero. SIGINT/SIGTERM
requests stop and join cleanup; unreachable cleanup relies on the bounded lease.

Linux native tests exercise actual local workloads without acquiring the server
guard. Windows cross-builds are not native runtime validation: run the Windows
`local-benchmarks` CTest and integration tests before treating its results as
validated.
