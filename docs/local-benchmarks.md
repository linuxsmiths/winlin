# Server-local benchmarks

The Linux client controls these tests through the ordinary HTTP control endpoint.
The selected Linux or Windows server runs the operation loop locally; the client
does not generate network load. Local and network workloads share the exclusive
run lease, including abandonment expiry and explicit stop/join cleanup.

```sh
winlin run --target linux.json --benchmark context-switch \
  --server-cpu 2 --duration 30 --repetitions 3

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

**Context-switch:** exactly two threads are pinned to the same logical CPU and
exchange a token using a mutex and condition variable, without a userspace spin
loop. Each full ping-pong counts two directed handoffs. Reported mean handoff
latency is half the measured round-trip mean, not a directly timed one-way
latency. Handoffs are not substituted for actual scheduler context switches.
Native mutex/wait implementations differ across platforms and are part of the
measurement. Scheduler counters, when available, cover the entire server
process, including HTTP control threads; Windows currently reports them as
unavailable. The JSON includes their rate and the round-trip mean separately.

**Syscall:** Linux calls `syscall(SYS_gettid)` explicitly; Windows calls
`NtQueryInformationThread(ThreadBasicInformation)` on the current thread. These
enter the kernel rather than reading a cached userspace thread ID. They do
different amounts of kernel work, so this is a labeled minimal-query comparison,
not a measurement of pure CPU privilege-transition cost. Timing and cancellation
checks occur between batches of 256 queries. Loop, checked API call, and shared
dispatch overhead remain included.

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

## Affinity, accounting, and limitations

Omitting `--server-cpu` selects an allowed Linux CPU or Windows CPU zero.
An explicit CPU is validated; failure to pin any participant fails the run.
Windows CPU indices are flattened across processor groups; Linux indices use
native logical CPU numbering. The actual selected CPU is reported. Allocation
workers are not pinned in this first version.

A fixed two-second warmup precedes repetitions, except for page-fault's single
untimed region. Workers are created for each
stage outside sampling, so per-thread allocator caches can be cold even after
global warmup. Setup, joins, and partial-allocation cleanup are outside measurement
boundaries; workers park while final CPU counters are captured.

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
