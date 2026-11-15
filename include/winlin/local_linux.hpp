#pragma once

#include "winlin/linux.hpp"
#include "winlin/local_benchmark.hpp"
#include <sched.h>
#include <sys/mman.h>

namespace winlin {
// Resolve an allowed logical CPU from the service's inherited affinity, not host CPU numbering
// alone. Explicit CPUs outside the process cpuset are rejected before acquiring worker affinity.
inline LocalOperations linux_local_operations() {
    LocalOperations result;
    result.resolve_cpu = [](int requested) {
        cpu_set_t allowed;
        CPU_ZERO(&allowed);
        if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
            throw system_error("Inspect local benchmark CPU affinity");
        }
        if (requested >= 0) {
            if (requested >= CPU_SETSIZE || !CPU_ISSET(requested, &allowed)) {
                throw std::invalid_argument("Requested logical CPU is outside server affinity");
            }
            return static_cast<unsigned>(requested);
        }
        for (unsigned cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
            if (CPU_ISSET(cpu, &allowed)) {
                return cpu;
            }
        }
        throw std::runtime_error("No allowed local benchmark CPU");
    };
    result.bind_cpu = [](unsigned cpu) {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        CPU_SET(cpu, &affinity);
        if (sched_setaffinity(0, sizeof(affinity), &affinity) != 0) {
            throw system_error("Pin local benchmark thread");
        }
    };
    result.query = [] {
        if (::syscall(SYS_gettid) < 0) {
            throw system_error("Minimal gettid syscall");
        }
    };
    result.host = host_usage;
    result.process = usage;
    result.environment = environment();
    result.syscall_name = "syscall(SYS_gettid)";
    const auto page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        throw system_error("Inspect allocation page size");
    }
    result.page_size = static_cast<std::size_t>(page_size);
    result.reserve_commit = [](std::size_t size) -> void* {
        void* region = mmap(nullptr, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (region == MAP_FAILED) {
            throw system_error("Reserve page-fault region");
        }
        // Disable THP only on this mapping. mprotect enables access but does not populate pages
        // or provide Windows-style commit accounting; that native difference stays explicit.
        if (madvise(region, size, MADV_NOHUGEPAGE) != 0 ||
            mprotect(region, size, PROT_READ | PROT_WRITE) != 0) {
            const auto error = system_error("Prepare ordinary page-fault region");
            if (munmap(region, size) != 0) {
                log_warning(system_error("Release failed page-fault setup").what());
            }
            throw error;
        }
        return region;
    };
    result.release_region = [](void* region, std::size_t size) {
        if (munmap(region, size) != 0) {
            throw system_error("Release page-fault region");
        }
    };
    result.page_faults = [] {
        rusage counters{};
        if (getrusage(RUSAGE_SELF, &counters) != 0) {
            throw system_error("Sample process page faults");
        }
        return Json{{"total", counters.ru_minflt + counters.ru_majflt},
                    {"minor", counters.ru_minflt},
                    {"major", counters.ru_majflt}};
    };
    result.memory_backend = "mmap anonymous private / mprotect; MADV_NOHUGEPAGE per region";
    return result;
}
}
