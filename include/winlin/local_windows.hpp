#pragma once

#include "winlin/windows.hpp"
#include "winlin/local_benchmark.hpp"

namespace winlin {
// Match the documented native ThreadBasicInformation layout without relying on SDK-private
// typedefs. NtQueryInformationThread writes this caller-owned buffer on every kernel query.
struct LocalThreadBasicInformation {
    LONG exit_status;
    PVOID teb;
    HANDLE process_id, thread_id;
    ULONG_PTR affinity;
    LONG priority, base_priority;
};

static_assert(sizeof(LocalThreadBasicInformation) == 48);

// Flatten Windows processor groups for CLI CPU IDs and pin workers to exactly one logical CPU.
// Allocation remains unpinned. Native NT query linkage is resolved explicitly, never replaced
// with a cached Win32 thread-ID API; errors propagate out of the measured worker.
inline LocalOperations windows_local_operations() {
    LocalOperations result;
    result.resolve_cpu = [](int requested) {
        const auto count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        if (!count) {
            throw windows_error("Inspect local benchmark processors");
        }
        const unsigned cpu = requested < 0 ? 0 : static_cast<unsigned>(requested);
        if (cpu >= count) {
            throw std::invalid_argument("Requested logical CPU is outside active processor groups");
        }
        return cpu;
    };
    result.bind_cpu = [](unsigned cpu) {
        WORD group = 0;
        for (; group < GetActiveProcessorGroupCount(); ++group) {
            const auto count = GetActiveProcessorCount(group);
            if (cpu < count) {
                break;
            }
            cpu -= count;
        }
        GROUP_AFFINITY affinity{};
        affinity.Group = group;
        affinity.Mask = KAFFINITY{1} << cpu;
        if (!SetThreadGroupAffinity(GetCurrentThread(), &affinity, nullptr)) {
            throw windows_error("Pin local benchmark thread");
        }
    };
    using QueryThread = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    if (!module) {
        throw windows_error("Find native query library");
    }
    const auto address = GetProcAddress(module, "NtQueryInformationThread");
    if (!address) {
        throw windows_error("Find NtQueryInformationThread");
    }
    static_assert(sizeof(QueryThread) == sizeof(address));
    QueryThread query{};
    std::memcpy(&query, &address, sizeof(query));
    result.query = [query] {
        LocalThreadBasicInformation information{};
        const LONG status =
            query(GetCurrentThread(), 0, &information, sizeof(information), nullptr);
        if (status < 0) {
            throw std::runtime_error("NtQueryInformationThread failed (NTSTATUS " +
                                     std::to_string(status) + ")");
        }
    };
    result.host = host_usage;
    result.process = usage;
    result.environment = environment();
    result.syscall_name = "NtQueryInformationThread(ThreadBasicInformation)";
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    result.page_size = system.dwPageSize;
    return result;
}
}
