#pragma once

#include "winlin/core.hpp"

#include <memory>
#include <cstddef>
#include <cstring>
#include <span>

#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <psapi.h>
#include <ws2tcpip.h>

namespace winlin {
inline std::runtime_error windows_error(std::string message, DWORD code = GetLastError()) {
    return std::runtime_error(std::move(message) + " (Windows error " + std::to_string(code) + ")");
}

// Size in UTF-16 code units first, then convert strictly; byte counts are not wide-character
// counts.
inline std::wstring wide(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                         static_cast<int>(text.size()), nullptr, 0);
    if (!size) {
        throw windows_error("Invalid UTF-8 path");
    }
    std::wstring result(size, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                             static_cast<int>(text.size()), result.data(), size)) {
        throw windows_error("UTF-8 conversion");
    }
    return result;
}

// Reject invalid native text rather than storing a lossy path or server argument in JSON.
inline std::string utf8(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    const int size =
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                            static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!size) {
        throw windows_error("Invalid Unicode argument");
    }
    std::string result(size, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                             static_cast<int>(text.size()), result.data(), size, nullptr,
                             nullptr)) {
        throw windows_error("Unicode conversion");
    }
    return result;
}

// Own a kernel handle for native helpers and the IOCP runtime. The handle is never copied; callers
// fill value with the API's out parameter and release dependent operations before destruction.
struct Handle {
    HANDLE value{};

    explicit Handle(HANDLE handle = nullptr) : value(handle) {
    }

    ~Handle() {
        reset();
    }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    void reset() {
        if (value && value != INVALID_HANDLE_VALUE && !CloseHandle(value)) {
            log_warning(windows_error("CloseHandle").what());
        }
        value = nullptr;
    }
};

inline void randomize(std::span<char> buffer) {
    const auto status =
        BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(buffer.data()),
                        static_cast<ULONG>(buffer.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        throw std::runtime_error("BCryptGenRandom failed: " + std::to_string(status));
    }
}

inline double filetime_seconds(FILETIME value) {
    ULARGE_INTEGER integer{};
    integer.LowPart = value.dwLowDateTime;
    integer.HighPart = value.dwHighDateTime;
    return static_cast<double>(integer.QuadPart) / 1e7;
}

// Snapshot application CPU/working set only. HTTP.sys and Schannel work charged to System is not
// included, and unsupported context-switch counts stay null rather than appearing artificially low.
inline Json usage() {
    FILETIME creation{}, exit{}, kernel{}, user{};
    PROCESS_MEMORY_COUNTERS memory{};
    memory.cb = sizeof(memory);
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user) ||
        !GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof(memory))) {
        throw windows_error("Cannot collect process telemetry");
    }
    ULONG64 cycles{};
    const bool cycles_available = QueryProcessCycleTime(GetCurrentProcess(), &cycles) != FALSE;
    const auto cycles_error = cycles_available ? ERROR_SUCCESS : GetLastError();
    return {{"cpu_cycles", cycles_available ? Json(cycles) : Json(nullptr)},
            {"cpu_cycles_source", cycles_available ? Json("QueryProcessCycleTime") : Json(nullptr)},
            {"cpu_cycles_unavailable_reason",
             cycles_available ? Json(nullptr)
                              : Json(windows_error("QueryProcessCycleTime", cycles_error).what())},
            {"user_cpu_seconds", filetime_seconds(user)},
            {"system_cpu_seconds", filetime_seconds(kernel)},
            {"peak_rss_bytes", memory.PeakWorkingSetSize},
            {"voluntary_context_switches", nullptr},
            {"involuntary_context_switches", nullptr}};
}

inline Json environment() {
    using VersionFunction = LONG(WINAPI*)(OSVERSIONINFOW*);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto address = module ? GetProcAddress(module, "RtlGetVersion") : nullptr;
    VersionFunction version_function{};
    static_assert(sizeof(version_function) == sizeof(address));
    // RtlGetVersion avoids compatibility-manifest version lies; memcpy avoids a nonportable cast.
    std::memcpy(&version_function, &address, sizeof(address));
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (!version_function || version_function(&version) != 0) {
        throw std::runtime_error("Cannot determine Windows build");
    }
    if (version.dwBuildNumber < 20348) {
        throw std::runtime_error("Windows Server 2022 or Windows 11 (TLS 1.3) is required");
    }
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    if (system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
        throw std::runtime_error("This Windows backend currently supports x86_64 only");
    }
#ifdef _MSC_VER
    const auto compiler = "MSVC " + std::to_string(_MSC_VER);
#else
    const auto compiler = std::string(__VERSION__);
#endif
    return {{"os", "Windows"},
            {"kernel", std::to_string(version.dwMajorVersion) + "." +
                           std::to_string(version.dwMinorVersion) + "." +
                           std::to_string(version.dwBuildNumber)},
            {"architecture", "x86_64"},
            {"logical_cpus", GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)},
            {"processor_groups", GetActiveProcessorGroupCount()},
            {"tls_library", "Schannel"},
            {"openssl", nullptr},
            {"winlin_version", WINLIN_VERSION},
            {"build_type", WINLIN_BUILD_TYPE},
            {"compiler", compiler}};
}
}
