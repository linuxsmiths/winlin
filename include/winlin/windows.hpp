#pragma once

#include "winlin/host.hpp"
#include "winlin/cpu.hpp"

#include <memory>
#include <cstddef>
#include <cstring>
#include <exception>
#include <span>

#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <psapi.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <http.h>

namespace winlin {
inline std::runtime_error windows_error(std::string message, DWORD code = GetLastError()) {
    return std::runtime_error(std::move(message) + " (Windows error " + std::to_string(code) + ")");
}

// Decode one already-dequeued completion without waiting. A successful batch dequeue does not
// imply successful I/O; ask Windows to translate each native OVERLAPPED result to a Win32 error.
// Synthetic submission failures already carry a Win32 error and have no native result to query.
inline ULONG completion_error(HANDLE handle, OVERLAPPED* overlapped, ULONG immediate_error) {
    if (immediate_error) {
        return immediate_error;
    }
    DWORD transferred{};
    return GetOverlappedResult(handle, overlapped, &transferred, FALSE) ? NO_ERROR : GetLastError();
}

// Adapt HTTP.sys's parsed request directly to the shared Agent header representation.
// Retain the same selected fields, header-size bound, normalization, and framing validation as
// the previous serialized-header path, without building and parsing a second HTTP message.
// Views borrow native receive storage, which Request retains unchanged through asynchronous body
// reads and response completion. Callers must not reuse or release it while these views are used.
inline RequestHead request_head(const HTTP_REQUEST& request) {
    std::string_view method;
    switch (request.Verb) {
    case HttpVerbGET:
        method = "GET";
        break;
    case HttpVerbPUT:
        method = "PUT";
        break;
    case HttpVerbPOST:
        method = "POST";
        break;
    default:
        method = "UNSUPPORTED";
        break;
    }
    RequestHead head;
    head.method = method;
    head.path = {request.pRawUrl, request.RawUrlLength};
    head.version =
        request.Version.MajorVersion == 1 && request.Version.MinorVersion == 1 ? "HTTP/1.1" : "";

    // Account for the request-line CRLF and final blank line, then each selected field's
    // serialized size. This preserves the old adapter's bound without allocating that text.
    std::size_t header_size = method.size() + 1 + head.path.size() + 6 +
                              std::to_string(request.Version.MajorVersion).size() + 1 +
                              std::to_string(request.Version.MinorVersion).size() + 4;
    if (header_size > max_header_size) {
        throw std::invalid_argument("Invalid HTTP header");
    }
    const auto add_field = [&](std::string_view name, std::string_view value) {
        header_size += name.size() + 2 + value.size() + 2;
        if (header_size > max_header_size) {
            throw std::invalid_argument("Invalid HTTP header");
        }
        add_request_field(head, name, value);
    };
    const std::array<std::pair<HTTP_HEADER_ID, std::string_view>, 4> names{
        {{HttpHeaderHost, "Host"},
         {HttpHeaderContentLength, "Content-Length"},
         {HttpHeaderConnection, "Connection"},
         {HttpHeaderTransferEncoding, "Transfer-Encoding"}}};
    for (const auto& [id, name] : names) {
        const auto& field = request.Headers.KnownHeaders[id];
        if (field.pRawValue) {
            add_field(name, {field.pRawValue, field.RawValueLength});
        }
    }

    // HTTP.sys exposes the lease through UnknownHeaders. Compare names without allocating
    // lowercase copies, and still reject repeated lease fields through shared field validation.
    for (USHORT index = 0; index < request.Headers.UnknownHeaderCount; ++index) {
        const auto& field = request.Headers.pUnknownHeaders[index];
        if (http_equal({field.pName, field.NameLength}, "x-winlin-run")) {
            add_field("X-Winlin-Run", {field.pRawValue, field.RawValueLength});
        }
    }
    finish_request_head(head);
    return head;
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

// GetSystemTimes includes idle in kernel time; remove it, retaining System/IRQ/DPC execution.
inline double group_busy_cpu_seconds() {
    FILETIME idle{}, kernel{}, user{};
    if (!GetSystemTimes(&idle, &kernel, &user)) {
        throw windows_error("Cannot collect whole-server CPU time");
    }
    return filetime_seconds(kernel) - filetime_seconds(idle) + filetime_seconds(user);
}

// GetSystemTimes covers only the caller's primary processor group on machines above 64 CPUs.
// A disposable sampler thread visits every active group without changing any server worker's
// affinity. Join before returning so results and exceptions have a single controlling owner.
inline Json host_usage() {
    unsigned sampled_groups{};
    auto result = sample_host_cpu("GetSystemTimes kernel+user-idle; all processor groups", [&] {
        const auto groups = GetActiveProcessorGroupCount();
        if (!groups) {
            throw windows_error("Cannot enumerate CPU processor groups");
        }
        if (groups == 1) {
            const auto busy = group_busy_cpu_seconds();
            sampled_groups = 1;
            return busy;
        }
        double busy{};
        std::exception_ptr failure;
        std::jthread sampler([&] {
            try {
                DWORD size{};
                if (GetLogicalProcessorInformationEx(RelationGroup, nullptr, &size) ||
                    GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                    throw windows_error("Cannot size CPU processor-group information");
                }
                std::vector<unsigned char> buffer(size);
                auto* information =
                    reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
                if (!GetLogicalProcessorInformationEx(RelationGroup, information, &size)) {
                    throw windows_error("Cannot read CPU processor-group information");
                }
                const auto group_offset = offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Group) +
                                          offsetof(GROUP_RELATIONSHIP, GroupInfo);
                if (size < group_offset || information->Relationship != RelationGroup ||
                    !information->Group.ActiveGroupCount ||
                    information->Group.ActiveGroupCount >
                        (size - group_offset) / sizeof(PROCESSOR_GROUP_INFO)) {
                    throw std::runtime_error("Incomplete CPU processor-group information");
                }
                for (WORD group = 0; group < information->Group.ActiveGroupCount; ++group) {
                    GROUP_AFFINITY affinity{};
                    affinity.Group = group;
                    affinity.Mask = information->Group.GroupInfo[group].ActiveProcessorMask;
                    if (!SetThreadGroupAffinity(GetCurrentThread(), &affinity, nullptr)) {
                        throw windows_error("Cannot sample CPU processor group " +
                                            std::to_string(group));
                    }
                    busy += group_busy_cpu_seconds();
                    ++sampled_groups;
                }
            } catch (...) {
                failure = std::current_exception();
            }
        });
        sampler.join();
        if (failure) {
            std::rethrow_exception(failure);
        }
        return busy;
    });
    result["processor_groups_sampled"] = sampled_groups;
    return result;
}

// Read the local Azure SKU leaf only, bypassing proxies and refusing redirects.
// Each WinHTTP operation has a short timeout; the bounded response contains no machine identity.
inline std::string azure_vm_sku() {
    const auto deadline = Clock::now() + std::chrono::seconds(2);
    auto close = [](void* handle) {
        if (!WinHttpCloseHandle(handle)) {
            log_warning(windows_error("WinHttpCloseHandle").what());
        }
    };
    using Internet = std::unique_ptr<void, decltype(close)>;
    Internet session(WinHttpOpen(L"Winlin", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                                 WINHTTP_NO_PROXY_BYPASS, 0),
                     close);
    if (!session || !WinHttpSetTimeouts(session.get(), 500, 500, 500, 500)) {
        throw windows_error("Cannot initialize Azure metadata request");
    }
    Internet connection(WinHttpConnect(session.get(), L"169.254.169.254", 80, 0), close);
    Internet request(
        connection ? WinHttpOpenRequest(
                         connection.get(), L"GET",
                         L"/metadata/instance/compute/vmSize?api-version=2021-02-01&format=text",
                         nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0)
                   : nullptr,
        close);
    DWORD disabled =
        WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    if (!request ||
        !WinHttpSetOption(request.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disabled,
                          sizeof(disabled)) ||
        !WinHttpSendRequest(request.get(), L"Metadata: true\r\n", static_cast<DWORD>(-1),
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.get(), nullptr)) {
        throw windows_error("Azure metadata request failed");
    }
    DWORD status{}, size = sizeof(status);
    if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                             WINHTTP_NO_HEADER_INDEX) ||
        status != 200) {
        throw std::runtime_error("Azure metadata SKU request was rejected");
    }
    std::string result;
    std::array<char, 129> buffer{};
    for (;;) {
        if (Clock::now() >= deadline) {
            throw std::runtime_error("Azure metadata SKU request timed out");
        }
        DWORD count{};
        if (!WinHttpReadData(request.get(), buffer.data(), static_cast<DWORD>(buffer.size()),
                             &count)) {
            throw windows_error("Cannot read Azure metadata SKU");
        }
        if (!count) {
            return result;
        }
        result.append(buffer.data(), count);
        if (result.size() > 128) {
            throw std::runtime_error("Azure metadata SKU exceeded size limit");
        }
    }
}

// Get only SMBIOS manufacturer/model and cache optional cloud metadata before benchmarking.
inline Json machine_environment() {
    static const Json machine = [] {
        auto result = describe_machine("", "");
        try {
            constexpr DWORD provider = 0x52534d42; // RSMB: raw SMBIOS firmware table.
            const auto size = GetSystemFirmwareTable(provider, 0, nullptr, 0);
            if (size < 8 || size > 1024 * 1024) {
                throw std::runtime_error("System SMBIOS table is missing or exceeds size limit");
            }
            std::vector<char> table(size);
            if (GetSystemFirmwareTable(provider, 0, table.data(), size) != size) {
                throw windows_error("Cannot read SMBIOS firmware");
            }
            DWORD length{};
            std::memcpy(&length, table.data() + 4, sizeof(length));
            if (length > size - 8) {
                throw std::runtime_error("Malformed SMBIOS firmware length");
            }
            const auto [manufacturer, model] =
                smbios_system(std::string_view(table.data() + 8, length));
            result = describe_machine(manufacturer, model);
            if (manufacturer == "Microsoft Corporation" && result.at("type") == "virtual_machine") {
                apply_azure_sku(result, azure_vm_sku());
            }
        } catch (const std::exception& error) {
            result["unavailable_reason"] = error.what();
        }
        return result;
    }();
    return machine;
}

// Keep OS/kernel first, then OS-visible capacity; Windows has no POSIX descriptor ceiling.
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
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    if (!GlobalMemoryStatusEx(&memory)) {
        throw windows_error("Cannot collect system RAM");
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
            {"system_ram_bytes", memory.ullTotalPhys},
            {"machine", machine_environment()},
            {"fd_limit",
             {{"soft", nullptr},
              {"hard", nullptr},
              {"unavailable_reason", "Not applicable: Windows has no POSIX FD limit"}}},
            {"tls_library", "Schannel"},
            {"openssl", nullptr},
            {"winlin_version", WINLIN_VERSION},
            {"build_type", WINLIN_BUILD_TYPE},
            {"allocator", WINLIN_ALLOCATOR},
            {"compiler", compiler}};
}
}
