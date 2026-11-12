#pragma once

#include "winlin/core.hpp"

#include <memory>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>

#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <psapi.h>
#include <sddl.h>
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

// Release buffers allocated by Windows security APIs, which require LocalFree rather than delete.
// The SID/ACL pointers returned alongside these buffers remain borrowed from this allocation.
struct LocalMemory {
    void* value{};

    ~LocalMemory() {
        if (value && LocalFree(value)) {
            log_warning(windows_error("LocalFree").what());
        }
    }
};

// Cache the process user's SID in stable aligned storage; returned pointers must never be freed.
inline PSID current_sid() {
    static const auto identity = [] {
        Handle token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) {
            throw windows_error("OpenProcessToken");
        }
        DWORD length{};
        const auto sized = GetTokenInformation(token.value, TokenUser, nullptr, 0, &length);
        if ((!sized && GetLastError() != ERROR_INSUFFICIENT_BUFFER) || !length) {
            throw windows_error("GetTokenInformation size");
        }
        std::vector<std::max_align_t> data((length + sizeof(std::max_align_t) - 1) /
                                           sizeof(std::max_align_t));
        if (!GetTokenInformation(token.value, TokenUser, data.data(), length, &length)) {
            throw windows_error("GetTokenInformation");
        }
        return data;
    }();
    return reinterpret_cast<const TOKEN_USER*>(identity.data())->User.Sid;
}

// Check owner, DACL and file type on the opened handle before exposing a credential to the agent.
// Reparse points and broad allow ACEs are rejected rather than relying on inherited permissions.
inline std::string read_private(const std::string& path, std::size_t maximum = 258) {
    const auto name = wide(path);
    Handle file(CreateFileW(name.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) {
        throw windows_error("Cannot open private credential file");
    }
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(file.value, &information)) {
        throw windows_error("GetFileInformationByHandle");
    }
    if (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
        throw std::runtime_error("Credential must be a regular, non-reparse file");
    }
    PSID owner{};
    PACL acl{};
    LocalMemory descriptor;
    const auto error = GetSecurityInfo(
        file.value, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
        nullptr, &acl, nullptr, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value));
    if (error != ERROR_SUCCESS) {
        throw windows_error("GetSecurityInfo", error);
    }
    if (!owner || !EqualSid(owner, current_sid()) || !acl) {
        throw std::runtime_error("Credential must be owned by this user with a restricted DACL");
    }
    BYTE system[SECURITY_MAX_SID_SIZE]{}, administrators[SECURITY_MAX_SID_SIZE]{};
    DWORD system_size = sizeof(system), administrator_size = sizeof(administrators);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &system_size) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators,
                            &administrator_size)) {
        throw windows_error("CreateWellKnownSid");
    }
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* entry{};
        if (!GetAce(acl, i, &entry)) {
            throw windows_error("GetAce");
        }
        const auto* header = static_cast<ACE_HEADER*>(entry);
        // Deny entries grant no access; unfamiliar ACE types cannot safely be treated as private.
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
            continue;
        }
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            throw std::runtime_error("Unsupported credential DACL entry");
        }
        auto* sid = &static_cast<ACCESS_ALLOWED_ACE*>(entry)->SidStart;
        if (!EqualSid(sid, owner) && !EqualSid(sid, system) && !EqualSid(sid, administrators)) {
            throw std::runtime_error(
                "Credential DACL grants access beyond owner, SYSTEM and Administrators");
        }
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.value, &size)) {
        throw windows_error("GetFileSizeEx");
    }
    if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > maximum) {
        throw std::runtime_error("Credential file is too large");
    }
    std::string content;
    std::array<char, 512> buffer{};
    for (;;) {
        DWORD count{};
        if (!ReadFile(file.value, buffer.data(), static_cast<DWORD>(buffer.size()), &count,
                      nullptr)) {
            throw windows_error("ReadFile");
        }
        if (!count) {
            break;
        }
        content.append(buffer.data(), count);
        if (content.size() > maximum) {
            throw std::runtime_error("Credential file is too large");
        }
    }
    return content;
}

inline std::string token_file(const std::string& path) {
    return parse_token(read_private(path));
}

// Treat only a missing file as an unpaired agent; access errors must not replace its identity.
inline std::optional<std::string> optional_token_file(const std::string& path) {
    if (GetFileAttributesW(wide(path).c_str()) != INVALID_FILE_ATTRIBUTES) {
        return token_file(path);
    }
    const auto error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
        throw windows_error("Cannot inspect session credential", error);
    }
    return std::nullopt;
}

inline void randomize(std::span<char> buffer) {
    const auto status =
        BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(buffer.data()),
                        static_cast<ULONG>(buffer.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        throw std::runtime_error("BCryptGenRandom failed: " + std::to_string(status));
    }
}

inline bool equal_secret(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    volatile unsigned difference = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        difference =
            difference | (static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]));
    }
    return difference == 0;
}

// Apply a protected owner/SYSTEM/Administrators DACL at creation, before writing any secret bytes.
// Persist successfully before publishing the credential to concurrent agent workers.
inline std::string issue_token_file(const std::string& path) {
    std::array<char, 32> bytes{};
    randomize(bytes);
    constexpr char hex[] = "0123456789abcdef";
    std::string secret;
    for (unsigned char byte : bytes) {
        secret += hex[byte >> 4];
        secret += hex[byte & 15];
    }
    LocalMemory sid_text;
    if (!ConvertSidToStringSidW(current_sid(), reinterpret_cast<LPWSTR*>(&sid_text.value))) {
        throw windows_error("ConvertSidToStringSid");
    }
    const auto sid = std::wstring(static_cast<LPCWSTR>(sid_text.value));
    const auto sddl = L"O:" + sid + L"D:P(A;;FA;;;" + sid + L")(A;;FA;;;SY)(A;;FA;;;BA)";
    LocalMemory descriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1,
            reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value), nullptr)) {
        throw windows_error("ConvertStringSecurityDescriptorToSecurityDescriptor");
    }
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor.value, FALSE};
    const auto name = wide(path);
    Handle file(CreateFileW(name.c_str(), GENERIC_WRITE, 0, &security, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) {
        throw windows_error("Cannot create session credential");
    }
    try {
        const auto content = secret + "\n";
        DWORD count{};
        if (!WriteFile(file.value, content.data(), static_cast<DWORD>(content.size()), &count,
                       nullptr) ||
            count != content.size() || !FlushFileBuffers(file.value)) {
            throw windows_error("Cannot save session credential");
        }
    } catch (...) {
        file.reset();
        if (!DeleteFileW(name.c_str())) {
            log_warning(windows_error("Cannot remove incomplete session credential").what());
        }
        throw;
    }
    return secret;
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
