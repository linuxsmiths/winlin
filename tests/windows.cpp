#include "winlin/windows.hpp"

#include <filesystem>
#include <iostream>

namespace {
using namespace winlin;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <class Function> void rejects(Function function) {
    try {
        function();
    } catch (const std::runtime_error&) {
        return;
    }
    throw std::runtime_error("Unsafe input was accepted");
}
}

int main() {
    namespace fs = std::filesystem;
    const auto directory =
        fs::temp_directory_path() / ("winlin-native-test-" + std::to_string(GetCurrentProcessId()) +
                                     "-" + std::to_string(GetTickCount64()));
    try {
        fs::create_directory(directory);
        const auto file = directory / "session";
        const auto path = utf8(file.wstring());
        require(!optional_token_file(path), "Missing session");
        const auto secret = issue_token_file(path);
        require(token_file(path) == secret, "Native private credential round trip");
        rejects([&] {
            issue_token_file(path);
        });
        require(token_file(path) == secret, "Existing session must not be overwritten");
        Handle handle(CreateFileW(file.c_str(), WRITE_DAC | READ_CONTROL, 0, nullptr, OPEN_EXISTING,
                                  0, nullptr));
        if (handle.value == INVALID_HANDLE_VALUE) {
            throw windows_error("Open test credential");
        }
        // Weaken the stored DACL deliberately: reads must validate current permissions, not assume
        // that credentials remain private merely because this process originally created them.
        PACL old_acl{}, new_acl{};
        LocalMemory descriptor;
        const auto result = GetSecurityInfo(
            handle.value, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &old_acl,
            nullptr, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value));
        if (result != ERROR_SUCCESS) {
            throw windows_error("GetSecurityInfo", result);
        }
        BYTE everyone[SECURITY_MAX_SID_SIZE]{};
        DWORD length = sizeof(everyone);
        if (!CreateWellKnownSid(WinWorldSid, nullptr, everyone, &length)) {
            throw windows_error("CreateWellKnownSid");
        }
        EXPLICIT_ACCESSW access{};
        access.grfAccessPermissions = GENERIC_READ;
        access.grfAccessMode = GRANT_ACCESS;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(everyone);
        const auto merged = SetEntriesInAclW(1, &access, old_acl, &new_acl);
        if (merged != ERROR_SUCCESS) {
            throw windows_error("SetEntriesInAcl", merged);
        }
        LocalMemory added_acl{new_acl};
        const auto updated =
            SetSecurityInfo(handle.value, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                            nullptr, new_acl, nullptr);
        if (updated != ERROR_SUCCESS) {
            throw windows_error("SetSecurityInfo", updated);
        }
        handle.reset();
        rejects([&] {
            token_file(path);
        });
        const auto snapshot = usage();
        require(snapshot.at("voluntary_context_switches").is_null(),
                "Unavailable counters are null");
        require(environment().at("os") == "Windows", "Native environment");
        require(wide(utf8(L"winlin-\u03b1")) == L"winlin-\u03b1", "Unicode path conversion");
        fs::remove(file);
        fs::remove(directory);
        std::cout << "Windows platform tests passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::error_code cleanup_error;
        fs::remove(directory / "session", cleanup_error);
        if (cleanup_error) {
            log_warning("Cannot remove test credential: " + cleanup_error.message());
        }
        fs::remove(directory, cleanup_error);
        if (cleanup_error) {
            log_warning("Cannot remove test directory: " + cleanup_error.message());
        }
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
