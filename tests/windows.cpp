#include "winlin/windows.hpp"

#include <iostream>

namespace {
using namespace winlin;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// Exercise the startup calibration before any host sample initializes its process-wide cache.
// Unsupported clocks remain valid, but sleeping-thread migration must not discard calibration.
void test_reference_clock() {
    GROUP_AFFINITY before{};
    if (!GetThreadGroupAffinity(GetCurrentThread(), &before)) {
        throw windows_error("Cannot query test thread affinity before calibration");
    }
    initialize_reference_clock();
    GROUP_AFFINITY after{};
    if (!GetThreadGroupAffinity(GetCurrentThread(), &after)) {
        throw windows_error("Cannot query test thread affinity after calibration");
    }
    require(before.Group == after.Group && before.Mask == after.Mask,
            "TSC calibration must preserve caller affinity");
    require(reference_clock().at("unavailable_reason") !=
                "TSC calibration could not obtain three same-CPU samples",
            "CPU-pinned TSC calibration must not reject samples for migration");
}

// Exercise the native header adapter without requiring provisioned HTTP.sys endpoints.
// The raw parser remains the reference for normalization and framing validation.
void test_request_headers() {
    HTTP_REQUEST request{};
    request.Verb = HttpVerbPUT;
    request.Version = HTTP_VERSION{1, 1};
    std::string path = "/v1/object";
    request.pRawUrl = path.data();
    request.RawUrlLength = static_cast<USHORT>(path.size());
    request.Headers.KnownHeaders[HttpHeaderHost] = {11, " localhost "};
    request.Headers.KnownHeaders[HttpHeaderContentLength] = {5, "\t256 "};
    request.Headers.KnownHeaders[HttpHeaderConnection] = {7, " CLOSE "};
    HTTP_UNKNOWN_HEADER lease{12, 7, "x-WiNlIn-RuN", " lease "};
    request.Headers.UnknownHeaderCount = 1;
    request.Headers.pUnknownHeaders = &lease;

    const auto adapted = request_head(request);
    const auto parsed =
        parse_request_head("PUT /v1/object HTTP/1.1\r\nHost: localhost\r\nContent-Length: 256\r\n"
                           "Connection: CLOSE\r\nX-Winlin-Run: lease\r\n\r\n");
    require(adapted == parsed, "Native metadata must preserve shared normalization and framing");
    require(adapted.path.data() == path.data() && adapted.run_id->data() == lease.pRawValue + 1,
            "Adapted fields must borrow the retained native storage without copying");
    request.Version = HTTP_VERSION{2, 0};
    require(request_head(request).version != "HTTP/1.1",
            "Native HTTP versions must not be silently substituted");
    request.Version = HTTP_VERSION{1, 1};

    // Native metadata must not bypass rejection of duplicate leases, transfer encodings,
    // malformed lengths, or the adapter's existing selected-header size limit.
    const auto rejects = [&] {
        try {
            request_head(request);
        } catch (const std::invalid_argument&) {
            return;
        }
        throw std::runtime_error("Invalid native header metadata was accepted");
    };
    std::array<HTTP_UNKNOWN_HEADER, 2> duplicate{lease, lease};
    request.Headers.UnknownHeaderCount = 2;
    request.Headers.pUnknownHeaders = duplicate.data();
    rejects();
    request.Headers.UnknownHeaderCount = 1;
    request.Headers.pUnknownHeaders = &lease;
    request.Headers.KnownHeaders[HttpHeaderTransferEncoding] = {7, "chunked"};
    rejects();
    request.Headers.KnownHeaders[HttpHeaderTransferEncoding] = {};
    request.Headers.KnownHeaders[HttpHeaderContentLength] = {2, "-1"};
    rejects();
    request.Headers.KnownHeaders[HttpHeaderContentLength] = {1, "0"};
    const std::string oversized(max_header_size, 'x');
    request.Headers.KnownHeaders[HttpHeaderHost] = {static_cast<USHORT>(oversized.size()),
                                                    oversized.data()};
    rejects();
}

// A batch can succeed while containing cancelled native I/O and synthetic submission failures.
// Use a local named pipe to generate real cancellation without privileged HTTP.sys provisioning.
void test_completion_errors() {
    const auto name = L"\\\\.\\pipe\\winlin-completion-" + std::to_wstring(GetCurrentProcessId()) +
                      L"-" + std::to_wstring(GetTickCount64());
    Handle pipe(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                                 PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr));
    if (pipe.value == INVALID_HANDLE_VALUE) {
        throw windows_error("Create completion-test pipe");
    }
    Handle port(CreateIoCompletionPort(pipe.value, nullptr, 0, 1));
    if (!port.value) {
        throw windows_error("Create completion-test port");
    }
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.value) {
        throw windows_error("Create completion-test event");
    }

    // Leave a real connect pending, and ensure failures elsewhere in the test still cancel and
    // drain it before stack-backed OVERLAPPED storage or its event can be released.
    OVERLAPPED cancelled{};
    cancelled.hEvent = event.value;
    const BOOL connected = ConnectNamedPipe(pipe.value, &cancelled);
    require(!connected && GetLastError() == ERROR_IO_PENDING, "Pipe connection must be pending");
    const auto drain = [&](OVERLAPPED* pending) {
        if (!CancelIoEx(pipe.value, pending) && GetLastError() != ERROR_NOT_FOUND) {
            log_warning(windows_error("Cancel completion-test I/O").what());
        }
        DWORD transferred{};
        if (!GetOverlappedResult(pipe.value, pending, &transferred, TRUE) &&
            GetLastError() != ERROR_OPERATION_ABORTED) {
            log_warning(windows_error("Drain completion-test I/O").what());
        }
    };
    std::unique_ptr<OVERLAPPED, decltype(drain)> cleanup(&cancelled, drain);

    OVERLAPPED synthetic{};
    if (!PostQueuedCompletionStatus(port.value, 0, 0, &synthetic) ||
        !CancelIoEx(pipe.value, &cancelled)) {
        throw windows_error("Queue mixed completion-test results");
    }

    bool saw_synthetic = false;
    bool saw_cancelled = false;
    while (!saw_synthetic || !saw_cancelled) {
        std::array<OVERLAPPED_ENTRY, 8> entries;
        ULONG count{};
        if (!GetQueuedCompletionStatusEx(port.value, entries.data(),
                                         static_cast<ULONG>(entries.size()), &count, 5000, FALSE)) {
            throw windows_error("Dequeue mixed completion-test results");
        }
        for (ULONG index = 0; index < count; ++index) {
            const auto& entry = entries[index];
            if (entry.lpOverlapped == &synthetic) {
                require(completion_error(pipe.value, entry.lpOverlapped, ERROR_INVALID_DATA) ==
                            ERROR_INVALID_DATA,
                        "Synthetic failures must retain their submission error");
                saw_synthetic = true;
            } else {
                require(entry.lpOverlapped == &cancelled, "Unexpected completion-test packet");
                require(completion_error(pipe.value, entry.lpOverlapped, NO_ERROR) ==
                            ERROR_OPERATION_ABORTED,
                        "A successful batch dequeue must not turn cancelled I/O into success");
                saw_cancelled = true;
            }
        }
    }
    cleanup.release();
}
}

int main() {
    try {
        test_reference_clock();
        test_request_headers();
        test_completion_errors();
        const auto snapshot = usage();
        require(snapshot.at("voluntary_context_switches").is_null(),
                "Unavailable counters are null");
        const auto host = host_usage();
        require(host.at("busy_cpu_seconds").is_number(), "Native whole-server CPU accounting");
        require(host.at("processor_groups_sampled") == GetActiveProcessorGroupCount(),
                "Whole-server CPU accounting visits every active processor group");
        const auto network = network_usage("127.0.0.1");
        require(network.at("received_bytes").is_number_unsigned() &&
                    network.at("transmitted_bytes").is_number_unsigned() &&
                    !network.at("interface_name").is_null(),
                "Native server interface RX/TX accounting");
        const auto invalid_network = network_usage("not-an-address");
        require(invalid_network.at("received_bytes").is_null() &&
                    !invalid_network.at("unavailable_reason").is_null(),
                "Unavailable interface counters retain a reason, not zero");
        require(environment().at("os") == "Windows", "Native environment");
        require(wide(utf8(L"winlin-\u03b1")) == L"winlin-\u03b1", "Unicode path conversion");
        std::cout << "Windows platform tests passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
