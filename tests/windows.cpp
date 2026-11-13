#include "winlin/windows.hpp"

#include <iostream>

namespace {
using namespace winlin;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
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
}

int main() {
    try {
        test_request_headers();
        const auto snapshot = usage();
        require(snapshot.at("voluntary_context_switches").is_null(),
                "Unavailable counters are null");
        const auto host = host_usage();
        require(host.at("busy_cpu_seconds").is_number(), "Native whole-server CPU accounting");
        require(host.at("processor_groups_sampled") == GetActiveProcessorGroupCount(),
                "Whole-server CPU accounting visits every active processor group");
        require(environment().at("os") == "Windows", "Native environment");
        require(wide(utf8(L"winlin-\u03b1")) == L"winlin-\u03b1", "Unicode path conversion");
        std::cout << "Windows platform tests passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
