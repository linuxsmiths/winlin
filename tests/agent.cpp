#include "winlin/agent.hpp"

#include <iostream>

namespace {
using namespace winlin;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

HttpHead head(std::string method, std::string path, std::string run_id, std::size_t length = 0) {
    return parse_head(method + " " + path +
                      " HTTP/1.1\r\nHost: 127.0.0.1:38080\r\n"
                      "X-Winlin-Run: " +
                      run_id + "\r\nContent-Length: " + std::to_string(length) + "\r\n\r\n");
}

// Exercise lease ownership and cleanup independently of privileged native listeners and counters.
struct TestBenchmark : BenchmarkInstance {
    std::atomic<unsigned>& live;
    BenchmarkOptions options;
    bool fail_sample;

    TestBenchmark(std::atomic<unsigned>& count, BenchmarkOptions settings, bool failure)
        : live(count), options(std::move(settings)), fail_sample(failure) {
        ++live;
    }

    ~TestBenchmark() override {
        --live;
    }

    Json describe() const override {
        return {{"port", 38444}, {"transport", options.tls == "off" ? "http" : "https"}};
    }

    Json telemetry() const override {
        if (fail_sample) {
            throw BenchmarkError(503, "test workload failed");
        }
        return {{"workers", options.workers}, {"get_response_data", options.get_response_data}};
    }
};

// Verify real payload copying and ownership, not merely mode metadata or identical wire bytes.
void test_get_response_payload() {
    std::vector<char> source{'a', 'b', 'c', 'd'};
    GetResponsePayload first;
    const auto* shared = first.prepare(source, source.size(), true);
    require(shared == source.data(), "Shared mode borrows the original payload");
    const auto* copied = first.prepare(source, source.size(), false);
    require(copied != source.data() && std::string_view(copied, source.size()) == "abcd",
            "Copy mode creates response-private data");
    source[0] = 'z';
    require(copied[0] == 'a' && shared[0] == 'z', "Copied data does not alias the shared source");
    require(first.prepare(source, source.size(), false) == copied &&
                std::string_view(copied, source.size()) == "zbcd",
            "Same-size responses refresh the reused buffer on every copy");
    source[3] = 'q';
    const auto* reused = first.prepare(source, 2, false);
    require(reused == copied && std::string_view(reused, 2) == "zb" && reused[3] == 'd',
            "Smaller responses copy only their requested bytes without reallocating");
    GetResponsePayload second;
    require(second.prepare(source, source.size(), false) != copied,
            "Outstanding responses own independent private storage");
    GetResponsePayload empty;
    empty.prepare({}, 0, false);
    require(first.prepare(source, source.size(), true) == source.data(),
            "Shared mode remains available after a previous private copy");
    try {
        first.prepare(source, source.size() + 1, false);
        require(false, "Oversized copies must not read beyond the source");
    } catch (const std::invalid_argument&) {
    }
}

// Check source rotation independently of random production data, including wrap and unused
// tails.
void test_rotating_get_source() {
    const std::string contents = "abcdefghijklmnopqr!";
    const std::vector<char> source(contents.begin(), contents.end());
    GetResponsePayload payload(5);
    std::vector<std::string> objects;
    for (unsigned index = 0; index < 6; ++index) {
        objects.emplace_back(payload.prepare(source, 3, false), 3);
    }
    const auto first = objects.front();
    const auto second = objects[1];
    std::sort(objects.begin(), objects.end());
    require(objects == std::vector<std::string>{"abc", "def", "ghi", "jkl", "mno", "pqr"},
            "Rotation covers every whole object without copying the partial source tail");
    require(std::string_view(payload.prepare(source, 3, false), 3) == first,
            "The source walk wraps only after a full cycle");
    payload.prepare(source, 0, false);
    require(std::string_view(payload.prepare(source, 3, false), 3) == second,
            "Zero-byte GETs do not restart or advance the source cursor");
    require(payload.prepare(source, 3, true) == source.data(),
            "Shared mode continues to borrow the hot prefix after rotated copies");

    // Distinct context streams must not simply walk one common sequence at adjacent positions.
    std::vector<char> larger_source(128 * 4);
    for (unsigned index = 0; index < 128; ++index) {
        larger_source[index * 4] = static_cast<char>(index);
    }
    GetResponsePayload first_stream(0), second_stream(1);
    std::vector<unsigned> first_objects, second_objects;
    for (unsigned index = 0; index < 8; ++index) {
        first_objects.push_back(
            static_cast<unsigned char>(*first_stream.prepare(larger_source, 4, false)));
        second_objects.push_back(
            static_cast<unsigned char>(*second_stream.prepare(larger_source, 4, false)));
    }
    require(first_objects != second_objects, "Context seeds select different objects");
    require((first_objects[1] + 128 - first_objects[0]) % 128 !=
                (second_objects[1] + 128 - second_objects[0]) % 128,
            "Context streams have different strides rather than a shared sliding window");
    require(first_stream.prepare(larger_source, larger_source.size(), false) !=
                larger_source.data(),
            "Changing object size safely reconfigures the source walk");
}
}

int main() {
    try {
        test_get_response_payload();
        test_rotating_get_source();
        const std::string access(64, 'b');
        AgentConfig config;
        config.backend = "httpsys-schannel";
        config.connection_metrics = false;
        config.workers = 2;
        config.environment = {{"os", "test"}};
        auto process = [] {
            return Json{{"voluntary_context_switches", nullptr}};
        };
        Agent agent(config, process);
        const ConnectionInfo tls{"TLSv1.3", config.cipher};
        auto metadata = agent.request(head("GET", "/v1/capabilities", access), tls);
        const auto discovery = Json::parse(metadata.text);
        require(discovery.contains("supported_backends") &&
                    discovery.at("supported_transports") == Json({"http", "https"}),
                "Discovery describes supported workload choices");
        require(discovery.at("supported_get_response_data_modes") == Json({"shared", "copy"}),
                "Both GET payload modes are advertised");
        for (const auto* key :
             {"backend", "transport", "cipher", "tls_version", "workers", "max_connections",
              "ktls_tx", "ktls_rx", "benchmark_control", "run"}) {
            require(!discovery.contains(key), "Discovery must not expose control settings");
        }
        auto get = agent.request(head("GET", "/v1/object?size=4194304", access), tls);
        require(get.kind == AgentReply::Kind::object && get.size == 4194304, "Shared GET route");
        auto put = agent.request(head("PUT", "/v1/object", access, 512), tls);
        require(put.kind == AgentReply::Kind::consume_put && put.size == 512,
                "PUT requires body consumption");
        require(agent.puts == 0, "Dispatch must not count an unconsumed PUT");
        require(agent.request(head("GET", "/v1/object?size=67108865", access), tls).status == 400,
                "GET size is bounded");
        require(agent.request(head("GET", "/v1/capabilities", access), {"TLSv1.2", config.cipher})
                        .status == 400,
                "TLS mismatch is rejected");
        require(agent.request(head("GET", "/v1/capabilities", access), {"TLSv1.3", "different"})
                        .status == 400,
                "Cipher mismatch is rejected");
        require(agent.telemetry().at("accepted_connections").is_null(),
                "Unsupported counters are null");
        Agent restarted(config, process);
        require(restarted.request(head("GET", "/v1/capabilities", access), tls).status == 200,
                "Control discovery needs no persistent client state after restart");
        config.backend = "openssl-ktls";
        Agent ktls(config, process);
        require(ktls.request(head("GET", "/v1/object?size=256", access), tls).status == 501,
                "kTLS TX cannot silently fall back");
        require(ktls.request(head("PUT", "/v1/object", access, 256), tls).status == 501,
                "kTLS RX cannot silently fall back");
        config.backend = "openssl";
        Agent open(config, process);
        const auto anonymous = parse_head(
            "GET /v1/capabilities HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
        const auto capabilities = open.request(anonymous, tls);
        require(capabilities.status == 200 &&
                    !Json::parse(capabilities.text).contains("authentication"),
                "Capabilities omit removed client settings");
        require(open.request(head("POST", "/v1/pair", ""), tls).status == 404,
                "Removed registration route is unavailable");
        require(open.request(head("GET", "/v1/object?size=512", ""), tls).kind ==
                    AgentReply::Kind::object,
                "Standalone GET route");
        require(open.request(head("PUT", "/v1/object", "", 512), tls).kind ==
                    AgentReply::Kind::consume_put,
                "Standalone PUT route");
        require(open.request(head("GET", "/v1/telemetry", ""), tls).status == 200,
                "Control telemetry route");
        require(open.request(anonymous, {"TLSv1.2", config.cipher}).status == 400,
                "Discovery still enforces the benchmark TLS contract");

        config.role = AgentConfig::Role::workload;
        Agent workload(config, process, access);
        require(workload.request(head("GET", "/v1/capabilities", access), tls).status == 404 &&
                    workload.request(head("GET", "/v1/capabilities", ""), tls).status == 404,
                "Capability discovery is available only through control");
        try {
            BenchmarkOptions::parse({{"max_connections", 32}});
            require(false, "Implementation connection ceiling must not be configurable");
        } catch (const std::invalid_argument&) {
        }
        require(workload.request(head("GET", "/v1/object?size=256", ""), tls).status == 409,
                "Workload requires its active run ID");
        require(workload.request(head("GET", "/v1/object?size=256", "wrong"), tls).status == 409,
                "Another run cannot issue workload requests");
        require(workload.request(head("GET", "/v1/object?size=256", access), tls).kind ==
                    AgentReply::Kind::object,
                "Matching run ID permits workload requests");

        std::atomic<unsigned> live{};
        bool fail_sample = false;
        BenchmarkController controller(
            [&] {
                return access;
            },
            [&](const BenchmarkOptions& options, const std::string&) {
                return std::make_unique<TestBenchmark>(live, options, fail_sample);
            });
        open.controller = &controller;
        open.config.role = AgentConfig::Role::control;
        const auto settings = Json{{"tls", "off"}, {"workers", 3}}.dump();
        const auto start = head("POST", "/v1/benchmark/start", "", settings.size());
        require(open.request(start, tls).kind == AgentReply::Kind::consume_control,
                "Control JSON must be fully buffered before starting workers");
        auto started = open.request(start, tls, settings);
        require(started.status == 200 && live == 1, "Starting creates exactly one workload");
        require(Json::parse(started.text).at("settings").at("get_response_data") == "shared",
                "Omitted GET data settings preserve the shared baseline");
        require(open.request(start, tls, settings).status == 409, "Overlapping runs are rejected");
        require(open.request(head("GET", "/v1/object?size=512", ""), tls).status == 404,
                "Permanent control endpoint never serves benchmark objects");
        require(open.request(head("GET", "/v1/benchmark/telemetry?run_id=wrong", ""), tls).status ==
                    409,
                "Another controller cannot sample the active run");
        require(controller.telemetry(access).at("workers") == 3,
                "Runtime settings reach the adapter");
        controller.stop(access);
        require(live == 0, "Stopping joins and releases the active runtime");
        const auto copied_run = controller.start({{"tls", "off"}, {"get_response_data", "copy"}});
        require(copied_run.at("settings").at("get_response_data") == "copy",
                "Selected GET data settings reach the run contract");
        require(controller.telemetry(access).at("get_response_data") == "copy",
                "The native adapter receives the selected payload mode");
        controller.stop(access);
        try {
            controller.start({{"get_response_data", "generated"}});
            require(false, "Unknown GET data modes must not silently fall back");
        } catch (const std::invalid_argument&) {
        }
        fail_sample = true;
        controller.start({{"workers", 1}});
        try {
            controller.stop(access);
            require(false, "Broken telemetry must be reported");
        } catch (const BenchmarkError&) {
        }
        require(live == 0, "A failed final sample must still release the runtime");
        fail_sample = false;
        controller.start({{"tls", "off"}, {"workers", 2}, {"lease_seconds", 1}});
        std::this_thread::sleep_for(std::chrono::milliseconds(2200));
        require(live == 0, "An abandoned workload is stopped when its lease expires");
        open.config.tls = false;
        open.config.cipher.clear();
        open.config.role = AgentConfig::Role::standalone;
        require(open.request(anonymous, {}).status == 200, "Explicit HTTP mode accepts plaintext");
        require(open.request(anonymous, tls).status == 400,
                "HTTP mode does not silently accept TLS");
        std::cout << "Shared agent tests passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
