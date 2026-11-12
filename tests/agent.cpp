#include "winlin/agent.hpp"

#include <iostream>

namespace {
using namespace winlin;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

HttpHead head(std::string method, std::string path, std::string token, std::size_t length = 0) {
    return parse_head(method + " " + path +
                      " HTTP/1.1\r\nHost: 127.0.0.1:38443\r\n"
                      "Authorization: Bearer " +
                      token + "\r\nContent-Length: " + std::to_string(length) + "\r\n\r\n");
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
        return {{"workers", options.workers}};
    }
};
}

int main() {
    try {
        const std::string bootstrap(64, 'a'), access(64, 'b');
        unsigned writes{};
        AgentConfig config;
        config.backend = "httpsys-schannel";
        config.connection_metrics = false;
        config.workers = 2;
        config.environment = {{"os", "test"}};
        // Isolate protocol behavior from native credential storage and process-counter providers.
        auto issue = [&] {
            ++writes;
            return access;
        };
        auto equal = [](std::string_view a, std::string_view b) {
            return a == b;
        };
        auto process = [] {
            return Json{{"voluntary_context_switches", nullptr}};
        };
        Agent agent(config, bootstrap, std::nullopt, issue, equal, process);
        const ConnectionInfo tls{"TLSv1.3", config.cipher};
        require(agent.request(head("GET", "/v1/capabilities", bootstrap), tls).status == 401,
                "Bootstrap credential cannot run benchmarks");
        auto paired = agent.request(head("POST", "/v1/pair", bootstrap), tls);
        require(paired.status == 200 && Json::parse(paired.text).at("access_token") == access,
                "Pairing exchanges bootstrap for a credential");
        require(writes == 1, "Pairing persists exactly once");
        require(agent.request(head("POST", "/v1/pair", bootstrap), tls).status == 409,
                "Pairing is single-use");
        auto metadata = agent.request(head("GET", "/v1/capabilities", access), tls);
        require(Json::parse(metadata.text).at("backend") == config.backend,
                "Shared capability schema");
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
        Agent restarted(config, bootstrap, access, issue, equal, process);
        require(restarted.request(head("GET", "/v1/capabilities", access), tls).status == 200,
                "Persisted credential survives restart");
        config.backend = "openssl-ktls";
        Agent ktls(config, bootstrap, access, issue, equal, process);
        require(ktls.request(head("GET", "/v1/object?size=256", access), tls).status == 501,
                "kTLS TX cannot silently fall back");
        require(ktls.request(head("PUT", "/v1/object", access, 256), tls).status == 501,
                "kTLS RX cannot silently fall back");
        require(parse_token(bootstrap + "\r\n") == bootstrap, "CRLF credential portability");

        config.backend = "openssl";
        Agent open(config, "", std::nullopt, issue, equal, process);
        const auto anonymous = parse_head(
            "GET /v1/capabilities HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
        const auto capabilities = open.request(anonymous, tls);
        require(capabilities.status == 200 &&
                    Json::parse(capabilities.text).at("authentication") == "none",
                "Default capabilities need no authentication");
        const auto before_registration = writes;
        for (unsigned attempt = 0; attempt < 2; ++attempt) {
            const auto registration = open.request(head("POST", "/v1/pair", ""), tls);
            require(registration.status == 200 &&
                        Json::parse(registration.text).at("access_token") == "",
                    "Default registration is repeatable and has no credential");
        }
        require(writes == before_registration, "Default registration never writes credentials");
        require(open.request(head("GET", "/v1/object?size=512", ""), tls).kind ==
                    AgentReply::Kind::object,
                "Default GET needs no credential");
        require(open.request(head("PUT", "/v1/object", "", 512), tls).kind ==
                    AgentReply::Kind::consume_put,
                "Default PUT needs no credential");
        require(open.request(head("GET", "/v1/telemetry", ""), tls).status == 200,
                "Default telemetry needs no credential");
        require(open.request(anonymous, {"TLSv1.2", config.cipher}).status == 400,
                "No-auth mode still enforces the benchmark TLS contract");

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
