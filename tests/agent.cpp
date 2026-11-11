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
                      " HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n"
                      "Authorization: Bearer " +
                      token + "\r\nContent-Length: " + std::to_string(length) + "\r\n\r\n");
}
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
        std::cout << "Shared agent tests passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
