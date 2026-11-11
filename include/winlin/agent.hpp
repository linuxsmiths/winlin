#pragma once

#include "winlin/core.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

namespace winlin {
struct AgentConfig {
    std::string backend;
    std::string cipher{"TLS_AES_128_GCM_SHA256"};
    unsigned connection_limit{32768};
    unsigned workers{};
    bool connection_metrics{true};
    Json environment;
    std::vector<std::string> unavailable_metrics{
        "hardware_cycles", "instructions", "cache_misses", "memory_bandwidth",
        "kernel_profiles", "network_counters", "numa_topology"};
    std::string process_cpu_scope{"server process only"};

    static AgentConfig from_args(const Args& args, std::string backend) {
        AgentConfig result;
        result.backend = std::move(backend);
        result.cipher = args.get("--cipher", result.cipher);
        result.connection_limit = static_cast<unsigned>(number(args.get("--max-connections", "32768"), 65536));
        result.workers = static_cast<unsigned>(number(args.get("--workers",
            std::to_string(std::min(8u, std::max(1u, std::thread::hardware_concurrency())))), 256));
        if (!result.connection_limit || !result.workers)
            throw std::invalid_argument("Connection and worker limits must be positive");
        return result;
    }
};

struct ConnectionInfo {
    std::string tls_version, cipher;
    bool ktls_tx{}, ktls_rx{};
};

struct AgentReply {
    enum class Kind { text, object, consume_put };
    int status{200};
    Kind kind{Kind::text};
    bool close{};
    std::string text;
    std::size_t size{};

    static AgentReply error(int status, std::string message) {
        return {status, Kind::text, true, Json{{"error", std::move(message)}}.dump(), 0};
    }
};

class Agent {
    std::string bootstrap_;
    std::atomic<std::shared_ptr<const std::string>> credential_;
    std::mutex pairing_mutex_;
    std::function<std::string()> issue_credential_;
    std::function<bool(std::string_view, std::string_view)> equal_;
    std::function<Json()> process_usage_;
public:
    AgentConfig config;
    std::atomic<std::uint64_t> connections{}, handshakes{}, tx_ktls{}, rx_ktls{};
    std::atomic<std::uint64_t> gets{}, puts{}, get_bytes{}, put_bytes{}, active{};

    Agent(AgentConfig settings, std::string bootstrap, std::optional<std::string> credential,
          std::function<std::string()> issue,
          std::function<bool(std::string_view, std::string_view)> equal,
          std::function<Json()> process_usage)
        : bootstrap_(std::move(bootstrap)), issue_credential_(std::move(issue)),
          equal_(std::move(equal)), process_usage_(std::move(process_usage)), config(std::move(settings)) {
        if (credential) credential_.store(std::make_shared<const std::string>(*credential));
    }

    Json telemetry() const {
        return {{"process", process_usage_()}, {"process_cpu_scope", config.process_cpu_scope},
                {"accepted_connections", config.connection_metrics ? Json(connections.load()) : Json(nullptr)},
                {"active_connections", config.connection_metrics ? Json(active.load()) : Json(nullptr)},
                {"tls_handshakes", config.connection_metrics ? Json(handshakes.load()) : Json(nullptr)},
                {"ktls_tx_connections", tx_ktls.load()}, {"ktls_rx_connections", rx_ktls.load()},
                {"get_completed", gets.load()}, {"put_completed", puts.load()},
                {"get_bytes", get_bytes.load()}, {"put_bytes", put_bytes.load()}};
    }

    Json capabilities(const ConnectionInfo& connection) const {
        return {{"protocol_version", 1}, {"environment", config.environment}, {"backend", config.backend},
                {"tls_version", connection.tls_version}, {"cipher", connection.cipher},
                {"http_version", "1.1"}, {"ktls_tx", connection.ktls_tx}, {"ktls_rx", connection.ktls_rx},
                {"max_object_size_bytes", max_object_size}, {"max_connections", config.connection_limit},
                {"workers", config.workers}, {"load_modes", {"closed_loop"}}, {"handshake_benchmark", false},
                {"unavailable_metrics", config.unavailable_metrics},
                {"process_cpu_scope", config.process_cpu_scope},
                {"telemetry_scope", "whole server process; use an exclusive test target"}};
    }

    AgentReply request(const HttpHead& head, const ConnectionInfo& connection) {
        try {
            const auto first_space = head.first.find(' ');
            const auto last_space = head.first.rfind(' ');
            if (first_space == std::string::npos || first_space == last_space ||
                head.first.substr(last_space + 1) != "HTTP/1.1" || !head.fields.contains("host") ||
                head.length > max_object_size)
                return AgentReply::error(400, "Expected HTTP/1.1 with Host and a bounded body");
            if (connection.tls_version != "TLSv1.3" || connection.cipher != config.cipher)
                return AgentReply::error(400, "Negotiated TLS version/cipher does not match server configuration");
            const auto method = head.first.substr(0, first_space);
            const auto path = head.first.substr(first_space + 1, last_space - first_space - 1);
            const bool pairing = method == "POST" && path == "/v1/pair";
            const auto credential = credential_.load();
            const auto auth = head.fields.find("authorization");
            const std::string_view supplied = auth == head.fields.end() ? std::string_view{} : auth->second;
            const auto expected = "Bearer " + (pairing ? bootstrap_ : credential ? *credential : "");
            if ((!pairing && !credential) || !equal_(supplied, expected))
                return AgentReply::error(401, "unauthorized");
            AgentReply reply;
            reply.close = head.close;
            if (pairing) {
                if (head.length) return AgentReply::error(400, "Pairing body must be empty");
                std::lock_guard lock(pairing_mutex_);
                if (credential_.load()) return AgentReply::error(409, "already paired");
                const auto token = issue_credential_();
                credential_.store(std::make_shared<const std::string>(token));
                reply.close = true;
                reply.text = Json{{"access_token", token}}.dump();
            } else if (method == "GET" && path == "/v1/capabilities" && !head.length) {
                reply.text = capabilities(connection).dump();
            } else if (method == "GET" && path == "/v1/telemetry" && !head.length) {
                reply.text = telemetry().dump();
            } else if (method == "GET" && path.starts_with("/v1/object?size=") && !head.length) {
                if (config.backend == "openssl-ktls" && !connection.ktls_tx)
                    return AgentReply::error(501, "kTLS TX is not active; refusing fallback");
                reply.kind = AgentReply::Kind::object;
                reply.size = static_cast<std::size_t>(number(std::string_view(path).substr(16), max_object_size));
            } else if (method == "PUT" && path == "/v1/object" && head.fields.contains("content-length")) {
                if (config.backend == "openssl-ktls" && !connection.ktls_rx)
                    return AgentReply::error(501, "kTLS RX is not active; refusing fallback");
                reply.kind = AgentReply::Kind::consume_put;
                reply.size = head.length;
            } else return AgentReply::error(404, "unsupported method or path");
            return reply;
        } catch (const std::invalid_argument&) {
            return AgentReply::error(400, "invalid request");
        }
    }
};
}
