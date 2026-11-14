#pragma once

#include "winlin/benchmark.hpp"

#include <atomic>
#include <cstring>
#include <functional>
#include <numeric>
#include <thread>

namespace winlin {
// Both native servers reserve this loopback TCP port for their entire lifetime, independently of
// the control endpoint. It carries no traffic and permits only one Winlin server per machine.
constexpr std::uint16_t server_guard_port = 8444;

// Describe platform capabilities without mixing transport APIs into the common agent. Native
// adapters must explicitly mark counters and CPU attribution they cannot collect accurately.
struct AgentConfig {
    enum class Role { standalone, control, workload } role{Role::standalone};
    std::string backend;
    bool tls{true};
    std::vector<std::string> benchmark_tls_modes;
    Json supported_backends = Json::array();
    std::vector<std::string> supported_ciphers{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"};
    std::string cipher{"TLS_AES_128_GCM_SHA256"};
    static constexpr unsigned connection_limit = server_connection_limit;
    unsigned workers{};
    bool connection_metrics{true};
    bool shared_get_data{true};
    // Describe application-side TLS staging, not the native transport's internal record packing.
    bool contiguous_tls_get{};
    Json environment;
    std::vector<std::string> unavailable_metrics{
        "hardware_cycles", "instructions",     "cache_misses", "memory_bandwidth",
        "kernel_profiles", "network_counters", "numa_topology"};
    std::string process_cpu_scope{"server process only"};

    // Control has no object source. Shared workloads retain their original payload allocation;
    // copied workloads populate a fixed, worker-shared 1 GiB source before accepting requests.
    std::size_t get_source_pool_size() const {
        if (role == Role::control) {
            return 0;
        }
        return shared_get_data ? max_object_size : copy_get_working_set_size;
    }

    // Start only a single plain-HTTP control worker. Workload adapters replace the worker count
    // with the client's per-run selection when constructing a separate workload endpoint.
    static AgentConfig control_config(std::string backend) {
        AgentConfig result;
        result.backend = std::move(backend);
        result.role = Role::control;
        result.tls = false;
        result.workers = 1;
        return result;
    }
};

// Own reusable GET data and optional header headroom for native transports. Each Linux Session or
// Windows Request owns one instance; only its current response may use the private buffer. Keep the
// shared source alive and immutable through send completion. Private storage retains its largest
// size for reuse and must not be prepared again while a partial/asynchronous send still references
// it. Each copy context has its own deterministic source cursor; neither this cursor nor its buffer
// is thread-safe. Native references/session ownership prevent concurrent preparation.
class GetResponsePayload {
    std::vector<char> private_data_;
    std::uint64_t stream_id_{};
    std::size_t source_size_{}, object_size_{}, object_count_{}, object_index_{}, object_stride_{};

public:
    // Seed one stream for this context's lifetime, including Windows request-cache reuse.
    explicit GetResponsePayload(std::uint64_t stream_id = 0) : stream_id_(stream_id) {
    }

    // Borrow the hot shared source or copy a changing object after an optional header prefix.
    // Return the body pointer; a copied prefix immediately precedes it in the same owned buffer.
    // Allocation occurs only when the private high-water size grows; invalid sizes are rejected.
    const char* prepare(const std::vector<char>& source, std::size_t size, bool use_shared,
                        std::string_view prefix = {}) {
        if (size > source.size()) {
            throw std::invalid_argument("GET response exceeds the prepared source payload");
        }

        if (use_shared) {
            if (!prefix.empty()) {
                throw std::invalid_argument("Shared GET data cannot use private header staging");
            }
            return source.data();
        }

        // Copy the body directly to its final offset rather than copying it a second time when
        // joining headers and data. Retain the combined allocation's high-water size for reuse.
        if (prefix.size() > private_data_.max_size() - size) {
            throw std::invalid_argument("GET response prefix exceeds private storage limits");
        }
        const auto required_size = prefix.size() + size;
        if (private_data_.size() < required_size) {
            private_data_.resize(required_size);
        }
        if (!prefix.empty()) {
            std::memcpy(private_data_.data(), prefix.data(), prefix.size());
        }
        if (!size) {
            return prefix.empty() ? private_data_.data() : private_data_.data() + prefix.size();
        }

        // Divide the source into whole objects of the requested size. A partial tail is unused,
        // so even non-power-of-two sizes cannot make a copy cross the end of the pool.
        if (source_size_ != source.size() || object_size_ != size) {
            source_size_ = source.size();
            object_size_ = size;
            object_count_ = source_size_ / object_size_;

            // A fixed large prime seeds jumps across the pool. Different context seeds and strides
            // avoid having every connection walk the same sequence one request apart. Adjust
            // the stride to be coprime with the object count so every object is visited before
            // a stream repeats; this work occurs only when the source/object size changes.
            constexpr std::uint64_t stride_seed = 104729;
            const auto seed = stream_id_ % object_count_;
            object_index_ = static_cast<std::size_t>((seed * stride_seed) % object_count_);
            object_stride_ = static_cast<std::size_t>((stride_seed + 2 * seed) % object_count_);
            while (std::gcd(object_stride_, object_count_) != 1) {
                ++object_stride_;
            }
        }

        auto* body = private_data_.data() + prefix.size();
        std::memcpy(body, source.data() + object_index_ * object_size_, size);

        // The index and stride are each below the object count, so one subtraction wraps the
        // cursor. Zero-byte GETs do not advance it, and a one-object pool naturally repeats.
        object_index_ += object_stride_;
        if (object_index_ >= object_count_) {
            object_index_ -= object_count_;
        }

        return body;
    }
};

// Carry negotiated, not merely requested, TLS properties from a transport into shared dispatch.
// The transport owns the connection and must verify these again for each accepted TLS session.
// Names borrow stable transport-owned strings or canonical literals through synchronous dispatch.
struct ConnectionInfo {
    std::string_view tls_version, cipher;
    bool ktls_tx{}, ktls_rx{};
};

// Tell a native transport whether to send text, reuse the object payload, or drain a PUT body.
// A consume_put reply is not an acknowledgement: the transport must finish receiving it first.
struct AgentReply {
    enum class Kind { text, object, consume_put, consume_control };
    int status{200};
    Kind kind{Kind::text};
    bool close{};
    std::string text;
    std::size_t size{};

    static AgentReply error(int status, std::string message) {
        log_warning("Request rejected (HTTP " + std::to_string(status) + "): " + message);
        return {status, Kind::text, true, Json{{"error", std::move(message)}}.dump(), 0};
    }
};

// Keep routes and result schemas identical across native servers. Workers share atomic counters;
// an immutable workload run ID associates data requests with the controller's active lease.
class Agent {
    std::string run_id_;
    std::function<Json()> process_usage_;
    std::function<Json()> host_usage_;
    std::function<Json()> network_usage_;
    std::atomic<std::uint64_t> next_get_payload_stream_{};

public:
    AgentConfig config;
    BenchmarkController* controller{};
    std::atomic<std::uint64_t> connections{}, handshakes{}, tx_ktls{}, rx_ktls{};
    std::atomic<std::uint64_t> gets{}, puts{}, get_bytes{}, put_bytes{}, active{};

    // Workload adapters must supply the active lease ID; control needs no saved client state.
    Agent(AgentConfig settings, std::function<Json()> process_usage, std::string run_id = {},
          std::function<Json()> host_usage = {}, std::function<Json()> network_usage = {})
        : run_id_(std::move(run_id)), process_usage_(std::move(process_usage)),
          host_usage_(std::move(host_usage)), network_usage_(std::move(network_usage)),
          config(std::move(settings)) {
        if (config.role == AgentConfig::Role::workload && run_id_.empty()) {
            throw std::invalid_argument("Workload requires an active run ID");
        }
    }

    // Reserve a stream only when a copy-mode connection/request context is created. Warm GETs
    // use private cursors, not a new contended atomic increment on every response.
    std::uint64_t reserve_get_payload_stream() {
        if (config.shared_get_data) {
            return 0;
        }
        return next_get_payload_stream_.fetch_add(1, std::memory_order_relaxed);
    }

    // Keep host CPU accounting separate from process profiling; whole-host attribution needs an
    // otherwise idle server, not merely an exclusive Winlin benchmark lease.
    Json telemetry() const {
        return {
            {"process", process_usage_()},
            {"host", host_usage_ ? host_usage_() : Json::object()},
            {"network", network_usage_ ? network_usage_() : Json::object()},
            {"process_cpu_scope", config.process_cpu_scope},
            {"get_response_data", config.shared_get_data ? "shared" : "copy"},
            {"get_response_source_access",
             config.role == AgentConfig::Role::control
                 ? Json(nullptr)
                 : Json(config.shared_get_data ? "hot-prefix" : "rotating-objects")},
            {"get_response_source_pool_bytes", config.get_source_pool_size()},
            {"get_response_contiguous_tls_buffer", config.contiguous_tls_get},
            {"accepted_connections",
             config.connection_metrics ? Json(connections.load()) : Json(nullptr)},
            {"active_connections", config.connection_metrics ? Json(active.load()) : Json(nullptr)},
            {"tls_handshakes", config.connection_metrics ? Json(handshakes.load()) : Json(nullptr)},
            {"ktls_tx_connections", tx_ktls.load()},
            {"ktls_rx_connections", rx_ktls.load()},
            {"get_completed", gets.load()},
            {"put_completed", puts.load()},
            {"get_bytes", get_bytes.load()},
            {"put_bytes", put_bytes.load()}};
    }

    // Control discovery describes supported workloads, never connection-specific settings.
    Json capabilities() const {
        const auto process = process_usage_();
        const auto host = host_usage_ ? host_usage_() : Json::object();
        const auto network = network_usage_ ? network_usage_() : Json::object();
        auto unavailable = config.unavailable_metrics;
        if (network.value("received_bytes", Json(nullptr)).is_number_unsigned() &&
            network.value("transmitted_bytes", Json(nullptr)).is_number_unsigned()) {
            std::erase(unavailable, "network_counters");
        }
        if (process.contains("cpu_cycles") && !process.at("cpu_cycles").is_null()) {
            std::erase(unavailable, "hardware_cycles");
        } else if (std::find(unavailable.begin(), unavailable.end(), "hardware_cycles") ==
                   unavailable.end()) {
            unavailable.push_back("hardware_cycles");
        }
        Json result{{"environment", config.environment},
                    {"supported_backends", config.supported_backends},
                    {"supported_transports", {"http", "https"}},
                    {"supported_tls_modes", config.benchmark_tls_modes},
                    {"supported_tls_versions", {"TLSv1.3"}},
                    {"supported_ciphers", config.supported_ciphers},
                    {"supported_http_versions", {"1.1"}},
                    {"supported_methods", {"get", "put", "mixed"}},
                    {"supported_get_response_data_modes", {"shared", "copy"}},
                    {"copy_get_working_set_bytes", copy_get_working_set_size},
                    {"supported_load_modes", {"closed_loop"}},
                    {"server_workers", {{"min", 1}, {"max", 256}}},
                    {"limits",
                     {{"max_connections", server_connection_limit},
                      {"max_object_size_bytes", max_object_size},
                      {"max_concurrent_runs", 1}}},
                    {"supports_handshake_benchmark", false},
                    {"telemetry",
                     {{"unavailable_metrics", unavailable},
                      {"cpu_cycles_source", process.value("cpu_cycles_source", Json(nullptr))},
                      {"cpu_cycles_unavailable_reason",
                       process.value("cpu_cycles_unavailable_reason", Json("Not collected"))},
                      {"process_cpu_scope", config.process_cpu_scope},
                      {"host_cpu_time_source", host.value("cpu_time_source", Json(nullptr))},
                      {"host_cpu_time_unavailable_reason",
                       host.value("cpu_time_unavailable_reason", Json("Not collected"))},
                      {"reference_clock", host.value("reference_clock", Json::object())},
                      {"network", network},
                      {"scope", "whole-server CPU, selected-interface network and separate process "
                                "telemetry; one active benchmark"}}}};
        return result;
    }

    // Enforce the selected transport and workload lease before dispatching a bounded request.
    AgentReply request(const RequestHead& head, const ConnectionInfo& connection,
                       std::string_view body = {}) {
        try {
            if (head.version != "HTTP/1.1" || !head.host || head.length > max_object_size) {
                return AgentReply::error(400, "Expected HTTP/1.1 with Host and a bounded body");
            }
            if ((config.tls &&
                 (connection.tls_version != "TLSv1.3" || connection.cipher != config.cipher)) ||
                (!config.tls && (!connection.tls_version.empty() || !connection.cipher.empty()))) {
                return AgentReply::error(
                    400, "Negotiated TLS version/cipher does not match server configuration");
            }
            const auto method = head.method;
            const auto path = head.path;
            // Dummy benchmark object, GET or PUT
            const bool object = path.starts_with("/v1/object");
            // Reject object requests to the control endpoint and control requests to the
            // workload endpoint.
            if ((config.role == AgentConfig::Role::control && object) ||
                (config.role == AgentConfig::Role::workload && !object)) {
                return AgentReply::error(404, "Use the advertised control or workload endpoint");
            }
            if (config.role == AgentConfig::Role::workload) {
                if (!head.run_id || *head.run_id != run_id_) {
                    return AgentReply::error(409, "Workload run ID does not match active lease");
                }
            }
            AgentReply reply;
            reply.close = head.close;
            if (controller && method == "POST" && path == "/v1/benchmark/start") {
                // "/v1/benchmark/start" must carry a JSON body describing the benchmark settings.
                // Bound it to 64 KiB to limit memory use and JSON parsing work.
                if (!head.length || head.length > 65536) {
                    return AgentReply::error(400, "Expected bounded JSON benchmark settings");
                }

                // The body has not yet been supplied to this handler. Ask the transport to
                // collect the declared body and call request() again with the complete JSON.
                if (body.empty()) {
                    reply.kind = AgentReply::Kind::consume_control;
                    reply.size = head.length;
                    return reply;
                }
                if (body.size() != head.length) {
                    return AgentReply::error(400, "Incomplete benchmark settings");
                }
                // Ok, full body received, parse and dispatch to the controller.
                // The controller may throw a BenchmarkError if the settings are invalid
                // or the benchmark cannot be started.
                reply.text = controller->start(Json::parse(body)).dump();
            } else if (controller && method == "GET" &&
                       path.starts_with("/v1/benchmark/telemetry?run_id=") && !head.length) {
                reply.text = controller->telemetry(std::string_view(path).substr(31)).dump();
            } else if (controller && method == "POST" &&
                       path.starts_with("/v1/benchmark/stop?run_id=") && !head.length) {
                reply.text = controller->stop(std::string_view(path).substr(26)).dump();
            } else if (method == "GET" && path == "/v1/capabilities" && !head.length) {
                reply.text = capabilities().dump();
            } else if (method == "GET" && path == "/v1/telemetry" && !head.length) {
                reply.text = telemetry().dump();
            } else if (method == "GET" && path.starts_with("/v1/object?size=") && !head.length) {
                // GET benchmark object of the requested size, bounded to max_object_size.
                if (config.backend == "openssl-ktls" && !connection.ktls_tx) {
                    return AgentReply::error(501, "kTLS TX is not active; refusing fallback");
                }
                // Client expects a raw object
                reply.kind = AgentReply::Kind::object;
                reply.size = static_cast<std::size_t>(
                    number(std::string_view(path).substr(16), max_object_size));
            } else if (method == "PUT" && path == "/v1/object" && head.content_length) {
                if (config.backend == "openssl-ktls" && !connection.ktls_rx) {
                    return AgentReply::error(501, "kTLS RX is not active; refusing fallback");
                }
                // PUT benchmark object, bounded to max_object_size.
                // We must consume the body before replying.
                reply.kind = AgentReply::Kind::consume_put;
                reply.size = head.length;
            } else {
                return AgentReply::error(404, "unsupported method or path");
            }
            return reply;
        } catch (const BenchmarkError& error) {
            return AgentReply::error(error.status, error.what());
        } catch (const Json::exception&) {
            return AgentReply::error(400, "Invalid benchmark JSON settings");
        } catch (const std::invalid_argument&) {
            return AgentReply::error(400, "invalid request");
        } catch (const std::exception& error) {
            return AgentReply::error(503, std::string("Benchmark service failed: ") + error.what());
        }
    }
};
}
