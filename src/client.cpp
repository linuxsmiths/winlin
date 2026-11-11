#include "winlin/linux.hpp"

#include <barrier>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <latch>
#include <mutex>
#include <unordered_map>

namespace {
using namespace winlin;
namespace fs = std::filesystem;

// Hold one approved server identity and its credential for controller/load workers. Never serialize
// this entire object into benchmark reports or diagnostics; token is private target-file data.
struct Target {
    std::string host, port, pin, token, cipher;
};

std::string checked_pin(std::string pin) {
    pin = lower(std::move(pin));
    if (pin.size() != 64 || !std::all_of(pin.begin(), pin.end(), [](unsigned char ch) {
            return std::isxdigit(ch);
        })) {
        throw std::invalid_argument("Fingerprint must be 64 hexadecimal SHA-256 digits");
    }
    return pin;
}

void check_host(const std::string& host) {
    in_addr address{};
    if (inet_pton(AF_INET, host.c_str(), &address) != 1) {
        throw std::invalid_argument("This first version requires a numeric IPv4 server address");
    }
}

// Reserve new outputs exclusively and replace existing results via a flushed private temporary
// file. A failed update must leave earlier completed repetitions intact.
void write_private(const fs::path& path, const Json& value, bool exclusive) {
    if (!exclusive) {
        struct stat status{};
        if (lstat(path.c_str(), &status) || !S_ISREG(status.st_mode) ||
            status.st_uid != geteuid() || (status.st_mode & 0077)) {
            throw std::runtime_error("Output must be a private regular file owned by this user");
        }
    }
    std::string temporary = path.string() + ".tmp.XXXXXX";
    Fd file(exclusive
                ? open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0600)
                : mkostemp(temporary.data(), O_CLOEXEC));
    if (file.value < 0) {
        throw system_error("Cannot open " + path.string());
    }
    try {
        const auto text = value.dump(2) + "\n";
        std::size_t offset{};
        while (offset < text.size()) {
            const auto count = ::write(file.value, text.data() + offset, text.size() - offset);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw system_error("write");
            }
            offset += count;
        }
        if (fsync(file.value)) {
            throw system_error("fsync");
        }
        if (!exclusive && rename(temporary.c_str(), path.c_str())) {
            throw system_error("rename output");
        }
    } catch (...) {
        if (!exclusive && unlink(temporary.c_str()) != 0) {
            log_warning(system_error("Cannot remove temporary result file").what());
        }
        throw;
    }
}

// Validate saved identity/credentials without letting JSON parse errors echo secret file contents.
Target load_target(const std::string& path) {
    const auto content = read_private(path);
    try {
        const auto json = Json::parse(content);
        Target result{json.at("host"), json.at("port"), json.at("certificate_sha256"),
                      json.at("access_token"), json.at("cipher")};
        check_host(result.host);
        if (!number(result.port, 65535)) {
            throw std::invalid_argument("Invalid port");
        }
        result.pin = checked_pin(result.pin);
        if (result.token.size() != 64 ||
            !std::all_of(result.token.begin(), result.token.end(), [](unsigned char ch) {
                return std::isxdigit(ch);
            })) {
            throw std::invalid_argument("Invalid token");
        }
        return result;
    } catch (const std::exception&) {
        throw std::runtime_error("Invalid target file (credentials are not displayed)");
    }
}

// Own one bounded control response independently of its TLS connection, which closes after
// exchange. Workload bodies use streaming buffers instead and must not allocate a Response per
// request.
struct Response {
    int status{};
    HttpHead head;
    std::string body;
};

// Use a separately pinned connection for control traffic, bounded independently of load duration.
Response exchange(SSL_CTX* ctx, const Target& target, const std::string& method,
                  const std::string& path) {
    auto socket = connect_tls(ctx, target.host, target.port, target.pin);
    const auto deadline = Clock::now() + std::chrono::seconds(10);
    const std::string request = method + " " + path + " HTTP/1.1\r\nHost: " + target.host + ":" +
                                target.port + "\r\nAuthorization: Bearer " + target.token +
                                "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    std::size_t sent{};
    while (sent < request.size()) {
        const int count = socket->write(request.data() + sent, request.size() - sent);
        if (count) {
            sent += count;
        } else {
            wait_socket(*socket, deadline);
        }
    }
    std::string input;
    std::array<char, 16384> buffer{};
    std::size_t boundary{};
    for (;;) {
        const auto position = input.find("\r\n\r\n");
        if (position != std::string::npos) {
            boundary = position + 4;
            break;
        }
        if (input.size() > max_header_size) {
            throw std::runtime_error("Oversized control response header");
        }
        const int count = socket->read(buffer.data(), buffer.size());
        if (count) {
            input.append(buffer.data(), count);
        } else {
            wait_socket(*socket, deadline);
        }
    }
    Response response;
    response.head = parse_head(std::string_view(input).substr(0, boundary));
    if (!response.head.first.starts_with("HTTP/1.1 ") || response.head.first.size() < 12 ||
        !response.head.fields.contains("content-length") || response.head.length > 65536) {
        throw std::runtime_error("Invalid control response");
    }
    response.status = number(std::string_view(response.head.first).substr(9, 3), 599);
    response.body = input.substr(boundary);
    while (response.body.size() < response.head.length) {
        const int count = socket->read(
            buffer.data(),
            std::min<std::size_t>(buffer.size(), response.head.length - response.body.size()));
        if (count) {
            response.body.append(buffer.data(), count);
        } else {
            wait_socket(*socket, deadline);
        }
    }
    if (response.body.size() != response.head.length) {
        throw std::runtime_error("Invalid response length");
    }
    return response;
}

Json control(SSL_CTX* ctx, const Target& target, const std::string& path) {
    const auto response = exchange(ctx, target, "GET", path);
    if (response.status != 200) {
        throw std::runtime_error("Server rejected control request (HTTP " +
                                 std::to_string(response.status) + ")");
    }
    return Json::parse(response.body);
}

fs::path state_directory() {
    const char* state = std::getenv("XDG_STATE_HOME");
    const char* home = std::getenv("HOME");
    fs::path directory;
    if (state && *state) {
        directory = fs::path(state) / "winlin";
    } else if (home && *home) {
        directory = fs::path(home) / ".local/state/winlin";
    } else {
        throw std::runtime_error("Set HOME or XDG_STATE_HOME");
    }
    fs::create_directories(directory);
    struct stat status{};
    if (stat(directory.c_str(), &status) || status.st_uid != geteuid()) {
        throw std::runtime_error("State directory must be owned by this user");
    }
    if (chmod(directory.c_str(), 0700)) {
        throw system_error("chmod state directory");
    }
    return directory;
}

// Reserve the local target file before consuming the one-time remote bootstrap token.
void pair_target(const std::string& host, const std::string& port, const std::string& token_path,
                 const std::string& pin, const fs::path& output, const std::string& cipher) {
    check_host(host);
    if (!number(port, 65535)) {
        throw std::invalid_argument("Port must be positive");
    }
    Target target{host, port, checked_pin(pin), token_file(token_path), cipher};
    auto ctx = context(false, cipher);
    write_private(output, Json::object(), true);
    try {
        const auto response = exchange(ctx.get(), target, "POST", "/v1/pair");
        if (response.status != 200) {
            throw std::runtime_error("Pairing rejected (HTTP " + std::to_string(response.status) +
                                     ")");
        }
        target.token = Json::parse(response.body).at("access_token");
        write_private(output,
                      {{"host", host},
                       {"port", port},
                       {"certificate_sha256", target.pin},
                       {"access_token", target.token},
                       {"cipher", cipher}},
                      false);
    } catch (...) {
        fs::remove(output);
        throw;
    }
    std::cout << "Paired target saved to " << output.string() << '\n';
    std::cout << control(ctx.get(), target, "/v1/capabilities").dump(2) << '\n';
}

// Accumulate one worker's counters and histograms without shared hot-path locks. The controller
// merges these only after joining workers; errors remain visible in both diagnostics and results.
struct Stats {
    std::uint64_t completed{}, errors{}, gets{}, puts{}, received{}, sent{};
    Histogram latency, get_latency, put_latency;
    std::string first_error;
    Clock::time_point end{};

    void fail(const std::string& message) {
        log_warning("Load request failed: " + message);
        ++errors;
        if (first_error.empty()) {
            first_error = message;
        }
    }

    void merge(const Stats& other) {
        completed += other.completed;
        errors += other.errors;
        gets += other.gets;
        puts += other.puts;
        received += other.received;
        sent += other.sent;
        latency.merge(other.latency);
        get_latency.merge(other.get_latency);
        put_latency.merge(other.put_latency);
        if (first_error.empty()) {
            first_error = other.first_error;
        }
        end = std::max(end, other.end);
    }
};

// Own one pinned persistent connection with at most one outstanding workload request. One worker
// drives it; response bytes are drained before latency is recorded or another request is issued.
struct LoadConnection {
    TlsSocket socket;
    enum class State {
        handshake,
        idle,
        send_head,
        send_body,
        read_head,
        read_body
    } state{State::handshake};
    bool alive{true}, get{};
    std::string header, input;
    std::array<char, 16384> buffer{};
    std::size_t offset{}, remaining{};
    Clock::time_point started;

    LoadConnection(Fd fd, SSL_CTX* ctx, const Target& target)
        : socket(std::exchange(fd.value, -1), ctx) {
        if (SSL_set_tlsext_host_name(socket.ssl.get(), target.host.c_str()) != 1) {
            throw tls_error("Cannot set load connection TLS server name");
        }
    }

    // Select methods from a global issued-request ticket so mixed ratios do not depend on which
    // method completes faster. In each complete group of 100 tickets the requested ratio is exact.
    void begin(const Target& target, const RunConfig& config, std::uint64_t index) {
        get = config.method == "get" ||
              (config.method == "mixed" &&
               ((index % 100) * config.get_percent) % 100 < config.get_percent);
        const auto path = get ? "/v1/object?size=" + std::to_string(config.get_size) : "/v1/object";
        header = std::string(get ? "GET " : "PUT ") + path + " HTTP/1.1\r\nHost: " + target.host +
                 ":" + target.port + "\r\nAuthorization: Bearer " + target.token +
                 "\r\nContent-Length: " + std::to_string(get ? 0 : config.put_size) + "\r\n\r\n";
        offset = 0;
        input.clear();
        started = Clock::now();
        state = State::send_head;
    }

    // Return true only when idle; partial I/O instead leaves readiness requirements in socket.want.
    bool pump(const Target& target, const RunConfig& config, const std::vector<char>& payload,
              Stats& stats) {
        for (unsigned step = 0; step < 128; ++step) {
            if (state == State::handshake) {
                if (!socket.handshake(false)) {
                    return false;
                }
                if (!equal_secret(fingerprint(socket.ssl.get()), target.pin)) {
                    throw std::runtime_error("Server certificate changed during load setup");
                }
                state = State::idle;
                return true;
            } else if (state == State::idle) {
                return true;
            } else if (state == State::send_head) {
                const int count = socket.write(header.data() + offset, header.size() - offset);
                if (!count) {
                    return false;
                }
                offset += count;
                if (offset == header.size()) {
                    offset = 0;
                    state = get ? State::read_head : State::send_body;
                }
            } else if (state == State::send_body) {
                if (offset == config.put_size) {
                    state = State::read_head;
                } else {
                    const int count =
                        socket.write(payload.data() + offset, config.put_size - offset);
                    if (!count) {
                        return false;
                    }
                    offset += count;
                }
            } else if (state == State::read_head) {
                const auto end = input.find("\r\n\r\n");
                if (end != std::string::npos) {
                    const auto head = parse_head(std::string_view(input).substr(0, end + 4));
                    if (!head.first.starts_with("HTTP/1.1 200 ") ||
                        !head.fields.contains("content-length") ||
                        head.length != (get ? config.get_size : 0) || head.close) {
                        throw std::runtime_error("Unexpected benchmark response: " + head.first);
                    }
                    const auto preloaded = input.size() - end - 4;
                    if (preloaded > head.length) {
                        throw std::runtime_error("Excess response bytes");
                    }
                    remaining = head.length - preloaded;
                    state = State::read_body;
                } else {
                    if (input.size() >= max_header_size) {
                        throw std::runtime_error("Oversized response header");
                    }
                    const int count = socket.read(buffer.data(), buffer.size());
                    if (!count) {
                        return false;
                    }
                    input.append(buffer.data(), count);
                }
            } else {
                if (remaining) {
                    const int count =
                        socket.read(buffer.data(), std::min(buffer.size(), remaining));
                    if (!count) {
                        return false;
                    }
                    remaining -= count;
                } else {
                    const auto ns =
                        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - started)
                            .count();
                    stats.latency.record(ns);
                    (get ? stats.get_latency : stats.put_latency).record(ns);
                    ++stats.completed;
                    if (get) {
                        ++stats.gets;
                        stats.received += config.get_size;
                    } else {
                        ++stats.puts;
                        stats.sent += config.put_size;
                    }
                    state = State::idle;
                    return true;
                }
            }
        }
        socket.want = EPOLLIN | EPOLLOUT;
        return false;
    }
};

// Multiplex a disjoint connection subset using one epoll queue. References belong to the controller
// and must outlive the worker; no connection or Stats object is shared between worker threads.
class LoadWorker {
    const Target& target_;
    const RunConfig& config_;
    const std::vector<char>& payload_;
    Epoll poller_;
    std::unordered_map<int, std::unique_ptr<LoadConnection>> connections_;
    std::array<epoll_event, 256> events_{};

public:
    LoadWorker(const Target& target, const RunConfig& config, const std::vector<char>& payload)
        : target_(target), config_(config), payload_(payload) {
    }

    // Complete and pin every handshake before warmup, keeping connection setup out of measured
    // load.
    void setup(SSL_CTX* ctx, unsigned count) {
        for (unsigned i = 0; i < count; ++i) {
            auto connection = std::make_unique<LoadConnection>(
                connect_socket(target_.host, target_.port), ctx, target_);
            const int fd = connection->socket.fd.value;
            poller_.set(fd, EPOLLIN | EPOLLOUT, true);
            connections_.emplace(fd, std::move(connection));
        }
        const auto deadline = Clock::now() + std::chrono::duration<double>(config_.timeout);
        unsigned ready{};
        Stats unused;
        while (ready != count) {
            if (Clock::now() >= deadline) {
                throw std::runtime_error("Connection setup timed out");
            }
            const int events = poller_.wait(events_.data(), events_.size(), 20);
            for (int i = 0; i < events; ++i) {
                auto& connection = *connections_.at(events_[i].data.fd);
                if (connection.state == LoadConnection::State::idle) {
                    continue;
                }
                if (connection.pump(target_, config_, payload_, unused)) {
                    ++ready;
                    poller_.set(connection.socket.fd.value, 0);
                } else {
                    poller_.set(connection.socket.fd.value, connection.socket.want);
                }
            }
        }
    }

    // Stop issuing at the first limit, but drain outstanding requests up to their individual
    // timeout.
    Stats phase(Clock::time_point start, double duration, std::atomic<std::uint64_t>& issued,
                std::uint64_t limit) {
        Stats stats;
        const auto deadline = start + std::chrono::duration<double>(duration);
        std::size_t active{};
        auto issue = [&](LoadConnection& connection) {
            if (!connection.alive || Clock::now() >= deadline) {
                return false;
            }
            auto ticket = issued.load(std::memory_order_relaxed);
            // Reserve a request globally before sending, including when the limit is below workers.
            do {
                if (limit && ticket >= limit) {
                    return false;
                }
            } while (!issued.compare_exchange_weak(ticket, ticket + 1, std::memory_order_relaxed));
            connection.begin(target_, config_, ticket);
            poller_.set(connection.socket.fd.value, EPOLLOUT);
            return true;
        };
        for (auto& [fd, connection] : connections_) {
            (void)fd;
            if (issue(*connection)) {
                ++active;
            }
        }
        while (active) {
            const int count = poller_.wait(events_.data(), events_.size(), 10);
            for (int i = 0; i < count; ++i) {
                auto& connection = *connections_.at(events_[i].data.fd);
                if (!connection.alive || connection.state == LoadConnection::State::idle) {
                    continue;
                }
                try {
                    if (connection.pump(target_, config_, payload_, stats)) {
                        --active;
                        if (issue(connection)) {
                            ++active;
                        } else {
                            poller_.set(connection.socket.fd.value, 0);
                        }
                    } else {
                        poller_.set(connection.socket.fd.value, connection.socket.want);
                    }
                } catch (const std::exception& error) {
                    stats.fail(error.what());
                    connection.alive = false;
                    connection.socket.fd = Fd{};
                    --active;
                }
            }
            const auto now = Clock::now();
            for (auto& [fd, connection] : connections_) {
                (void)fd;
                if (connection->alive && connection->state != LoadConnection::State::idle &&
                    std::chrono::duration<double>(now - connection->started).count() >=
                        config_.timeout) {
                    stats.fail("Request timed out");
                    connection->alive = false;
                    connection->socket.fd = Fd{};
                    --active;
                }
            }
        }
        stats.end = Clock::now();
        return stats;
    }
};

// Coordinate setup, warmup and measurement without charging connection establishment to throughput.
// Every worker must reach both gates even after failure, or the controller would wait forever.
Json trial(SSL_CTX* ctx, const Target& target, const RunConfig& config,
           const std::vector<char>& payload, unsigned repetition) {
    std::latch setup_done(config.workers), warmup_done(config.workers);
    std::barrier gate(static_cast<std::ptrdiff_t>(config.workers + 1));
    std::atomic<bool> abort{};
    std::atomic<std::uint64_t> warmup_issued{}, issued{};
    Clock::time_point warmup_start, measure_start;
    std::mutex failure_mutex;
    std::string failure;
    std::vector<Stats> results(config.workers);
    std::vector<std::jthread> threads;
    auto fail = [&](const std::string& message) {
        std::lock_guard lock(failure_mutex);
        if (failure.empty()) {
            failure = message;
        }
        abort = true;
    };
    try {
        for (unsigned index = 0; index < config.workers; ++index) {
            threads.emplace_back([&, index] {
                std::unique_ptr<LoadWorker> worker;
                try {
                    worker = std::make_unique<LoadWorker>(target, config, payload);
                    worker->setup(ctx, config.connections / config.workers +
                                           (index < config.connections % config.workers ? 1 : 0));
                } catch (const std::exception& error) {
                    fail(error.what());
                }
                setup_done.count_down();
                gate.arrive_and_wait();
                if (!abort) {
                    try {
                        const auto warmup =
                            worker->phase(warmup_start, config.warmup, warmup_issued, 0);
                        if (warmup.errors) {
                            fail("Warmup failed: " + warmup.first_error);
                        }
                    } catch (const std::exception& error) {
                        fail(error.what());
                    }
                }
                warmup_done.count_down();
                gate.arrive_and_wait();
                if (!abort) {
                    try {
                        results[index] =
                            worker->phase(measure_start, config.duration, issued, config.requests);
                    } catch (const std::exception& error) {
                        fail(error.what());
                    }
                }
            });
        }
    } catch (const std::exception& error) {
        fail(std::string("Cannot start load workers: ") + error.what());
        for (auto index = threads.size(); index < config.workers; ++index) {
            // Threads that were never started cannot participate in latches or barrier phases.
            setup_done.count_down();
            warmup_done.count_down();
            gate.arrive_and_drop();
        }
    }
    // All workers share a start time only after their connections have finished setup.
    setup_done.wait();
    warmup_start = Clock::now();
    gate.arrive_and_wait();
    // Drain warmup before taking the baseline; no warmup request may leak into measurement.
    warmup_done.wait();
    Json server_before, client_before;
    if (!abort) {
        try {
            server_before = control(ctx, target, "/v1/telemetry");
            client_before = usage();
        } catch (const std::exception& error) {
            fail(error.what());
        }
    }
    measure_start = Clock::now();
    gate.arrive_and_wait();
    threads.clear();
    if (abort) {
        throw std::runtime_error(failure);
    }
    Stats combined;
    for (const auto& stats : results) {
        combined.merge(stats);
    }
    const double elapsed = std::chrono::duration<double>(combined.end - measure_start).count();
    const auto client_after = usage();
    const auto server_after = control(ctx, target, "/v1/telemetry");
    auto client_usage = usage_delta(client_before, client_after, elapsed);
    auto server_usage =
        usage_delta(server_before.at("process"), server_after.at("process"), elapsed);
    std::vector<std::string> warnings{
        "Closed-loop workload: percentiles exclude arrival-rate queueing and do not establish an "
        "SLA.",
        "Server telemetry is process-wide; concurrent users invalidate attribution.",
        "CPU telemetry includes control sampling; server sample boundaries slightly exceed the "
        "load interval.",
        "In-flight requests are drained after the duration limit; elapsed time includes draining."};
    if (client_usage.at("cpu_core_equivalents").get<double>() >= config.workers * .85) {
        warnings.emplace_back(
            "Load-generator workers may be CPU saturated; do not assume a server limit.");
    }
    if (combined.errors) {
        warnings.emplace_back(
            "Request failures occurred; this is not an error-free throughput result.");
    }
    if (!combined.completed) {
        warnings.emplace_back("No requests completed successfully.");
    }
    if (server_before.at("process").at("voluntary_context_switches").is_null()) {
        warnings.emplace_back("Server context-switch counters are unavailable; null is not zero.");
    }
    if (server_before.value("process_cpu_scope", "").find("System") != std::string::npos) {
        warnings.emplace_back(
            "Server process CPU excludes HTTP.sys/Schannel work charged to System; "
            "CPU/request is not total OS CPU cost.");
    }
    const double server_cpu = server_usage.at("user_cpu_seconds").get<double>() +
                              server_usage.at("system_cpu_seconds").get<double>();
    return {{"repetition", repetition},
            {"elapsed_seconds", elapsed},
            {"issued", issued.load()},
            {"completed", combined.completed},
            {"errors", combined.errors},
            {"first_error", combined.first_error},
            {"get_completed", combined.gets},
            {"put_completed", combined.puts},
            {"received_object_bytes", combined.received},
            {"sent_object_bytes", combined.sent},
            {"requests_per_second", combined.completed / elapsed},
            {"object_goodput_bytes_per_second", (combined.received + combined.sent) / elapsed},
            {"server_cpu_seconds_per_request",
             combined.completed ? Json(server_cpu / combined.completed) : Json(nullptr)},
            {"latency", combined.latency.json()},
            {"client_process", client_usage},
            {"latency_by_method",
             {{"get", combined.get_latency.json()}, {"put", combined.put_latency.json()}}},
            {"server_process", server_usage},
            {"server_before", server_before},
            {"server_after", server_after},
            {"warnings", warnings}};
}

RunConfig configuration(const Args& args) {
    RunConfig config;
    config.method = lower(args.get("--method", "get"));
    config.get_size = object_size(args.get("--get-size", "4KiB"));
    config.put_size = object_size(args.get("--put-size", "4KiB"));
    config.get_percent = number(args.get("--get-percent", "50"), 100);
    config.connections = number(args.get("--connections", "256"), 16384);
    config.workers =
        number(args.get("--workers",
                        std::to_string(std::min(
                            config.connections,
                            std::min(8u, std::max(1u, std::thread::hardware_concurrency()))))),
               256);
    config.warmup = seconds(args.get("--warmup", "10"));
    config.duration = seconds(args.get("--duration", "30"));
    config.repetitions = number(args.get("--repetitions", "3"), 1000);
    config.requests = number(args.get("--requests", "0"));
    config.timeout = seconds(args.get("--timeout", "10"), 3600);
    config.validate();
    return config;
}

// Persist every finished repetition and a final failure status; a nonzero result must remain
// visible to automation even when useful partial measurements were saved.
int run(Target target, const RunConfig& config, const fs::path& output) {
    auto ctx = context(false, target.cipher);
    auto capabilities = control(ctx.get(), target, "/v1/capabilities");
    if (capabilities.at("backend") == "openssl-ktls" &&
        (((config.method == "get" || (config.method == "mixed" && config.get_percent)) &&
          !capabilities.at("ktls_tx").get<bool>()) ||
         ((config.method == "put" || (config.method == "mixed" && config.get_percent < 100)) &&
          !capabilities.at("ktls_rx").get<bool>()))) {
        throw std::runtime_error(
            "Requested kTLS direction is unavailable; refusing userspace fallback");
    }
    if (config.connections + 1 > capabilities.at("max_connections").get<unsigned>()) {
        throw std::invalid_argument(
            "Server connection limit must allow load connections plus control sampling");
    }
    std::vector<char> payload(std::max<std::size_t>(1, config.put_size));
    if (RAND_bytes(reinterpret_cast<unsigned char*>(payload.data()), payload.size()) != 1) {
        throw tls_error("RAND_bytes");
    }
    Json report = {
        {"schema_version", 1},
        {"benchmark", "https"},
        {"status", "running"},
        {"target",
         {{"host", target.host}, {"port", target.port}, {"certificate_sha256", target.pin}}},
        {"configuration", config.json()},
        {"client_environment", environment()},
        {"server_capabilities", capabilities},
        {"started_unix_seconds",
         std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch())
             .count()},
        {"results", Json::array()}};
    report["configuration"]["cipher"] = target.cipher;
    if (!output.parent_path().empty()) {
        fs::create_directories(output.parent_path());
    }
    write_private(output, report, true);
    bool errors = false;
    try {
        std::cout << "Run  requests/s     p50(us)     p99(us)   errors\n";
        for (unsigned index = 1; index <= config.repetitions; ++index) {
            auto result = trial(ctx.get(), target, config, payload, index);
            errors = errors || result.at("errors").get<std::uint64_t>() != 0 ||
                     result.at("completed").get<std::uint64_t>() == 0;
            std::cout << std::fixed << std::setprecision(2) << std::setw(3) << index
                      << std::setw(12) << result.at("requests_per_second").get<double>()
                      << std::setw(12) << result.at("latency").at("p50_us").get<double>()
                      << std::setw(12) << result.at("latency").at("p99_us").get<double>()
                      << std::setw(9) << result.at("errors").get<std::uint64_t>() << '\n';
            for (const auto& warning : result.at("warnings")) {
                log_warning(warning.get<std::string>());
            }
            report["results"].push_back(std::move(result));
            write_private(output, report, false);
        }
        report["status"] = errors ? "completed_with_errors" : "completed";
        write_private(output, report, false);
    } catch (const std::exception& error) {
        report["status"] = "failed";
        report["failure"] = error.what();
        write_private(output, report, false);
        throw;
    }
    std::cout << "Results saved to " << output.string() << '\n';
    if (errors) {
        log_warning(
            "Benchmark completed with errors; do not treat it as a valid throughput result");
    }
    return errors ? 2 : 0;
}

std::string default_output() {
    return "results/https-" +
           std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count()) +
           ".json";
}

std::string prompt(const std::string& label, const std::string& fallback = {}) {
    std::cout << label;
    if (!fallback.empty()) {
        std::cout << " [" << fallback << "]";
    }
    std::cout << ": " << std::flush;
    std::string value;
    if (!std::getline(std::cin, value)) {
        throw std::runtime_error("Input closed");
    }
    return value.empty() ? fallback : value;
}

std::string select_target() {
    std::vector<std::string> paths;
    for (const auto& entry : fs::directory_iterator(state_directory())) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            paths.push_back(entry.path());
        }
    }
    std::sort(paths.begin(), paths.end());
    if (paths.empty()) {
        throw std::runtime_error("No registered targets; pair a server first");
    }
    for (std::size_t index = 0; index < paths.size(); ++index) {
        const auto target = load_target(paths[index]);
        std::cout << index + 1 << ". " << target.host << ':' << target.port << '\n';
    }
    const auto index = number(prompt("Target number", "1"), paths.size());
    if (!index) {
        throw std::invalid_argument("Target numbers start at 1");
    }
    return paths[index - 1];
}

// Keep recoverable input/run failures local to the menu; CLI fatal failures instead exit nonzero.
void interactive() {
    while (std::cin) {
        std::cout
            << "\nWinlin\n1. Add server\n2. Inspect server\n3. Run HTTPS benchmark\n0. Exit\n";
        const auto action = prompt("Select", "0");
        if (action == "0") {
            return;
        }
        try {
            if (action == "1") {
                const auto host = prompt("Server IPv4 address");
                check_host(host);
                const auto port = prompt("Agent port", "8443");
                const auto cipher = prompt("TLS 1.3 cipher", "TLS_AES_128_GCM_SHA256");
                auto ctx = context(false, cipher);
                auto socket = connect_tls(ctx.get(), host, port, {});
                const auto pin = fingerprint(socket->ssl.get());
                std::cout << "Server certificate SHA-256: " << pin
                          << "\nVerify this fingerprint through a trusted channel.\n";
                if (prompt("Trust this certificate? Type yes", "no") != "yes") {
                    continue;
                }
                const auto token = prompt("Path to private pairing-token file");
                pair_target(host, port, token, pin,
                            state_directory() / (host + "-" + port + ".json"), cipher);
            } else if (action == "2") {
                const auto target = load_target(select_target());
                auto ctx = context(false, target.cipher);
                std::cout << control(ctx.get(), target, "/v1/capabilities").dump(2) << '\n';
            } else if (action == "3") {
                const auto target = load_target(select_target());
                RunConfig config;
                config.method = lower(prompt("Method: get / put / mixed", "get"));
                std::cout << "Size presets: 256B, 512B, 1KiB, 4KiB, 8KiB, 16KiB, 64KiB, 256KiB, "
                             "1MiB, 4MiB\n";
                config.get_size = object_size(prompt("GET size", "4KiB"));
                config.put_size = object_size(prompt("PUT size", "4KiB"));
                if (config.method == "mixed") {
                    config.get_percent =
                        number(prompt("GET percentage by request count", "50"), 100);
                }
                config.connections = number(prompt("Connections (1-16384)", "256"), 16384);
                config.workers = number(
                    prompt("Load-generator workers",
                           std::to_string(std::min(
                               config.connections,
                               std::min(8u, std::max(1u, std::thread::hardware_concurrency()))))),
                    256);
                config.warmup = seconds(prompt("Warmup seconds", "10"));
                config.duration = seconds(prompt("Measurement seconds", "30"));
                config.requests = number(prompt("Request limit (0 = duration only)", "0"));
                config.repetitions = number(prompt("Repetitions", "3"), 1000);
                config.validate();
                run(target, config, prompt("Result file", default_output()));
            } else {
                std::cout << "Unknown selection\n";
            }
        } catch (const std::exception& error) {
            log_warning(error.what());
        }
    }
}
}

int main(int argc, char** argv) {
    using namespace winlin;
    try {
        std::signal(SIGPIPE, SIG_IGN);
        if (argc == 1) {
            interactive();
            return 0;
        }
        const std::string command = argv[1];
        if (command == "--help" || command == "help") {
            std::cout
                << "winlin                         Interactive console\n"
                   "winlin pair --host IP --token-file FILE --fingerprint SHA256 --target FILE\n"
                   "            [--port 8443] [--cipher TLS_AES_128_GCM_SHA256]\n"
                   "winlin inspect --target FILE\n"
                   "winlin run --target FILE [--method get|put|mixed] [--get-size 4KiB]\n"
                   "           [--put-size 4KiB] [--get-percent 50] [--connections 256]\n"
                   "           [--workers N] [--warmup 10] [--duration 30] [--requests 0]\n"
                   "           [--repetitions 3] [--timeout 10] [--output FILE] [--cipher SUITE]\n"
                   "Closed-loop persistent HTTPS only; paced load and handshake tests are not "
                   "implemented yet.\n";
            return 0;
        }
        Args args(argc, argv, 2);
        if (command == "pair") {
            args.allow(
                {"--host", "--port", "--token-file", "--fingerprint", "--target", "--cipher"});
            pair_target(args.require("--host"), args.get("--port", "8443"),
                        args.require("--token-file"), args.require("--fingerprint"),
                        args.require("--target"), args.get("--cipher", "TLS_AES_128_GCM_SHA256"));
            return 0;
        }
        if (command == "inspect") {
            args.allow({"--target"});
            const auto target = load_target(args.require("--target"));
            auto ctx = context(false, target.cipher);
            std::cout << control(ctx.get(), target, "/v1/capabilities").dump(2) << '\n';
            return 0;
        }
        if (command == "run") {
            args.allow({"--target", "--method", "--get-size", "--put-size", "--get-percent",
                        "--connections", "--workers", "--warmup", "--duration", "--requests",
                        "--repetitions", "--timeout", "--output", "--cipher"});
            const auto config = configuration(args);
            auto target = load_target(args.require("--target"));
            target.cipher = args.get("--cipher", target.cipher);
            return run(target, config, args.get("--output", default_output()));
        }
        throw std::invalid_argument("Unknown command; use winlin --help");
    } catch (const std::exception& error) {
        std::cerr << "winlin: FATAL: " << error.what() << '\n';
        return 1;
    }
}
