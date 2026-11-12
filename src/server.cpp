#include "winlin/linux.hpp"
#include "winlin/agent.hpp"

#include <iostream>
#include <latch>
#include <mutex>
#include <unordered_map>

namespace {
using namespace winlin;
std::atomic<bool> interrupted{};
static_assert(std::atomic<bool>::is_always_lock_free);

void on_signal(int) {
    interrupted.store(true, std::memory_order_relaxed);
}

AgentConfig linux_config(const Args& args) {
    const auto backend = args.get("--backend", "openssl");
    if (backend != "openssl") {
        throw std::invalid_argument(
            "Select benchmark TLS/kTLS from the client; control uses OpenSSL");
    }
    auto config = AgentConfig::from_args(args, "openssl");
    config.benchmark_tls_modes = {"on", "off", "ktls"};
    config.environment = environment();
    return config;
}

// Apply requested tuning only to the per-run workload, leaving the control endpoint unchanged.
AgentConfig workload_config(const Args& args, const BenchmarkOptions& options) {
    auto config = linux_config(args);
    config.role = AgentConfig::Role::workload;
    config.tls = options.tls != "off";
    config.backend = options.tls == "off"    ? "http"
                     : options.tls == "ktls" ? "openssl-ktls"
                                             : "openssl";
    config.cipher = options.cipher;
    config.workers = options.workers;
    config.connection_limit = options.max_connections;
    return config;
}

// Share immutable TLS configuration/payload and atomic agent counters across Linux workers.
// Each worker owns separate listeners and sessions; this server must outlive all of them.
struct Server : Agent {
    Context tls;
    std::vector<char> payload;
    bool ktls{};
    std::atomic<bool> stop{};

    Server(const Args& args, const BenchmarkOptions* options = nullptr,
           const std::string& run_id = {})
        : Agent(
              options ? workload_config(args, *options) : linux_config(args),
              options                            ? "workload"
              : args.get("--token-file").empty() ? ""
                                                 : token_file(args.get("--token-file")),
              options ? std::optional<std::string>(run_id)
              : args.get("--token-file").empty()
                  ? std::nullopt
                  : optional_token_file(
                        args.get("--session-file", args.get("--token-file") + ".session")),
              [path = args.get("--session-file", args.get("--token-file") + ".session")] {
                  return issue_token_file(path);
              },
              equal_secret, usage),
          tls(options && options->tls == "off"
                  ? Context(nullptr, SSL_CTX_free)
                  : context(true,
                            options ? options->cipher
                                    : args.get("--cipher", "TLS_AES_128_GCM_SHA256"),
                            options && options->tls == "ktls")),
          payload(options ? max_object_size : 0), ktls(options && options->tls == "ktls") {
        if (!options && args.get("--token-file").empty()) {
            log_warning("Authentication disabled; use only on an isolated benchmark network");
        }
        if (tls &&
            (SSL_CTX_use_certificate_chain_file(tls.get(), args.require("--cert").c_str()) != 1 ||
             SSL_CTX_use_PrivateKey_file(tls.get(), args.require("--key").c_str(),
                                         SSL_FILETYPE_PEM) != 1 ||
             SSL_CTX_check_private_key(tls.get()) != 1)) {
            throw tls_error("Cannot load matching certificate/private key");
        }
        if (!payload.empty() &&
            RAND_bytes(reinterpret_cast<unsigned char*>(payload.data()), payload.size()) != 1) {
            throw tls_error("Cannot generate reusable payload");
        }
    }
};

// Drive one persistent HTTP/TLS connection without blocking a worker. Buffers survive partial I/O;
// PUT counts advance only after receipt, GET counts only after the response has been sent.
// The accept loop reserves an active slot before construction, released by this session's
// destructor.
struct Session {
    StreamSocket socket;
    Server& server;
    enum class State {
        handshake,
        header,
        body,
        control_body,
        send_header,
        send_body
    } state{State::handshake};
    std::string input, output, text_body;
    std::array<char, 16384> buffer{};
    std::size_t offset{}, body_remaining{}, body_size{};
    bool close{}, object_response{}, get{}, put{}, tx{}, rx{};
    std::optional<HttpHead> control_head;
    std::string control_body;
    Clock::time_point activity{Clock::now()};

    Session(int fd, Server& owner) : socket(fd, owner.tls.get()), server(owner) {
    }

    ~Session() {
        --server.active;
    }

    void respond(int status, std::string body = {}, bool object = false, std::size_t size = 0) {
        text_body = std::move(body);
        object_response = object;
        body_size = object ? size : text_body.size();
        output = "HTTP/1.1 " + std::to_string(status) + " " + (status == 200 ? "OK" : "Error") +
                 "\r\nContent-Length: " + std::to_string(body_size) +
                 "\r\nContent-Type: " + (object ? "application/octet-stream" : "application/json") +
                 "\r\nCache-Control: no-store\r\nConnection: " + (close ? "close" : "keep-alive") +
                 "\r\nX-Winlin-Ktls-Tx: " + (tx ? "1" : "0") +
                 "\r\nX-Winlin-Ktls-Rx: " + (rx ? "1" : "0") + "\r\n\r\n";
        offset = 0;
        state = State::send_header;
    }

    // Translate shared dispatch into transport states; a PUT must be drained before responding.
    void request(const HttpHead& head) {
        body_remaining = 0;
        const ConnectionInfo connection{socket.ssl ? SSL_get_version(socket.ssl.get()) : "",
                                        socket.ssl ? SSL_get_cipher_name(socket.ssl.get()) : "", tx,
                                        rx};
        const auto reply = server.Agent::request(head, connection);
        close = reply.close;
        get = reply.kind == AgentReply::Kind::object;
        put = reply.kind == AgentReply::Kind::consume_put;
        if (reply.kind == AgentReply::Kind::consume_control) {
            control_head = head;
            control_body.clear();
            body_remaining = reply.size;
            state = State::control_body;
        } else if (put) {
            body_size = body_remaining = reply.size;
            state = State::body;
        } else {
            respond(reply.status, reply.text, get, reply.size);
        }
    }

    // Advance until OpenSSL needs readiness or the fairness budget is exhausted. False tells the
    // worker to destroy this session; it does not mean an individual syscall should be retried.
    bool pump() {
        for (unsigned step = 0; step < 128; ++step) {
            if (state == State::handshake) {
                if (!socket.handshake(true)) {
                    return true;
                }
                if (socket.ssl) {
                    tx = BIO_get_ktls_send(SSL_get_wbio(socket.ssl.get()));
                    rx = BIO_get_ktls_recv(SSL_get_rbio(socket.ssl.get()));
                    ++server.handshakes;
                }
                if (tx) {
                    ++server.tx_ktls;
                }
                if (rx) {
                    ++server.rx_ktls;
                }
                state = State::header;
            } else if (state == State::header) {
                const auto end = input.find("\r\n\r\n");
                if (end != std::string::npos) {
                    // Clear accounting before parsing: parser failures bypass shared dispatch.
                    get = put = false;
                    try {
                        const auto head = parse_head(std::string_view(input).substr(0, end + 4));
                        input.erase(0, end + 4);
                        request(head);
                    } catch (const std::invalid_argument& error) {
                        log_warning(std::string("Rejected malformed HTTP header: ") + error.what());
                        close = true;
                        respond(400, R"({"error":"invalid request"})");
                    }
                } else {
                    if (input.size() >= max_header_size) {
                        log_warning("HTTP header exceeds the supported size; closing connection");
                        return false;
                    }
                    const int count = socket.read(buffer.data(), buffer.size());
                    if (!count) {
                        return true;
                    }
                    input.append(buffer.data(), count);
                }
            } else if (state == State::control_body) {
                const auto count = std::min(body_remaining, input.size());
                control_body.append(input.data(), count);
                input.erase(0, count);
                body_remaining -= count;
                if (!body_remaining) {
                    const auto reply = server.Agent::request(
                        *control_head,
                        {SSL_get_version(socket.ssl.get()), SSL_get_cipher_name(socket.ssl.get())},
                        control_body);
                    control_head.reset();
                    control_body.clear();
                    close = reply.close;
                    respond(reply.status, reply.text);
                } else {
                    const auto count =
                        socket.read(buffer.data(), std::min(buffer.size(), body_remaining));
                    if (!count) {
                        return true;
                    }
                    input.append(buffer.data(), count);
                }
            } else if (state == State::body) {
                const auto count = std::min(body_remaining, input.size());
                input.erase(0, count);
                body_remaining -= count;
                if (!body_remaining) {
                    ++server.puts;
                    server.put_bytes += body_size;
                    respond(200);
                } else {
                    const int bytes =
                        socket.read(buffer.data(), std::min(buffer.size(), body_remaining));
                    if (!bytes) {
                        return true;
                    }
                    body_remaining -= bytes;
                }
            } else if (state == State::send_header) {
                const int bytes = socket.write(output.data() + offset, output.size() - offset);
                if (!bytes) {
                    return true;
                }
                offset += bytes;
                if (offset == output.size()) {
                    offset = 0;
                    state = State::send_body;
                }
            } else {
                if (offset < body_size) {
                    const char* data = object_response ? server.payload.data() : text_body.data();
                    const int bytes = socket.write(data + offset, body_size - offset);
                    if (!bytes) {
                        return true;
                    }
                    offset += bytes;
                } else {
                    if (get) {
                        ++server.gets;
                        server.get_bytes += body_size;
                    }
                    if (close) {
                        return false;
                    }
                    state = State::header;
                }
            }
            activity = Clock::now();
        }
        socket.want = EPOLLIN | EPOLLOUT;
        return true;
    }
};

// Claim machine-wide server ownership before constructing workers. Unlike HTTPS listeners, this
// socket must never enable either reuse option; closing it also releases ownership after a crash.
Fd server_guard() {
    Fd fd(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (fd.value < 0) {
        throw system_error("Create server guard socket");
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(server_guard_port);
    if (bind(fd.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
        listen(fd.value, 1)) {
        throw system_error("Cannot reserve exclusive server guard on 127.0.0.1:" +
                           std::to_string(server_guard_port) +
                           "; another Winlin server or application may already own this port");
    }
    return fd;
}

// Bind one reuse-port listener per worker; the first ephemeral port is reused by later workers.
Fd listener(const std::string& bind_address, unsigned& port) {
    Fd fd(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (fd.value < 0) {
        throw system_error("socket");
    }
    int one = 1;
    if (setsockopt(fd.value, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
        setsockopt(fd.value, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one))) {
        throw system_error("SO_REUSEPORT");
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_address.c_str(), &address.sin_addr) != 1) {
        throw std::invalid_argument("--bind must be an IPv4 address");
    }
    if (bind(fd.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
        listen(fd.value, 4096)) {
        throw system_error("bind/listen");
    }
    socklen_t length = sizeof(address);
    if (getsockname(fd.value, reinterpret_cast<sockaddr*>(&address), &length)) {
        throw system_error("getsockname");
    }
    port = ntohs(address.sin_port);
    return fd;
}

// Own all sessions for one listener. Per-connection errors are recoverable; listener/epoll failures
// escape to main so a partial worker pool cannot masquerade as a successful server.
void serve(Server& server, Fd listener_fd, const std::function<void()>& ready = {}) {
    Epoll poller;
    poller.set(listener_fd.value, EPOLLIN, true);
    if (ready) {
        ready();
    }
    std::unordered_map<int, std::unique_ptr<Session>> sessions;
    std::array<epoll_event, 256> events{};
    auto sweep = Clock::now();
    while (!interrupted && !server.stop) {
        const int count = poller.wait(events.data(), events.size(), 100);
        for (int i = 0; i < count; ++i) {
            const int fd = events[i].data.fd;
            if (fd == listener_fd.value) {
                for (unsigned accepted = 0; accepted < 256; ++accepted) {
                    Fd client(accept4(fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
                    if (client.value < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        if (errno == EINTR) {
                            continue;
                        }
                        throw system_error("accept");
                    }
                    if (server.active.fetch_add(1) >= server.config.connection_limit) {
                        log_warning("Server connection limit reached; rejecting connection");
                        --server.active;
                        continue;
                    }
                    const int client_fd = client.value;
                    try {
                        auto session =
                            std::make_unique<Session>(std::exchange(client.value, -1), server);
                        sessions.emplace(client_fd, std::move(session));
                        poller.set(client_fd, EPOLLIN, true);
                        ++server.connections;
                    } catch (...) {
                        if (!sessions.erase(client_fd)) {
                            --server.active;
                        }
                        throw;
                    }
                }
            } else if (const auto it = sessions.find(fd); it != sessions.end()) {
                try {
                    if (!it->second->pump()) {
                        sessions.erase(it);
                    } else {
                        poller.set(fd, it->second->socket.want);
                    }
                } catch (const PeerClosed& error) {
                    if (it->second->state == Session::State::header && !it->second->input.empty()) {
                        log_warning("Peer closed an incomplete HTTP header");
                    } else if (it->second->state != Session::State::header) {
                        log_warning(std::string("Peer closed an unfinished request: ") +
                                    error.what());
                    }
                    sessions.erase(fd);
                } catch (const std::exception& error) {
                    log_warning(std::string("Closing failed connection: ") + error.what());
                    sessions.erase(fd);
                }
            }
        }
        if (Clock::now() - sweep >= std::chrono::seconds(1)) {
            sweep = Clock::now();
            std::erase_if(sessions, [&](const auto& entry) {
                const auto& session = *entry.second;
                const bool expired = sweep - session.activity > std::chrono::seconds(60);
                if (expired &&
                    (session.state != Session::State::header || !session.input.empty())) {
                    log_warning("Server session timed out with an unfinished request");
                }
                return expired;
            });
        }
    }
}

// Reuse exactly the native epoll/HTTP engine for all workload modes. Only TLS record processing
// differs; listeners and worker counts are replaced between exclusive runs, never during a run.
class LinuxBenchmark final : public BenchmarkInstance {
    Server server_;
    unsigned port_;
    mutable std::mutex failure_mutex_;
    std::string failure_;
    std::vector<std::jthread> workers_;

public:
    LinuxBenchmark(const Args& args, const BenchmarkOptions& options, const std::string& id)
        : server_(args, &options, id),
          port_(static_cast<unsigned>(
              number(args.get(options.tls == "off" ? "--http-port" : "--https-port",
                              options.tls == "off" ? "38444" : "38445"),
                     65535))) {
        std::vector<Fd> listeners;
        auto ready = std::make_shared<std::latch>(options.workers);
        try {
            for (unsigned index = 0; index < options.workers; ++index) {
                listeners.push_back(listener(args.get("--bind", "0.0.0.0"), port_));
            }
            for (auto& fd : listeners) {
                workers_.emplace_back([this, ready, owned = std::move(fd)]() mutable {
                    bool announced = false;
                    try {
                        serve(server_, std::move(owned), [&] {
                            announced = true;
                            ready->count_down();
                        });
                    } catch (const std::exception& error) {
                        std::lock_guard lock(failure_mutex_);
                        failure_ = error.what();
                        server_.stop = true;
                        if (!announced) {
                            ready->count_down();
                        }
                    }
                });
            }
            ready->wait();
            std::lock_guard lock(failure_mutex_);
            if (!failure_.empty()) {
                throw std::runtime_error(failure_);
            }
        } catch (...) {
            server_.stop = true;
            workers_.clear();
            throw;
        }
    }

    ~LinuxBenchmark() override {
        server_.stop = true;
        workers_.clear();
    }

    Json describe() const override {
        return {{"port", port_},
                {"transport", server_.config.tls ? "https" : "http"},
                {"backend", server_.config.backend}};
    }

    Json telemetry() const override {
        std::lock_guard lock(failure_mutex_);
        if (!failure_.empty()) {
            throw BenchmarkError(503, "Workload worker failed: " + failure_);
        }
        return server_.telemetry();
    }
};
}

int main(int argc, char** argv) {
    using namespace winlin;
    if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
        std::cout
            << "winlin-server --cert certificate.pem --key private.key\n"
               "  [--bind 0.0.0.0] [--port 38443] [--workers 8]\n"
               "  [--http-port 38444] [--https-port 38445]\n"
               "  Benchmark workers/TLS/kTLS are selected by the client per run.\n"
               "  [--cipher TLS_AES_128_GCM_SHA256] [--max-connections 32768]\n"
               "  [--token-file path] (optional authentication; default: none)\n"
               "  [--session-file path] (requires --token-file; default: TOKEN-FILE.session)\n";
        return 0;
    }
    try {
        std::signal(SIGPIPE, SIG_IGN);
        std::signal(SIGINT, on_signal);
        std::signal(SIGTERM, on_signal);
        Args args(argc, argv);
        args.allow({"--cert", "--key", "--token-file", "--bind", "--port", "--workers", "--backend",
                    "--cipher", "--max-connections", "--session-file", "--http-port",
                    "--https-port"});
        const auto control_port = number(args.get("--port", "38443"), 65535);
        const auto http_port = number(args.get("--http-port", "38444"), 65535);
        const auto https_port = number(args.get("--https-port", "38445"), 65535);
        if ((control_port && (control_port == http_port || control_port == https_port)) ||
            (http_port && http_port == https_port)) {
            throw std::invalid_argument("Control, HTTP and HTTPS workload ports must be distinct");
        }
        const auto instance_guard = server_guard();
        process_cycles = std::make_unique<ProcessCycles>();
        BenchmarkController controller(
            [] {
                std::array<unsigned char, 32> bytes{};
                if (RAND_bytes(bytes.data(), bytes.size()) != 1) {
                    throw tls_error("Cannot generate benchmark lease");
                }
                std::string id;
                constexpr char hex[] = "0123456789abcdef";
                for (auto byte : bytes) {
                    id += hex[byte >> 4];
                    id += hex[byte & 15];
                }
                return id;
            },
            [&](const BenchmarkOptions& options, const std::string& id) {
                return std::make_unique<LinuxBenchmark>(args, options, id);
            });
        Server server(args);
        server.config.role = AgentConfig::Role::control;
        server.controller = &controller;
        const auto bind_address = args.get("--bind", "0.0.0.0");
        auto port = static_cast<unsigned>(number(args.get("--port", "38443"), 65535));
        const auto workers = server.config.workers;
        std::vector<Fd> listeners;
        for (unsigned i = 0; i < workers; ++i) {
            listeners.push_back(listener(bind_address, port));
        }
        std::mutex error_mutex;
        std::string failure;
        std::vector<std::jthread> threads;
        try {
            for (auto& fd : listeners) {
                threads.emplace_back([&, owned = std::move(fd)]() mutable {
                    try {
                        serve(server, std::move(owned));
                    } catch (const std::exception& error) {
                        std::lock_guard lock(error_mutex);
                        failure = error.what();
                        server.stop = true;
                    }
                });
            }
        } catch (...) {
            server.stop = true;
            throw;
        }
        std::cout << Json{{"event", "listening"},
                          {"bind", bind_address},
                          {"port", port},
                          {"backend", server.ktls ? "openssl-ktls" : "openssl"},
                          {"workers", workers}}
                         .dump()
                  << std::endl;
        threads.clear();
        if (!failure.empty()) {
            throw std::runtime_error(failure);
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "winlin-server: FATAL: " << error.what() << '\n';
        return 1;
    }
}
