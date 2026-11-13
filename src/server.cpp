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

// Signal handlers only request shutdown. Worker loops observe this flag and release their own
// sockets and sessions; cleanup and logging must not run inside the signal handler.
void on_signal(int) {
    interrupted.store(true, std::memory_order_relaxed);
}

// Describe the permanent plain-HTTP control endpoint and the workload backends this host supports.
// Advertising kTLS does not guarantee activation: each workload connection must verify the
// requested direction after its TLS handshake.
AgentConfig linux_config(const Args& args) {
    auto config = AgentConfig::from_args(args, "http");
    config.tls = false;
    config.benchmark_tls_modes = {"on", "off", "ktls"};
    config.supported_ciphers = supported_tls_ciphers();
    config.supported_backends = {
        {{"name", "http"}, {"transport", "http"}, {"tls_mode", "off"}},
        {{"name", "openssl"}, {"transport", "https"}, {"tls_mode", "on"}},
        {{"name", "openssl-ktls"},
         {"transport", "https"},
         {"tls_mode", "ktls"},
         {"availability", "conditional"},
         {"requirement",
          "Kernel/OpenSSL support and verified activation for the requested direction"}}};
    config.environment = environment();
    return config;
}

// Build the temporary workload's configuration from the settings selected by the client.
// The control endpoint keeps its original workers and plain-HTTP transport. A kTLS workload still
// uses OpenSSL for the handshake, but requests kernel TLS record processing afterward.
AgentConfig workload_config(const Args& args, const BenchmarkOptions& options) {
    auto config = linux_config(args);
    config.role = AgentConfig::Role::workload;
    config.tls = options.tls != "off";
    config.backend = options.tls == "off"    ? "http"
                     : options.tls == "ktls" ? "openssl-ktls"
                                             : "openssl";
    config.cipher = options.cipher;
    config.workers = options.workers;
    return config;
}

// Hold the configuration and shared resources for either the control endpoint or one workload.
// Agent supplies the common Linux/Windows routing, request validation, and telemetry counters.
// This class adds the Linux TLS context and a reusable random payload for GET responses.
//
// Workload workers read the same payload instead of generating bytes for every request. The TLS
// context is configured before workers start; each accepted connection creates its own TLS session.
// Workers update Agent's atomic counters, but own separate listeners and connection state.
// Keep this Server alive until all workers and their sessions have been destroyed.
struct Server : Agent {
    Context tls;
    std::vector<char> payload;
    bool ktls{};
    std::atomic<bool> stop{};

    // Without options, construct a plain-HTTP control server. With options, prepare the selected
    // workload backend, loading a matching certificate/key only when HTTPS was requested.
    Server(const Args& args, const BenchmarkOptions* options = nullptr,
           const std::string& run_id = {})
        : Agent(options ? workload_config(args, *options) : linux_config(args), usage, run_id,
                host_usage),
          tls(options && options->tls != "off"
                  ? context(true, options->cipher, options->tls == "ktls")
                  : Context(nullptr, SSL_CTX_free)),
          payload(options ? max_object_size : 0), ktls(options && options->tls == "ktls") {
        if (tls &&
            (SSL_CTX_use_certificate_chain_file(tls.get(), args.require("--cert").c_str()) != 1 ||
             SSL_CTX_use_PrivateKey_file(tls.get(), args.require("--key").c_str(),
                                         SSL_FILETYPE_PEM) != 1 ||
             SSL_CTX_check_private_key(tls.get()) != 1)) {
            throw tls_error("Cannot load matching certificate/private key");
        }
        // Generate dummy GET data once, outside request processing. PUT bodies are discarded,
        // so neither method performs storage I/O during the benchmark.
        if (!payload.empty() &&
            RAND_bytes(reinterpret_cast<unsigned char*>(payload.data()), payload.size()) != 1) {
            throw tls_error("Cannot generate reusable payload");
        }
    }
};

// Process requests on one persistent client connection. A serve() worker owns this Session and
// calls pump() when epoll reports socket readiness. There is no separate thread for the connection.
//
// The state machine first completes TCP/TLS setup, then reads a header and asks Agent how to handle
// the request. PUT data is consumed and discarded before its response is prepared. Control JSON
// is retained until the full body can be dispatched. GET responses use Server's shared payload.
// After sending a response, return to reading headers unless the connection must close.
//
// Buffers and offsets remain valid across partial reads, writes, and OpenSSL retries. PUT counters
// advance after the complete body is received; GET counters advance after the complete response
// has been accepted by the socket/TLS write path, not after confirmation from the client.
// Server must outlive this object. The accept loop reserves an active-connection slot before
// construction, and the Session destructor releases it.
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

    // Take ownership of an accepted socket and borrow the worker's shared Server resources.
    Session(int fd, Server& owner) : socket(fd, owner.tls.get()), server(owner) {
    }

    // Release the connection slot when the worker removes this session or shuts down.
    ~Session() {
        --server.active;
    }

    // Prepare the response but do not send it yet. Keep JSON text and serialized headers in this
    // session until pump() finishes writing; object bodies instead borrow Server's GET payload.
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

    // Let the shared Agent validate and route the header, then select the native next step.
    // PUT and control requests need their full bodies before completion; other replies can be
    // prepared immediately. Preserve the negotiated TLS information for backend validation.
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

    // Advance the connection without waiting inside a socket operation. Process at most 128 steps
    // so one large transfer cannot monopolize the worker. A pending read/write returns true with
    // socket.want identifying the readiness needed; budget exhaustion also returns true.
    // False means the worker should remove and close this session, not retry an I/O operation.
    bool pump() {
        for (unsigned step = 0; step < 128; ++step) {
            if (state == State::handshake) {
                if (!socket.handshake(true)) {
                    return true;
                }
                // Inspect actual kTLS activation after OpenSSL completes the handshake. TX and RX
                // can differ; the shared request handler checks the direction needed by each
                // method.
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
                // Header reads may already have received part of the JSON body. Consume those
                // bytes first, then read only the missing amount before dispatching the command.
                const auto count = std::min(body_remaining, input.size());
                control_body.append(input.data(), count);
                input.erase(0, count);
                body_remaining -= count;
                if (!body_remaining) {
                    const auto reply = server.Agent::request(
                        *control_head,
                        {socket.ssl ? SSL_get_version(socket.ssl.get()) : "",
                         socket.ssl ? SSL_get_cipher_name(socket.ssl.get()) : ""},
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
                // Discard a PUT body without storing it. Account for bytes already read alongside
                // the header, and acknowledge only after the entire declared body is consumed.
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
                // Preserve the offset on partial writes, including retries required by OpenSSL.
                // Start the response body only after every header byte has been written.
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
                // Send either the shared dummy object or the session's JSON response. A completed
                // persistent response returns to header processing and may use already buffered
                // input.
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
        // The work budget ended without an operation reporting a wait. Either readiness event
        // schedules another pump() call after this worker has had a chance to serve other sessions.
        socket.want = EPOLLIN | EPOLLOUT;
        return true;
    }
};

// Reserve a loopback port solely to prevent multiple Winlin servers from running on this machine.
// It carries no benchmark traffic. Unlike worker listeners, it must not use address/port reuse.
// Main retains the returned socket until shutdown; process exit also releases it after a crash.
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

// Create one nonblocking listening socket for a worker. SO_REUSEPORT lets multiple workers bind
// the same endpoint so the kernel distributes incoming connections between their listeners.
// If port is zero, record the kernel-selected port and use it for the remaining workers.
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

// Run one server worker's event loop. This thread owns its listener, epoll queue, and all sessions
// accepted through that listener; other workers never access those sessions.
//
// Listener readiness accepts a bounded batch of connections. Session readiness advances requests
// through pump(), then either updates the event mask or removes a closed/failed session.
// A periodic sweep removes sessions with no progress for 60 seconds.
//
// Individual connection failures are logged and isolated. Listener or event-loop failures escape
// to the worker's owner, which stops the server rather than silently losing part of its worker
// pool. The optional ready callback announces that the listener is registered and this loop is
// ready.
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
                // Bound each accept batch so a busy listener does not starve existing requests.
                // Reserve a slot in the server-wide counter before creating a Session.
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
                        // Undo the reserved slot if construction failed. If a Session was inserted,
                        // erasing it releases the slot through its destructor instead.
                        if (!sessions.erase(client_fd)) {
                            --server.active;
                        }
                        throw;
                    }
                }
            } else if (const auto it = sessions.find(fd); it != sessions.end()) {
                // Keep live sessions registered for their next required event. Erasing a session
                // closes its descriptor, which also removes the descriptor from epoll.
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
            // Check inactivity once per second rather than scanning every session after every
            // event batch. An idle keep-alive close is normal; an unfinished request is warned.
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

// Own the temporary Linux workload created by a control-channel benchmark-start command.
// HTTP, OpenSSL HTTPS, and kTLS all use the same Server/Session event loop; only TLS configuration
// differs. The requested worker count and listeners are created for this run, not changed mid-run.
//
// Construction waits until every worker has registered its listener, or startup has failed.
// Worker failures are retained for telemetry requests and stop the workload. Destruction signals
// every worker to exit and joins them before destroying the Server resources they reference.
// The permanent control server is separate and remains available when this workload stops.
class LinuxBenchmark final : public BenchmarkInstance {
    Server server_;
    unsigned port_;
    mutable std::mutex failure_mutex_;
    std::string failure_;
    std::vector<std::jthread> workers_;

public:
    // Bind all workload listeners before starting threads. Publish a usable endpoint only after
    // each worker has announced readiness, and join partially started workers if setup fails.
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
                        // A startup failure must also release its latch slot; otherwise the
                        // constructor could wait forever for readiness that will never arrive.
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

    // Stop and join workload threads while their shared Server and TLS context are still alive.
    ~LinuxBenchmark() override {
        server_.stop = true;
        workers_.clear();
    }

    // Return the bound endpoint and selected backend for the client's workload connections.
    Json describe() const override {
        return {{"port", port_},
                {"transport", server_.config.tls ? "https" : "http"},
                {"backend", server_.config.backend}};
    }

    // Report worker failure explicitly instead of presenting a stopped workload's counters as
    // evidence of a healthy run.
    Json telemetry() const override {
        std::lock_guard lock(failure_mutex_);
        if (!failure_.empty()) {
            throw BenchmarkError(503, "Workload worker failed: " + failure_);
        }
        return server_.telemetry();
    }
};
}

// Start the permanent control service and provide a factory for temporary workloads. Keep the
// machine-wide guard and shared controller alive until control workers have finished.
int main(int argc, char** argv) {
    using namespace winlin;
    if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
        std::cout << "winlin-server [--cert certificate.pem --key private.key]\n"
                     "  [--bind 0.0.0.0] [--port 38443] [--workers 8]\n"
                     "  [--http-port 38444] [--https-port 38445]\n"
                     "  Control uses plain HTTP; certificate/key apply only to HTTPS workloads.\n"
                     "  Benchmark workers/TLS/kTLS/cipher are selected by the client per run.\n";
        return 0;
    }
    try {
        std::signal(SIGPIPE, SIG_IGN);
        std::signal(SIGINT, on_signal);
        std::signal(SIGTERM, on_signal);
        Args args(argc, argv);
        args.allow(
            {"--cert", "--key", "--bind", "--port", "--workers", "--http-port", "--https-port"});
        const auto control_port = number(args.get("--port", "38443"), 65535);
        const auto http_port = number(args.get("--http-port", "38444"), 65535);
        const auto https_port = number(args.get("--https-port", "38445"), 65535);
        if ((control_port && (control_port == http_port || control_port == https_port)) ||
            (http_port && http_port == https_port)) {
            throw std::invalid_argument("Control, HTTP and HTTPS workload ports must be distinct");
        }
        // Reserve exclusive ownership and initialize CPU measurement before serving requests.
        const auto instance_guard = server_guard();
        reference_clock();
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
        // Control requests create and stop workloads through the shared controller. Each workload
        // has its own listener pool, while these workers continue to serve control and telemetry.
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
                          {"backend", server.config.backend},
                          {"workers", workers}}
                         .dump()
                  << std::endl;
        // Joining waits for a signal or worker failure to stop the loops. Only afterward is it
        // safe to inspect the recorded failure and destroy the resources used by those threads.
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
