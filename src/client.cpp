#include "winlin/linux.hpp"

#include <barrier>
#include <cassert>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <latch>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <unordered_map>

namespace {
using namespace winlin;
namespace fs = std::filesystem;

// Hold the server address, expected workload certificate and optional workload lease.
// Load workers share this read-only; control always uses plain HTTP.
// Run IDs exist only in memory and must not be serialized into results or saved targets.
struct Target {
    // host:port is the IP:port of the target server.
    // pin is the sha256 fingerprint of the workload's TLS certificate, which is our self-signed
    // certificate.
    // run_id is a unique identifier for the current workload lease, which is used to isolate
    // telemetry and other server state from other concurrent workloads.
    std::string host, port, pin, run_id;
};

// Check if pin is a valid SHA-256 fingerprint (64 hexadecimal digits) and convert it to
// lowercase and return it. Throw std::invalid_argument if the pin is invalid.
std::string checked_pin(std::string pin) {
    pin = lower(std::move(pin));
    if (pin.size() != 64 || !std::all_of(pin.begin(), pin.end(), [](unsigned char ch) {
            return std::isxdigit(ch);
        })) {
        throw std::invalid_argument("Fingerprint must be 64 hexadecimal SHA-256 digits");
    }
    return pin;
}

// Validate that host is a valid numeric IPv4 address.
void check_host(const std::string& host) {
    in_addr address{};
    if (inet_pton(AF_INET, host.c_str(), &address) != 1) {
        throw std::invalid_argument("This first version requires a numeric IPv4 server address");
    }
}

// Reserve new outputs exclusively and replace existing results via a flushed private temporary
// file. A failed update must leave earlier completed repetitions intact.
void write_private(const fs::path& path, const Json& value, bool exclusive) {
    // If exclusive, then the file must not exist and will be created with 0600 permissions.
    // If not exclusive, then the file must exist and be a private regular file owned by this user.
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
        // Now, write the JSON to the file and flush it to disk. The temporary file is renamed
        // to the final path only after a successful write and flush.
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
        // If exclusive, the json was written directly to the final path. If not exclusive,
        // rename the temporary file to the final path.
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

// Load a target from a JSON file, validating its contents.
// Typical target file looks like this:
// tomar@KVPerf-servernew-himanshu:~/winlin$ cat ~/.local/state/winlin/172.16.0.4-38443.json
// {
//   "certificate_sha256": "a7f93f90b9dc1d7e7ed5d5e640d70d4c7c634285045388eeba9040ef0debc912",
//   "host": "172.16.0.4",
//   "port": "38443"
// }
Target load_target(const std::string& path) {
    const auto content = read_private(path);
    try {
        const auto json = Json::parse(content);
        Target result{json.at("host"), json.at("port"), json.at("certificate_sha256"),
                      "" /* run_id */};
        // Validate host is a numeric IPv4 address
        check_host(result.host);
        // port must be less than 65535
        if (!number(result.port, 65535)) {
            throw std::invalid_argument("Invalid port");
        }
        // Validate pin is a valid SHA-256 fingerprint
        result.pin = checked_pin(result.pin);
        return result;
    } catch (const std::exception&) {
        throw std::runtime_error("Invalid target file");
    }
}

// Own one bounded control response independently of its connection, which closes after
// exchange. Workload bodies use streaming buffers instead and must not allocate a Response per
// request.
//
// This is used only for small, bounded HTTP control traffic.
// Used for control requests like fetching server capabilities (/v1/capabilities),
// starting and stopping benchmarks (/v1/benchmark/start and /v1/benchmark/stop),
// and fetching telemetry after the benchmark (/v1/benchmark/telemetry).
struct Response {
    // The HTTP status code of the response (e.g., 200 for OK, 404 for Not Found).
    int status{};
    // The parsed HTTP response header, including the status line and any fields.
    HttpHead head;
    // The body of the HTTP response, which may contain JSON or other data.
    std::string body;
};

// Send one HTTP control request to the server and receive the response in Response.
// The connection is closed after the exchange.
// method is the HTTP method (GET, POST, etc.), path is the request path, and body is the
// optional request body (for POST requests).
// path is one of:
// /v1/capabilities
// /v1/benchmark/start
// /v1/benchmark/stop
// /v1/benchmark/telemetry
Response exchange(const Target& target, const std::string& method, const std::string& path,
                  const std::string& body = {}) {
    auto socket = connect_stream(nullptr, target.host, target.port, {});
    const auto deadline = Clock::now() + std::chrono::seconds(10);
    const std::string request = method + " " + path + " HTTP/1.1\r\nHost: " + target.host + ":" +
                                target.port + "\r\nContent-Length: " + std::to_string(body.size()) +
                                "\r\nConnection: close\r\n\r\n" + body;
    // Write the request to the socket, handling partial writes, and wait for the socket to
    // be ready if needed.
    std::size_t sent{};
    while (sent < request.size()) {
        const int count = socket->write(request.data() + sent, request.size() - sent);
        if (count) {
            sent += count;
        } else {
            wait_socket(*socket, deadline);
        }
    }

    // Gather the response header, handling partial reads, and wait for the socket to
    // be ready if needed.
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

    // Validate the response header and parse it into a Response object.
    Response response;
    response.head = parse_head(std::string_view(input).substr(0, boundary));
    if (!response.head.first.starts_with("HTTP/1.1 ") || response.head.first.size() < 12 ||
        !response.head.fields.contains("content-length") || response.head.length > 65536) {
        throw std::runtime_error("Invalid control response");
    }
    response.status = number(std::string_view(response.head.first).substr(9, 3), 599);
    response.body = input.substr(boundary);
    // Read the response body, handling partial reads
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

// Send one HTTP control request to the server and parse the response body as JSON.
Json control(const Target& target, const std::string& path) {
    const auto response = exchange(target, "GET", path);
    if (response.status != 200) {
        throw std::runtime_error("Server rejected control request (HTTP " +
                                 std::to_string(response.status) + ")");
    }
    return Json::parse(response.body);
}

// Return the state directory for storing target files and results.
// Use XDG_STATE_HOME if set, otherwise use HOME/.local/state/winlin. Create the
// directory if it does not exist.
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

// Discover the HTTP controller; save the expected certificate only for future HTTPS workloads.
void add_target(const std::string& host, const std::string& port, const std::string& pin,
                const fs::path& output) {
    check_host(host);
    if (!number(port, 65535)) {
        throw std::invalid_argument("Port must be positive");
    }
    Target target{host, port, checked_pin(pin), ""};
    // CLI onboarding should work on a fresh client without a manual target-directory setup step.
    if (!output.parent_path().empty()) {
        fs::create_directories(output.parent_path());
    }
    // Query the server for its capabilities
    const auto capabilities = control(target, "/v1/capabilities");
    // This writes a target file like
    // tomar@KVPerf-servernew-himanshu:~/winlin$ cat ~/.local/state/winlin/172.16.0.4-38443.json
    // {
    //    "certificate_sha256": "a7f93f90b9dc1d7e7ed5d5e640d70d4c7c634285045388eeba9040ef0debc912",
    //    "host": "172.16.0.4",
    //    "port": "38443"
    // }
    write_private(output, {{"host", host}, {"port", port}, {"certificate_sha256", target.pin}},
                  true);
    std::cout << "Target saved to " << output.string() << '\n';
    std::cout << capabilities.dump(2) << '\n';
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

// Own the two immutable wire headers shared by every connection in one trial. Construction
// happens before worker startup; the trial retains them until all workers and TLS retries end.
struct LoadHeaders {
    std::string get, put;

    // Build both methods from fixed trial settings and the active workload lease, not per I/O.
    LoadHeaders(const Target& target, const RunConfig& config) {
        const auto fields = " HTTP/1.1\r\nHost: " + target.host + ":" + target.port +
                            (target.run_id.empty() ? "" : "\r\nX-Winlin-Run: " + target.run_id) +
                            "\r\nContent-Length: ";
        get = "GET /v1/object?size=" + std::to_string(config.get_size) + fields + "0\r\n\r\n";
        put = "PUT /v1/object" + fields + std::to_string(config.put_size) + "\r\n\r\n";
    }
};

// LoadConnection represents one persistent benchmark connection to the server.
// It owns the socket, runs as many requests (GET or PUT) as assigned to it and tracks one
// GET or PUT request at a time. It is a non-blocking state machine that can be multiplexed
// with epoll.
// One worker drives it; response bytes are drained before latency is recorded or another
// request is issued.
struct LoadConnection {
    StreamSocket socket;
    // An HTTP(S) request is a sequence of states:
    // handshake, idle, send_head, send_body, read_head, read_body.
    //
    // GET: handshake -> idle -> send_head -> read_head -> read_body -> idle
    // PUT: handshake -> idle -> send_head -> send_body -> read_head -> read_body -> idle
    enum class State {
        handshake,
        idle,
        send_head,
        send_body,
        read_head,
        read_body
    } state{State::handshake};
    bool alive{true}, get{};
    // Borrow the selected immutable trial header, including through partial writes/TLS retries.
    std::string_view header;
    // buffer: accumulate response headers directly, then reuse it to discard response body bytes
    std::array<char, max_header_size> buffer{};
    // offset tracks the number of bytes sent in the request header or body
    std::size_t offset{}, remaining{};
    // Retain partial headers and resume scanning with overlap for a split delimiter.
    // header_received: Number of header bytes received so far, including any body bytes
    //                  that may have been read into buffer.
    // header_search: Offset at which the next search for the header delimiter begins.
    //                Revisit up to three bytes so a delimiter split across reads is found,
    //                without searching the entire accumulated header again. To be precise this is the next search offset.
    std::size_t header_received{}, header_search{};
    Clock::time_point started;

    // Constructor
    // Takes ownership if an already created socket, fd, if TLS is enabled (ctx is not null)
    // creates the TLS session
    LoadConnection(Fd fd, SSL_CTX* ctx, const Target& target)
        : socket(std::exchange(fd.value, -1), ctx) {
        if (socket.ssl && SSL_set_tlsext_host_name(socket.ssl.get(), target.host.c_str()) != 1) {
            throw tls_error("Cannot set load connection TLS server name");
        }
    }

    // Start the LoadConnection.
    // Select methods from a global issued-request ticket so mixed ratios do not depend on which
    // method completes faster. In each complete group of 100 tickets the requested ratio is exact.
    void begin(const LoadHeaders& headers, const RunConfig& config, std::uint64_t index) {
        // Which method to issue: GET, PUT, on this connection.
        get = config.method == "get" ||
              (config.method == "mixed" &&
               ((index % 100) * config.get_percent) % 100 < config.get_percent);
        header = get ? headers.get : headers.put;
        offset = 0;
        header_received = 0;
        header_search = 0;
        started = Clock::now();
        // By this time the socket is already connected and optionally handshaked;
        // set the state to send_head to start the request.
        state = State::send_head;
    }

    // pump() advances the LoadConnection state machine as far as posssible without blocking.
    // It returns true when the connection is idle and ready for a new request, or false when
    // more processing is needed. The caller must wait for the socket to be ready for reading
    // or writing before calling pump() again. The socket.want field is updated to indicate
    // which events the socket is waiting for. The caller must handle EPOLLIN and EPOLLOUT events
    // and call pump() again when the socket is ready.
    //
    // payload: outgoing PUT request body, passed by reference to avoid copying. It must be
    //          at least config.put_size bytes long.
    bool pump(const Target& target, const RunConfig& config, const std::vector<char>& payload,
              Stats& stats) {
        // Every pump() call makes forward progress on the current request.
        // It returns true when the request is complete and the connection is idle, or false
        // when more processing is needed. The caller must wait for the socket to be ready
        // for reading or writing before calling pump() again.
        // Even if socket is ready, pump() may not complete the request, as it has a budget
        // of 128 steps to avoid starvation of other connections. e.g., one TLS write can
        // only do 16KiB so it may take multiple steps to send a 4MiB PUT body, or even when
        // reading a response body it might take multiple steps to read the entire body if
        // the socket is not ready for reading.
        for (unsigned step = 0; step < 128; ++step) {
            if (state == State::handshake) {
                if (!socket.handshake(false)) {
                    // Still awaiting handshake completion
                    return false;
                }
                if (socket.ssl && !equal_secret(fingerprint(socket.ssl.get()), target.pin)) {
                    throw std::runtime_error("Server certificate changed during load setup");
                }
                // Handshake completed successfully; the connection is now idle and ready
                // for a new request, we return true to signal that.
                // Caller will then call begin() which will set the state to send_head and
                // start the request.
                state = State::idle;
                return true;
            } else if (state == State::idle) {
                return true;
            } else if (state == State::send_head) {
                const int count = socket.write(header.data() + offset, header.size() - offset);
                if (!count) {
                    // Socket is not ready for writing, return false to signal that we need
                    // to wait for the socket to be ready before calling pump() again.
                    // Note that we use non-blocking sockets.
                    return false;
                }
                offset += count;
                if (offset == header.size()) {
                    offset = 0;
                    // header is fully sent, now we can either send the body (for PUT) or
                    // read the response (for GET).
                    state = get ? State::read_head : State::send_body;
                }
            } else if (state == State::send_body) {
                if (offset == config.put_size) {
                    // All body bytes have been sent, now we can read the response.
                    state = State::read_head;
                } else {
                    // Continue sending the body bytes from payload, up to config.put_size.
                    const int count =
                        socket.write(payload.data() + offset, config.put_size - offset);
                    if (!count) {
                        return false;
                    }
                    offset += count;
                }
            } else if (state == State::read_head) {
                const std::string_view received(buffer.data(), header_received);
                // Find the end of the HTTP response header in the received bytes,
                // searching only new bytes and the overlap needed for a split delimiter.
                const auto end = find_http_header_end(received, header_search);
                if (end != std::string_view::npos) {
                    // OK, full header received, parse it and validate it. Note that we may
                    // have already read some of the response body bytes into buffer, which
                    // is fine, we will correctly handle that in the next state (read_body).
                    const auto head = parse_workload_response_head(received.substr(0, end + 4));
                    // Server must respond with 200 OK and the expected Content-Length, and
                    // must not close the connection. Otherwise, fail this request and close
                    // its connection. A measurement reports the failure while other connections
                    // continue; a warmup failure prevents measurement from starting.
                    if (!head.first.starts_with("HTTP/1.1 200 ") || !head.has_length ||
                        head.length != (get ? config.get_size : 0) || head.close) {
                        throw std::runtime_error(
                            std::string(config.tls == "ktls"
                                            ? "Unexpected kTLS benchmark response: "
                                            : "Unexpected benchmark response: ") +
                            std::string(head.first));
                    }
                    // Count response body bytes already consumed by the header reads, so they
                    // are not read again. Their contents are no longer needed.
                    // Note that header_received includes any body bytes that may have
                    // been read into buffer.
                    const auto preloaded = header_received - end - 4;
                    if (preloaded > head.length) {
                        throw std::runtime_error("Excess response bytes");
                    }
                    remaining = head.length - preloaded;
                    state = State::read_body;
                } else {
                    // Header end not found yet, continue reading more bytes into buffer.
                    //
                    // Already accumulated max_header_size bytes without finding the end
                    // of the header, which is an error.
                    if (header_received == buffer.size()) {
                        throw std::runtime_error("Oversized response header");
                    }
                    // Read more header bytes.
                    // Note that we may end up reading some of the response body bytes into
                    // buffer, which is fine, as we will handle that in the next state (read_body).
                    // Read directly after existing header bytes, without a scratch-buffer copy.
                    const int count = socket.read(buffer.data() + header_received,
                                                  buffer.size() - header_received);
                    if (!count) {
                        return false;
                    }
                    // Number of header bytes received so far, including any body bytes
                    // that may have been read into buffer.
                    header_received += count;
                }
            } else {
                assert(state == State::read_body);
                if (remaining) {
                    // Read upto buffer.size() or remaining bytes, whichever is smaller.
                    // Note that we discard the bytes read, we only care about reading
                    // the full response body to measure latency and throughput.
                    const int count =
                        socket.read(buffer.data(), std::min(buffer.size(), remaining));
                    if (!count) {
                        return false;
                    }
                    remaining -= count;
                } else {
                    // All response body bytes have been read and the request is complete,
                    // we can record the latency and update the stats.
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
                    // Ready for a new request, we return true to signal that.
                    state = State::idle;
                    return true;
                }
            }
        }
        // If we reach here, we have exhausted our 128 steps budget without completing
        // the request. This can happen when a large body needs many successful reads or writes.
        socket.want = EPOLLIN | EPOLLOUT;
        return false;
    }
};

// Run benchmark requests over several connections using one thread, rather than one thread per
// connection. trial() creates the worker threads and divides the connections between them.
// This class does not create a thread itself; its methods run on the thread created by trial().
//
// Each LoadConnection knows how to send a request and read its response. LoadWorker decides which
// connection to work on next. It asks epoll which sockets are ready, then calls pump() on those
// connections. If a connection cannot continue yet, the worker moves on to others instead of
// blocking the whole thread. pump() also limits how much work it does in one call so that a large
// request does not keep the worker from serving its other connections.
//
// setup() opens all of this worker's connections, completes their TCP/TLS setup, and checks the
// certificate pins for TLS connections. This happens before warmup, so connection setup is not
// included in the measured request performance.
//
// phase() runs either warmup or measurement using those same connections. Each connection has at
// most one outstanding request. When that request finishes, the worker starts another on the same
// connection if time and request limits allow. The request counter is shared across workers so
// that the request limit applies to the whole run, not separately to each worker.
//
// Once the phase's time or request limit is reached, the worker stops starting new requests.
// It continues processing requests already started until they finish, fail, or time out.
// phase() returns this worker's statistics; trial() combines the measured results from all workers.
//
// Only this worker's thread uses its connections, epoll queue, and local statistics. The target,
// configuration, and PUT payload are not copied into the worker: it holds read-only references
// to them. The caller must keep those objects alive and unchanged while the worker uses them.
//
// e.g., for 1024 connections with 16 workers, there will be 16 LoadWorker instances, each with
// 64 LoadConnection instances. Each worker runs on its own thread and uses epoll to multiplex
// its 64 connections without blocking.
class LoadWorker {
    const Target& target_;
    const RunConfig& config_;
    const std::vector<char>& payload_;
    const LoadHeaders& headers_;
    Epoll poller_;
    // All the LoadConnection instances managed by this LoadWorker.
    // connections_ maps each connection's socket fd to its LoadConnection instance.
    std::unordered_map<int, std::unique_ptr<LoadConnection>> connections_;
    std::array<epoll_event, 256> events_{};

public:
    // target: Target details (host, port, pin, run_id) for this worker's connections.
    // config: RunConfig details (method, sizes, counts, timeouts) for this worker's requests.
    // payload: PUT request body to send for each PUT request. Must be at least config.put_size
    //          bytes.
    // headers: Immutable trial headers, kept alive with target, config and payload until join.
    LoadWorker(const Target& target, const RunConfig& config, const std::vector<char>& payload,
               const LoadHeaders& headers)
        : target_(target), config_(config), payload_(payload), headers_(headers) {
    }

    // Complete and pin every handshake before warmup, keeping connection setup out of measured
    // load.
    void setup(SSL_CTX* ctx, unsigned count) {
        for (unsigned i = 0; i < count; ++i) {
            // Connect to the server and create a LoadConnection for it.
            // connect_socket() may return before the nonblocking TCP connection has completed.
            // pump() finishes TCP/TLS setup when readiness events arrive.
            auto connection = std::make_unique<LoadConnection>(
                connect_socket(target_.host, target_.port), ctx, target_);
            const int fd = connection->socket.fd.value;
            // Register the connection's socket fd with epoll for both read and write events
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
                // Advance TCP/TLS setup; more readiness events and pump() calls may be needed.
                // payload_ is not used here, but we pass it to satisfy the pump() signature.
                if (connection.pump(target_, config_, payload_, unused)) {
                    ++ready;
                    poller_.set(connection.socket.fd.value, 0);
                } else {
                    poller_.set(connection.socket.fd.value, connection.socket.want);
                }
            }
        }
    }

    // Generate the workload for either warmup or measurement. Stop starting new requests when
    // the time limit or global request limit is reached, then finish outstanding requests.
    // The phase can run beyond its duration while draining, or end early if all connections fail.
    // Return the statistics for this worker's requests.
    // Stop issuing at the first limit, but drain outstanding requests up to their individual
    // timeout.
    Stats phase(Clock::time_point start, double duration, std::atomic<std::uint64_t>& issued,
                std::uint64_t limit) {
        Stats stats;
        const auto deadline = start + std::chrono::duration<double>(duration);
        std::size_t active{};

        auto issue = [&](LoadConnection& connection) {
            // If time limit is reached or the connection is dead, do not issue a new request.
            if (!connection.alive || Clock::now() >= deadline) {
                return false;
            }
            // The reserved-request count is also the candidate ticket for the next request.
            auto ticket = issued.load(std::memory_order_relaxed);
            // Reserve a request globally before sending, including when the limit is below workers.
            do {
                // limit is 0 for no limit, otherwise stop issuing when the limit is reached.
                if (limit && ticket >= limit) {
                    return false;
                }
                // Reserve the next ticket atomically; retry if another worker reserved it first.
            } while (!issued.compare_exchange_weak(ticket, ticket + 1, std::memory_order_relaxed));

            // Start the request on this connection, which sets its state to send_head and begins
            // the request. The connection will then be driven by pump() until it is idle again
            // and ready for another request.
            connection.begin(headers_, config_, ticket);
            // Enable write notifications for the socket already registered with epoll.
            poller_.set(connection.socket.fd.value, EPOLLOUT);
            return true;
        };

        // Try to assign an initial request to each live connection. Time and request limits
        // may prevent some connections from receiving one. Reuse these connections for more
        // requests as they complete, while the limits still allow new requests.
        for (auto& [fd, connection] : connections_) {
            (void)fd;
            if (issue(*connection)) {
                ++active;
            }
        }

        // The main loop of the phase. It continues until there are no more active requests,
        // either because issuance has stopped and outstanding requests have been drained,
        // or because all connections have failed.
        while (active) {
            // Each active connection has one outstanding request. Wait for socket readiness
            // so those requests can make progress; other connections may be idle or dead.
            const int count = poller_.wait(events_.data(), events_.size(), 10);
            // Process each ready connection. pump() will advance the state machine for that
            // connection as far as possible without blocking. If the connection becomes idle,
            // issue() will start a new request on it, if the time and request limits allow
            for (int i = 0; i < count; ++i) {
                auto& connection = *connections_.at(events_[i].data.fd);
                // Connections can be closed by the server or fail during the phase, skip
                // them, also skip connections that are idle. Note that typically an idle
                // connection would mean that it is ready for a new request, but since we
                // issue new requests immediately as soon as a connection completes its
                // request (see pump() call below()), an idle connection here means there
                // are no more requests to issue, either because the time limit or request limit
                // has been reached.
                if (!connection.alive || connection.state == LoadConnection::State::idle) {
                    continue;
                }
                try {
                    // This connection is ready for reading or writing, call pump() to advance
                    // its state machine.
                    if (connection.pump(target_, config_, payload_, stats)) {
                        // True return value means the connection is done with the current request
                        // and is now idle, ready for a new request. Try to issue a new request on
                        // this connection, if the time and request limits allow.
                        --active;
                        if (issue(connection)) {
                            ++active;
                        } else {
                            // No further request was assigned for this phase. Disable normal
                            // read/write notifications, but leave the socket registered and open.
                            // Errors or hangups may still be reported. Keep live connections for
                            // measurement after warmup; worker destruction eventually closes them.
                            poller_.set(connection.socket.fd.value, 0);
                        }
                    } else {
                        // False return from pump() means the connection is still processing
                        // its current request, and we need to wait for it to be ready for
                        // reading or writing again, or resume after yielding its step budget.
                        poller_.set(connection.socket.fd.value, connection.socket.want);
                    }
                } catch (const std::exception& error) {
                    stats.fail(error.what());
                    // Report the failure here, while the socket is still identifiable. Later
                    // events skip this dead connection, so they must not repeat the warning.
                    log_warning(
                        "Workload connection fd " + std::to_string(connection.socket.fd.value) +
                        " became dead: " + error.what() +
                        ". Closing it without replacement; remaining connections continue.");
                    connection.alive = false;
                    connection.socket.fd = Fd{};
                    --active;
                }
            }

            // After processing ready connections, check how long each outstanding request
            // has been running. The timeout applies to the request, not the connection's age.
            const auto now = Clock::now();
            for (auto& [fd, connection] : connections_) {
                (void)fd;
                // Fail a request that has exceeded its timeout, and permanently close its
                // connection so no further requests are assigned to it.
                if (connection->alive && connection->state != LoadConnection::State::idle &&
                    std::chrono::duration<double>(now - connection->started).count() >=
                        config_.timeout) {
                    stats.fail("Request timed out");
                    // A timeout also permanently removes this connection from the workload.
                    // Log once before closing it; the alive check prevents repeated reports.
                    log_warning("Workload connection fd " +
                                std::to_string(connection->socket.fd.value) +
                                " became dead: Request timed out. Closing it without replacement; "
                                "remaining connections continue.");
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

// Run one benchmark repetition using several worker threads, then combine their results into a
// JSON report. Each thread creates a LoadWorker and owns a share of the configured connections.
// The calling thread coordinates when the workers start warmup and measurement, and collects
// client and server telemetry around the measured workload.
//
// First, wait for every worker to finish establishing its connections. Release them together
// using a common warmup start time. Next, wait for every worker to finish warmup, including all
// outstanding warmup requests, before collecting the initial telemetry. Only then release the
// workers for measurement using a common measurement start time. This keeps connection setup
// and warmup requests out of the measured workload.
//
// The two latches tell the calling thread when setup and warmup have finished. The same barrier
// is used twice: workers wait there until the calling thread has prepared the next phase.
// A worker that encounters a fatal error records it and skips further workload, but must still
// signal both latches and participate in both barrier waits. Otherwise, the calling thread or
// another worker could wait forever for a participant that exited early. If a thread cannot be
// created, the calling thread accounts for its missing latch signals and barrier participation.
//
// Join all workers before reading their results or allowing the objects they reference to go
// out of scope. If a fatal error was recorded, throw it after the threads have finished.
// Otherwise, merge the measured request statistics, collect final telemetry, and return the
// report with warnings for request failures or possible client CPU saturation.
Json trial(SSL_CTX* ctx, const Target& target, const RunConfig& config,
           const std::vector<char>& payload, unsigned repetition, const Target& control_target,
           const std::string& run_id) {
    const LoadHeaders headers(target, config);
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
        // Create one thread per worker, each of which will create its own LoadWorker and manage
        // its share of the configured connections. The threads will wait for the calling thread
        // to signal when to start warmup and measurement, and will report any fatal errors back
        // to the calling thread via the fail() lambda.
        for (unsigned index = 0; index < config.workers; ++index) {
            threads.emplace_back([&, index] {
                std::unique_ptr<LoadWorker> worker;
                try {
                    // One LoadWorker per worker thread
                    worker = std::make_unique<LoadWorker>(target, config, payload, headers);
                    // setup() opens and handshakes the worker's share of connections
                    worker->setup(ctx, config.connections / config.workers +
                                           (index < config.connections % config.workers ? 1 : 0));
                } catch (const std::exception& error) {
                    fail(error.what());
                }
                // Synchronize with the calling thread to ensure all workers have finished setup
                // before starting warmup.
                setup_done.count_down();
                gate.arrive_and_wait();
                if (!abort) {
                    try {
                        // Issue warmup requests for config.warmup seconds, then drain them.
                        const auto warmup =
                            worker->phase(warmup_start, config.warmup, warmup_issued, 0);
                        if (warmup.errors) {
                            fail("Warmup failed: " + warmup.first_error);
                        }
                    } catch (const std::exception& error) {
                        fail(error.what());
                    }
                }
                // Synchronize with the calling thread to ensure all workers have finished
                // warmup before starting measurement.
                warmup_done.count_down();
                gate.arrive_and_wait();
                if (!abort) {
                    try {
                        // Issue measurement requests for config.duration seconds or until
                        // config.requests have been issued, whichever comes first.
                        // Then drain outstanding requests before returning the results.
                        // The issued counter is shared across all workers, so the request limit
                        // applies to the whole run.
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

    // All workers have signalled warmup completion. They wait at the barrier before proceeding
    // to measurement, unless a failure causes them to skip the measured workload.
    Json server_before, client_before;
    if (!abort) {
        try {
            // Collect baseline telemetry before starting measurement, so that the measurement
            // phase can be compared against the baseline. The server telemetry is collected via
            // the control API, and the client telemetry is collected via the usage() function.
            server_before = control(control_target, "/v1/benchmark/telemetry?run_id=" + run_id);
            client_before = usage();
        } catch (const std::exception& error) {
            fail(error.what());
        }
    }
    measure_start = Clock::now();
    // Release worker threads to start measurement phase
    gate.arrive_and_wait();

    // Destroying the jthread objects joins every worker before their results are read.
    threads.clear();
    if (abort) {
        throw std::runtime_error(failure);
    }
    Stats combined;
    for (const auto& stats : results) {
        combined.merge(stats);
    }
    const double elapsed = std::chrono::duration<double>(combined.end - measure_start).count();
    // Collect telemetry after measurement, so that the measurement phase can be compared against
    // the baseline.
    const auto client_after = usage();
    const auto server_after = control(control_target, "/v1/benchmark/telemetry?run_id=" + run_id);
    auto client_usage = usage_delta(client_before, client_after, elapsed);
    auto server_usage =
        usage_delta(server_before.at("process"), server_after.at("process"), elapsed);
    auto server_host = host_usage_delta(server_before.value("host", Json::object()),
                                        server_after.value("host", Json::object()));
    auto server_network = network_usage_delta(server_before.value("network", Json::object()),
                                              server_after.value("network", Json::object()));
    std::vector<std::string> warnings;
    if (client_usage.at("cpu_utilization_percent").get<double>() >= config.workers * 85.0) {
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
            {"server_reference_cycles_per_io",
             combined.completed && !server_host.at("reference_cycles").is_null()
                 ? Json(server_host.at("reference_cycles").get<double>() / combined.completed)
                 : Json(nullptr)},
            {"latency", combined.latency.json()},
            {"client_process", client_usage},
            {"latency_by_method",
             {{"get", combined.get_latency.json()}, {"put", combined.put_latency.json()}}},
            {"server_process", server_usage},
            {"server_host", server_host},
            {"server_network", server_network},
            {"server_before", server_before},
            {"server_after", server_after},
            {"warnings", warnings}};
}

RunConfig configuration(const Args& args) {
    RunConfig config;
    config.tls = args.get("--tls", "on");
    config.cipher = args.get("--cipher", config.cipher);
    config.server_workers = number(args.get("--server-workers", "8"), 256);
    config.method = lower(args.get("--method", "get"));
    config.get_response_data = args.get("--get-response-data", config.get_response_data);
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

// Always report console metrics and failures; persist detailed repetitions and final status only
// when requested. Console-only runs still collect the telemetry needed for metrics and warnings.
int run(Target target, const RunConfig& config, const std::optional<fs::path>& output) {
    auto capabilities = control(target, "/v1/capabilities");
    if (!capabilities.contains("supported_tls_modes") || !capabilities.contains("limits") ||
        !capabilities.contains("supported_get_response_data_modes")) {
        throw std::runtime_error("Server capabilities are outdated; update and restart the server");
    }
    const auto modes = capabilities.at("supported_tls_modes").get<std::vector<std::string>>();
    if (std::find(modes.begin(), modes.end(), config.tls) == modes.end()) {
        throw std::invalid_argument("Server does not support requested TLS mode: " + config.tls);
    }
    const auto data_modes =
        capabilities.at("supported_get_response_data_modes").get<std::vector<std::string>>();
    if (std::find(data_modes.begin(), data_modes.end(), config.get_response_data) ==
        data_modes.end()) {
        throw std::invalid_argument("Server does not support requested GET response data mode: " +
                                    config.get_response_data);
    }
    if (config.get_response_data == "copy" &&
        capabilities.value("copy_get_working_set_bytes", std::size_t{}) !=
            copy_get_working_set_size) {
        throw std::runtime_error(
            "Copy-mode source capabilities are outdated; update and restart the server "
            "for the fixed 1 GiB rotating working set");
    }
    if (config.connections > capabilities.at("limits").at("max_connections").get<unsigned>()) {
        throw std::invalid_argument("Requested connections exceed the server implementation limit");
    }
    const auto worker_range = capabilities.at("server_workers");
    if (config.server_workers < worker_range.at("min").get<unsigned>() ||
        config.server_workers > worker_range.at("max").get<unsigned>()) {
        throw std::invalid_argument("Requested server workers exceed the supported range");
    }
    const auto ciphers = capabilities.at("supported_ciphers").get<std::vector<std::string>>();
    if (config.tls != "off" &&
        std::find(ciphers.begin(), ciphers.end(), config.cipher) == ciphers.end()) {
        throw std::invalid_argument("Server does not support requested workload cipher");
    }
    std::vector<char> payload(std::max<std::size_t>(1, config.put_size));
    if (RAND_bytes(reinterpret_cast<unsigned char*>(payload.data()), payload.size()) != 1) {
        throw tls_error("RAND_bytes");
    }
    // Keep interpretation notes once per report, separate from detected per-repetition problems.
    std::vector<std::string> notes{
        "Closed-loop workload: percentiles exclude arrival-rate queueing and do not establish an "
        "SLA.",
        "Server process telemetry includes the HTTP controller; one benchmark lease is active.",
        "CPU telemetry includes control sampling; server sample boundaries slightly exceed the "
        "load interval.",
        "Reference CPIO attributes all OS-visible server CPU work to the benchmark, including "
        "unrelated workloads; use an otherwise idle server. It is not measured core-clock cycles.",
        "Reference cycles use a fixed calibrated invariant-TSC frequency, not turbo frequency. "
        "CPU accounting granularity and sampling overhead can dominate very short runs.",
        "Network Gbps uses selected server-interface RX+TX counters over server-side sample "
        "boundaries, including protocol overhead and unrelated traffic. These are OS interface "
        "bytes, not payload goodput or a physical-wire capture; loopback RX+TX counts both "
        "directions. Counter reads add boundary-only overhead and may have a small sampling skew.",
        "In-flight requests are drained after the duration limit; elapsed time includes draining."};
    if (config.get_response_data == "copy") {
        notes.emplace_back(
            "GET copies changing objects from a fixed 1 GiB startup-generated source pool into "
            "reusable response-private storage. Shared mode serves a hot prefix, so comparing "
            "the modes changes source-cache behavior as well as copying. Application TLS "
            "header/body staging may also differ by backend/version; see server telemetry "
            "when available. No per-request RNG is used. Buffers "
            "retain their largest size; first use/growth includes allocation and initialization "
            "costs, so use warmup for steady-state comparisons.");
    }
    const auto telemetry = capabilities.at("telemetry");
    const auto unavailable = telemetry.value("unavailable_metrics", std::vector<std::string>{});
    if (std::find(unavailable.begin(), unavailable.end(), "voluntary_context_switches") !=
        unavailable.end()) {
        notes.emplace_back("Server context-switch counters are unavailable; null is not zero.");
    }
    if (telemetry.value("process_cpu_scope", "").find("System") != std::string::npos) {
        notes.emplace_back("Server process CPU excludes HTTP.sys/Schannel work charged to System; "
                           "whole-server reference CPIO includes that work.");
    }
    Json report = {
        {"schema_version", 5},
        {"benchmark", config.tls == "off" ? "http" : "https"},
        {"notes", notes},
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
    if (output) {
        if (!output->parent_path().empty()) {
            fs::create_directories(output->parent_path());
        }
        write_private(*output, report, true);
    }
    bool errors = false;
    std::string run_id;
    auto command = [&](const std::string& path, const std::string& body = {}) {
        const auto response = exchange(target, "POST", path, body);
        if (response.status != 200) {
            throw std::runtime_error(
                "Server rejected benchmark control (HTTP " + std::to_string(response.status) +
                "): " + Json::parse(response.body).value("error", "unknown error"));
        }
        return Json::parse(response.body);
    };
    try {
        const Json settings{
            {"tls", config.tls},
            {"cipher", config.cipher},
            {"workers", config.server_workers},
            {"get_response_data", config.get_response_data},
            {"lease_seconds", static_cast<unsigned>(std::ceil(config.warmup + config.duration +
                                                              3 * config.timeout + 60))}};
        const auto started = command("/v1/benchmark/start", settings.dump());
        run_id = started.at("run_id");
        // Setup the final Target
        Target workload{target.host, std::to_string(started.at("port").get<unsigned>()), target.pin,
                        run_id};
        const bool workload_tls = config.tls != "off";
        auto workload_ctx =
            workload_tls ? context(false, config.cipher) : Context(nullptr, SSL_CTX_free);
        // Start already reports the configured workload. Actual TLS and kTLS requirements are
        // enforced on the load connections, not by a separate workload metadata exchange.
        const auto& applied = started.at("settings");
        if (started.at("transport") != (workload_tls ? "https" : "http") ||
            applied.at("tls") != config.tls || applied.at("workers") != config.server_workers ||
            applied.at("get_response_data") != config.get_response_data ||
            (workload_tls && applied.at("cipher") != config.cipher)) {
            throw std::runtime_error("Server did not apply the requested benchmark settings");
        }
        report["server_run"] = applied;
        report["server_run"]["backend"] = started.at("backend");
        report["server_run"]["transport"] = started.at("transport");
        report["server_configuration"] = started.at("settings");
        report["workload_endpoint"] = {
            {"host", target.host}, {"port", workload.port}, {"transport", started.at("transport")}};
        if (output) {
            write_private(*output, report, false);
        }
        std::cout << "Run  requests/s     p50(us)     p90(us)     p99(us)   errors    Net Gbps"
                     "   Client CPU(%)   Avg CPU(%)       Ref CPIO\n";
        for (unsigned index = 1; index <= config.repetitions; ++index) {
            // Run trial() for each repetition, which creates the worker threads, assigns
            // a subset of connections to each worker, issues requests, and collects the
            // measured telemetry.
            auto result =
                trial(workload_ctx.get(), workload, config, payload, index, target, run_id);
            errors = errors || result.at("errors").get<std::uint64_t>() != 0 ||
                     result.at("completed").get<std::uint64_t>() == 0;
            std::cout << std::fixed << std::setprecision(2) << std::setw(3) << index
                      << std::setw(12) << result.at("requests_per_second").get<double>()
                      << std::setw(12) << result.at("latency").at("p50_us").get<double>()
                      << std::setw(12) << result.at("latency").at("p90_us").get<double>()
                      << std::setw(12) << result.at("latency").at("p99_us").get<double>()
                      << std::setw(9) << result.at("errors").get<std::uint64_t>() << ' ';
            const auto& network = result.at("server_network").at("gigabits_per_second");
            if (network.is_null()) {
                std::cout << std::setw(11) << "N/A";
            } else {
                std::cout << std::setw(11) << network.get<double>();
            }
            std::cout << ' ' << std::setw(15)
                      << result.at("client_process").at("cpu_utilization_percent").get<double>()
                      << ' ';
            const auto& cpu = result.at("server_host").at("cpu_utilization_percent");
            if (cpu.is_null()) {
                std::cout << std::setw(12) << "N/A";
            } else {
                std::cout << std::setw(12) << cpu.get<double>();
            }
            std::cout << ' ';
            const auto& cpio = result.at("server_reference_cycles_per_io");
            if (cpio.is_null()) {
                std::cout << std::setw(14) << "N/A";
            } else {
                std::cout << std::setw(14) << cpio.get<double>();
            }
            std::cout << '\n';
            for (const auto& warning : result.at("warnings")) {
                log_warning(warning.get<std::string>());
            }
            report["results"].push_back(std::move(result));
            if (output) {
                write_private(*output, report, false);
            }
        }
        report["server_final_telemetry"] = command("/v1/benchmark/stop?run_id=" + run_id);
        run_id.clear();
        report["status"] = errors ? "completed_with_errors" : "completed";
        if (output) {
            write_private(*output, report, false);
        }
    } catch (const std::exception& error) {
        if (!run_id.empty()) {
            try {
                command("/v1/benchmark/stop?run_id=" + run_id);
            } catch (const std::exception& cleanup) {
                log_warning(std::string("Cannot stop workload; its bounded lease will expire: ") +
                            cleanup.what());
            }
        }
        report["status"] = "failed";
        report["failure"] = error.what();
        if (output) {
            write_private(*output, report, false);
        }
        throw;
    }
    // Keep details in the report; explain unavailable reference CPIO only once per reason.
    std::vector<std::string> cycle_reasons;
    std::vector<std::string> network_reasons;
    for (const auto& result : report["results"]) {
        const auto& host = result.at("server_host");
        if (host.at("reference_cycles").is_null()) {
            const auto reason = host.at("reference_cycles_unavailable_reason").get<std::string>();
            if (std::find(cycle_reasons.begin(), cycle_reasons.end(), reason) ==
                cycle_reasons.end()) {
                cycle_reasons.push_back(reason);
                log_warning("Reference CPIO unavailable: " + reason);
            }
        }
        const auto& network = result.at("server_network");
        if (network.at("gigabits_per_second").is_null()) {
            const auto reason = network.at("unavailable_reason").get<std::string>();
            if (std::find(network_reasons.begin(), network_reasons.end(), reason) ==
                network_reasons.end()) {
                network_reasons.push_back(reason);
                log_warning("Server network throughput unavailable: " + reason);
            }
        }
    }
    if (output) {
        std::cout << "Results saved to " << output->string() << '\n';
    }
    if (errors) {
        log_warning(
            "Benchmark completed with errors; do not treat it as a valid throughput result");
    }
    return errors ? 2 : 0;
}

// Keep default result names consistent with the selected workload, not the control transport.
std::string default_output(const RunConfig& config) {
    return std::string("results/") + (config.tls == "off" ? "http-" : "https-") +
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
        throw std::runtime_error("No registered targets; add a server first");
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

// Quote a literal argument for POSIX shells, preserving spaces, apostrophes and metacharacters.
std::string shell_argument(std::string_view value) {
    std::string quoted{"'"};
    for (const auto character : value) {
        if (character == '\'') {
            quoted.append("'\\''");
        } else {
            quoted.push_back(character);
        }
    }
    quoted.push_back('\'');
    return quoted;
}

// Render the effective configuration without relying on CLI defaults or exposing target contents.
// Preserve floating-point settings exactly so fractional durations survive a noninteractive rerun.
std::string benchmark_command(std::string_view executable, const std::string& target,
                              const RunConfig& config, const std::optional<fs::path>& output) {
    std::ostringstream command;
    command << std::setprecision(std::numeric_limits<double>::max_digits10);
    command << shell_argument(executable) << " run";
    command << " --target " << shell_argument(target);
    command << " --tls " << shell_argument(config.tls);
    command << " --server-workers " << config.server_workers;
    command << " --method " << shell_argument(config.method);
    command << " --get-response-data " << shell_argument(config.get_response_data);
    command << " --get-size " << config.get_size;
    command << " --put-size " << config.put_size;
    command << " --get-percent " << config.get_percent;
    command << " --connections " << config.connections;
    command << " --workers " << config.workers;
    command << " --warmup " << config.warmup;
    command << " --duration " << config.duration;
    command << " --requests " << config.requests;
    command << " --repetitions " << config.repetitions;
    command << " --timeout " << config.timeout;
    if (config.tls != "off") {
        command << " --cipher " << shell_argument(config.cipher);
    }
    if (output) {
        command << " --output " << shell_argument(output->string());
    }
    return command.str();
}

// Keep recoverable input/run failures local to the menu; CLI fatal failures instead exit nonzero.
void interactive(std::string_view executable) {
    while (std::cin) {
        std::cout
            << "\nWinlin\n1. Add server\n2. Inspect server\n3. Run HTTP/HTTPS benchmark\n0. Exit\n";
        const auto action = prompt("Select", "0");
        if (action == "0") {
            return;
        }
        try {
            if (action == "1") {
                const auto host = prompt("Server IPv4 address");
                check_host(host);
                const auto port = prompt("Agent port", "38080");
                add_target(host, port, std::string(benchmark_certificate_sha256),
                           state_directory() / (host + "-" + port + ".json"));
            } else if (action == "2") {
                const auto target = load_target(select_target());
                std::cout << control(target, "/v1/capabilities").dump(2) << '\n';
            } else if (action == "3") {
                const auto target_path = select_target();
                const auto target = load_target(target_path);
                RunConfig config;
                config.tls = lower(prompt("Benchmark TLS: on / off / ktls", "on"));
                if (config.tls != "off") {
                    config.cipher = prompt("Benchmark TLS 1.3 cipher", config.cipher);
                }
                config.server_workers = number(prompt("Server workers (1-256)", "8"), 256);
                config.method = lower(prompt("Method: get / put / mixed", "get"));
                std::cout << "Size presets: 256B, 512B, 1KiB, 4KiB, 8KiB, 16KiB, 64KiB, 256KiB, "
                             "1MiB, 4MiB\n";
                if (config.method == "get" || config.method == "mixed") {
                    config.get_size = object_size(prompt("GET size", "4KiB"));
                    config.get_response_data = lower(
                        trim(prompt("GET response data: shared / copy", config.get_response_data)));
                }
                if (config.method == "put" || config.method == "mixed") {
                    config.put_size = object_size(prompt("PUT size", "4KiB"));
                }
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
                const auto save = lower(trim(prompt("Save detailed telemetry? yes / no", "no")));
                if (save != "yes" && save != "y" && save != "no" && save != "n") {
                    throw std::invalid_argument("Answer yes or no to saving detailed telemetry");
                }
                std::optional<fs::path> output;
                if (save == "yes" || save == "y") {
                    output = prompt("Result file", default_output(config));
                }
                std::cout << "\nNoninteractive command:\n"
                          << benchmark_command(executable, target_path, config, output) << '\n';
                if (output) {
                    std::cout << "For another run, choose a new --output path; existing result "
                                 "files are not overwritten.\n";
                }
                std::cout << '\n';
                run(target, config, output);
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
        // If started w/o options, start interactive mode.
        if (argc == 1) {
            interactive(argv[0]);
            return 0;
        }
        const std::string command = argv[1];
        if (command == "--help" || command == "help") {
            std::cout
                << "winlin                         Interactive console\n"
                   "winlin add --host IP --target FILE [--fingerprint "
                   "SHA256]\n"
                   "            [--port 38080] Control uses plain HTTP.\n"
                   "            HTTPS workloads default to the PUBLIC benchmark certificate.\n"
                   "            Custom workload certificates require --fingerprint.\n"
                   "winlin inspect --target FILE\n"
                   "winlin run --target FILE [--method get|put|mixed] [--get-size 4KiB]\n"
                   "           [--get-response-data shared|copy] (default: copy)\n"
                   "           [--tls on|off|ktls] [--server-workers 8]\n"
                   "           [--put-size 4KiB] [--get-percent 50] [--connections 256]\n"
                   "           [--workers N] [--warmup 10] [--duration 30] [--requests 0]\n"
                   "           [--repetitions 3] [--timeout 10] [--output FILE] [--cipher SUITE]\n"
                   "Without --output, results are displayed in the console only.\n"
                   "Closed-loop persistent HTTP/HTTPS; paced load and handshake tests are not "
                   "implemented yet.\n";
            return 0;
        }
        Args args(argc, argv, 2);
        if (command == "add" || command == "pair") {
            args.allow({"--host", "--port", "--fingerprint", "--target"});
            add_target(args.require("--host"), args.get("--port", "38080"),
                       args.get("--fingerprint", std::string(benchmark_certificate_sha256)),
                       args.require("--target"));
            return 0;
        }
        if (command == "inspect") {
            args.allow({"--target"});
            const auto target = load_target(args.require("--target"));
            std::cout << control(target, "/v1/capabilities").dump(2) << '\n';
            return 0;
        }
        if (command == "run") {
            args.allow({"--target", "--method", "--get-size", "--get-response-data", "--put-size",
                        "--get-percent", "--connections", "--workers", "--warmup", "--duration",
                        "--requests", "--repetitions", "--timeout", "--output", "--cipher", "--tls",
                        "--server-workers"});
            const auto config = configuration(args);
            auto target = load_target(args.require("--target"));
            std::optional<fs::path> output;
            if (args.contains("--output")) {
                output = args.require("--output");
            }
            return run(target, config, output);
        }
        throw std::invalid_argument("Unknown command; use winlin --help");
    } catch (const std::exception& error) {
        std::cerr << "winlin: FATAL: " << error.what() << '\n';
        return 1;
    }
}
