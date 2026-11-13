#pragma once

#include "winlin/host.hpp"
#include "winlin/cpu.hpp"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <thread>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace winlin {
inline std::runtime_error system_error(std::string message) {
    return std::runtime_error(std::move(message) + ": " + std::strerror(errno));
}

inline std::runtime_error tls_error(std::string message) {
    char buffer[256]{};
    ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
    return std::runtime_error(std::move(message) + ": " + buffer);
}

// Give sockets, files and epoll descriptors one move-only owner. Native helpers transfer ownership
// with std::exchange; never retry a failed close because the descriptor may already be reused.
struct Fd {
    int value{-1};

    explicit Fd(int fd = -1) : value(fd) {
    }

    ~Fd() {
        release();
    }

    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;

    Fd(Fd&& other) noexcept : value(std::exchange(other.value, -1)) {
    }

    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) {
            release();
            value = std::exchange(other.value, -1);
        }
        return *this;
    }

private:
    void release() {
        if (value >= 0 && ::close(value) != 0) {
            log_warning(system_error("close descriptor").what());
        }
        value = -1;
    }
};

using Context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

// Enumerate TLS 1.3 suites usable by this OpenSSL build/provider, not the control cipher.
inline std::vector<std::string> supported_tls_ciphers() {
    Context ctx(SSL_CTX_new(TLS_method()), SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(ctx ? SSL_new(ctx.get()) : nullptr, SSL_free);
    if (!ssl) {
        throw tls_error("Cannot enumerate supported TLS ciphers");
    }
    auto* ciphers = SSL_get1_supported_ciphers(ssl.get());
    if (!ciphers) {
        throw tls_error("Cannot enumerate supported TLS ciphers");
    }
    std::vector<std::string> result;
    for (int index = 0; index < sk_SSL_CIPHER_num(ciphers); ++index) {
        const auto* cipher = sk_SSL_CIPHER_value(ciphers, index);
        if (std::string_view(SSL_CIPHER_get_version(cipher)) == "TLSv1.3") {
            result.emplace_back(SSL_CIPHER_get_name(cipher));
        }
    }
    sk_SSL_CIPHER_free(ciphers);
    return result;
}

// Pin the protocol and one cipher suite for reproducibility. Enabling kTLS is only a request;
// native server sessions must inspect the negotiated BIO state before accepting a workload.
inline Context context(bool server, const std::string& cipher, bool ktls = false) {
    Context ctx(SSL_CTX_new(server ? TLS_server_method() : TLS_client_method()), SSL_CTX_free);
    if (!ctx || SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx.get(), cipher.c_str()) != 1) {
        throw tls_error("Cannot configure TLS 1.3/cipher");
    }
    if (cipher.find(':') != std::string::npos) {
        throw std::invalid_argument("Select exactly one TLS 1.3 cipher suite");
    }
    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_mode(ctx.get(),
                     SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (ktls) {
#ifdef SSL_OP_ENABLE_KTLS
        SSL_CTX_set_options(ctx.get(), SSL_OP_ENABLE_KTLS);
#else
        throw std::runtime_error("This OpenSSL build does not expose kTLS");
#endif
    }
#ifdef SSL_OP_ENABLE_KTLS
    else
        SSL_CTX_clear_options(ctx.get(), SSL_OP_ENABLE_KTLS);
#endif
    // The client authenticates the exact peer certificate using its saved SHA-256 pin.
    if (!server) {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    }
    return ctx;
}

// Return the SHA-256 fingerprint of the peer certificate, or throw if no certificate was sent.
inline std::string fingerprint(SSL* ssl) {
    auto* certificate = SSL_get0_peer_certificate(ssl);
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned length{};
    if (!certificate || X509_digest(certificate, EVP_sha256(), digest, &length) != 1) {
        throw tls_error("Cannot fingerprint peer certificate");
    }
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (unsigned i = 0; i < length; ++i) {
        result += hex[digest[i] >> 4];
        result += hex[digest[i] & 15];
    }
    return result;
}

inline bool equal_secret(std::string_view a, std::string_view b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// Distinguish peer EOF from protocol/internal failures. An idle server connection may close
// normally; a client waiting for response bytes must still report this as a failed request.
class PeerClosed : public std::runtime_error {
public:
    PeerClosed() : std::runtime_error("Peer closed connection") {
    }
};

// Own a nonblocking TCP stream, with an OpenSSL session only when TLS was explicitly selected.
// A zero read/write result means retry with want events, not EOF; terminal TLS errors throw.
// One worker owns a session, and buffers must remain suitable for OpenSSL's retry requirements.
struct StreamSocket {
    // Socket fd
    Fd fd;
    // TLS session, or nullptr for plaintext TCP
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl{nullptr, SSL_free};
    // wait_socket() must wait for these events before calling read/write/handshake again.
    std::uint32_t want{EPOLLIN | EPOLLOUT};

    StreamSocket(int socket, SSL_CTX* ctx)
        : fd(socket), ssl(ctx ? SSL_new(ctx) : nullptr, SSL_free) {
        if (ctx && (!ssl || SSL_set_fd(ssl.get(), fd.value) != 1)) {
            throw tls_error("SSL_set_fd");
        }
        int one = 1;
        if (setsockopt(fd.value, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
            throw system_error("TCP_NODELAY");
        }
    }

    // Translate OpenSSL's cross-direction retries: a read may require writability and vice versa.
    bool outcome(int result) {
        if (result > 0) {
            return true;
        }
        // SSL_ERROR_SYSCALL may have no OpenSSL error queued; preserve the OS cause before calling
        // SSL_get_error or any diagnostic helper that might change errno.
        const int socket_error = errno;
        const auto error = SSL_get_error(ssl.get(), result);
        // Our short-lived control clients may close without close_notify. Treat that as peer EOF,
        // not an internal TLS failure; the protocol state machine decides whether EOF was
        // premature.
        if (error == SSL_ERROR_ZERO_RETURN ||
            (error == SSL_ERROR_SSL &&
             ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) ||
            (error == SSL_ERROR_SYSCALL && result == 0 && socket_error == 0)) {
            throw PeerClosed();
        }
        // SSL_ERROR_WANT_READ -> wait for EPOLLIN
        // SSL_ERROR_WANT_WRITE -> wait for EPOLLOUT.
        if (error == SSL_ERROR_WANT_READ) {
            want = EPOLLIN;
        } else if (error == SSL_ERROR_WANT_WRITE) {
            want = EPOLLOUT;
        } else if (error == SSL_ERROR_SYSCALL) {
            if (socket_error) {
                throw std::runtime_error(
                    "TLS socket I/O failed: " + std::string(std::strerror(socket_error)) +
                    " (errno " + std::to_string(socket_error) + ")");
            }
            throw std::runtime_error("TLS socket I/O failed without an operating-system error");
        } else {
            throw tls_error("TLS I/O failed");
        }
        return false;
    }

    bool handshake(bool server) {
        if (!ssl) {
            if (server) {
                return true;
            }
            // Plain TCP client, wait for POLLOUT.
            pollfd ready{fd.value, POLLOUT, 0};
            const auto result = poll(&ready, 1, 0);
            if (result < 0 && errno != EINTR) {
                throw system_error("poll TCP connection");
            }
            if (result <= 0) {
                // Not connected yet, wait_socket() must wait for EPOLLOUT
                want = EPOLLOUT;
                return false;
            }
            int error{};
            socklen_t size = sizeof(error);
            // Connect failure will set socket error
            if (getsockopt(fd.value, SOL_SOCKET, SO_ERROR, &error, &size)) {
                throw system_error("Inspect TCP connection");
            }
            if (error) {
                errno = error;
                throw system_error("TCP connection");
            }
            // Connected w/o error
            return true;
        }
        // TLS client or server, SSL_accept() or SSL_connect() may require multiple calls,
        // as socket becomes readable/writable.
        // SSL_get_error() requires an empty thread-local queue before the operation. Peeking
        // avoids clearing every error slot when the queue is already empty, as it normally is.
        if (ERR_peek_error() != 0) {
            ERR_clear_error();
        }
        errno = 0;
        return outcome(server ? SSL_accept(ssl.get()) : SSL_connect(ssl.get()));
    }

    int read(char* buffer, std::size_t length) {
        if (!ssl) {
            return plain_result(::recv(fd.value, buffer, std::min<std::size_t>(length, 16384), 0),
                                EPOLLIN);
        }
        if (ERR_peek_error() != 0) {
            ERR_clear_error();
        }
        errno = 0;
        const int result =
            SSL_read(ssl.get(), buffer, static_cast<int>(std::min<std::size_t>(length, 16384)));
        return outcome(result) ? result : 0;
    }

    int write(const char* buffer, std::size_t length) {
        if (!ssl) {
            return plain_result(
                ::send(fd.value, buffer, std::min<std::size_t>(length, 16384), MSG_NOSIGNAL),
                EPOLLOUT);
        }
        if (ERR_peek_error() != 0) {
            ERR_clear_error();
        }
        errno = 0;
        const int result =
            SSL_write(ssl.get(), buffer, static_cast<int>(std::min<std::size_t>(length, 16384)));
        return outcome(result) ? result : 0;
    }

    // Keep retry and EOF semantics identical for HTTP and HTTPS state machines.
    int plain_result(ssize_t result, std::uint32_t direction) {
        if (result > 0) {
            return static_cast<int>(result);
        }
        if (result == 0) {
            throw PeerClosed();
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            want = direction;
            return 0;
        }
        throw system_error("TCP stream I/O");
    }
};

// Own one worker's level-triggered event queue. Sessions remain owned by the worker, not by epoll;
// closing their descriptors removes registrations, so an idle session need not be explicitly
// deleted.
class Epoll {
    // Epoll control fd
    Fd fd_{epoll_create1(EPOLL_CLOEXEC)};

public:
    Epoll() {
        if (fd_.value < 0) {
            throw system_error("epoll_create1");
        }
    }

    void set(int socket, std::uint32_t events, bool add = false) {
        epoll_event event{};
        event.events = events;
        event.data.fd = socket;
        if (epoll_ctl(fd_.value, add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, socket, &event) != 0) {
            throw system_error("epoll_ctl");
        }
    }

    int wait(epoll_event* events, int count, int timeout) {
        const int result = epoll_wait(fd_.value, events, count, timeout);
        if (result < 0 && errno != EINTR) {
            throw system_error("epoll_wait");
        }
        return std::max(0, result);
    }
};

// Return the first usable nonblocking connection; TLS setup checks completion and applies a
// timeout.
inline Fd connect_socket(const std::string& host, const std::string& port) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* addresses{};
    const int error = getaddrinfo(host.c_str(), port.c_str(), &hints, &addresses);
    if (error) {
        throw std::runtime_error(gai_strerror(error));
    }
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(addresses, freeaddrinfo);
    for (auto* address = addresses; address; address = address->ai_next) {
        Fd socket(::socket(address->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
        if (socket.value < 0) {
            continue;
        }
        if (::connect(socket.value, address->ai_addr, address->ai_addrlen) == 0 ||
            errno == EINPROGRESS) {
            return socket;
        }
    }
    throw system_error("connect to " + host + ":" + port);
}

inline void wait_socket(StreamSocket& socket, Clock::time_point deadline) {
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    // Deadline expired?
    if (remaining <= 0) {
        throw std::runtime_error("Connection operation timed out");
    }
    pollfd event{socket.fd.value,
                 static_cast<short>((socket.want & EPOLLIN ? POLLIN : 0) |
                                    (socket.want & EPOLLOUT ? POLLOUT : 0)),
                 0};
    const int result = poll(&event, 1, static_cast<int>(std::min<std::int64_t>(remaining, 10000)));
    if (result < 0 && errno != EINTR) {
        throw system_error("poll");
    }
}

// Finish the selected transport setup before sending bytes. A null context explicitly selects
// plaintext for an advertised workload endpoint; HTTPS is never automatically downgraded.
// Only interactive discovery may omit a TLS pin.
inline std::unique_ptr<StreamSocket> connect_stream(SSL_CTX* ctx, const std::string& host,
                                                    const std::string& port, const std::string& pin,
                                                    double timeout = 10) {
    auto fd = connect_socket(host, port);
    auto socket = std::make_unique<StreamSocket>(std::exchange(fd.value, -1), ctx);
    if (ctx && SSL_set_tlsext_host_name(socket->ssl.get(), host.c_str()) != 1) {
        throw tls_error("Cannot set TLS server name");
    }
    const auto deadline = Clock::now() + std::chrono::duration_cast<Clock::duration>(
                                             std::chrono::duration<double>(timeout));
    try {
        // TLS handshake may require multiple SSL_connect calls, as socket becomes writeable.
        while (!socket->handshake(false)) {
            wait_socket(*socket, deadline);
        }
    } catch (const std::exception& error) {
        throw std::runtime_error(std::string(ctx ? "TLS" : "TCP") + " connection to " + host + ":" +
                                 port + " failed: " + error.what());
    }
    // Verify the server's certificate fingerprint against the pinned SHA-256 digest, if any.
    if (ctx && !pin.empty() && !equal_secret(fingerprint(socket->ssl.get()), pin)) {
        throw std::runtime_error("Server certificate changed; refusing connection");
    }
    // Return connected socket
    return socket;
}

// Start before creating server threads so perf inheritance covers control and workload workers.
// Do not substitute CPU-time/frequency estimates when hardware counters are denied or multiplexed.
class ProcessCycles {
    Fd event_;
    std::string unavailable_;

public:
    ProcessCycles() {
        perf_event_attr settings{};
        settings.size = sizeof(settings);
        settings.type = PERF_TYPE_HARDWARE;
        settings.config = PERF_COUNT_HW_CPU_CYCLES;
        settings.inherit = 1;
        settings.exclude_hv = 1;
        settings.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
        event_ = Fd(static_cast<int>(
            syscall(SYS_perf_event_open, &settings, 0, -1, -1, PERF_FLAG_FD_CLOEXEC)));
        if (event_.value < 0) {
            const auto error = errno;
            unavailable_ =
                "perf_event_open hardware cycles unavailable: " + std::string(std::strerror(error));
            if (error == EPERM || error == EACCES) {
                unavailable_ +=
                    "; allow the server hardware-counter access using CAP_PERFMON or an "
                    "administrator-approved perf policy";
            } else if (error == ENOENT || error == ENODEV || error == EOPNOTSUPP) {
                unavailable_ += "; the host/VM must expose a hardware CPU-cycle PMU";
            }
        }
    }

    // Preserve the actual counter source and the reason for any unavailable sample.
    Json sample() const {
        Json result{
            {"cpu_cycles", nullptr},
            {"cpu_cycles_source", "perf_event_open; inherited process threads, user+kernel"},
            {"cpu_cycles_unavailable_reason", nullptr}};
        if (event_.value < 0) {
            result["cpu_cycles_unavailable_reason"] = unavailable_;
            return result;
        }
        std::array<std::uint64_t, 3> sample{};
        if (::read(event_.value, sample.data(), sizeof(sample)) != sizeof(sample)) {
            result["cpu_cycles_unavailable_reason"] = "Cannot read hardware cycle counter";
        } else if (!sample[2] || sample[1] != sample[2]) {
            result["cpu_cycles_unavailable_reason"] =
                "Hardware cycle counter was not continuously scheduled; no estimate substituted";
        } else {
            result["cpu_cycles"] = sample[0];
        }
        return result;
    }
};

inline std::unique_ptr<ProcessCycles> process_cycles;

// Snapshot this process, not the whole host; Linux reports ru_maxrss in KiB.
inline Json usage() {
    rusage data{};
    if (getrusage(RUSAGE_SELF, &data) != 0) {
        throw system_error("getrusage");
    }
    Json result{{"user_cpu_seconds", data.ru_utime.tv_sec + data.ru_utime.tv_usec / 1e6},
                {"system_cpu_seconds", data.ru_stime.tv_sec + data.ru_stime.tv_usec / 1e6},
                {"peak_rss_bytes", static_cast<std::uint64_t>(data.ru_maxrss) * 1024},
                {"voluntary_context_switches", data.ru_nvcsw},
                {"involuntary_context_switches", data.ru_nivcsw}};
    if (process_cycles) {
        result.update(process_cycles->sample());
    }
    return result;
}

// Sum executed CPU time, not idle/I/O wait or stolen VM time. Linux user/nice already include
// guest/guest_nice, so adding those fields again would double count guest execution.
inline Json host_usage() {
    return sample_host_cpu("/proc/stat aggregate user+nice+system+irq+softirq", [] {
        const auto ticks_per_second = sysconf(_SC_CLK_TCK);
        if (ticks_per_second <= 0) {
            throw std::runtime_error("Cannot determine Linux CPU accounting tick frequency");
        }
        std::ifstream input("/proc/stat");
        std::string line, label;
        if (!std::getline(input, line)) {
            throw std::runtime_error("Cannot read aggregate CPU counters from /proc/stat");
        }
        std::istringstream fields(line);
        std::array<std::uint64_t, 7> ticks{};
        if (!(fields >> label) || label != "cpu") {
            throw std::runtime_error("Missing aggregate CPU counters in /proc/stat");
        }
        for (auto& value : ticks) {
            if (!(fields >> value)) {
                throw std::runtime_error("Incomplete aggregate CPU counters in /proc/stat");
            }
        }
        const double busy =
            static_cast<double>(ticks[0]) + ticks[1] + ticks[2] + ticks[5] + ticks[6];
        return busy / ticks_per_second;
    });
}

// Query only Azure's SKU leaf over link-local TCP, without proxies, redirects or credentials.
// A single short deadline bounds all I/O; failures become metadata unavailability, not guesses.
inline std::string azure_vm_sku() {
    const auto deadline = Clock::now() + std::chrono::seconds(1);
    auto socket = connect_stream(nullptr, "169.254.169.254", "80", "", 0.5);
    const std::string request =
        "GET /metadata/instance/compute/vmSize?api-version=2021-02-01&format=text HTTP/1.1\r\n"
        "Host: 169.254.169.254\r\nMetadata: true\r\nConnection: close\r\n\r\n";
    std::size_t sent{};
    while (sent < request.size()) {
        const auto count = socket->write(request.data() + sent, request.size() - sent);
        sent += count;
        if (!count) {
            wait_socket(*socket, deadline);
        }
    }
    std::string response;
    std::array<char, 1024> buffer{};
    for (;;) {
        const auto boundary = response.find("\r\n\r\n");
        if (boundary != std::string::npos) {
            const auto head = parse_head(std::string_view(response).substr(0, boundary + 4));
            if (!head.first.starts_with("HTTP/1.1 200 ") ||
                !head.fields.contains("content-length") || head.length > 128) {
                throw std::runtime_error("Azure metadata SKU request was rejected or malformed");
            }
            if (response.size() >= boundary + 4 + head.length) {
                return response.substr(boundary + 4, head.length);
            }
        }
        if (response.size() > max_header_size + 128) {
            throw std::runtime_error("Azure metadata response exceeded size limit");
        }
        const auto count = socket->read(buffer.data(), buffer.size());
        if (count) {
            response.append(buffer.data(), count);
        } else {
            wait_socket(*socket, deadline);
        }
    }
}

// Cache immutable machine metadata once, outside measurements; inaccessible firmware stays unknown.
inline Json machine_environment() {
    static const Json machine = [] {
        auto firmware = [](const char* path) {
            std::ifstream input(path);
            std::string value;
            if (!std::getline(input, value) || value.empty() || value.size() > 256) {
                throw std::runtime_error(
                    "SMBIOS manufacturer/model files are missing or unreadable");
            }
            return value;
        };
        auto result = describe_machine("", "");
        try {
            const auto manufacturer = firmware("/sys/class/dmi/id/sys_vendor");
            const auto model = firmware("/sys/class/dmi/id/product_name");
            result = describe_machine(manufacturer, model);
            if (manufacturer == "Microsoft Corporation" && result.at("type") == "virtual_machine") {
                apply_azure_sku(result, azure_vm_sku());
            }
        } catch (const std::exception& error) {
            result["unavailable_reason"] = error.what();
        }
        return result;
    }();
    return machine;
}

// Report OS-visible capacity and this process's effective descriptor limits, not launcher defaults.
inline Json environment() {
    utsname data{};
    if (uname(&data) != 0) {
        throw system_error("uname");
    }
    rlimit descriptors{};
    const auto pages = sysconf(_SC_PHYS_PAGES);
    const auto page_size = sysconf(_SC_PAGESIZE);
    if (getrlimit(RLIMIT_NOFILE, &descriptors) != 0 || pages < 0 || page_size < 0) {
        throw system_error("Cannot collect host RAM/file-descriptor limits");
    }
    auto limit = [](rlim_t value) -> Json {
        return value == RLIM_INFINITY ? Json("unlimited") : Json(value);
    };
    return {{"os", data.sysname},
            {"kernel", data.release},
            {"architecture", data.machine},
            {"logical_cpus", sysconf(_SC_NPROCESSORS_ONLN)},
            {"system_ram_bytes", static_cast<std::uint64_t>(pages) * page_size},
            {"machine", machine_environment()},
            {"fd_limit",
             {{"soft", limit(descriptors.rlim_cur)},
              {"hard", limit(descriptors.rlim_max)},
              {"unavailable_reason", nullptr}}},
            {"openssl", OpenSSL_version(OPENSSL_VERSION)},
            {"winlin_version", WINLIN_VERSION},
            {"build_type", WINLIN_BUILD_TYPE},
            {"allocator", WINLIN_ALLOCATOR},
            {"compiler", __VERSION__}};
}

// Validate the opened inode, not just its pathname, before reading saved target metadata.
// O_NONBLOCK prevents a hostile special file from hanging validation; only regular files pass.
inline std::string read_private(const std::string& path, std::size_t maximum = 65536) {
    Fd file(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.value < 0) {
        throw system_error("Cannot open private file");
    }
    struct stat status{};
    if (fstat(file.value, &status) != 0) {
        throw system_error("Cannot stat private file");
    }
    if (!S_ISREG(status.st_mode) || (status.st_mode & 0077) != 0 || status.st_uid != geteuid()) {
        throw std::runtime_error("Private file must be owned by this user with mode 0600");
    }
    if (status.st_size < 0 || static_cast<std::uint64_t>(status.st_size) > maximum) {
        throw std::runtime_error("Private file is too large");
    }
    std::string content;
    std::array<char, 4096> buffer{};
    for (;;) {
        const auto count = ::read(file.value, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            throw system_error("read private file");
        }
        if (count == 0) {
            break;
        }
        content.append(buffer.data(), count);
        if (content.size() > maximum) {
            throw std::runtime_error("Private file is too large");
        }
    }
    return content;
}

}
