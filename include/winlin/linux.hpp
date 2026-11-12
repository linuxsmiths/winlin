#pragma once

#include "winlin/core.hpp"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <optional>
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
    Fd fd;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl{nullptr, SSL_free};
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
            pollfd ready{fd.value, POLLOUT, 0};
            const auto result = poll(&ready, 1, 0);
            if (result < 0 && errno != EINTR) {
                throw system_error("poll TCP connection");
            }
            if (result <= 0) {
                want = EPOLLOUT;
                return false;
            }
            int error{};
            socklen_t size = sizeof(error);
            if (getsockopt(fd.value, SOL_SOCKET, SO_ERROR, &error, &size)) {
                throw system_error("Inspect TCP connection");
            }
            if (error) {
                errno = error;
                throw system_error("TCP connection");
            }
            return true;
        }
        ERR_clear_error();
        errno = 0;
        return outcome(server ? SSL_accept(ssl.get()) : SSL_connect(ssl.get()));
    }

    int read(char* buffer, std::size_t length) {
        if (!ssl) {
            return plain_result(::recv(fd.value, buffer, std::min<std::size_t>(length, 16384), 0),
                                EPOLLIN);
        }
        ERR_clear_error();
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
        ERR_clear_error();
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
// TLS pins are checked before credentials; only interactive discovery may omit a TLS pin.
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
        while (!socket->handshake(false)) {
            wait_socket(*socket, deadline);
        }
    } catch (const std::exception& error) {
        throw std::runtime_error(std::string(ctx ? "TLS" : "TCP") + " connection to " + host + ":" +
                                 port + " failed: " + error.what());
    }
    if (ctx && !pin.empty() && !equal_secret(fingerprint(socket->ssl.get()), pin)) {
        throw std::runtime_error("Server certificate changed; refusing connection");
    }
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
            unavailable_ =
                "perf_event_open hardware cycles unavailable: " + std::string(std::strerror(errno));
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

inline Json environment() {
    utsname data{};
    if (uname(&data) != 0) {
        throw system_error("uname");
    }
    return {{"os", data.sysname},
            {"kernel", data.release},
            {"architecture", data.machine},
            {"logical_cpus", sysconf(_SC_NPROCESSORS_ONLN)},
            {"openssl", OpenSSL_version(OPENSSL_VERSION)},
            {"winlin_version", WINLIN_VERSION},
            {"build_type", WINLIN_BUILD_TYPE},
            {"compiler", __VERSION__}};
}

// Validate the opened inode, not just its pathname, before reading credentials or target metadata.
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

inline std::string token_file(const std::string& path) {
    return parse_token(read_private(path, 258));
}

// Only absence means unpaired; permission and filesystem failures must not reset an existing
// identity.
inline std::optional<std::string> optional_token_file(const std::string& path) {
    struct stat status{};
    if (lstat(path.c_str(), &status) == 0) {
        return token_file(path);
    }
    if (errno != ENOENT) {
        throw system_error("Cannot inspect session file");
    }
    return std::nullopt;
}

// Create the credential exclusively with private permissions, then flush before publishing it.
inline std::string issue_token_file(const std::string& path) {
    unsigned char bytes[32]{};
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        throw tls_error("RAND_bytes");
    }
    constexpr char hex[] = "0123456789abcdef";
    std::string secret;
    for (auto byte : bytes) {
        secret += hex[byte >> 4];
        secret += hex[byte & 15];
    }
    Fd file(open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (file.value < 0) {
        throw system_error("Cannot create session credential");
    }
    try {
        const auto content = secret + "\n";
        std::size_t offset{};
        while (offset < content.size()) {
            const auto count =
                ::write(file.value, content.data() + offset, content.size() - offset);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw system_error("Cannot write session credential");
            }
            offset += count;
        }
        if (fsync(file.value)) {
            throw system_error("Cannot flush session credential");
        }
    } catch (...) {
        if (unlink(path.c_str()) != 0) {
            log_warning(system_error("Cannot remove incomplete session credential").what());
        }
        throw;
    }
    return secret;
}
}
