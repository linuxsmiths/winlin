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

struct Fd {
    int value{-1};
    explicit Fd(int fd = -1) : value(fd) {}
    ~Fd() { if (value >= 0) ::close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value(std::exchange(other.value, -1)) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) {
            if (value >= 0) ::close(value);
            value = std::exchange(other.value, -1);
        }
        return *this;
    }
};

using Context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
inline Context context(bool server, const std::string& cipher, bool ktls = false) {
    Context ctx(SSL_CTX_new(server ? TLS_server_method() : TLS_client_method()), SSL_CTX_free);
    if (!ctx || SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx.get(), cipher.c_str()) != 1)
        throw tls_error("Cannot configure TLS 1.3/cipher");
    if (cipher.find(':') != std::string::npos)
        throw std::invalid_argument("Select exactly one TLS 1.3 cipher suite");
    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_mode(ctx.get(), SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (ktls) {
#ifdef SSL_OP_ENABLE_KTLS
        SSL_CTX_set_options(ctx.get(), SSL_OP_ENABLE_KTLS);
#else
        throw std::runtime_error("This OpenSSL build does not expose kTLS");
#endif
    }
#ifdef SSL_OP_ENABLE_KTLS
    else SSL_CTX_clear_options(ctx.get(), SSL_OP_ENABLE_KTLS);
#endif
    // The client authenticates the exact peer certificate using its saved SHA-256 pin.
    if (!server) SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    return ctx;
}

inline std::string fingerprint(SSL* ssl) {
    auto* certificate = SSL_get0_peer_certificate(ssl);
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned length{};
    if (!certificate || X509_digest(certificate, EVP_sha256(), digest, &length) != 1)
        throw tls_error("Cannot fingerprint peer certificate");
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

struct TlsSocket {
    Fd fd;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl{nullptr, SSL_free};
    std::uint32_t want{EPOLLIN | EPOLLOUT};
    TlsSocket(int socket, SSL_CTX* ctx) : fd(socket), ssl(SSL_new(ctx), SSL_free) {
        if (!ssl || SSL_set_fd(ssl.get(), fd.value) != 1) throw tls_error("SSL_set_fd");
        int one = 1;
        if (setsockopt(fd.value, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0)
            throw system_error("TCP_NODELAY");
    }
    bool outcome(int result) {
        if (result > 0) return true;
        const auto error = SSL_get_error(ssl.get(), result);
        if (error == SSL_ERROR_WANT_READ) want = EPOLLIN;
        else if (error == SSL_ERROR_WANT_WRITE) want = EPOLLOUT;
        else throw tls_error(error == SSL_ERROR_ZERO_RETURN ? "Peer closed TLS" : "TLS I/O failed");
        return false;
    }
    bool handshake(bool server) {
        ERR_clear_error();
        return outcome(server ? SSL_accept(ssl.get()) : SSL_connect(ssl.get()));
    }
    int read(char* buffer, std::size_t length) {
        ERR_clear_error();
        const int result = SSL_read(ssl.get(), buffer, static_cast<int>(std::min<std::size_t>(length, 16384)));
        return outcome(result) ? result : 0;
    }
    int write(const char* buffer, std::size_t length) {
        ERR_clear_error();
        const int result = SSL_write(ssl.get(), buffer, static_cast<int>(std::min<std::size_t>(length, 16384)));
        return outcome(result) ? result : 0;
    }
};

class Epoll {
    Fd fd_{epoll_create1(EPOLL_CLOEXEC)};
public:
    Epoll() { if (fd_.value < 0) throw system_error("epoll_create1"); }
    void set(int socket, std::uint32_t events, bool add = false) {
        epoll_event event{};
        event.events = events;
        event.data.fd = socket;
        if (epoll_ctl(fd_.value, add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, socket, &event) != 0)
            throw system_error("epoll_ctl");
    }
    int wait(epoll_event* events, int count, int timeout) {
        const int result = epoll_wait(fd_.value, events, count, timeout);
        if (result < 0 && errno != EINTR) throw system_error("epoll_wait");
        return std::max(0, result);
    }
};

inline Fd connect_socket(const std::string& host, const std::string& port) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* addresses{};
    const int error = getaddrinfo(host.c_str(), port.c_str(), &hints, &addresses);
    if (error) throw std::runtime_error(gai_strerror(error));
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(addresses, freeaddrinfo);
    for (auto* address = addresses; address; address = address->ai_next) {
        Fd socket(::socket(address->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
        if (socket.value < 0) continue;
        if (::connect(socket.value, address->ai_addr, address->ai_addrlen) == 0 || errno == EINPROGRESS)
            return socket;
    }
    throw system_error("connect");
}

inline void wait_socket(TlsSocket& socket, Clock::time_point deadline) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    if (remaining <= 0) throw std::runtime_error("TLS operation timed out");
    pollfd event{socket.fd.value, static_cast<short>(
        (socket.want & EPOLLIN ? POLLIN : 0) | (socket.want & EPOLLOUT ? POLLOUT : 0)), 0};
    const int result = poll(&event, 1, static_cast<int>(std::min<std::int64_t>(remaining, 10000)));
    if (result < 0 && errno != EINTR) throw system_error("poll");
}

inline std::unique_ptr<TlsSocket> connect_tls(SSL_CTX* ctx, const std::string& host,
                                             const std::string& port, const std::string& pin,
                                             double timeout = 10) {
    auto fd = connect_socket(host, port);
    auto socket = std::make_unique<TlsSocket>(std::exchange(fd.value, -1), ctx);
    SSL_set_tlsext_host_name(socket->ssl.get(), host.c_str());
    const auto deadline = Clock::now() + std::chrono::duration_cast<Clock::duration>(
        std::chrono::duration<double>(timeout));
    while (!socket->handshake(false)) wait_socket(*socket, deadline);
    if (!pin.empty() && !equal_secret(fingerprint(socket->ssl.get()), pin))
        throw std::runtime_error("Server certificate changed; refusing connection");
    return socket;
}

inline Json usage() {
    rusage data{};
    if (getrusage(RUSAGE_SELF, &data) != 0) throw system_error("getrusage");
    return {{"user_cpu_seconds", data.ru_utime.tv_sec + data.ru_utime.tv_usec / 1e6},
            {"system_cpu_seconds", data.ru_stime.tv_sec + data.ru_stime.tv_usec / 1e6},
            {"peak_rss_bytes", static_cast<std::uint64_t>(data.ru_maxrss) * 1024},
            {"voluntary_context_switches", data.ru_nvcsw},
            {"involuntary_context_switches", data.ru_nivcsw}};
}

inline Json environment() {
    utsname data{};
    if (uname(&data) != 0) throw system_error("uname");
    return {{"os", data.sysname}, {"kernel", data.release}, {"architecture", data.machine},
            {"logical_cpus", sysconf(_SC_NPROCESSORS_ONLN)}, {"openssl", OpenSSL_version(OPENSSL_VERSION)},
            {"winlin_version", WINLIN_VERSION}, {"build_type", WINLIN_BUILD_TYPE}, {"compiler", __VERSION__}};
}

inline std::string read_private(const std::string& path, std::size_t maximum = 65536) {
    Fd file(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.value < 0) throw system_error("Cannot open private file");
    struct stat status{};
    if (fstat(file.value, &status) != 0) throw system_error("Cannot stat private file");
    if (!S_ISREG(status.st_mode) || (status.st_mode & 0077) != 0 || status.st_uid != geteuid())
        throw std::runtime_error("Private file must be owned by this user with mode 0600");
    if (status.st_size < 0 || static_cast<std::uint64_t>(status.st_size) > maximum)
        throw std::runtime_error("Private file is too large");
    std::string content;
    std::array<char, 4096> buffer{};
    for (;;) {
        const auto count = ::read(file.value, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw system_error("read private file");
        if (count == 0) break;
        content.append(buffer.data(), count);
        if (content.size() > maximum) throw std::runtime_error("Private file is too large");
    }
    return content;
}

inline std::string token_file(const std::string& path) {
    return parse_token(read_private(path, 258));
}

inline std::optional<std::string> optional_token_file(const std::string& path) {
    struct stat status{};
    if (lstat(path.c_str(), &status) == 0) return token_file(path);
    if (errno != ENOENT) throw system_error("Cannot inspect session file");
    return std::nullopt;
}

inline std::string issue_token_file(const std::string& path) {
    unsigned char bytes[32]{};
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) throw tls_error("RAND_bytes");
    constexpr char hex[] = "0123456789abcdef";
    std::string secret;
    for (auto byte : bytes) {
        secret += hex[byte >> 4];
        secret += hex[byte & 15];
    }
    Fd file(open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (file.value < 0) throw system_error("Cannot create session credential");
    try {
        const auto content = secret + "\n";
        std::size_t offset{};
        while (offset < content.size()) {
            const auto count = ::write(file.value, content.data() + offset, content.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw system_error("Cannot write session credential");
            offset += count;
        }
        if (fsync(file.value)) throw system_error("Cannot flush session credential");
    } catch (...) {
        unlink(path.c_str());
        throw;
    }
    return secret;
}
}
