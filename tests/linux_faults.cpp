// Test-only syscall interposition. CTest preloads this library into its own child processes;
// no production executable links it or exposes these fault controls.
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <netinet/tcp.h>
#include <string_view>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// OpenSSL owns this opaque type. Resolve its APIs dynamically so the shim does not require
// OpenSSL linkage when testing executables that never use TLS.
struct ssl_st;

namespace {

std::atomic<long> teardown_cpu_seconds{};
std::atomic<int> control_listener{-1};
std::atomic<in_port_t> control_port{}, workload_port{};

// Retain one injected write's borrowed TLS session/buffer until its owning worker retries.
// Thread-local state prevents other controller/workload threads from checking too early.
struct TlsRetry {
    ssl_st* session{};
    const void* buffer{};
    int length{}, error{};
    int fd{-1};
    bool read_wait{}, checked_wait{}, large_write_completed{};
    bool client_put{};
    std::array<char, 16384> saved_bytes{};
};

thread_local TlsRetry tls_retry;

// Resolve libc directly so an injected syscall can delegate without recursively calling itself.
template <typename Function> Function next_symbol(const char* name) {
    const auto address = dlsym(RTLD_NEXT, name);
    if (!address) {
        std::fprintf(stderr, "Fatal winlin test shim error: cannot resolve %s: %s\n", name,
                     dlerror());
        std::_Exit(127);
    }
    return reinterpret_cast<Function>(address);
}

// Match only the test's workload sockets, leaving control exchanges and unrelated descriptors
// alone.
bool workload_socket(int fd) {
    static const char* port = std::getenv("WINLIN_TEST_DATA_PORT");
    if (!port) {
        return false;
    }
    sockaddr_in peer{};
    socklen_t length = sizeof(peer);
    const int saved_errno = errno;
    const bool matches = getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &length) == 0 &&
                         peer.sin_family == AF_INET &&
                         ntohs(peer.sin_port) == std::strtoul(port, nullptr, 10);
    errno = saved_errno;
    return matches;
}

// Arm deadline faults after warmup when the test controller publishes the baseline marker.
bool measurement_ready() {
    static const char* marker = std::getenv("WINLIN_TEST_MEASUREMENT_MARKER");
    if (!marker || access(marker, F_OK) == 0) {
        return true;
    }
    if (errno != ENOENT) {
        std::perror("Fatal winlin test shim measurement marker error");
        std::_Exit(127);
    }
    return false;
}

// Check the actual kernel flag, including while the server is parked on a TLS retry.
void verify_cork(int fd, int expected) {
    int cork{};
    socklen_t length = sizeof(cork);
    if (getsockopt(fd, IPPROTO_TCP, TCP_CORK, &cork, &length) != 0) {
        std::perror("Fatal winlin test shim cork query error");
        std::_Exit(127);
    }
    if (cork != expected) {
        std::fprintf(stderr, "Fatal winlin test shim error: TCP_CORK=%d, expected %d\n", cork,
                     expected);
        std::_Exit(127);
    }
}

// Check accepted sockets: NODELAY stays enabled; control/request reads must never stay corked.
void verify_server_options(int fd, int expected_cork = 0) {
    sockaddr_in local{};
    socklen_t local_length = sizeof(local);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_length) != 0) {
        std::perror("Fatal winlin test shim socket-address query error");
        std::_Exit(127);
    }
    // Environment discovery also receives HTTP data; restrict checks to accepted listener ports.
    if (local.sin_family != AF_INET ||
        (local.sin_port != control_port.load() && local.sin_port != workload_port.load())) {
        return;
    }
    int no_delay{};
    socklen_t option_length = sizeof(no_delay);
    if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, &option_length) != 0) {
        std::perror("Fatal winlin test shim socket-option query error");
        std::_Exit(127);
    }
    const bool is_control = local.sin_port == control_port.load();
    if (no_delay != 1 || (is_control && expected_cork)) {
        std::fprintf(stderr, "Fatal winlin test shim error: unexpected %s TCP_NODELAY=%d\n",
                     is_control ? "control" : "workload", no_delay);
        std::_Exit(127);
    }
    verify_cork(fd, expected_cork);
    static std::atomic<bool> checked_control{}, checked_workload{};
    auto& checked = is_control ? checked_control : checked_workload;
    if (!checked.exchange(true)) {
        std::fprintf(stderr, "winlin-test: %s TCP_NODELAY=%d\n",
                     is_control ? "control" : "workload", no_delay);
    }
}

// Borrow the descriptor associated with OpenSSL's socket BIO without inspecting private state.
int tls_descriptor(const ssl_st* session) {
    using GetFd = int (*)(const ssl_st*);
    static const auto get_fd = next_symbol<GetFd>("SSL_get_fd");
    return get_fd(session);
}

// Cross a request deadline at a known readiness/read boundary, rather than relying on server
// timing.
void delay_response() {
    timespec remaining{0, 100000000};
    while (nanosleep(&remaining, &remaining) != 0) {
        if (errno != EINTR) {
            std::perror("Fatal winlin test shim nanosleep error");
            std::_Exit(127);
        }
    }
}

} // namespace

// Fail two accepts on the controller and two on the workload, without consuming queued connections.
extern "C" int accept4(int fd, sockaddr* address, socklen_t* length, int flags) {
    static const auto real_accept = next_symbol<decltype(&accept4)>("accept4");
    static const bool inject = std::getenv("WINLIN_TEST_ACCEPT_ERRORS") != nullptr;
    static const bool verify_nodelay = std::getenv("WINLIN_TEST_VERIFY_SERVER_NODELAY") != nullptr;
    static std::atomic<unsigned> control_attempts{}, workload_attempts{};
    if (inject || verify_nodelay) {
        int unset = -1;
        control_listener.compare_exchange_strong(unset, fd);
    }
    if (inject) {
        auto& attempts = fd == control_listener.load() ? control_attempts : workload_attempts;
        const auto attempt = attempts.fetch_add(1);
        if (attempt < 2) {
            errno = attempt == 0 ? ECONNABORTED : EPROTO;
            return -1;
        }
    }
    const int client = real_accept(fd, address, length, flags);
    if (verify_nodelay && client >= 0) {
        sockaddr_in local{};
        socklen_t local_length = sizeof(local);
        if (getsockname(client, reinterpret_cast<sockaddr*>(&local), &local_length) != 0) {
            std::perror("Fatal winlin test shim accepted-socket query error");
            std::_Exit(127);
        }
        auto& port = fd == control_listener.load() ? control_port : workload_port;
        port.store(local.sin_port);
    }
    return client;
}

// Deliver an already-ready response only after its deadline has passed.
extern "C" int epoll_wait(int fd, epoll_event* events, int count, int timeout) {
    static const auto real_wait = next_symbol<decltype(&epoll_wait)>("epoll_wait");
    static const bool inject = std::getenv("WINLIN_TEST_LATE_READY") != nullptr;
    static std::atomic<bool> delayed{};
    if (tls_retry.session && !tls_retry.checked_wait) {
        if (!tls_retry.client_put) {
            verify_cork(tls_retry.fd, tls_retry.read_wait ? 0 : 1);
        }
        tls_retry.checked_wait = true;
        std::fprintf(stderr, "winlin-test: checked %s TLS %s wait\n",
                     tls_retry.read_wait ? "uncorked" : "corked",
                     tls_retry.read_wait ? "read" : "write");
    }
    const int result = real_wait(fd, events, count, timeout);
    if (inject && measurement_ready()) {
        for (int index = 0; index < result; ++index) {
            if ((events[index].events & EPOLLIN) && workload_socket(events[index].data.fd) &&
                !delayed.exchange(true)) {
                delay_response();
                std::fprintf(stderr, "winlin-test: delayed ready response\n");
            }
        }
    }
    return result;
}

// Cross the deadline inside pump(), after readiness passed its initial deadline check.
extern "C" ssize_t recv(int fd, void* buffer, std::size_t length, int flags) {
    static const auto real_recv = next_symbol<decltype(&recv)>("recv");
    static const bool inject = std::getenv("WINLIN_TEST_LATE_RECV") != nullptr;
    static const bool verify_nodelay = std::getenv("WINLIN_TEST_VERIFY_SERVER_NODELAY") != nullptr;
    static std::atomic<bool> delayed{};
    const auto result = real_recv(fd, buffer, length, flags);
    if (verify_nodelay && result > 0) {
        verify_server_options(fd);
    }
    if (inject && result > 0 && workload_socket(fd) && measurement_ready() &&
        !delayed.exchange(true)) {
        delay_response();
        std::fprintf(stderr, "winlin-test: delayed received response\n");
    }
    return result;
}

// Observe both cork transitions on real workload sockets, including encrypted responses.
extern "C" int setsockopt(int fd, int level, int option, const void* value,
                          socklen_t length) noexcept {
    static const auto real_set = next_symbol<decltype(&setsockopt)>("setsockopt");
    static const bool verify = std::getenv("WINLIN_TEST_VERIFY_SERVER_NODELAY") != nullptr;
    const int result = real_set(fd, level, option, value, length);
    if (verify && result == 0 && level == IPPROTO_TCP && option == TCP_CORK &&
        length == sizeof(int)) {
        int cork{};
        std::memcpy(&cork, value, sizeof(cork));
        verify_server_options(fd, cork);
        static std::atomic<bool> checked_enabled{}, checked_disabled{};
        auto& checked = cork ? checked_enabled : checked_disabled;
        if (!checked.exchange(true)) {
            std::fprintf(stderr, "winlin-test: workload TCP_CORK=%d\n", cork);
        }
    }
    return result;
}

// Request/header/body reads occur outside response submission, for both HTTP and HTTPS.
extern "C" int SSL_read(ssl_st* session, void* buffer, int length) {
    static const auto real_read = next_symbol<decltype(&SSL_read)>("SSL_read");
    static const bool verify = std::getenv("WINLIN_TEST_VERIFY_SERVER_NODELAY") != nullptr;
    if (verify) {
        verify_server_options(tls_descriptor(session));
    }
    return real_read(session, buffer, length);
}

// Force one corked application write to need readiness, without changing OpenSSL's real state.
// A read retry is injected after one full record, allowing the client to trigger peer readiness.
extern "C" int SSL_write(ssl_st* session, const void* buffer, int length) {
    static const auto real_write = next_symbol<decltype(&SSL_write)>("SSL_write");
    static const char* mode = std::getenv("WINLIN_TEST_CORK_RETRY");
    static std::atomic<bool> injected{};
    if (tls_retry.session == session) {
        if (!tls_retry.checked_wait || tls_retry.buffer != buffer || tls_retry.length != length) {
            std::fprintf(stderr, "Fatal winlin test shim error: TLS retry changed its buffer\n");
            std::_Exit(127);
        }
        if (tls_retry.client_put &&
            std::memcmp(tls_retry.saved_bytes.data(), buffer, length) != 0) {
            std::fprintf(stderr, "Fatal winlin test shim error: TLS PUT retry bytes changed\n");
            std::_Exit(127);
        }
        tls_retry.session = nullptr;
        std::fprintf(stderr, "winlin-test: preserved TLS retry buffer\n");
        return real_write(session, buffer, length);
    }
    // Observe actual application TLS submissions, not TCP packetization. One synthetic
    // WANT_WRITE verifies that the immutable combined prefix survives a readiness retry.
    static const char* put_size = std::getenv("WINLIN_TEST_TLS_PUT_SIZE");
    if (put_size && workload_socket(tls_descriptor(session))) {
        const std::string_view bytes(static_cast<const char*>(buffer), length);
        if (bytes.starts_with("PUT ")) {
            const auto boundary = bytes.find("\r\n\r\n");
            const auto size = std::strtoul(put_size, nullptr, 10);
            const auto total = boundary + 4 + size;
            if (boundary == std::string_view::npos ||
                static_cast<std::size_t>(length) != (total < 16384 ? total : 16384)) {
                std::fprintf(stderr,
                             "Fatal winlin test shim error: TLS PUT prefix is incomplete\n");
                std::_Exit(127);
            }
            static std::atomic<bool> checked{};
            if (!checked.exchange(true)) {
                std::fprintf(stderr, "winlin-test: verified combined TLS PUT prefix\n");
                tls_retry.session = session;
                tls_retry.buffer = buffer;
                tls_retry.length = length;
                tls_retry.fd = tls_descriptor(session);
                tls_retry.client_put = true;
                tls_retry.error = 3;
                std::memcpy(tls_retry.saved_bytes.data(), buffer, length);
                return -1;
            }
        }
    }
    if (!mode || injected.load()) {
        return real_write(session, buffer, length);
    }

    const int fd = tls_descriptor(session);
    int cork{};
    socklen_t option_length = sizeof(cork);
    if (getsockopt(fd, IPPROTO_TCP, TCP_CORK, &cork, &option_length) != 0) {
        std::perror("Fatal winlin test shim TLS cork query error");
        std::_Exit(127);
    }
    const bool read_wait = std::strcmp(mode, "read") == 0;
    if (cork && (!read_wait || tls_retry.large_write_completed) && !injected.exchange(true)) {
        tls_retry.session = session;
        tls_retry.buffer = buffer;
        tls_retry.length = length;
        tls_retry.fd = fd;
        tls_retry.read_wait = read_wait;
        // Public OpenSSL error codes: SSL_ERROR_WANT_READ=2 and SSL_ERROR_WANT_WRITE=3.
        tls_retry.error = read_wait ? 2 : 3;
        return -1;
    }
    const int result = real_write(session, buffer, length);
    if (cork && result == 16384) {
        tls_retry.large_write_completed = true;
    }
    return result;
}

// Translate only the synthetic failure; all real TLS outcomes retain OpenSSL's interpretation.
extern "C" int SSL_get_error(const ssl_st* session, int result) {
    static const auto real_error = next_symbol<decltype(&SSL_get_error)>("SSL_get_error");
    if (tls_retry.session == session && tls_retry.error) {
        const int error = tls_retry.error;
        tls_retry.error = 0;
        return error;
    }
    return real_error(session, result);
}

// Model a known CPU cost at workload teardown; final CPU samples must not include this cost.
extern "C" int close(int fd) {
    static const auto real_close = next_symbol<decltype(&close)>("close");
    static const bool inject = std::getenv("WINLIN_TEST_TEARDOWN_CPU") != nullptr;
    static const bool verify = std::getenv("WINLIN_TEST_VERIFY_SERVER_NODELAY") != nullptr;
    if (verify) {
        // Regular files and unrelated discovery sockets are expected here too. Only listener
        // ports owned by this test need the closing-socket check; listeners themselves are
        // uncorked.
        sockaddr_in local{};
        socklen_t length = sizeof(local);
        const int saved_errno = errno;
        if (getsockname(fd, reinterpret_cast<sockaddr*>(&local), &length) == 0 &&
            local.sin_family == AF_INET &&
            (local.sin_port == control_port.load() || local.sin_port == workload_port.load())) {
            verify_cork(fd, 0);
        }
        errno = saved_errno;
    }
    const bool workload = inject && workload_socket(fd);
    const int result = real_close(fd);
    if (workload && result == 0) {
        teardown_cpu_seconds.fetch_add(5);
        std::fprintf(stderr, "winlin-test: accounted teardown CPU\n");
    }
    return result;
}

// Add the synthetic teardown cost to actual CPU counters, preserving their monotonic semantics.
extern "C" int getrusage(int who, rusage* data) noexcept {
    static const auto real_usage = next_symbol<decltype(&getrusage)>("getrusage");
    const int result = real_usage(who, data);
    if (result == 0 && who == RUSAGE_SELF) {
        data->ru_utime.tv_sec += teardown_cpu_seconds.load();
    }
    return result;
}

// Leave one real worker alive, then force thread creation failure to exercise missing participants.
extern "C" int pthread_create(pthread_t* thread, const pthread_attr_t* attributes,
                              void* (*start)(void*), void* argument) noexcept {
    static const auto real_create = next_symbol<decltype(&pthread_create)>("pthread_create");
    static const bool inject = std::getenv("WINLIN_TEST_FAIL_THREAD_CREATE") != nullptr;
    static std::atomic<unsigned> attempts{};
    if (inject && attempts.fetch_add(1) == 1) {
        return EAGAIN;
    }
    return real_create(thread, attributes, start, argument);
}
