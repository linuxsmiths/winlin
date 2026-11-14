// Test-only syscall interposition. CTest preloads this library into its own child processes;
// no production executable links it or exposes these fault controls.
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

namespace {

std::atomic<long> teardown_cpu_seconds{};

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
    static std::atomic<int> control_listener{-1};
    static std::atomic<unsigned> control_attempts{}, workload_attempts{};
    if (inject) {
        int unset = -1;
        control_listener.compare_exchange_strong(unset, fd);
        auto& attempts = fd == control_listener.load() ? control_attempts : workload_attempts;
        const auto attempt = attempts.fetch_add(1);
        if (attempt < 2) {
            errno = attempt == 0 ? ECONNABORTED : EPROTO;
            return -1;
        }
    }
    return real_accept(fd, address, length, flags);
}

// Deliver an already-ready response only after its deadline has passed.
extern "C" int epoll_wait(int fd, epoll_event* events, int count, int timeout) {
    static const auto real_wait = next_symbol<decltype(&epoll_wait)>("epoll_wait");
    static const bool inject = std::getenv("WINLIN_TEST_LATE_READY") != nullptr;
    static std::atomic<bool> delayed{};
    const int result = real_wait(fd, events, count, timeout);
    if (inject) {
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
    static std::atomic<bool> delayed{};
    const auto result = real_recv(fd, buffer, length, flags);
    if (inject && result > 0 && workload_socket(fd) && !delayed.exchange(true)) {
        delay_response();
        std::fprintf(stderr, "winlin-test: delayed received response\n");
    }
    return result;
}

// Model a known CPU cost at workload teardown; final CPU samples must not include this cost.
extern "C" int close(int fd) {
    static const auto real_close = next_symbol<decltype(&close)>("close");
    static const bool inject = std::getenv("WINLIN_TEST_TEARDOWN_CPU") != nullptr;
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
