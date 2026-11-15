#ifdef _WIN32
#include "winlin/local_windows.hpp"
#else
#include "winlin/local_linux.hpp"
#endif

#include <iostream>

namespace {
using namespace winlin;

// Fail native workload regressions explicitly rather than hiding unavailable operations.
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// Use the actual native query and affinity operations, not a userspace timing substitute.
LocalOperations native_operations() {
#ifdef _WIN32
    return windows_local_operations();
#else
    return linux_local_operations();
#endif
}

// Poll completed stages under their snapshot mutex, with a bounded wait for worker failures.
Json finish(LocalBenchmark& benchmark) {
    const auto deadline = Clock::now() + std::chrono::seconds(10);
    while (Clock::now() < deadline) {
        const auto sample = benchmark.telemetry();
        if (sample.at("status") != "running") {
            return sample;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    throw std::runtime_error("Local benchmark did not finish");
}

// Check real same-CPU handoffs, native syscalls, and allocation/free pairs across repetitions.
void test_workloads() {
    auto native = native_operations();
    for (const auto& [name, touch] :
         {std::pair{"context-switch", "none"}, std::pair{"syscall", "none"},
          std::pair{"allocation", "none"}, std::pair{"allocation", "pages"}}) {
        auto options =
            BenchmarkOptions::parse({{"benchmark", name}, {"duration", 0.02}, {"repetitions", 2}});
        if (options.benchmark == "allocation") {
            options.workers = 2;
            options.memory_touch = touch;
            options.live_allocations = 8;
        }
        LocalBenchmark benchmark(options, native);
        const auto sample = finish(benchmark);
        require(sample.at("status") == "completed", sample.dump().c_str());
        require(sample.at("results").size() == 2, "Each repetition needs a result");
        for (const auto& result : sample.at("results")) {
            require(result.at("operations").get<std::uint64_t>() > 0 &&
                        result.at("operations_per_second").get<double>() > 0 &&
                        result.at("mean_operation_ns").get<double>() > 0,
                    "Real operations must produce positive throughput and amortized latency");
            if (options.benchmark == "context-switch") {
                require(result.at("operations").get<std::uint64_t>() ==
                            2 * result.at("round_trips").get<std::uint64_t>(),
                        "Each ping-pong round trip counts exactly two directed handoffs");
            }
        }
    }
}

// Invalid settings and worker failures must surface and unblock all participants, not hang.
void test_failures() {
    for (const auto& value : {Json{{"benchmark", "syscall"}, {"tls", "on"}},
                              Json{{"benchmark", "context-switch"}, {"workers", 2}},
                              Json{{"benchmark", "allocation"},
                                   {"allocation_size", 67108864},
                                   {"live_allocations", 65536}},
                              Json{{"benchmark", "syscall"}, {"server_cpu", -1}},
                              Json{{"benchmark", "allocation"}, {"memory_touch", "unknown"}}}) {
        try {
            BenchmarkOptions::parse(value);
            throw std::runtime_error("Invalid local settings were accepted");
        } catch (const std::invalid_argument&) {
        }
    }
    auto native = native_operations();
    native.query = [] {
        throw std::runtime_error("injected native query failure");
    };
    {
        LocalBenchmark benchmark(
            BenchmarkOptions::parse({{"benchmark", "syscall"}, {"duration", 0.02}}), native);
        const auto sample = finish(benchmark);
        require(sample.at("status") == "failed" &&
                    sample.at("failure") == "injected native query failure",
                "A worker failure must reach the controlling client");
    }
    native.bind_cpu = [](unsigned) {
        throw std::runtime_error("injected affinity failure");
    };
    {
        LocalBenchmark benchmark(
            BenchmarkOptions::parse({{"benchmark", "context-switch"}, {"duration", 0.02}}), native);
        require(finish(benchmark).at("status") == "failed",
                "A failed ping-pong participant must unblock its peer");
    }
    // Destroying an active run must wake waits and join, even during warmup/setup.
    native = native_operations();
    LocalBenchmark cancelled(
        BenchmarkOptions::parse({{"benchmark", "context-switch"}, {"duration", 30}}), native);
}
}

// Native local tests need no listeners, credentials, or exclusive HTTP server guard.
int main() {
    try {
        test_workloads();
        test_failures();
        std::cout << "Native local benchmark tests passed\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Local tests: FATAL: " << exception.what() << '\n';
        return 1;
    }
}
