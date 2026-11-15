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

// Each region is untouched until the measured pass and released only after final samples.
// Validate the actual writes at release, plus page/fault counts and failure cleanup.
void test_page_faults() {
    auto native = native_operations();
    const auto reserve = native.reserve_commit;
    const auto release = native.release_region;
    const auto host = native.host;
    unsigned regions{}, releases{}, samples{};
    bool allocated{};
    native.reserve_commit = [&](std::size_t size) {
        require(!allocated, "A fresh region must replace the released previous one");
        auto* region = reserve(size);
        allocated = true;
        ++regions;
        return region;
    };
    native.release_region = [&](void* region, std::size_t size) {
        auto* bytes = static_cast<volatile unsigned char*>(region);
        bool correct = true;
        for (std::size_t offset = 0; offset < size; offset += native.page_size) {
            correct = correct && bytes[offset] == 1;
        }
        release(region, size);
        allocated = false;
        ++releases;
        require(correct, "Every base page must receive its first-touch write");
    };
    native.host = [&] {
        require(allocated, "Both CPU samples must precede region release and follow setup");
        ++samples;
        return host();
    };
    {
        LocalBenchmark benchmark(
            BenchmarkOptions::parse(
                {{"benchmark", "page-fault"}, {"region_size", 1048576}, {"repetitions", 2}}),
            native);
        const auto sample = finish(benchmark);
        require(sample.at("status") == "completed", sample.dump().c_str());
        require(sample.at("results").size() == 2, "Each fresh-region pass needs a result");
        for (const auto& result : sample.at("results")) {
            require(result.at("operations").get<std::size_t>() == 1048576 / native.page_size,
                    "First-touch operation counts are base pages, not inferred fault counts");
            require(result.at("observed_page_faults").at("total").is_number(),
                    "Native process page-fault observations must be reported");
#ifndef _WIN32
            require(result.at("observed_page_faults").at("minor").get<std::uint64_t>() >=
                        result.at("operations").get<std::uint64_t>(),
                    "Linux anonymous base pages must fault inside the measured pass");
#else
            require(result.at("observed_page_faults").at("minor").is_null() &&
                        result.at("observed_page_faults").at("major").is_null(),
                    "Windows unavailable fault classifications must remain unavailable");
#endif
        }
    }
    require(regions == 3 && releases == 3 && samples == 4,
            "Warmup and measured regions must all be released outside CPU sampling");
    try {
        LocalBenchmark unaligned(BenchmarkOptions::parse({{"benchmark", "page-fault"},
                                                          {"region_size", native.page_size + 1}}),
                                 native);
        throw std::runtime_error("Unaligned native-page region was accepted");
    } catch (const std::invalid_argument&) {
    }
    for (const auto& settings : {Json{{"benchmark", "page-fault"}, {"duration", 10}},
                                 Json{{"benchmark", "page-fault"}, {"region_size", 0}},
                                 Json{{"benchmark", "page-fault"}, {"region_size", 1073741825}}}) {
        try {
            BenchmarkOptions::parse(settings);
            throw std::runtime_error("Invalid page-fault settings were accepted");
        } catch (const std::invalid_argument&) {
        }
    }
    native = native_operations();
    native.reserve_commit = [](std::size_t) -> void* {
        throw std::runtime_error("injected region setup failure");
    };
    {
        LocalBenchmark failed(BenchmarkOptions::parse({{"benchmark", "page-fault"}}), native);
        require(finish(failed).at("status") == "failed",
                "Failed setup must not become a successful pass");
    }

    // A later release failure must retain completed passes and mark the run incomplete.
    native = native_operations();
    releases = 0;
    native.release_region = [&](void* region, std::size_t size) {
        release(region, size);
        if (++releases == 3) {
            throw std::runtime_error("injected region release failure");
        }
    };
    {
        LocalBenchmark failed(
            BenchmarkOptions::parse(
                {{"benchmark", "page-fault"}, {"region_size", 1048576}, {"repetitions", 2}}),
            native);
        const auto sample = finish(failed);
        require(sample.at("status") == "failed" && sample.at("results").size() == 1 &&
                    sample.at("failure") == "injected region release failure",
                "Release failure must reach the client without discarding earlier passes");
    }

    // Failed boundary sampling must still start/unblock the worker and release its region.
    native = native_operations();
    releases = 0;
    native.host = []() -> Json {
        throw std::runtime_error("injected page CPU sampling failure");
    };
    native.release_region = [&](void* region, std::size_t size) {
        release(region, size);
        ++releases;
    };
    {
        LocalBenchmark failed(
            BenchmarkOptions::parse({{"benchmark", "page-fault"}, {"region_size", 1048576}}),
            native);
        require(finish(failed).at("status") == "failed",
                "Boundary sampling failure must not produce a completed pass");
    }
    require(releases == 2, "Failed sampling must release warmup and measured regions");

    // Cancel while a region is being prepared; joining must still release every allocation.
    native = native_operations();
    regions = releases = 0;
    std::latch region_ready(1), allow_start(1), cancelling(1);
    native.reserve_commit = [&](std::size_t size) {
        auto* region = reserve(size);
        if (++regions == 1) {
            region_ready.count_down();
        }
        allow_start.wait();
        return region;
    };
    native.release_region = [&](void* region, std::size_t size) {
        release(region, size);
        ++releases;
    };
    auto cancelled = std::make_unique<LocalBenchmark>(
        BenchmarkOptions::parse({{"benchmark", "page-fault"}, {"region_size", 1048576}}), native);
    region_ready.wait();
    std::jthread cancellation([&] {
        cancelling.count_down();
        cancelled.reset();
    });
    cancelling.wait();
    allow_start.count_down();
    cancellation.join();
    require(regions == releases, "Page-fault cancellation must release all prepared regions");
}
}

// Native local tests need no listeners, credentials, or exclusive HTTP server guard.
int main() {
    try {
        test_workloads();
        test_failures();
        test_page_faults();
        std::cout << "Native local benchmark tests passed\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Local tests: FATAL: " << exception.what() << '\n';
        return 1;
    }
}
