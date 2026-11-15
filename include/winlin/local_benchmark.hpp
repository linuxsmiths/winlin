#pragma once

#include "winlin/benchmark.hpp"
#include "winlin/cpu.hpp"

#include <cstdlib>
#include <atomic>
#include <latch>
#include <numeric>

namespace winlin {
// Supply native operations to the shared local workload. Affinity resolves a default allowed CPU
// or validates an explicit one before workers start; bind_cpu must fail rather than run unpinned.
// The query must enter the kernel, check its native error, and not print identifiers.
struct LocalOperations {
    std::function<unsigned(int)> resolve_cpu;
    std::function<void(unsigned)> bind_cpu;
    std::function<void()> query;
    std::function<Json()> host;
    std::function<Json()> process;
    std::function<void*(std::size_t)> reserve_commit;
    std::function<void(void*, std::size_t)> release_region;
    std::function<Json()> page_faults;
    Json environment;
    std::string syscall_name;
    std::string memory_backend;
    std::size_t page_size{};
};

// Own a server-local run under the ordinary exclusive benchmark lease. One coordinator executes
// warmup/repetitions and publishes immutable completed results under a mutex. Native workers own
// their counters and allocation storage; control polling never enters the measured hot loop.
// Destruction requests cancellation, wakes blocked ping-pong threads, and joins the coordinator,
// which joins all its workers. Both platforms use the same workload and accounting definitions.
class LocalBenchmark final : public BenchmarkInstance {
    BenchmarkOptions options_;
    LocalOperations native_;
    unsigned cpu_{};
    std::atomic<bool> stop_{};
    std::atomic<bool> cancelled_{};
    std::mutex handoff_mutex_;
    std::condition_variable handoff_;
    mutable std::mutex results_mutex_;
    Json results_ = Json::array();
    std::string status_{"running"}, failure_;
    std::jthread coordinator_;

    // Execute one stage. Workers finish setup before the boundary and park after their last
    // operation until telemetry is captured, keeping thread teardown outside CPU sampling.
    Json stage(double duration, bool measure) {
        const unsigned count = options_.benchmark == "context-switch" ? 2 : options_.workers;
        std::latch ready(count), start(1), finished(count), release(1);
        std::vector<std::jthread> workers;
        std::vector<std::uint64_t> operations(count);
        std::vector<double> worker_seconds(count);
        std::mutex error_mutex;
        std::string error;
        std::atomic<bool> failed{};
        bool turn{}, done{};
        Clock::time_point begin;
        // Retain the first worker error and wake a peer that might otherwise block forever.
        const auto fail = [&](const std::exception& exception) {
            {
                std::lock_guard lock(error_mutex);
                if (error.empty()) {
                    error = exception.what();
                }
            }
            {
                std::lock_guard lock(handoff_mutex_);
                failed = true;
            }
            handoff_.notify_all();
        };
        try {
            for (unsigned index = 0; index < count; ++index) {
                workers.emplace_back([&, index] {
                    std::vector<void*> blocks;
                    void* region{};
                    try {
                        if (options_.benchmark != "allocation") {
                            native_.bind_cpu(cpu_);
                        } else {
                            blocks.resize(options_.live_allocations);
                        }
                        if (options_.benchmark == "page-fault") {
                            // Address reservation and commitment are outside every measured
                            // boundary; each repetition receives a fresh, untouched region.
                            region = native_.reserve_commit(options_.region_size);
                        }
                    } catch (const std::exception& exception) {
                        fail(exception);
                    }
                    ready.count_down();
                    start.wait();
                    const auto worker_begin = Clock::now();
                    std::uint64_t completed{};
                    // Amortize clock checks for tiny allocations, but avoid processing hundreds
                    // of large live sets before honoring the time limit or cancellation.
                    const auto allocation_batches = std::max<std::size_t>(
                        1, std::min(std::size_t{256} / options_.live_allocations,
                                    std::size_t{65536} /
                                        (options_.allocation_size * options_.live_allocations)));
                    const auto deadline = begin + std::chrono::duration<double>(duration);
                    try {
                        if (options_.benchmark == "page-fault") {
                            if (!failed) {
                                // A volatile write faults in each ordinary base page exactly
                                // once. Cancellation checks are batched; no per-page timer is used.
                                auto* bytes = static_cast<volatile unsigned char*>(region);
                                for (std::size_t offset = 0; offset < options_.region_size;
                                     offset += native_.page_size) {
                                    if ((completed % 256) == 0 && stop_) {
                                        break;
                                    }
                                    bytes[offset] = 1;
                                    ++completed;
                                }
                            }
                        } else if (options_.benchmark == "context-switch") {
                            // A mutex/condition-variable handoff blocks instead of spinning.
                            // Both threads share one logical CPU; only thread zero counts a
                            // completed round trip (two directed handoffs).
                            std::unique_lock lock(handoff_mutex_);
                            if (index == 0) {
                                while (!stop_ && !failed && Clock::now() < deadline) {
                                    turn = true;
                                    handoff_.notify_one();
                                    handoff_.wait(lock, [&] {
                                        return !turn || stop_ || failed;
                                    });
                                    if (!stop_ && !failed) {
                                        completed += 2;
                                    }
                                }
                                done = true;
                                handoff_.notify_all();
                            } else {
                                for (;;) {
                                    handoff_.wait(lock, [&] {
                                        return turn || done || stop_ || failed;
                                    });
                                    if (done || stop_ || failed) {
                                        break;
                                    }
                                    turn = false;
                                    handoff_.notify_one();
                                }
                            }
                        } else {
                            // Check time/cancellation between batches, not around every operation.
                            // The batch's loop/control overhead remains part of this measurement.
                            while (!stop_ && !failed && Clock::now() < deadline) {
                                if (options_.benchmark == "syscall") {
                                    for (unsigned call = 0; call < 256; ++call) {
                                        native_.query();
                                        ++completed;
                                    }
                                } else {
                                    // Retain a batch of real allocations before freeing it, so
                                    // allocator calls cannot collapse to an unused malloc/free.
                                    for (std::size_t batch = 0; batch < allocation_batches;
                                         ++batch) {
                                        for (auto& block : blocks) {
                                            block = std::malloc(options_.allocation_size);
                                            if (!block) {
                                                throw std::runtime_error("Allocation failed");
                                            }
                                            if (options_.memory_touch == "pages") {
                                                auto* bytes =
                                                    static_cast<volatile unsigned char*>(block);
                                                for (std::size_t offset = 0;
                                                     offset < options_.allocation_size;
                                                     offset += native_.page_size) {
                                                    bytes[offset] = 1;
                                                }
                                                bytes[options_.allocation_size - 1] = 1;
                                            }
                                        }
                                        for (auto& block : blocks) {
                                            std::free(block);
                                            block = nullptr;
                                            ++completed;
                                        }
                                    }
                                }
                            }
                        }
                    } catch (const std::exception& exception) {
                        fail(exception);
                    }
                    worker_seconds[index] =
                        std::chrono::duration<double>(Clock::now() - worker_begin).count();
                    operations[index] = completed;
                    finished.count_down();
                    release.wait();
                    // Free partial batches only after sampling; failed pairs are not counted.
                    for (auto* block : blocks) {
                        std::free(block);
                    }
                    if (region) {
                        try {
                            native_.release_region(region, options_.region_size);
                        } catch (const std::exception& exception) {
                            fail(exception);
                        }
                    }
                });
            }
        } catch (...) {
            {
                std::lock_guard lock(handoff_mutex_);
                stop_ = true;
            }
            handoff_.notify_all();
            start.count_down();
            release.count_down();
            workers.clear();
            throw;
        }
        ready.wait();
        Json before, process_before, after, process_after, faults_before, faults_after;
        try {
            if (measure) {
                process_before = native_.process();
                if (options_.benchmark == "page-fault") {
                    faults_before = native_.page_faults();
                }
                before = native_.host();
            }
            begin = Clock::now();
            start.count_down();
            finished.wait();
            const auto elapsed = std::chrono::duration<double>(Clock::now() - begin).count();
            if (measure) {
                after = native_.host();
                if (options_.benchmark == "page-fault") {
                    faults_after = native_.page_faults();
                }
                process_after = native_.process();
            }
            release.count_down();
            workers.clear();
            if (!error.empty()) {
                throw std::runtime_error(error);
            }
            if (stop_) {
                throw std::runtime_error("Local benchmark stopped before completion");
            }
            const auto total =
                std::accumulate(operations.begin(), operations.end(), std::uint64_t{});
            if (!total) {
                throw std::runtime_error("Local benchmark completed no operations");
            }
            const auto host = measure ? host_usage_delta(before, after) : Json::object();
            Json cycles = nullptr;
            if (measure && host.at("reference_cycles").is_number()) {
                cycles = host.at("reference_cycles").get<double>() / total;
            }
            double seconds =
                options_.benchmark == "context-switch"
                    ? worker_seconds[0]
                    : std::accumulate(worker_seconds.begin(), worker_seconds.end(), 0.0);
            Json result{{"operations", total},
                        {"elapsed_seconds", elapsed},
                        {"operations_per_second", total / elapsed},
                        {"mean_operation_ns", seconds * 1e9 / total},
                        {"reference_cycles_per_operation", cycles},
                        {"server_host", host},
                        {"server_process_before", process_before},
                        {"server_process_after", process_after},
                        {"errors", 0},
                        {"scheduler_context_switches", nullptr},
                        {"scheduler_context_switches_per_second", nullptr}};
            // Process context-switch counters are not exact pair-only counts: control activity
            // also contributes. Never substitute handoffs for unavailable scheduler counters.
            if (measure &&
                process_before.value("voluntary_context_switches", Json(nullptr)).is_number() &&
                process_after.value("voluntary_context_switches", Json(nullptr)).is_number() &&
                process_before.value("involuntary_context_switches", Json(nullptr)).is_number() &&
                process_after.value("involuntary_context_switches", Json(nullptr)).is_number()) {
                const auto delta =
                    process_after.at("voluntary_context_switches").get<std::int64_t>() -
                    process_before.at("voluntary_context_switches").get<std::int64_t>() +
                    process_after.at("involuntary_context_switches").get<std::int64_t>() -
                    process_before.at("involuntary_context_switches").get<std::int64_t>();
                if (delta < 0) {
                    throw std::runtime_error("Process context-switch counters decreased");
                }
                result["scheduler_context_switches"] = delta;
                result["scheduler_context_switches_per_second"] = delta / elapsed;
            }
            if (options_.benchmark == "context-switch") {
                result["round_trips"] = total / 2;
                result["mean_round_trip_ns"] = seconds * 1e9 / (total / 2);
            }
            if (options_.benchmark == "page-fault") {
                result["region_size_bytes"] = options_.region_size;
                result["native_page_size_bytes"] = native_.page_size;
                result["observed_page_faults"] = Json::object();
                for (const auto* key : {"total", "minor", "major"}) {
                    Json delta = nullptr;
                    if (measure && faults_before.value(key, Json(nullptr)).is_number() &&
                        faults_after.value(key, Json(nullptr)).is_number()) {
                        const auto count = faults_after.at(key).get<std::int64_t>() -
                                           faults_before.at(key).get<std::int64_t>();
                        if (count < 0) {
                            throw std::runtime_error("Native page-fault counters decreased");
                        }
                        delta = count;
                    }
                    result["observed_page_faults"][key] = delta;
                }
                result["page_fault_counter_scope"] = "server process, including control threads";
            }
            return result;
        } catch (...) {
            {
                std::lock_guard lock(handoff_mutex_);
                stop_ = true;
            }
            handoff_.notify_all();
            // If sampling failed before start, workers still need both gates released.
            if (!start.try_wait()) {
                start.count_down();
            }
            if (!release.try_wait()) {
                release.count_down();
            }
            workers.clear();
            throw;
        }
    }

    // Warm once, then preserve each completed repetition even if a later one fails.
    void execute() noexcept {
        try {
            if (options_.benchmark == "page-fault") {
                stage(0, false);
            } else {
                stage(2, false);
            }
            for (unsigned repetition = 1; repetition <= options_.repetitions; ++repetition) {
                auto result = stage(options_.duration, true);
                result["repetition"] = repetition;
                std::lock_guard lock(results_mutex_);
                results_.push_back(std::move(result));
            }
            std::lock_guard lock(results_mutex_);
            status_ = "completed";
        } catch (const std::exception& exception) {
            std::lock_guard lock(results_mutex_);
            status_ = cancelled_ ? "interrupted" : "failed";
            failure_ = exception.what();
            log_warning("Local benchmark incomplete: " + failure_);
        }
    }

public:
    // Validate native hooks and resolve affinity before publishing the leased runtime.
    LocalBenchmark(BenchmarkOptions options, LocalOperations native)
        : options_(std::move(options)), native_(std::move(native)) {
        if (!native_.page_size) {
            throw std::invalid_argument("Native page size is unavailable");
        }
        if (options_.benchmark != "allocation") {
            cpu_ = native_.resolve_cpu(options_.server_cpu);
        }
        if (options_.benchmark == "page-fault") {
            if (options_.region_size % native_.page_size != 0) {
                throw std::invalid_argument(
                    "Page-fault region must be a multiple of native page size");
            }
            if (!native_.reserve_commit || !native_.release_region || !native_.page_faults) {
                throw std::invalid_argument("Native page-fault operations are unavailable");
            }
        }
        coordinator_ = std::jthread([this] {
            execute();
        });
    }

    // Stop only this run, unblock its peer, and join every native thread before lease release.
    ~LocalBenchmark() override {
        {
            std::lock_guard lock(handoff_mutex_);
            cancelled_ = true;
            stop_ = true;
        }
        handoff_.notify_all();
        coordinator_.join();
    }

    // Describe operation semantics and platform differences without exposing the run bearer.
    Json describe() const override {
        return {
            {"benchmark", options_.benchmark},
            {"transport", "server-local"},
            {"operation_unit", options_.benchmark == "context-switch" ? "directed handoff"
                               : options_.benchmark == "allocation"   ? "allocation/free pair"
                               : options_.benchmark == "page-fault"   ? "first-touch base page"
                                                                      : "native kernel query"},
            {"server_cpu", options_.benchmark == "allocation" ? Json(nullptr) : Json(cpu_)},
            {"native_syscall",
             options_.benchmark == "syscall" ? Json(native_.syscall_name) : Json(nullptr)},
            {"environment", native_.environment},
            {"warmup_seconds", options_.benchmark == "page-fault" ? Json(nullptr) : Json(2)},
            {"warmup_regions", options_.benchmark == "page-fault" ? Json(1) : Json(nullptr)},
            {"execution_threads", options_.benchmark == "context-switch" ? 2 : options_.workers},
            {"native_page_size_bytes", native_.page_size},
            {"memory_backend",
             options_.benchmark == "page-fault" ? Json(native_.memory_backend) : Json(nullptr)},
            {"measurement_scope", options_.benchmark == "page-fault"
                                      ? "One fresh region: first write per base page; reserve, "
                                        "commit, and release excluded"
                                      : "Timed operation loop"},
            {"notes",
             {"Batch/loop and synchronization overhead is included.",
              "Mean operation latency is amortized, not a percentile distribution.",
              "Whole-server reference cycles include unrelated OS work; use an idle host.",
              "First-touch page counts are not observed faults; fault counters include control "
              "activity and short passes suffer CPU sample granularity.",
              "Scheduler counts are process-wide, including control activity; null means "
              "unavailable.",
              "Workers are recreated outside sampling for each stage; allocator thread caches may "
              "be cold.",
              "Allocation measures the reported build allocator, not OS overhead alone.",
              "Minimal native queries have different kernel work on Linux and Windows."}}};
    }

    // Polling reads only completed results; no worker-owned hot counters are sampled mid-stage.
    Json telemetry() const override {
        std::lock_guard lock(results_mutex_);
        return {{"status", status_},
                {"results", results_},
                {"failure", failure_.empty() ? Json(nullptr) : Json(failure_)}};
    }
};
}
