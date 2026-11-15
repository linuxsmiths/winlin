#pragma once

#include "winlin/core.hpp"

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace winlin {
// Describe only per-run tuning. Bind addresses, ports, certificates and OS permissions stay local.
struct BenchmarkOptions {
    std::string benchmark{"https"}, operation{"minimal-query"}, memory_touch{"none"};
    double duration{30};
    unsigned repetitions{3};
    unsigned threads{2};
    unsigned latency_sample_every{1024};
    int server_cpu{-1};
    std::size_t allocation_size{4096}, live_allocations{1};
    std::size_t region_size{64 * 1024 * 1024};
    std::string tls{"on"}, cipher{"TLS_AES_128_GCM_SHA256"};
    std::string get_response_data{"copy"};
    unsigned workers{8}, lease_seconds{300};

    // Reject unknown or out-of-range settings rather than silently changing the requested run.
    static BenchmarkOptions parse(const Json& value) {
        if (!value.is_object()) {
            throw std::invalid_argument("Benchmark settings must be a JSON object");
        }
        const auto benchmark = value.value("benchmark", std::string("https"));
        if (benchmark != "https" && benchmark != "context-switch" && benchmark != "syscall" &&
            benchmark != "allocation" && benchmark != "page-fault" &&
            benchmark != "thread-create" && benchmark != "lock-contention") {
            throw std::invalid_argument("Unknown benchmark: " + benchmark);
        }
        for (const auto& [key, ignored] : value.items()) {
            const bool common = key == "benchmark" || key == "workers" || key == "lease_seconds";
            const bool network = benchmark == "https" &&
                                 (key == "tls" || key == "cipher" || key == "get_response_data");
            const bool local =
                benchmark != "https" &&
                ((key == "duration" && benchmark != "page-fault") || key == "repetitions" ||
                 (key == "server_cpu" && benchmark != "allocation" &&
                  benchmark != "thread-create" && benchmark != "lock-contention") ||
                 (key == "operation" && benchmark == "syscall") ||
                 (key == "threads" && benchmark == "context-switch") ||
                 (benchmark == "allocation" &&
                  (key == "allocation_size" || key == "live_allocations" ||
                   key == "memory_touch")) ||
                 (benchmark == "page-fault" && key == "region_size") ||
                 (benchmark == "lock-contention" && key == "latency_sample_every"));
            if (!common && !network && !local) {
                throw std::invalid_argument("Unknown benchmark setting: " + key);
            }
        }
        BenchmarkOptions result;
        result.benchmark = benchmark;
        result.tls = value.value("tls", result.tls);
        result.cipher = value.value("cipher", result.cipher);
        result.get_response_data = value.value("get_response_data", result.get_response_data);
        auto bounded = [&](const char* key, unsigned fallback, unsigned maximum) {
            if (value.contains(key) && !value.at(key).is_number_integer()) {
                throw std::invalid_argument(std::string(key) + " must be an integer");
            }
            const auto number = value.value(key, static_cast<std::int64_t>(fallback));
            if (number < 1 || number > maximum) {
                throw std::invalid_argument(std::string(key) + " is outside supported limits");
            }
            return static_cast<unsigned>(number);
        };
        result.workers = bounded(
            "workers", benchmark == "https" || benchmark == "lock-contention" ? result.workers : 1,
            256);
        result.lease_seconds = bounded("lease_seconds", result.lease_seconds, 604800);
        if (benchmark != "https") {
            result.duration = value.value("duration", result.duration);
            result.repetitions = bounded("repetitions", result.repetitions, 1000);
            result.threads = bounded("threads", 2, 1024);
            if (result.threads < 2) {
                throw std::invalid_argument("Context-switch requires 2-1024 threads");
            }
            if (!std::isfinite(result.duration) || result.duration < 0.01 ||
                result.duration > 3600) {
                throw std::invalid_argument("Local benchmark duration must be 0.01-3600 seconds");
            }
            if (benchmark != "allocation" && benchmark != "lock-contention" &&
                result.workers != 1) {
                throw std::invalid_argument("This local benchmark uses one CPU/worker or pair");
            }
            if (value.contains("server_cpu")) {
                if (!value.at("server_cpu").is_number_integer()) {
                    throw std::invalid_argument("server_cpu must be an integer");
                }
                const auto cpu = value.at("server_cpu").get<std::int64_t>();
                if (cpu < 0 || cpu > 65535) {
                    throw std::invalid_argument("server_cpu is outside supported limits");
                }
                result.server_cpu = static_cast<int>(cpu);
            }
            result.operation = value.value("operation", result.operation);
            if (result.operation != "minimal-query") {
                throw std::invalid_argument("Only minimal-query is supported");
            }
            result.allocation_size = bounded("allocation_size", 4096, max_object_size);
            result.live_allocations = bounded("live_allocations", 1, 65536);
            result.memory_touch = value.value("memory_touch", result.memory_touch);
            result.region_size = bounded("region_size", 64 * 1024 * 1024, 1024 * 1024 * 1024);
            result.latency_sample_every = bounded("latency_sample_every", 1024, 1048576);
            if (result.memory_touch != "none" && result.memory_touch != "pages") {
                throw std::invalid_argument("memory_touch must be none or pages");
            }
            if (benchmark == "allocation" &&
                result.allocation_size * result.live_allocations * result.workers >
                    std::size_t{1024} * 1024 * 1024) {
                throw std::invalid_argument("Allocation live working set exceeds 1 GiB");
            }
            return result;
        }
        if (result.tls != "on" && result.tls != "off" && result.tls != "ktls") {
            throw std::invalid_argument("TLS mode must be on, off, or ktls");
        }
        if (result.get_response_data != "shared" && result.get_response_data != "copy") {
            throw std::invalid_argument("GET response data mode must be shared or copy");
        }
        if (result.tls == "off") {
            result.cipher.clear();
        }
        return result;
    }

    // Return the settings actually used by the workload adapter, never a credential.
    Json json() const {
        if (benchmark != "https") {
            Json result{{"benchmark", benchmark},
                        {"repetitions", repetitions},
                        {"workers", workers}};
            if (benchmark != "page-fault") {
                result["duration"] = duration;
            } else {
                result["region_size"] = region_size;
            }
            if (benchmark == "allocation") {
                result["allocation_size"] = allocation_size;
                result["live_allocations"] = live_allocations;
                result["memory_touch"] = memory_touch;
            } else if (benchmark == "lock-contention") {
                result["latency_sample_every"] = latency_sample_every;
            } else if (benchmark != "thread-create") {
                if (benchmark == "context-switch") {
                    result["threads"] = threads;
                }
                result["server_cpu"] = server_cpu < 0 ? Json(nullptr) : Json(server_cpu);
                if (benchmark == "syscall") {
                    result["operation"] = operation;
                }
            }
            return result;
        }
        return {{"tls", tls},
                {"cipher", tls == "off" ? Json(nullptr) : Json(cipher)},
                {"get_response_data", get_response_data},
                {"workers", workers}};
    }
};

// Give the controller ownership of one native workload runtime. Destruction must stop and join
// all its workers before releasing the listener; describe() is called only after it is ready.
class BenchmarkInstance {
public:
    virtual ~BenchmarkInstance() = default;
    virtual Json describe() const = 0;
    virtual Json telemetry() const = 0;
};

// Preserve protocol error statuses across native adapters without logging run IDs or bodies.
class BenchmarkError : public std::runtime_error {
public:
    int status;

    BenchmarkError(int code, std::string message)
        : std::runtime_error(std::move(message)), status(code) {
    }
};

// Serialize run ownership across control workers. A bounded lease releases abandoned workloads;
// its opaque ID also gates data traffic and is never part of a saved benchmark report.
class BenchmarkController {
    std::mutex mutex_;
    std::condition_variable wake_;
    bool stopping_{};
    std::unique_ptr<BenchmarkInstance> active_;
    std::string id_;
    Clock::time_point deadline_;
    unsigned lease_seconds_{};
    std::function<std::string()> issue_id_;
    std::function<std::unique_ptr<BenchmarkInstance>(const BenchmarkOptions&, const std::string&)>
        factory_;
    std::jthread reaper_;

    // Only the lease owner may sample or stop a live workload.
    void require_owner(std::string_view id) const {
        if (!active_ || id != id_) {
            throw BenchmarkError(409,
                                 "Benchmark lease is absent, expired, or owned by another run");
        }
    }

public:
    BenchmarkController(std::function<std::string()> issue_id,
                        std::function<std::unique_ptr<BenchmarkInstance>(const BenchmarkOptions&,
                                                                         const std::string&)>
                            factory)
        : issue_id_(std::move(issue_id)), factory_(std::move(factory)), reaper_([this] {
              std::unique_lock lock(mutex_);
              while (!stopping_) {
                  wake_.wait_for(lock, std::chrono::seconds(1));
                  if (active_ && Clock::now() >= deadline_) {
                      log_warning("Benchmark lease expired; stopping abandoned workload");
                      active_.reset();
                      id_.clear();
                  }
              }
          }) {
    }

    // Join the reaper before member teardown; destroying the active runtime joins its workers.
    ~BenchmarkController() {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        wake_.notify_all();
        reaper_.join();
        active_.reset();
    }

    // Acquire ownership before creating listeners. Factory failures leave no partial active run.
    Json start(const Json& settings) {
        const auto options = BenchmarkOptions::parse(settings);
        std::lock_guard lock(mutex_);
        if (active_) {
            throw BenchmarkError(409, "A benchmark is already active on this server");
        }
        auto id = issue_id_();
        auto instance = factory_(options, id);
        auto result = instance->describe();
        result["settings"] = options.json();
        result["run_id"] = id;
        id_ = std::move(id);
        active_ = std::move(instance);
        lease_seconds_ = options.lease_seconds;
        deadline_ = Clock::now() + std::chrono::seconds(options.lease_seconds);
        return result;
    }

    // Sample only the active workload's counters; process CPU still includes control overhead.
    Json telemetry(std::string_view id) {
        std::lock_guard lock(mutex_);
        require_owner(id);
        auto result = active_->telemetry();
        deadline_ = Clock::now() + std::chrono::seconds(lease_seconds_);
        return result;
    }

    // Snapshot before teardown, then release ownership only after all native workers are joined.
    Json stop(std::string_view id) {
        std::lock_guard lock(mutex_);
        require_owner(id);
        auto instance = std::move(active_);
        id_.clear();
        auto final = instance->telemetry();
        instance.reset();
        return final;
    }
};
}
