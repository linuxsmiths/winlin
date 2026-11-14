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
    std::string tls{"on"}, cipher{"TLS_AES_128_GCM_SHA256"};
    std::string get_response_data{"shared"};
    unsigned workers{8}, lease_seconds{300};

    // Reject unknown or out-of-range settings rather than silently changing the requested run.
    static BenchmarkOptions parse(const Json& value) {
        if (!value.is_object()) {
            throw std::invalid_argument("Benchmark settings must be a JSON object");
        }
        for (const auto& [key, ignored] : value.items()) {
            if (key != "tls" && key != "cipher" && key != "workers" && key != "lease_seconds" &&
                key != "get_response_data") {
                throw std::invalid_argument("Unknown benchmark setting: " + key);
            }
        }
        BenchmarkOptions result;
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
        result.workers = bounded("workers", result.workers, 256);
        result.lease_seconds = bounded("lease_seconds", result.lease_seconds, 604800);
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
