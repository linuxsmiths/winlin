#pragma once

#include "winlin/core.hpp"

#include <thread>

#if defined(_M_X64) || defined(__x86_64__)
#ifdef _MSC_VER
#include <intrin.h>
#include <immintrin.h>
#else
#include <cpuid.h>
#include <x86intrin.h>
#endif
#endif

namespace winlin {
#if defined(_M_X64) || defined(__x86_64__)
// Query TSC feature bits identically on MSVC and GCC/Clang, without OS frequency files.
inline std::array<unsigned, 4> tsc_cpuid(unsigned leaf) {
#ifdef _MSC_VER
    int registers[4]{};
    __cpuidex(registers, static_cast<int>(leaf), 0);
    return {static_cast<unsigned>(registers[0]), static_cast<unsigned>(registers[1]),
            static_cast<unsigned>(registers[2]), static_cast<unsigned>(registers[3])};
#else
    std::array<unsigned, 4> registers{};
    __cpuid_count(leaf, 0, registers[0], registers[1], registers[2], registers[3]);
    return registers;
#endif
}

// Bound timestamp reads against instruction reordering and identify migration during calibration.
inline std::pair<std::uint64_t, unsigned> reference_timestamp() {
    unsigned processor{};
    _mm_lfence();
    const auto ticks = __rdtscp(&processor);
    _mm_lfence();
    return {ticks, processor};
}
#endif

// Calibrate once outside measurement. The immutable result is shared safely by all server threads.
// Only an invariant x86_64 TSC is accepted; unsupported or unstable clocks remain explicitly
// absent.
inline const Json& reference_clock() {
    static const Json clock = [] {
        Json result{{"source", "invariant TSC calibrated against std::chrono::steady_clock"},
                    {"frequency_hz", nullptr},
                    {"calibration_seconds", nullptr},
                    {"calibration_samples", 0},
                    {"unavailable_reason", nullptr}};
#if defined(_M_X64) || defined(__x86_64__)
        if (tsc_cpuid(0)[0] < 1 || !(tsc_cpuid(1)[3] & (1u << 4)) ||
            tsc_cpuid(0x80000000)[0] < 0x80000007 || !(tsc_cpuid(0x80000001)[3] & (1u << 27)) ||
            !(tsc_cpuid(0x80000007)[3] & (1u << 8))) {
            result["unavailable_reason"] = "An invariant TSC with RDTSCP support is required";
            return result;
        }

        const auto started = Clock::now();
        std::vector<double> frequencies;
        // Sleep avoids calibration CPU load; actual monotonic time accounts for oversleeping.
        // Reject migrations and require three agreeing samples, tolerating scheduling outliers.
        for (unsigned attempt = 0; attempt < 10 && frequencies.size() < 5; ++attempt) {
            const auto before = Clock::now();
            const auto [first, first_cpu] = reference_timestamp();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            const auto [last, last_cpu] = reference_timestamp();
            const auto elapsed = std::chrono::duration<double>(Clock::now() - before).count();
            if (first_cpu == last_cpu && last > first && elapsed > 0) {
                frequencies.push_back(static_cast<double>(last - first) / elapsed);
            }
        }
        result["calibration_seconds"] =
            std::chrono::duration<double>(Clock::now() - started).count();
        if (frequencies.size() < 3) {
            result["unavailable_reason"] =
                "TSC calibration could not obtain three same-CPU samples";
            return result;
        }
        std::sort(frequencies.begin(), frequencies.end());
        const auto median = frequencies[frequencies.size() / 2];
        const auto stable = std::count_if(frequencies.begin(), frequencies.end(), [&](double hz) {
            return std::abs(hz / median - 1) <= .01;
        });
        if (!std::isfinite(median) || median <= 0 || stable < 3) {
            result["unavailable_reason"] = "TSC calibration samples disagreed by more than 1%";
            return result;
        }
        result["frequency_hz"] = median;
        result["calibration_samples"] = stable;
#else
        result["unavailable_reason"] = "Reference CPIO currently requires an invariant x86_64 TSC";
#endif
        return result;
    }();
    return clock;
}

// Native adapters provide cumulative whole-OS busy CPU seconds, including all logical CPUs.
// Counter failures degrade only this metric; the client reports the reason without inventing zero.
template <typename Sampler> inline Json sample_host_cpu(std::string_view source, Sampler sample) {
    Json result{{"scope", "whole server OS; all logical CPUs, including unrelated workloads"},
                {"cpu_time_source", source},
                {"busy_cpu_seconds", nullptr},
                {"sampled_at_monotonic_seconds", nullptr},
                {"cpu_time_unavailable_reason", nullptr},
                {"reference_clock", reference_clock()}};
    try {
        const auto busy = sample();
        if (!std::isfinite(busy) || busy < 0) {
            throw std::runtime_error("Invalid whole-server busy CPU time");
        }
        result["busy_cpu_seconds"] = busy;
    } catch (const std::exception& error) {
        result["cpu_time_unavailable_reason"] = error.what();
    }
    result["sampled_at_monotonic_seconds"] =
        std::chrono::duration<double>(Clock::now().time_since_epoch()).count();
    return result;
}

// Attribute all whole-OS busy time between server-side boundaries to this exclusive benchmark.
// Reference cycles are an estimate in fixed TSC units, never a hardware core-cycle measurement.
inline Json host_usage_delta(const Json& before, const Json& after) {
    const auto clock = after.value("reference_clock", Json::object());
    Json result{{"scope", after.value("scope", Json(nullptr))},
                {"cpu_time_source", after.value("cpu_time_source", Json(nullptr))},
                {"busy_cpu_seconds", nullptr},
                {"elapsed_seconds", nullptr},
                {"cpu_utilization_percent", nullptr},
                {"cpu_utilization_basis", "100% = one logical CPU"},
                {"reference_cycles", nullptr},
                {"reference_clock", clock},
                {"reference_cycles_unavailable_reason", nullptr}};
    if (!before.value("busy_cpu_seconds", Json(nullptr)).is_number() ||
        !after.value("busy_cpu_seconds", Json(nullptr)).is_number()) {
        auto reason = after.value("cpu_time_unavailable_reason", Json(nullptr));
        if (reason.is_null()) {
            reason = before.value("cpu_time_unavailable_reason", Json(nullptr));
        }
        result["reference_cycles_unavailable_reason"] =
            reason.is_null() ? Json("Whole-server CPU counters are required at both boundaries")
                             : reason;
        return result;
    }
    if (!before.value("sampled_at_monotonic_seconds", Json(nullptr)).is_number() ||
        !after.value("sampled_at_monotonic_seconds", Json(nullptr)).is_number()) {
        result["reference_cycles_unavailable_reason"] =
            "Server-side monotonic timestamps are required at both boundaries";
        return result;
    }
    const auto busy =
        after.at("busy_cpu_seconds").get<double>() - before.at("busy_cpu_seconds").get<double>();
    const auto elapsed = after.value("sampled_at_monotonic_seconds", 0.0) -
                         before.value("sampled_at_monotonic_seconds", 0.0);
    if (!std::isfinite(busy) || busy < 0 || !std::isfinite(elapsed) || elapsed <= 0) {
        result["reference_cycles_unavailable_reason"] =
            "Whole-server CPU time must be monotonic with a positive sample interval";
        return result;
    }
    result["busy_cpu_seconds"] = busy;
    result["elapsed_seconds"] = elapsed;
    result["cpu_utilization_percent"] = 100 * busy / elapsed;

    const auto old_clock = before.value("reference_clock", Json::object());
    const auto frequency = clock.value("frequency_hz", Json(nullptr));
    if (!frequency.is_number() || frequency != old_clock.value("frequency_hz", Json(nullptr))) {
        const auto reason = clock.value("unavailable_reason", Json(nullptr));
        result["reference_cycles_unavailable_reason"] =
            reason.is_null()
                ? Json("The same calibrated TSC frequency is required at both boundaries")
                : reason;
        return result;
    }
    const auto hz = frequency.get<double>();
    if (!std::isfinite(hz) || hz <= 0 || !std::isfinite(busy * hz)) {
        result["reference_cycles_unavailable_reason"] = "Invalid calibrated TSC frequency";
        return result;
    }
    result["reference_cycles"] = busy * hz;
    return result;
}
}
