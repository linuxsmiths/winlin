#pragma once

#include "winlin/core.hpp"

namespace winlin {
// Sample one selected interface outside the request hot path. Native adapters identify the
// interface and supply cumulative RX/TX counters; failures remain unavailable, never zero.
template <class Collector> Json sample_network_usage(std::string_view source, Collector collect) {
    Json result{{"source", source},
                {"scope", "Selected server interface; RX+TX including unrelated traffic"},
                {"interface_id", nullptr},
                {"interface_name", nullptr},
                {"received_bytes", nullptr},
                {"transmitted_bytes", nullptr},
                {"sampled_at_monotonic_seconds", nullptr},
                {"unavailable_reason", nullptr}};
    try {
        result.update(collect());
        result["sampled_at_monotonic_seconds"] =
            std::chrono::duration<double>(Clock::now().time_since_epoch()).count();
    } catch (const std::exception& error) {
        result["unavailable_reason"] = error.what();
    }
    return result;
}

// Compute decimal Gbps from matching server-side interface samples. Counter resets, interface
// changes, and missing timestamps invalidate the rate rather than inventing network throughput.
inline Json network_usage_delta(const Json& before, const Json& after) {
    Json result{{"source", after.value("source", Json(nullptr))},
                {"scope", after.value("scope", Json(nullptr))},
                {"interface_id", after.value("interface_id", Json(nullptr))},
                {"interface_name", after.value("interface_name", Json(nullptr))},
                {"received_bytes", nullptr},
                {"transmitted_bytes", nullptr},
                {"elapsed_seconds", nullptr},
                {"gigabits_per_second", nullptr},
                {"unavailable_reason", nullptr}};
    for (const auto* field : {"received_bytes", "transmitted_bytes"}) {
        if (!before.value(field, Json(nullptr)).is_number_unsigned() ||
            !after.value(field, Json(nullptr)).is_number_unsigned()) {
            auto reason = after.value("unavailable_reason", Json(nullptr));
            if (reason.is_null()) {
                reason = before.value("unavailable_reason", Json(nullptr));
            }
            result["unavailable_reason"] =
                reason.is_null() ? Json("Server interface counters are required at both boundaries")
                                 : reason;
            return result;
        }
    }
    if (before.value("interface_id", Json(nullptr)).is_null() ||
        before.value("interface_id", Json(nullptr)) != after.value("interface_id", Json(nullptr)) ||
        before.value("interface_name", Json(nullptr)) !=
            after.value("interface_name", Json(nullptr)) ||
        before.value("source", Json(nullptr)) != after.value("source", Json(nullptr))) {
        result["unavailable_reason"] = "Server network interface changed between samples";
        return result;
    }
    if (!before.value("sampled_at_monotonic_seconds", Json(nullptr)).is_number() ||
        !after.value("sampled_at_monotonic_seconds", Json(nullptr)).is_number()) {
        result["unavailable_reason"] = "Server network timestamps are required at both boundaries";
        return result;
    }
    const auto elapsed = after.at("sampled_at_monotonic_seconds").get<double>() -
                         before.at("sampled_at_monotonic_seconds").get<double>();
    const auto old_received = before.at("received_bytes").get<std::uint64_t>();
    const auto old_transmitted = before.at("transmitted_bytes").get<std::uint64_t>();
    const auto received = after.at("received_bytes").get<std::uint64_t>();
    const auto transmitted = after.at("transmitted_bytes").get<std::uint64_t>();
    if (!std::isfinite(elapsed) || elapsed <= 0 || received < old_received ||
        transmitted < old_transmitted) {
        result["unavailable_reason"] =
            "Server interface counters must be monotonic with a positive sample interval";
        return result;
    }
    const auto received_delta = received - old_received;
    const auto transmitted_delta = transmitted - old_transmitted;
    const auto gigabits =
        (static_cast<double>(received_delta) + static_cast<double>(transmitted_delta)) * 8 / 1e9;
    const auto rate = gigabits / elapsed;
    if (!std::isfinite(rate)) {
        result["unavailable_reason"] = "Invalid server network throughput";
        return result;
    }
    result["received_bytes"] = received_delta;
    result["transmitted_bytes"] = transmitted_delta;
    result["elapsed_seconds"] = elapsed;
    result["gigabits_per_second"] = rate;
    return result;
}
}
