#include "winlin/core.hpp"
#include <iostream>

namespace {
void check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <class Function> void rejects(Function function) {
    try {
        function();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error("Invalid input was accepted");
}
}

int main() {
    using namespace winlin;
    try {
        check(object_size("4MiB") == 4194304, "Size suffix");
        check(object_size("256") == 256, "Byte size");
        rejects([] {
            object_size("65MiB");
        });
        rejects([] {
            object_size("-1");
        });
        rejects([] {
            object_size("1GB");
        });
        rejects([] {
            seconds("nan");
        });
        rejects([] {
            seconds("-1");
        });
        rejects([] {
            number("12junk");
        });
        auto request = parse_head(
            "PUT /v1/object HTTP/1.1\r\nContent-Length: 256\r\nConnection: close\r\n\r\n");
        check(request.length == 256 && request.close, "HTTP fields");
        rejects([] {
            parse_head("GET / HTTP/1.1\r\nContent-Length: 1\r\ncontent-length: 2\r\n\r\n");
        });
        rejects([] {
            parse_head("GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        });
        rejects([] {
            parse_head("GET / HTTP/1.1\r\nContent-Length: -1\r\n\r\n");
        });
        auto config = RunConfig{};
        config.connections = 16385;
        rejects([&] {
            config.validate();
        });
        config.connections = 1;
        config.get_percent = 101;
        rejects([&] {
            config.validate();
        });
        // Bucket upper bounds may overestimate percentiles, but never exceed the observed maximum.
        Histogram histogram;
        check(histogram.json()["samples"] == 0, "Empty histogram");
        histogram.record(1000);
        histogram.record(2000);
        Histogram second;
        second.record(3000);
        histogram.merge(second);
        check(histogram.json()["samples"] == 3, "Merged histogram");
        check(histogram.percentile(.5) >= 2 && histogram.percentile(.5) <= 2.032,
              "Percentile bound");
        check(histogram.percentile(.99) == 3, "Maximum bound");
        // Missing Windows counters must not turn into zero-valued measurements after subtraction.
        const Json before{{"user_cpu_seconds", 1.0},
                          {"system_cpu_seconds", .5},
                          {"peak_rss_bytes", 4096},
                          {"voluntary_context_switches", nullptr},
                          {"involuntary_context_switches", nullptr}};
        auto after = before;
        after["user_cpu_seconds"] = 2.0;
        const auto delta = usage_delta(before, after, 2.0);
        check(delta.at("voluntary_context_switches").is_null() &&
                  delta.at("involuntary_context_switches").is_null(),
              "Unavailable Windows counters stay null");
        check(delta.at("cpu_core_equivalents") == .5, "CPU deltas with unavailable counters");
        check(delta.at("cpu_cycles").is_null(),
              "Missing cycles must not be estimated from CPU time");
        auto counted_before = before;
        auto counted_after = after;
        counted_before["cpu_cycles"] = 1000;
        counted_after["cpu_cycles"] = 2500;
        counted_after["cpu_cycles_source"] = "test hardware counter";
        const auto counted = usage_delta(counted_before, counted_after, 2);
        check(counted.at("cpu_cycles") == 1500 && counted.at("cpu_utilization_percent") == 50,
              "Cycles and CPU utilization use measured sample deltas");
        counted_before["cpu_cycles"] = nullptr;
        const auto missing_boundary = usage_delta(counted_before, counted_after, 2);
        check(missing_boundary.at("cpu_cycles").is_null() &&
                  !missing_boundary.at("cpu_cycles_unavailable_reason").is_null(),
              "Cycles unavailable at either boundary need a reason, never an estimate");
        std::cout << "core tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
