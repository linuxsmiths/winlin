#include "winlin/host.hpp"
#include "winlin/cpu.hpp"
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
        // Firmware evidence must not turn missing metadata into a bare-metal or invented-SKU claim.
        check(describe_machine("", "").at("type") == "unknown", "Missing firmware is unknown");
        auto machine = describe_machine("Microsoft Corporation", "Virtual Machine");
        check(machine.at("type") == "virtual_machine" && machine.at("vm_sku").is_null() &&
                  machine.at("cloud_provider").is_null(),
              "Hyper-V firmware alone does not prove Azure");
        apply_azure_sku(machine, "Standard_D96as_v5\n");
        check(machine.at("vm_sku") == "Standard_D96as_v5" &&
                  machine.at("cloud_provider") == "Azure",
              "Azure SKU comes from explicit metadata");
        check(describe_machine("Amazon EC2", "i3.metal").at("type") == "bare_metal" &&
                  describe_machine("Amazon EC2", "EC2").at("vm_sku").is_null(),
              "AWS firmware distinguishes known SKU from a generic model");
        const auto firmware = std::string("\x01\x06\0\0\x01\x02", 6) + "Microsoft Corporation" +
                              '\0' + "Virtual Machine" + std::string("\0\0", 2);
        const auto [vendor, product] = smbios_system(firmware);
        check(vendor == "Microsoft Corporation" && product == "Virtual Machine",
              "Bounded SMBIOS string extraction");
        bool rejected_firmware = false;
        try {
            smbios_system(firmware.substr(0, firmware.size() - 1));
        } catch (const std::runtime_error&) {
            rejected_firmware = true;
        }
        check(rejected_firmware, "Truncated firmware cannot be read beyond its buffer");
        bool rejected_sku = false;
        try {
            apply_azure_sku(machine, "{\"unexpected\":\"metadata\"}");
        } catch (const std::runtime_error&) {
            rejected_sku = true;
        }
        check(rejected_sku, "Only a SKU leaf is accepted, not arbitrary metadata");
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
        check(delta.at("cpu_utilization_percent") == 50 && !delta.contains("cpu_core_equivalents"),
              "CPU utilization is expressed only as a percentage");
        check(usage_delta(before, after, .25).at("cpu_utilization_percent") == 400,
              "CPU utilization is not capped at 100 percent or normalized by host core count");
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

        // Whole-host reference cycles include every busy CPU, independently of process counters.
        const Json host_before{{"busy_cpu_seconds", 1000.0},
                               {"sampled_at_monotonic_seconds", 10.0},
                               {"reference_clock", {{"frequency_hz", 2e9}}}};
        auto host_after = host_before;
        host_after["busy_cpu_seconds"] = 1006.0;
        host_after["sampled_at_monotonic_seconds"] = 12.0;
        const auto host = host_usage_delta(host_before, host_after);
        check(host.at("cpu_utilization_percent") == 300 && host.at("reference_cycles") == 12e9 &&
                  host.at("reference_cycles_unavailable_reason").is_null(),
              "Reference cycles use all busy CPU seconds at calibrated reference frequency");
        auto no_clock = host_after;
        no_clock["reference_clock"] = {{"frequency_hz", nullptr},
                                       {"unavailable_reason", "No invariant TSC"}};
        const auto unavailable_clock = host_usage_delta(host_before, no_clock);
        check(
            unavailable_clock.at("cpu_utilization_percent") == 300 &&
                unavailable_clock.at("reference_cycles").is_null() &&
                unavailable_clock.at("reference_cycles_unavailable_reason") == "No invariant TSC",
            "An unavailable reference clock preserves OS CPU utilization with an explicit reason");
        auto no_cpu = host_after;
        no_cpu["busy_cpu_seconds"] = nullptr;
        no_cpu["cpu_time_unavailable_reason"] = "Host CPU counters unavailable";
        check(host_usage_delta(host_before, no_cpu).at("reference_cycles_unavailable_reason") ==
                  "Host CPU counters unavailable",
              "Missing host CPU samples must not become zero reference cycles");
        auto reset_cpu = host_after;
        reset_cpu["busy_cpu_seconds"] = 999.0;
        check(host_usage_delta(host_before, reset_cpu).at("reference_cycles").is_null(),
              "Regressing whole-host CPU counters are rejected");
        auto changed_clock = host_after;
        changed_clock["reference_clock"]["frequency_hz"] = 3e9;
        check(host_usage_delta(host_before, changed_clock).at("reference_cycles").is_null(),
              "Changing reference frequencies between boundaries cannot be mixed");
        auto missing_timestamp = host_after;
        missing_timestamp.erase("sampled_at_monotonic_seconds");
        check(host_usage_delta(host_before, missing_timestamp).at("reference_cycles").is_null(),
              "Missing server timestamps cannot silently use a zero baseline");
        std::cout << "core tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
