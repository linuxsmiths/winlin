#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace winlin {
using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;
constexpr std::size_t max_object_size = 64 * 1024 * 1024;
constexpr std::size_t max_header_size = 16384;
constexpr std::array<std::size_t, 10> size_presets{
    256, 512, 1024, 4096, 8192, 16384, 65536, 262144, 1048576, 4194304};

inline std::string parse_token(std::string token) {
    if (!token.empty() && token.back() == '\n') token.pop_back();
    if (!token.empty() && token.back() == '\r') token.pop_back();
    if (token.size() < 32 || token.size() > 256 ||
        !std::all_of(token.begin(), token.end(), [](unsigned char ch) { return std::isxdigit(ch); }))
        throw std::runtime_error("Credential must contain 32-256 hexadecimal characters");
    return token;
}

inline std::uint64_t number(std::string_view text, std::uint64_t maximum =
                            std::numeric_limits<std::uint64_t>::max()) {
    std::uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || error != std::errc{} || end != text.data() + text.size() ||
        value > maximum)
        throw std::invalid_argument("Invalid nonnegative integer: " + std::string(text));
    return value;
}

inline std::size_t object_size(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    const auto suffix = text.find_first_not_of("0123456789");
    const auto digits = std::string_view(text).substr(0, suffix);
    const auto unit = suffix == std::string::npos ? "" : text.substr(suffix);
    std::uint64_t multiplier = 1;
    if (unit == "k" || unit == "kib") multiplier = 1024;
    else if (unit == "m" || unit == "mib") multiplier = 1024 * 1024;
    else if (!unit.empty() && unit != "b") throw std::invalid_argument("Use bytes, KiB or MiB");
    return static_cast<std::size_t>(number(digits, max_object_size / multiplier) * multiplier);
}

inline double seconds(std::string_view text, double maximum = 86400) {
    double value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || error != std::errc{} || end != text.data() + text.size() ||
        !std::isfinite(value) || value < 0 || value > maximum)
        throw std::invalid_argument("Invalid seconds: " + std::string(text));
    return value;
}

class Args {
    std::map<std::string, std::string> values_;
public:
    Args(int argc, char** argv, int first = 1) {
        for (int i = first; i < argc; ++i) {
            std::string key = argv[i];
            if (!key.starts_with("--") || i + 1 == argc || values_.contains(key))
                throw std::invalid_argument("Expected unique --option value pairs: " + key);
            values_.emplace(std::move(key), argv[++i]);
        }
    }
    void allow(std::initializer_list<std::string_view> names) const {
        for (const auto& [key, value] : values_) {
            (void)value;
            if (std::find(names.begin(), names.end(), key) == names.end())
                throw std::invalid_argument("Unknown option: " + key);
        }
    }
    std::string get(const std::string& key, std::string fallback = {}) const {
        const auto it = values_.find(key);
        return it == values_.end() ? std::move(fallback) : it->second;
    }
    std::string require(const std::string& key) const {
        auto value = get(key);
        if (value.empty()) throw std::invalid_argument("Missing " + key);
        return value;
    }
};

inline std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return text;
}

inline std::string trim(std::string_view text) {
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string_view::npos) return {};
    return std::string(text.substr(first, text.find_last_not_of(" \t") - first + 1));
}

struct HttpHead {
    std::string first;
    std::map<std::string, std::string> fields;
    std::uint64_t length{};
    bool close{};
};

inline HttpHead parse_head(std::string_view text) {
    if (text.size() > max_header_size || !text.ends_with("\r\n\r\n"))
        throw std::invalid_argument("Invalid HTTP header");
    HttpHead head;
    auto end = text.find("\r\n");
    head.first = text.substr(0, end);
    auto position = end + 2;
    while (position < text.size() - 2) {
        end = text.find("\r\n", position);
        const auto line = text.substr(position, end - position);
        const auto colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0)
            throw std::invalid_argument("Invalid HTTP field");
        auto name = lower(std::string(line.substr(0, colon)));
        for (unsigned char ch : name) {
            if (!std::isalnum(ch) && ch != '-')
                throw std::invalid_argument("Invalid HTTP field name");
        }
        if (!head.fields.emplace(std::move(name), trim(line.substr(colon + 1))).second)
            throw std::invalid_argument("Duplicate HTTP field");
        position = end + 2;
    }
    if (head.fields.contains("transfer-encoding"))
        throw std::invalid_argument("Transfer-Encoding is not supported");
    if (head.fields.contains("content-length"))
        head.length = number(head.fields.at("content-length"), max_object_size);
    head.close = head.fields.contains("connection") &&
                 lower(head.fields.at("connection")) == "close";
    return head;
}

struct RunConfig {
    std::string method{"get"};
    std::size_t get_size{4096};
    std::size_t put_size{4096};
    unsigned get_percent{50};
    unsigned connections{256};
    unsigned workers{1};
    double warmup{10};
    double duration{30};
    unsigned repetitions{3};
    std::uint64_t requests{};
    double timeout{10};

    void validate() const {
        if (method != "get" && method != "put" && method != "mixed")
            throw std::invalid_argument("Method must be get, put or mixed");
        if (!connections || connections > 16384 || !workers || workers > 256 ||
            workers > connections || !repetitions || repetitions > 1000 ||
            duration <= 0 || !std::isfinite(duration) || duration > 86400 ||
            warmup < 0 || !std::isfinite(warmup) || warmup > 86400 ||
            timeout <= 0 || !std::isfinite(timeout) || timeout > 3600 ||
            get_size > max_object_size || put_size > max_object_size || get_percent > 100)
            throw std::invalid_argument("Run configuration is outside supported limits");
    }
    Json json() const {
        return {{"method", method}, {"get_size_bytes", get_size},
                {"put_size_bytes", put_size}, {"get_percent", get_percent},
                {"connections", connections}, {"workers", workers},
                {"warmup_seconds", warmup}, {"duration_seconds", duration},
                {"repetitions", repetitions}, {"request_limit", requests},
                {"timeout_seconds", timeout}, {"load_mode", "closed_loop"},
                {"tls_version", "TLSv1.3"}};
    }
};

inline Json usage_delta(const Json& before, const Json& after, double elapsed) {
    const auto user = after.at("user_cpu_seconds").get<double>() - before.at("user_cpu_seconds").get<double>();
    const auto system = after.at("system_cpu_seconds").get<double>() - before.at("system_cpu_seconds").get<double>();
    auto difference = [&](const char* key) -> Json {
        if (!before.contains(key) || !after.contains(key) ||
            !before.at(key).is_number_integer() || !after.at(key).is_number_integer()) return nullptr;
        return after.at(key).get<std::int64_t>() - before.at(key).get<std::int64_t>();
    };
    return {{"user_cpu_seconds", user}, {"system_cpu_seconds", system},
            {"cpu_core_equivalents", (user + system) / elapsed},
            {"peak_rss_bytes", after.at("peak_rss_bytes")},
            {"voluntary_context_switches", difference("voluntary_context_switches")},
            {"involuntary_context_switches", difference("involuntary_context_switches")}};
}

class Histogram {
    std::array<std::uint64_t, 4096> bins_{};
    std::uint64_t count_{};
    std::uint64_t maximum_{};
    long double sum_{};
public:
    void record(std::uint64_t ns) {
        ns = std::max<std::uint64_t>(1, ns);
        const unsigned exponent = std::bit_width(ns) - 1;
        const auto base = std::uint64_t{1} << exponent;
        const auto sub = exponent >= 6 ? (ns - base) >> (exponent - 6)
                                      : (ns - base) * 64 / base;
        ++bins_[exponent * 64 + sub];
        ++count_;
        maximum_ = std::max(maximum_, ns);
        sum_ += ns;
    }
    void merge(const Histogram& other) {
        for (std::size_t i = 0; i < bins_.size(); ++i) bins_[i] += other.bins_[i];
        count_ += other.count_;
        sum_ += other.sum_;
        maximum_ = std::max(maximum_, other.maximum_);
    }
    double percentile(double fraction) const {
        if (!count_) return 0;
        const auto target = static_cast<std::uint64_t>(std::ceil(count_ * fraction));
        std::uint64_t accumulated{};
        for (unsigned i = 0; i < bins_.size(); ++i) {
            accumulated += bins_[i];
            if (accumulated >= target) {
                const auto base = std::uint64_t{1} << (i / 64);
                const long double upper = static_cast<long double>(base) *
                                          (1 + (i % 64 + 1) / 64.0L);
                return static_cast<double>(std::min<long double>(upper, maximum_) / 1000);
            }
        }
        return static_cast<double>(maximum_) / 1000;
    }
    Json json() const {
        Json buckets = Json::array();
        for (unsigned i = 0; i < bins_.size(); ++i) {
            if (!bins_[i]) continue;
            const long double base = static_cast<long double>(std::uint64_t{1} << (i / 64));
            buckets.push_back({{"upper_bound_us", static_cast<double>(base * (1 + (i % 64 + 1) / 64.0L) / 1000)},
                               {"count", bins_[i]}});
        }
        return {{"samples", count_}, {"mean_us", count_ ? static_cast<double>(sum_ / count_ / 1000) : 0},
                {"p50_us", percentile(.50)}, {"p90_us", percentile(.90)},
                {"p99_us", percentile(.99)}, {"p999_us", percentile(.999)},
                {"max_us", static_cast<double>(maximum_) / 1000},
                {"histogram", buckets},
                {"percentile_method", "logarithmic histogram; upper bounds within 1.5625%"}};
    }
};
}
