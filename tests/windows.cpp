#include "winlin/windows.hpp"

#include <iostream>

namespace {
using namespace winlin;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

}

int main() {
    try {
        const auto snapshot = usage();
        require(snapshot.at("voluntary_context_switches").is_null(),
                "Unavailable counters are null");
        require(environment().at("os") == "Windows", "Native environment");
        require(wide(utf8(L"winlin-\u03b1")) == L"winlin-\u03b1", "Unicode path conversion");
        std::cout << "Windows platform tests passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
