#include "winlin/linux.hpp"

#include <future>
#include <iostream>

namespace {
using namespace winlin;

// Fail this bounded native regression without turning a transport error into a successful run.
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// Complete the ordinary OpenSSL handshake before testing TX kTLS and explicit file offsets.
void handshake(StreamSocket& socket, bool server, Clock::time_point deadline) {
    while (!socket.handshake(server)) {
        wait_socket(socket, deadline);
    }
}
}

// Exercise actual kTLS file transmission independently of the server's machine-wide guard.
// All sockets bind loopback ephemeral ports; no running benchmark service is inspected or altered.
int main() {
    using namespace winlin;
    try {
        std::signal(SIGPIPE, SIG_IGN);
        std::vector<char> payload(2 * 1024 * 1024);
        for (std::size_t index = 0; index < payload.size(); ++index) {
            payload[index] = static_cast<char>(index % 251);
        }
        auto source = sealed_payload_file(payload);
        require(pwrite(source.value, "x", 1, 0) == -1 && errno == EPERM,
                "File data must be immutable through retransmission");
        require(ftruncate(source.value, 0) == -1 && errno == EPERM,
                "The source must not shrink while a send is pending");

        auto server_context = context(true, "TLS_AES_128_GCM_SHA256", true);
        require(SSL_CTX_use_certificate_chain_file(server_context.get(),
                                                   WINLIN_TEST_CERT_DIR "/server.pem") == 1 &&
                    SSL_CTX_use_PrivateKey_file(server_context.get(),
                                                WINLIN_TEST_CERT_DIR "/server.key",
                                                SSL_FILETYPE_PEM) == 1,
                "Load the public TLS test fixture");
        auto client_context = context(false, "TLS_AES_128_GCM_SHA256");
        Fd listener(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
        if (listener.value < 0) {
            throw system_error("Create kTLS test listener");
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            listen(listener.value, 1) != 0) {
            throw system_error("Bind kTLS test listener");
        }
        socklen_t address_size = sizeof(address);
        if (getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &address_size) !=
            0) {
            throw system_error("Inspect kTLS test port");
        }

        const auto deadline = Clock::now() + std::chrono::seconds(15);
        std::promise<bool> blocked;
        auto ready = blocked.get_future();
        std::exception_ptr server_failure;
        std::jthread sender([&] {
            bool announced = false;
            try {
                pollfd incoming{listener.value, POLLIN, 0};
                require(poll(&incoming, 1, 10000) > 0, "kTLS test accept timed out");
                Fd accepted(
                    accept4(listener.value, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
                if (accepted.value < 0) {
                    throw system_error("Accept kTLS test connection");
                }
                const int buffer_size = 65536;
                if (setsockopt(accepted.value, SOL_SOCKET, SO_SNDBUF, &buffer_size,
                               sizeof(buffer_size)) != 0) {
                    throw system_error("Bound kTLS test send buffer");
                }
                StreamSocket socket(std::exchange(accepted.value, -1), server_context.get());
                handshake(socket, true, deadline);
                if (!BIO_get_ktls_send(SSL_get_wbio(socket.ssl.get()))) {
                    blocked.set_value(false);
                    return;
                }

                // Do not let the client read until backpressure occurs. Then finish the file
                // and a second nonzero-offset range, checking that retries preserve every byte.
                for (const auto& range :
                     {std::pair<std::size_t, std::size_t>{0, payload.size()}, {4093, 8193}}) {
                    auto offset = range.first;
                    auto remaining = range.second;
                    while (remaining) {
                        const auto written =
                            socket.send_file(source.value, static_cast<off_t>(offset), remaining);
                        if (!written) {
                            require(socket.want == EPOLLOUT,
                                    "File backpressure must wait for socket writability");
                            if (!announced) {
                                blocked.set_value(true);
                                announced = true;
                            }
                            wait_socket(socket, deadline);
                        } else {
                            require(written <= remaining, "sendfile returned excess progress");
                            offset += written;
                            remaining -= written;
                        }
                    }
                }
                require(announced, "The file transfer must exercise backpressure");
                bool rejected_eof = false;
                try {
                    socket.send_file(source.value, static_cast<off_t>(payload.size()), 1);
                } catch (const std::runtime_error& error) {
                    rejected_eof =
                        std::string_view(error.what()).find("source EOF") != std::string_view::npos;
                }
                require(rejected_eof, "Premature file EOF must fail rather than retry forever");
            } catch (...) {
                server_failure = std::current_exception();
                if (!announced) {
                    blocked.set_exception(server_failure);
                }
            }
        });

        auto connected = connect_socket("127.0.0.1", std::to_string(ntohs(address.sin_port)));
        StreamSocket receiver(std::exchange(connected.value, -1), client_context.get());
        bool rejected_fallback = false;
        try {
            receiver.send_file(source.value, 0, 1);
        } catch (const std::runtime_error& error) {
            rejected_fallback = std::string_view(error.what()).find("refusing sendfile fallback") !=
                                std::string_view::npos;
        }
        require(rejected_fallback, "Ordinary TLS must not silently replace the kTLS file path");
        std::exception_ptr client_failure;
        bool available{};
        try {
            handshake(receiver, false, deadline);
            require(ready.wait_until(deadline) == std::future_status::ready,
                    "kTLS sender did not reach backpressure");
            available = ready.get();
            if (available) {
                std::vector<char> received(payload.size() + 8193);
                std::size_t offset{};
                while (offset < received.size()) {
                    const auto count =
                        receiver.read(received.data() + offset, received.size() - offset);
                    if (count) {
                        offset += static_cast<std::size_t>(count);
                    } else {
                        wait_socket(receiver, deadline);
                    }
                }
                require(std::equal(payload.begin(), payload.end(), received.begin()) &&
                            std::equal(payload.begin() + 4093, payload.begin() + 4093 + 8193,
                                       received.begin() + payload.size()),
                        "Partial file sends must preserve exact plaintext and range offsets");
            }
        } catch (...) {
            client_failure = std::current_exception();
        }
        sender.join();
        if (server_failure) {
            std::rethrow_exception(server_failure);
        }
        if (client_failure) {
            std::rethrow_exception(client_failure);
        }
        if (!available) {
            std::cout << "Native TX kTLS unavailable; file transmission test skipped\n";
            return 77;
        }
        require(lseek(source.value, 0, SEEK_CUR) == static_cast<off_t>(payload.size()),
                "Explicit per-connection offsets must not change the shared descriptor position");
        std::cout
            << "Immutable kTLS file source, payload integrity, backpressure, and EOF passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "kTLS sendfile test failed: " << error.what() << '\n';
        return 1;
    }
}
