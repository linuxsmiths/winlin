#include "winlin/linux.hpp"
#include "winlin/agent.hpp"

#include <iostream>
#include <mutex>
#include <unordered_map>

namespace {
using namespace winlin;
std::atomic<bool> interrupted{};
static_assert(std::atomic<bool>::is_always_lock_free);
void on_signal(int) { interrupted.store(true, std::memory_order_relaxed); }

AgentConfig linux_config(const Args& args) {
    const auto backend = args.get("--backend", "openssl");
    if (backend != "openssl" && backend != "ktls")
        throw std::invalid_argument("Linux backend must be openssl or ktls");
    auto config = AgentConfig::from_args(args, backend == "ktls" ? "openssl-ktls" : "openssl");
    config.environment = environment();
    return config;
}

struct Server : Agent {
    Context tls;
    std::vector<char> payload;
    bool ktls{};
    std::atomic<bool> stop{};

    Server(const Args& args)
        : Agent(linux_config(args), token_file(args.require("--token-file")),
                optional_token_file(args.get("--session-file", args.require("--token-file") + ".session")),
                [path = args.get("--session-file", args.require("--token-file") + ".session")] {
                    return issue_token_file(path);
                }, equal_secret, usage),
          tls(context(true, args.get("--cipher", "TLS_AES_128_GCM_SHA256"),
                      args.get("--backend", "openssl") == "ktls")),
          payload(max_object_size), ktls(args.get("--backend", "openssl") == "ktls") {
        if (SSL_CTX_use_certificate_chain_file(tls.get(), args.require("--cert").c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(tls.get(), args.require("--key").c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(tls.get()) != 1)
            throw tls_error("Cannot load matching certificate/private key");
        if (RAND_bytes(reinterpret_cast<unsigned char*>(payload.data()), payload.size()) != 1)
            throw tls_error("Cannot generate reusable payload");
    }
};

struct Session {
    TlsSocket socket;
    Server& server;
    enum class State { handshake, header, body, send_header, send_body } state{State::handshake};
    std::string input, output, text_body;
    std::array<char, 16384> buffer{};
    std::size_t offset{}, body_remaining{}, body_size{};
    bool close{}, object_response{}, get{}, put{}, tx{}, rx{};
    Clock::time_point activity{Clock::now()};

    Session(int fd, Server& owner) : socket(fd, owner.tls.get()), server(owner) {}
    ~Session() { --server.active; }

    void respond(int status, std::string body = {}, bool object = false, std::size_t size = 0) {
        text_body = std::move(body);
        object_response = object;
        body_size = object ? size : text_body.size();
        output = "HTTP/1.1 " + std::to_string(status) + " " +
                 (status == 200 ? "OK" : "Error") + "\r\nContent-Length: " +
                 std::to_string(body_size) + "\r\nContent-Type: " +
                 (object ? "application/octet-stream" : "application/json") +
                 "\r\nCache-Control: no-store\r\nConnection: " + (close ? "close" : "keep-alive") +
                 "\r\nX-Winlin-Ktls-Tx: " + (tx ? "1" : "0") +
                 "\r\nX-Winlin-Ktls-Rx: " + (rx ? "1" : "0") + "\r\n\r\n";
        offset = 0;
        state = State::send_header;
    }

    void request(const HttpHead& head) {
        body_remaining = 0;
        const auto reply = server.Agent::request(head,
            {SSL_get_version(socket.ssl.get()), SSL_get_cipher_name(socket.ssl.get()), tx, rx});
        close = reply.close;
        get = reply.kind == AgentReply::Kind::object;
        put = reply.kind == AgentReply::Kind::consume_put;
        if (put) {
            body_size = body_remaining = reply.size;
            state = State::body;
        } else respond(reply.status, reply.text, get, reply.size);
    }

    bool pump() {
        for (unsigned step = 0; step < 128; ++step) {
            if (state == State::handshake) {
                if (!socket.handshake(true)) return true;
                tx = BIO_get_ktls_send(SSL_get_wbio(socket.ssl.get()));
                rx = BIO_get_ktls_recv(SSL_get_rbio(socket.ssl.get()));
                ++server.handshakes;
                if (tx) ++server.tx_ktls;
                if (rx) ++server.rx_ktls;
                state = State::header;
            } else if (state == State::header) {
                const auto end = input.find("\r\n\r\n");
                if (end != std::string::npos) {
                    get = put = false;
                    try {
                        const auto head = parse_head(std::string_view(input).substr(0, end + 4));
                        input.erase(0, end + 4);
                        request(head);
                    } catch (const std::invalid_argument&) {
                        close = true;
                        respond(400, R"({"error":"invalid request"})");
                    }
                } else {
                    if (input.size() >= max_header_size) return false;
                    const int count = socket.read(buffer.data(), buffer.size());
                    if (!count) return true;
                    input.append(buffer.data(), count);
                }
            } else if (state == State::body) {
                const auto count = std::min(body_remaining, input.size());
                input.erase(0, count);
                body_remaining -= count;
                if (!body_remaining) {
                    ++server.puts;
                    server.put_bytes += body_size;
                    respond(200);
                } else {
                    const int bytes = socket.read(buffer.data(), std::min(buffer.size(), body_remaining));
                    if (!bytes) return true;
                    body_remaining -= bytes;
                }
            } else if (state == State::send_header) {
                const int bytes = socket.write(output.data() + offset, output.size() - offset);
                if (!bytes) return true;
                offset += bytes;
                if (offset == output.size()) {
                    offset = 0;
                    state = State::send_body;
                }
            } else {
                if (offset < body_size) {
                    const char* data = object_response ? server.payload.data() : text_body.data();
                    const int bytes = socket.write(data + offset, body_size - offset);
                    if (!bytes) return true;
                    offset += bytes;
                } else {
                    if (get) { ++server.gets; server.get_bytes += body_size; }
                    if (close) return false;
                    state = State::header;
                }
            }
            activity = Clock::now();
        }
        socket.want = EPOLLIN | EPOLLOUT;
        return true;
    }
};

Fd listener(const std::string& bind_address, unsigned& port) {
    Fd fd(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (fd.value < 0) throw system_error("socket");
    int one = 1;
    if (setsockopt(fd.value, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
        setsockopt(fd.value, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)))
        throw system_error("SO_REUSEPORT");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_address.c_str(), &address.sin_addr) != 1)
        throw std::invalid_argument("--bind must be an IPv4 address");
    if (bind(fd.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(fd.value, 4096))
        throw system_error("bind/listen");
    socklen_t length = sizeof(address);
    if (getsockname(fd.value, reinterpret_cast<sockaddr*>(&address), &length))
        throw system_error("getsockname");
    port = ntohs(address.sin_port);
    return fd;
}

void serve(Server& server, Fd listener_fd) {
    Epoll poller;
    poller.set(listener_fd.value, EPOLLIN, true);
    std::unordered_map<int, std::unique_ptr<Session>> sessions;
    std::array<epoll_event, 256> events{};
    auto sweep = Clock::now();
    while (!interrupted && !server.stop) {
        const int count = poller.wait(events.data(), events.size(), 100);
        for (int i = 0; i < count; ++i) {
            const int fd = events[i].data.fd;
            if (fd == listener_fd.value) {
                for (unsigned accepted = 0; accepted < 256; ++accepted) {
                    Fd client(accept4(fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
                    if (client.value < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno == EINTR) continue;
                        throw system_error("accept");
                    }
                    if (server.active.fetch_add(1) >= server.config.connection_limit) {
                        --server.active;
                        continue;
                    }
                    const int client_fd = client.value;
                    try {
                        auto session = std::make_unique<Session>(std::exchange(client.value, -1), server);
                        sessions.emplace(client_fd, std::move(session));
                        poller.set(client_fd, EPOLLIN, true);
                        ++server.connections;
                    } catch (...) {
                        if (!sessions.erase(client_fd)) --server.active;
                        throw;
                    }
                }
            } else if (const auto it = sessions.find(fd); it != sessions.end()) {
                try {
                    if (!it->second->pump()) sessions.erase(it);
                    else poller.set(fd, it->second->socket.want);
                } catch (const std::exception&) {
                    sessions.erase(fd);
                }
            }
        }
        if (Clock::now() - sweep >= std::chrono::seconds(1)) {
            sweep = Clock::now();
            std::erase_if(sessions, [&](const auto& entry) {
                return sweep - entry.second->activity > std::chrono::seconds(60);
            });
        }
    }
}
}

int main(int argc, char** argv) {
    using namespace winlin;
    if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
        std::cout << "winlin-server --cert certificate.pem --key private.key --token-file pairing-token\n"
                     "  [--bind 127.0.0.1] [--port 8443] [--workers 8] [--backend openssl|ktls]\n"
                     "  [--cipher TLS_AES_128_GCM_SHA256] [--max-connections 32768]\n"
                     "  [--session-file path] (default: TOKEN-FILE.session)\n";
        return 0;
    }
    try {
        std::signal(SIGPIPE, SIG_IGN);
        std::signal(SIGINT, on_signal);
        std::signal(SIGTERM, on_signal);
        Args args(argc, argv);
        args.allow({"--cert", "--key", "--token-file", "--bind", "--port", "--workers",
                    "--backend", "--cipher", "--max-connections", "--session-file"});
        Server server(args);
        auto port = static_cast<unsigned>(number(args.get("--port", "8443"), 65535));
        const auto workers = server.config.workers;
        std::vector<Fd> listeners;
        for (unsigned i = 0; i < workers; ++i)
            listeners.push_back(listener(args.get("--bind", "127.0.0.1"), port));
        std::mutex error_mutex;
        std::string failure;
        std::vector<std::jthread> threads;
        try {
            for (auto& fd : listeners) {
                threads.emplace_back([&, owned = std::move(fd)]() mutable {
                    try { serve(server, std::move(owned)); }
                    catch (const std::exception& error) {
                        std::lock_guard lock(error_mutex);
                        failure = error.what();
                        server.stop = true;
                    }
                });
            }
        } catch (...) {
            server.stop = true;
            throw;
        }
        std::cout << Json{{"event", "listening"}, {"port", port},
            {"backend", server.ktls ? "openssl-ktls" : "openssl"}, {"workers", workers}}.dump()
                  << std::endl;
        threads.clear();
        if (!failure.empty()) throw std::runtime_error(failure);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "winlin-server: " << error.what() << '\n';
        return 1;
    }
}
