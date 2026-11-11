#include "winlin/windows.hpp"
#include "winlin/agent.hpp"

#include <cstddef>
#include <cstring>
#include <http.h>
#include <iostream>

namespace {
using namespace winlin;
HANDLE stop_event{};
BOOL WINAPI on_console(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && event != CTRL_CLOSE_EVENT) return FALSE;
    return stop_event && SetEvent(stop_event);
}

void check(ULONG result, const char* operation) {
    if (result != NO_ERROR) throw windows_error(operation, result);
}

struct HttpApi {
    HttpApi() { check(HttpInitialize(HTTPAPI_VERSION{2, 0}, HTTP_INITIALIZE_SERVER, nullptr), "HttpInitialize"); }
    ~HttpApi() { HttpTerminate(HTTP_INITIALIZE_SERVER, nullptr); }
};
struct Winsock {
    Winsock() {
        WSADATA data{};
        const auto result = WSAStartup(MAKEWORD(2, 2), &data);
        if (result) throw windows_error("WSAStartup", result);
    }
    ~Winsock() { WSACleanup(); }
};
struct Queue {
    HANDLE value{};
    ~Queue() { if (value) HttpCloseRequestQueue(value); }
};
struct ServerSession {
    HTTP_SERVER_SESSION_ID value{};
    ~ServerSession() { if (value) HttpCloseServerSession(value); }
};
struct UrlGroup {
    HTTP_URL_GROUP_ID value{};
    ~UrlGroup() { if (value) HttpCloseUrlGroup(value); }
};

AgentConfig windows_config(const Args& args) {
    if (args.get("--backend", "httpsys") != "httpsys")
        throw std::invalid_argument("Windows backend must be httpsys (HTTP.sys/Schannel)");
    auto config = AgentConfig::from_args(args, "httpsys-schannel");
    if (config.cipher != "TLS_AES_128_GCM_SHA256" && config.cipher != "TLS_AES_256_GCM_SHA384")
        throw std::invalid_argument("Schannel backend supports TLS_AES_128_GCM_SHA256 or TLS_AES_256_GCM_SHA384");
    config.environment = environment();
    config.connection_metrics = false;
    config.unavailable_metrics.insert(config.unavailable_metrics.end(),
        {"accepted_connections", "active_connections", "tls_handshakes",
         "voluntary_context_switches", "involuntary_context_switches", "kernel_tls_cpu_attribution"});
    config.process_cpu_scope = "application process only; excludes HTTP.sys/Schannel work charged to System";
    return config;
}

// MinGW's HTTP header predates this Win8 ABI; MSVC uses the current SDK definition.
#ifdef __MINGW32__
struct SslProtocolInfo {
    ULONG Protocol, CipherType, CipherStrength, HashType, HashStrength, KeyExchangeType, KeyExchangeStrength;
};
#else
using SslProtocolInfo = HTTP_SSL_PROTOCOL_INFO;
#endif

ConnectionInfo connection_info(const HTTP_REQUEST& request) {
    if (!request.pSslInfo) throw std::invalid_argument("HTTPS is required");
    for (USHORT index = 0; index < request.RequestInfoCount; ++index) {
        const auto& information = request.pRequestInfo[index];
        if (static_cast<unsigned>(information.InfoType) != 2 || information.InfoLength < sizeof(SslProtocolInfo) ||
            !information.pInfo) continue;
        const auto& ssl = *static_cast<const SslProtocolInfo*>(information.pInfo);
        if (!(ssl.Protocol & 0x3000)) throw std::invalid_argument("TLS 1.3 is required");
        // Schannel's TLS 1.3 AES suites are AES-GCM; match its negotiated ALG_ID and key size.
        if ((ssl.CipherType == 0x660e || ssl.CipherType == 0x6611) && ssl.CipherStrength == 128)
            return {"TLSv1.3", "TLS_AES_128_GCM_SHA256"};
        if ((ssl.CipherType == 0x6610 || ssl.CipherType == 0x6611) && ssl.CipherStrength == 256)
            return {"TLSv1.3", "TLS_AES_256_GCM_SHA384"};
        throw std::invalid_argument("Cannot verify negotiated Schannel cipher");
    }
    throw std::invalid_argument("HTTP.sys did not expose negotiated TLS protocol information");
}

HttpHead request_head(const HTTP_REQUEST& request) {
    std::string method;
    switch (request.Verb) {
        case HttpVerbGET: method = "GET"; break;
        case HttpVerbPUT: method = "PUT"; break;
        case HttpVerbPOST: method = "POST"; break;
        default: method = "UNSUPPORTED"; break;
    }
    std::string text = method + " " + std::string(request.pRawUrl, request.RawUrlLength) +
        " HTTP/" + std::to_string(request.Version.MajorVersion) + "." +
        std::to_string(request.Version.MinorVersion) + "\r\n";
    const std::array<std::pair<HTTP_HEADER_ID, const char*>, 5> names{{
        {HttpHeaderHost, "Host"}, {HttpHeaderAuthorization, "Authorization"},
        {HttpHeaderContentLength, "Content-Length"}, {HttpHeaderConnection, "Connection"},
        {HttpHeaderTransferEncoding, "Transfer-Encoding"}}};
    for (const auto& [id, name] : names) {
        const auto& header = request.Headers.KnownHeaders[id];
        if (header.pRawValue)
            text += std::string(name) + ": " + std::string(header.pRawValue, header.RawValueLength) + "\r\n";
    }
    text += "\r\n";
    return parse_head(text);
}

struct Runtime;
struct Request {
    struct Operation {
        OVERLAPPED overlapped{};
        Request* request{};
        ULONG immediate_error{};
    } operation;
    Runtime& runtime;
    enum class State { receive, body, send } state{State::receive};
    std::vector<std::max_align_t> storage;
    std::array<char, 16384> body_buffer{};
    HTTP_REQUEST_ID id{};
    AgentReply reply;
    std::size_t remaining{};
    HTTP_RESPONSE response{};
    HTTP_DATA_CHUNK chunk{};
    std::array<HTTP_UNKNOWN_HEADER, 2> extra_headers{};
    HTTP_CACHE_POLICY cache_policy{HttpCachePolicyNocache, 0};
    std::string content_length;

    explicit Request(Runtime& owner);
    ~Request();
    HTTP_REQUEST* header() { return reinterpret_cast<HTTP_REQUEST*>(storage.data()); }
    void receive();
    void read_body();
    void send();
    void complete(ULONG error, DWORD bytes) noexcept;
    void submitted(ULONG result);
};
static_assert(offsetof(Request::Operation, overlapped) == 0);

struct Runtime {
    Agent agent;
    std::vector<char> payload{std::vector<char>(max_object_size)};
    HttpApi api;
    Queue queue;
    ServerSession session;
    UrlGroup group;
    Handle completion_port;
    Handle stopping_event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::atomic<bool> stopping{};
    std::atomic<unsigned> live{};
    std::mutex failure_mutex;
    std::string failure;
    std::vector<std::jthread> threads;
    std::string stop_file;
    std::string address;
    unsigned port{};

    explicit Runtime(const Args& args)
        : agent(windows_config(args), token_file(args.require("--token-file")),
                optional_token_file(args.get("--session-file", args.require("--token-file") + ".session")),
                [path = args.get("--session-file", args.require("--token-file") + ".session")] {
                    return issue_token_file(path);
                }, equal_secret, usage),
          stop_file(args.get("--stop-file")), address(args.get("--bind", "127.0.0.1")),
          port(static_cast<unsigned>(number(args.get("--port", "8443"), 65535))) {
        if (!port) throw std::invalid_argument("HTTP.sys requires an explicitly bound nonzero port");
        IN_ADDR ip{};
        if (InetPtonA(AF_INET, address.c_str(), &ip) != 1 || address == "0.0.0.0")
            throw std::invalid_argument("--bind must be a specific numeric IPv4 address, not a wildcard");
        if (!stopping_event.value) throw windows_error("CreateEvent");
        if (!stop_file.empty() && GetFileAttributesW(wide(stop_file).c_str()) != INVALID_FILE_ATTRIBUTES)
            throw std::invalid_argument("Stop file already exists; choose a fresh path");
        randomize(payload);
        check(HttpCreateRequestQueue(HTTPAPI_VERSION{2, 0}, nullptr, nullptr, 0, &queue.value), "HttpCreateRequestQueue");
        check(HttpCreateServerSession(HTTPAPI_VERSION{2, 0}, &session.value, 0), "HttpCreateServerSession");
        check(HttpCreateUrlGroup(session.value, &group.value, 0), "HttpCreateUrlGroup");
        HTTP_BINDING_INFO binding{};
        binding.Flags.Present = 1;
        binding.RequestQueueHandle = queue.value;
        check(HttpSetUrlGroupProperty(group.value, HttpServerBindingProperty, &binding, sizeof(binding)),
              "Bind HTTP.sys request queue");
        HTTP_CONNECTION_LIMIT_INFO limit{};
        limit.Flags.Present = 1;
        limit.MaxConnections = agent.config.connection_limit;
        HTTP_QOS_SETTING_INFO qos{HttpQosSettingTypeConnectionLimit, &limit};
        check(HttpSetUrlGroupProperty(group.value, HttpServerQosProperty, &qos, sizeof(qos)),
              "Set connection limit");
        ULONG queue_length = agent.config.connection_limit;
        check(HttpSetRequestQueueProperty(queue.value, HttpServerQueueLengthProperty,
                                         &queue_length, sizeof(queue_length), 0, nullptr),
              "Set request queue length");
        HTTP_TIMEOUT_LIMIT_INFO timeouts{};
        timeouts.Flags.Present = 1;
        timeouts.EntityBody = timeouts.DrainEntityBody = timeouts.RequestQueue = 60;
        timeouts.IdleConnection = timeouts.HeaderWait = 60;
        timeouts.MinSendRate = std::numeric_limits<ULONG>::max();
        check(HttpSetUrlGroupProperty(group.value, HttpServerTimeoutsProperty, &timeouts, sizeof(timeouts)),
              "Set HTTP.sys timeouts");
        const auto url = wide("https://" + address + ":" + std::to_string(port) + "/");
        check(HttpAddUrlToUrlGroup(group.value, url.c_str(), 0, 0),
              "Register HTTPS URL (check URL ACL and certificate binding)");
        completion_port.value = CreateIoCompletionPort(queue.value, nullptr, 0, agent.config.workers);
        if (!completion_port.value) throw windows_error("CreateIoCompletionPort");
    }

    ~Runtime() {
        shutdown();
        threads.clear();
    }
    void shutdown() {
        if (!stopping.exchange(true)) {
            HttpShutdownRequestQueue(queue.value);
            CancelIoEx(queue.value, nullptr);
        }
    }
    void fail(const std::string& message) {
        {
            std::lock_guard lock(failure_mutex);
            if (failure.empty()) failure = message;
        }
        SetEvent(stopping_event.value);
    }
    void accept() {
        if (!stopping) (new Request(*this))->receive();
    }
    void worker() {
        while (!stopping || live.load() != 0) {
            DWORD bytes{};
            ULONG_PTR key{};
            OVERLAPPED* overlapped{};
            const BOOL success = GetQueuedCompletionStatus(completion_port.value, &bytes, &key, &overlapped, 100);
            if (!overlapped) {
                if (!success && GetLastError() != WAIT_TIMEOUT) {
                    fail("GetQueuedCompletionStatus failed");
                    return;
                }
                continue;
            }
            auto* operation = reinterpret_cast<Request::Operation*>(overlapped);
            const auto error = operation->immediate_error ? operation->immediate_error :
                               success ? NO_ERROR : GetLastError();
            operation->request->complete(error, bytes);
        }
    }
    void run() {
        try {
            for (unsigned i = 0; i < agent.config.workers; ++i)
                threads.emplace_back([this] { worker(); });
            for (unsigned i = 0; i < agent.config.workers * 4; ++i) accept();
            stop_event = stopping_event.value;
            SetConsoleCtrlHandler(on_console, TRUE);
            std::cout << Json{{"event", "listening"}, {"port", port}, {"backend", agent.config.backend},
                              {"workers", agent.config.workers}}.dump() << std::endl;
            while (WaitForSingleObject(stopping_event.value, 100) == WAIT_TIMEOUT) {
                if (!stop_file.empty() && GetFileAttributesW(wide(stop_file).c_str()) != INVALID_FILE_ATTRIBUTES)
                    SetEvent(stopping_event.value);
            }
            SetConsoleCtrlHandler(on_console, FALSE);
            stop_event = nullptr;
            shutdown();
            threads.clear();
            if (!failure.empty()) throw std::runtime_error(failure);
        } catch (...) {
            SetConsoleCtrlHandler(on_console, FALSE);
            stop_event = nullptr;
            shutdown();
            throw;
        }
    }
};

Request::Request(Runtime& owner)
    : runtime(owner), storage((65536 + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t)) {
    operation.request = this;
    ++runtime.live;
}
Request::~Request() { --runtime.live; }

void Request::submitted(ULONG result) {
    if (result != NO_ERROR && result != ERROR_IO_PENDING) {
        operation.immediate_error = result;
        if (!PostQueuedCompletionStatus(runtime.completion_port.value, 0, 0, &operation.overlapped)) {
            runtime.fail("Cannot enqueue HTTP.sys I/O error");
            delete this;
        }
    }
}
void Request::receive() {
    state = State::receive;
    operation.overlapped = {};
    operation.immediate_error = 0;
    submitted(HttpReceiveHttpRequest(runtime.queue.value, HTTP_NULL_ID, 0, header(),
        static_cast<ULONG>(storage.size() * sizeof(std::max_align_t)), nullptr, &operation.overlapped));
}
void Request::read_body() {
    if (!remaining) {
        ++runtime.agent.puts;
        runtime.agent.put_bytes += reply.size;
        const auto close = reply.close;
        reply = AgentReply{};
        reply.close = close;
        send();
        return;
    }
    state = State::body;
    operation.overlapped = {};
    operation.immediate_error = 0;
    submitted(HttpReceiveRequestEntityBody(runtime.queue.value, id, 0, body_buffer.data(),
        static_cast<ULONG>(std::min(body_buffer.size(), remaining)), nullptr, &operation.overlapped));
}
void Request::send() {
    state = State::send;
    response = {};
    response.Version = HTTP_VERSION{1, 1};
    response.StatusCode = static_cast<USHORT>(reply.status);
    response.pReason = reply.status == 200 ? "OK" : "Error";
    response.ReasonLength = static_cast<USHORT>(std::strlen(response.pReason));
    const auto size = reply.kind == AgentReply::Kind::object ? reply.size : reply.text.size();
    content_length = std::to_string(size);
    auto field = [&](HTTP_HEADER_ID id, const char* value, std::size_t length) {
        response.Headers.KnownHeaders[id].pRawValue = value;
        response.Headers.KnownHeaders[id].RawValueLength = static_cast<USHORT>(length);
    };
    field(HttpHeaderContentLength, content_length.data(), content_length.size());
    const char* content_type = reply.kind == AgentReply::Kind::object ?
        "application/octet-stream" : "application/json";
    field(HttpHeaderContentType, content_type, std::strlen(content_type));
    field(HttpHeaderCacheControl, "no-store", 8);
    const char* connection = reply.close ? "close" : "keep-alive";
    field(HttpHeaderConnection, connection, std::strlen(connection));
    extra_headers[0] = {16, 1, "X-Winlin-Ktls-Tx", "0"};
    extra_headers[1] = {16, 1, "X-Winlin-Ktls-Rx", "0"};
    extra_headers[0].NameLength = static_cast<USHORT>(std::strlen(extra_headers[0].pName));
    extra_headers[1].NameLength = static_cast<USHORT>(std::strlen(extra_headers[1].pName));
    response.Headers.UnknownHeaderCount = static_cast<USHORT>(extra_headers.size());
    response.Headers.pUnknownHeaders = extra_headers.data();
    if (size) {
        chunk = {};
        chunk.DataChunkType = HttpDataChunkFromMemory;
        chunk.FromMemory.pBuffer = reply.kind == AgentReply::Kind::object ?
            runtime.payload.data() : reply.text.data();
        chunk.FromMemory.BufferLength = static_cast<ULONG>(size);
        response.EntityChunkCount = 1;
        response.pEntityChunks = &chunk;
    }
    operation.overlapped = {};
    operation.immediate_error = 0;
    submitted(HttpSendHttpResponse(runtime.queue.value, id,
        reply.close ? HTTP_SEND_RESPONSE_FLAG_DISCONNECT : 0, &response, &cache_policy,
        nullptr, nullptr, 0, &operation.overlapped, nullptr));
}
void Request::complete(ULONG error, DWORD bytes) noexcept {
    try {
        if (state == State::receive) {
            id = header()->RequestId;
            if (error == ERROR_INVALID_PARAMETER || error == ERROR_INVALID_HANDLE ||
                error == ERROR_NOT_ENOUGH_MEMORY) {
                runtime.fail(windows_error("HttpReceiveHttpRequest", error).what());
            } else runtime.accept();
        }
        if (runtime.stopping || error != NO_ERROR) {
            if (id) HttpCancelHttpRequest(runtime.queue.value, id, nullptr);
            delete this;
            return;
        }
        if (state == State::receive) {
            try { reply = runtime.agent.request(request_head(*header()), connection_info(*header())); }
            catch (const std::invalid_argument& failure) { reply = AgentReply::error(400, failure.what()); }
            if (reply.kind == AgentReply::Kind::consume_put) {
                remaining = reply.size;
                read_body();
            } else send();
        } else if (state == State::body) {
            if (!bytes || bytes > remaining) {
                reply = AgentReply::error(400, "Incomplete PUT body");
                send();
            } else {
                remaining -= bytes;
                read_body();
            }
        } else {
            if (reply.kind == AgentReply::Kind::object) {
                ++runtime.agent.gets;
                runtime.agent.get_bytes += reply.size;
            }
            delete this;
        }
    } catch (const std::exception& failure) {
        runtime.fail(failure.what());
        if (id) HttpCancelHttpRequest(runtime.queue.value, id, nullptr);
        delete this;
    }
}
}

int wmain(int argc, wchar_t** argv) {
    using namespace winlin;
    if (argc == 1 || (argc == 2 && std::wstring_view(argv[1]) == L"--help")) {
        std::cout <<
            "winlin-server --token-file pairing-token [--bind 127.0.0.1] [--port 8443]\n"
            "  [--workers 8] [--backend httpsys] [--cipher TLS_AES_128_GCM_SHA256]\n"
            "  [--max-connections 32768] [--session-file path] [--stop-file path]\n"
            "Configure the HTTP.sys certificate binding and URL ACL using scripts/setup-server.ps1 first.\n";
        return 0;
    }
    try {
        Winsock winsock;
        std::vector<std::string> values;
        for (int i = 0; i < argc; ++i) values.push_back(utf8(argv[i]));
        std::vector<char*> arguments;
        for (auto& value : values) arguments.push_back(value.data());
        Args args(argc, arguments.data());
        args.allow({"--token-file", "--bind", "--port", "--workers", "--backend",
                    "--cipher", "--max-connections", "--session-file", "--stop-file"});
        Runtime server(args);
        server.run();
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << "winlin-server: " << failure.what() << '\n';
        return 1;
    }
}
