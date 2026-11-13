#include "winlin/windows.hpp"
#include "winlin/agent.hpp"

#include <cstddef>
#include <condition_variable>
#include <cstring>
#include <http.h>
#include <iostream>

namespace {
using namespace winlin;
HANDLE stop_event{};

// Ask the control runtime to stop on supported console signals. The controller thread performs
// shutdown; this callback does not cancel requests or release their buffers itself.
BOOL WINAPI on_console(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && event != CTRL_CLOSE_EVENT) {
        return FALSE;
    }
    return stop_event && SetEvent(stop_event);
}

// Turn a failed HTTP Server API call into an exception with the operation and Windows error code.
void check(ULONG result, const char* operation) {
    if (result != NO_ERROR) {
        throw windows_error(operation, result);
    }
}

// Initialize the HTTP Server API for a Runtime and release that initialization when it is
// destroyed. Its request queue, URL group, and server session require the API to remain
// initialized. Runtime declares this member before those handles so reverse member destruction
// closes the dependent handles first. Worker threads must already be joined before member cleanup
// begins.
struct HttpApi {
    HttpApi() {
        check(HttpInitialize(HTTPAPI_VERSION{2, 0}, HTTP_INITIALIZE_SERVER, nullptr),
              "HttpInitialize");
    }

    ~HttpApi() {
        const auto result = HttpTerminate(HTTP_INITIALIZE_SERVER, nullptr);
        if (result != NO_ERROR) {
            log_warning(windows_error("HttpTerminate", result).what());
        }
    }
};

// Keep Winsock initialized for numeric address conversion and the exclusive server-guard socket.
// Main creates this before those users and destroys it after them. HTTP.sys handles benchmark
// connections itself; Winsock here does not provide an alternative workload transport.
struct Winsock {
    Winsock() {
        WSADATA data{};
        const auto result = WSAStartup(MAKEWORD(2, 2), &data);
        if (result) {
            throw windows_error("WSAStartup", result);
        }
    }

    ~Winsock() {
        if (WSACleanup() != 0) {
            log_warning(windows_error("WSACleanup", WSAGetLastError()).what());
        }
    }
};

// Prevent another Winlin server from starting on this machine by reserving the same loopback port
// as the Linux implementation. This socket carries no traffic and is separate from HTTP.sys.
// Exclusive address ownership is intentional: unlike workload listeners, this reservation must
// not be shared. Main keeps it alive through runtime shutdown, with Winsock outliving the socket.
struct ServerGuard {
    SOCKET value{INVALID_SOCKET};

    // Acquire exclusive ownership before constructing the HTTPS runtime; undo partial setup on
    // error.
    ServerGuard() {
        value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (value == INVALID_SOCKET) {
            throw windows_error("Create server guard socket", WSAGetLastError());
        }
        try {
            const BOOL exclusive = TRUE;
            if (setsockopt(value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                           reinterpret_cast<const char*>(&exclusive), sizeof(exclusive))) {
                throw windows_error("SO_EXCLUSIVEADDRUSE for server guard", WSAGetLastError());
            }
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = htons(server_guard_port);
            if (bind(value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
                listen(value, 1)) {
                const auto error = WSAGetLastError();
                throw windows_error(
                    "Cannot reserve exclusive server guard on 127.0.0.1:" +
                        std::to_string(server_guard_port) +
                        "; another Winlin server or application may already own this port",
                    error);
            }
        } catch (...) {
            release();
            throw;
        }
    }

    // Release the reservation only after the native HTTPS runtime has finished shutting down.
    ~ServerGuard() {
        release();
    }

    ServerGuard(const ServerGuard&) = delete;
    ServerGuard& operator=(const ServerGuard&) = delete;

private:
    // Preserve the original startup failure if closing a partially configured socket also fails.
    void release() {
        if (value != INVALID_SOCKET && closesocket(value) != 0) {
            log_warning(windows_error("Close server guard socket", WSAGetLastError()).what());
        }
        value = INVALID_SOCKET;
    }
};

// Own the handle through which HTTP.sys delivers requests and accepts asynchronous response I/O.
// Runtime associates this queue with its completion port and URL group. Before this handle closes,
// workers must process every outstanding completion so no operation still references request data.
struct Queue {
    HANDLE value{};

    ~Queue() {
        if (value) {
            const auto result = HttpCloseRequestQueue(value);
            if (result != NO_ERROR) {
                log_warning(windows_error("HttpCloseRequestQueue", result).what());
            }
        }
    }
};

// Own an HTTP Server API configuration session. This is not a TCP connection or a client request:
// it groups the URL configuration used by a Runtime. Its URL groups must be closed before the
// session itself, so Runtime declares this member before its UrlGroup.
struct ServerSession {
    HTTP_SERVER_SESSION_ID value{};

    ~ServerSession() {
        if (value) {
            const auto result = HttpCloseServerSession(value);
            if (result != NO_ERROR) {
                log_warning(windows_error("HttpCloseServerSession", result).what());
            }
        }
    }
};

// Own the URL group that binds this Runtime's endpoint to its request queue. HTTP.sys routes
// matching requests through that binding. Closing the group removes this Runtime's registered
// URLs, but does not remove the machine's pre-provisioned URL reservations or certificate bindings.
struct UrlGroup {
    HTTP_URL_GROUP_ID value{};

    ~UrlGroup() {
        if (value) {
            const auto result = HttpCloseUrlGroup(value);
            if (result != NO_ERROR) {
                log_warning(windows_error("HttpCloseUrlGroup", result).what());
            }
        }
    }
};

// Describe the permanent HTTP control endpoint and the native Windows workload backends.
// HTTP.sys/Schannel handles connections and TLS outside this application, so unavailable connection
// metrics stay unavailable and process CPU telemetry must not be mistaken for whole-server cost.
AgentConfig windows_config() {
    auto config = AgentConfig::control_config("httpsys");
    config.benchmark_tls_modes = {"on", "off"};
    config.supported_backends = {
        {{"name", "httpsys"}, {"transport", "http"}, {"tls_mode", "off"}},
        {{"name", "httpsys-schannel"}, {"transport", "https"}, {"tls_mode", "on"}}};
    config.environment = environment();
    config.connection_metrics = false;
    std::erase(config.unavailable_metrics, "hardware_cycles");
    config.unavailable_metrics.insert(config.unavailable_metrics.end(),
                                      {"accepted_connections", "active_connections",
                                       "tls_handshakes", "voluntary_context_switches",
                                       "involuntary_context_switches",
                                       "kernel_tls_cpu_attribution"});
    config.process_cpu_scope =
        "application process only; excludes HTTP.sys/Schannel work charged to System";
    return config;
}

// Prepare a temporary workload using the client's requested transport, cipher, and worker count.
// Reject unsupported settings rather than silently substituting a different backend. This changes
// only the workload configuration; the permanent control endpoint remains plain HTTP.
AgentConfig workload_config(const AgentConfig& host, const BenchmarkOptions& options) {
    if (options.tls == "ktls") {
        throw BenchmarkError(501, "Windows HTTP.sys/Schannel does not support kTLS");
    }
    if (options.tls != "on" && options.tls != "off") {
        throw std::invalid_argument("Windows TLS mode must be on or off");
    }
    if (options.tls == "on" && options.cipher != "TLS_AES_128_GCM_SHA256" &&
        options.cipher != "TLS_AES_256_GCM_SHA384") {
        throw std::invalid_argument("Unsupported Schannel TLS 1.3 cipher");
    }
    auto config = host;
    config.role = AgentConfig::Role::workload;
    config.tls = options.tls == "on";
    config.backend = config.tls ? "httpsys-schannel" : "httpsys";
    config.cipher = options.cipher;
    config.workers = options.workers;
    return config;
}

// Generate an ephemeral run bearer without creating or changing any host credential file.
std::string issue_run_id() {
    std::array<char, 32> bytes{};
    randomize(bytes);
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (unsigned char byte : bytes) {
        result += hex[byte >> 4];
        result += hex[byte & 15];
    }
    return result;
}

// Match the Windows SDK layout for negotiated TLS metadata when cross-building with MinGW,
// whose HTTP header lacks this definition. MSVC uses the SDK's own structure instead.
#ifdef __MINGW32__
struct SslProtocolInfo {
    ULONG Protocol, CipherType, CipherStrength, HashType, HashStrength, KeyExchangeType,
        KeyExchangeStrength;
};
#else
using SslProtocolInfo = HTTP_SSL_PROTOCOL_INFO;
#endif

// Extract and validate the TLS protocol and cipher that HTTP.sys reports for this request.
// A certificate binding or global Schannel policy does not prove what was actually negotiated.
// Reject missing or unsupported metadata before the shared Agent accepts an HTTPS workload.
ConnectionInfo connection_info(const HTTP_REQUEST& request) {
    if (!request.pSslInfo) {
        throw std::invalid_argument("HTTPS is required");
    }
    for (USHORT index = 0; index < request.RequestInfoCount; ++index) {
        const auto& information = request.pRequestInfo[index];
        if (static_cast<unsigned>(information.InfoType) != 2 ||
            information.InfoLength < sizeof(SslProtocolInfo) || !information.pInfo) {
            continue;
        }
        const auto& ssl = *static_cast<const SslProtocolInfo*>(information.pInfo);
        if (!(ssl.Protocol & 0x3000)) {
            throw std::invalid_argument("TLS 1.3 is required");
        }
        // Schannel's TLS 1.3 AES suites are AES-GCM; match its negotiated ALG_ID and key size.
        if ((ssl.CipherType == 0x660e || ssl.CipherType == 0x6611) && ssl.CipherStrength == 128) {
            return {"TLSv1.3", "TLS_AES_128_GCM_SHA256"};
        }
        if ((ssl.CipherType == 0x6610 || ssl.CipherType == 0x6611) && ssl.CipherStrength == 256) {
            return {"TLSv1.3", "TLS_AES_256_GCM_SHA384"};
        }
        throw std::invalid_argument("Cannot verify negotiated Schannel cipher");
    }
    throw std::invalid_argument("HTTP.sys did not expose negotiated TLS protocol information");
}

struct Runtime;
struct RequestCache;

// Carry one HTTP request through an asynchronous receive -> optional body reads -> response send.
// Unlike a Linux Session, this object represents a request, not a persistent client connection.
// HTTP.sys owns the connection and TLS state, including reuse across successive requests.
//
// Runtime posts receives before requests arrive. Each Request submits one operation at a time,
// and an IOCP worker calls complete() when that operation finishes. The next completion may run on
// a different worker thread, even before the submitting callback returns. References keep both
// the submitter and each outstanding completion alive until they finish using this object.
//
// Store headers, body buffers, response structures, and OVERLAPPED state here because HTTP.sys may
// still reference them after an API call returns. The final reference returns this object and its
// buffers to the current worker's bounded cache, or deletes them during shutdown/cache overflow.
// Runtime and its shared GET payload must outlive every reference and every worker cache.
struct Request {
    // IOCP returns the OVERLAPPED pointer submitted to HTTP.sys. Keep it first so the worker can
    // recover this enclosing operation and its Request without a separate lookup table.
    struct Operation {
        OVERLAPPED overlapped{};
        Request* request{};
        ULONG immediate_error{};
    } operation;

    Runtime& runtime;
    std::atomic<unsigned> references{};
    enum class State { receive, body, send } state{State::receive};
    std::vector<std::max_align_t> storage;
    std::array<char, 16384> body_buffer{};
    HTTP_REQUEST_ID id{};
    AgentReply reply;
    // These views borrow storage, never body_buffer; neither receive storage nor its pointers
    // change while this Request advances through body reads and response completion.
    RequestHead parsed_head;
    ConnectionInfo connection;
    std::string control_body;
    std::size_t remaining{};
    HTTP_RESPONSE response{};
    HTTP_DATA_CHUNK chunk{};
    std::array<HTTP_UNKNOWN_HEADER, 2> extra_headers{};
    HTTP_CACHE_POLICY cache_policy{HttpCachePolicyNocache, 0};
    std::string content_length;

    explicit Request(Runtime& owner);

    // View the aligned receive storage as the native request structure filled by HTTP.sys.
    HTTP_REQUEST* header() {
        return reinterpret_cast<HTTP_REQUEST*>(storage.data());
    }

    void prepare();
    void release(RequestCache* cache) noexcept;
    void receive();
    void read_body();
    void send();
    void complete(ULONG error, DWORD bytes, RequestCache& cache) noexcept;
    void submitted(ULONG result);
};

static_assert(offsetof(Request::Operation, overlapped) == 0);

// Retain a small hot set of whole requests, including their 64 KiB receive and 16 KiB body buffers.
// Only the owning IOCP worker accesses this cache, so checkout/return needs no shared pool lock.
// At most 16 idle requests remain per worker: about 1.3 MiB of native/body buffers, plus metadata
// and any retained control JSON capacity. Active requests are not capped here.
// Worker exit destroys idle storage before Runtime joins the thread and releases native handles.
struct RequestCache {
    std::array<std::unique_ptr<Request>, 16> idle;
    std::size_t count{};

    // Transfer an idle request to the caller, or request a fresh allocation when the cache is
    // empty.
    Request* take() noexcept {
        if (!count) {
            return nullptr;
        }
        return idle[--count].release();
    }

    // Take ownership only when there is room; the caller deletes requests that exceed the bound.
    bool put(Request* request) noexcept {
        if (count == idle.size()) {
            return false;
        }
        idle[count++].reset(request);
        return true;
    }
};

// Release one adopted caller/completion reference on every exit path, including exceptions.
// The optional cache belongs to the current thread, not necessarily the request's original worker.
// This deleter recycles only the final reference; it does not necessarily destroy the Request.
struct RequestReleaser {
    RequestCache* cache{};

    // Pair an existing reference with its eventual release, without acquiring another reference.
    void operator()(Request* request) const noexcept {
        request->release(cache);
    }
};

using RequestReference = std::unique_ptr<Request, RequestReleaser>;

// Run either the permanent control endpoint or one temporary workload using native HTTP.sys.
// Agent supplies common routing and telemetry. HTTP.sys owns HTTP framing, client connections,
// and Schannel TLS processing; application workers consume completions from one shared IOCP queue.
//
// The controller thread calls run(), which starts completion workers and posts several pending
// request receives. A completed header receive normally posts a replacement receive so requests
// can keep arriving while earlier requests read bodies or send responses.
//
// Shutdown first prevents new request receives and cancels queued I/O. Workers keep processing
// completion packets until live reaches zero, meaning no request has a caller or completion
// reference. Workers then destroy their idle caches. Join them before closing HTTP.sys/IOCP
// handles or destroying the shared GET payload.
// Process telemetry covers this application only, not kernel HTTP.sys/Schannel work charged to
// System.
struct Runtime {
    Agent agent;
    std::vector<char> payload;
    HttpApi api;
    Queue queue;
    ServerSession session;
    UrlGroup group;
    Handle completion_port;
    Handle stopping_event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::atomic<bool> stopping{};
    std::atomic<unsigned> live{};
    mutable std::mutex failure_mutex;
    std::string failure;
    std::vector<std::jthread> threads;
    std::string stop_file;
    std::string address;
    unsigned port{};

    // Create the control endpoint from local settings. It has no synthetic GET payload.
    explicit Runtime(const Args& args)
        : agent(windows_config(), usage, {}, host_usage), stop_file(args.get("--stop-file")),
          address(args.get("--bind", "127.0.0.1")),
          port(static_cast<unsigned>(number(args.get("--port", "38080"), 65535))) {
        initialize();
    }

    // Create a workload with its own queue, workers, and reusable GET payload. It uses the same
    // native engine as control, but has a separate endpoint and an in-memory run lease.
    Runtime(AgentConfig config, const std::string& run_id, std::string bind_address,
            unsigned bind_port)
        : agent(std::move(config), usage, run_id, host_usage), payload(max_object_size),
          address(std::move(bind_address)), port(bind_port) {
        initialize();
    }

    // Configure native request routing, limits, timeouts, and completion delivery before workers
    // start. URL permissions and HTTPS certificate bindings must already have been provisioned;
    // this method registers a URL but does not modify machine-wide certificate policy.
    void initialize() {
        if (!port) {
            throw std::invalid_argument("HTTP.sys requires an explicitly bound nonzero port");
        }
        IN_ADDR ip{};
        if (InetPtonA(AF_INET, address.c_str(), &ip) != 1 || address == "0.0.0.0") {
            throw std::invalid_argument(
                "--bind must be a specific numeric IPv4 address, not a wildcard");
        }
        if (!stopping_event.value) {
            throw windows_error("CreateEvent");
        }
        if (!stop_file.empty() &&
            GetFileAttributesW(wide(stop_file).c_str()) != INVALID_FILE_ATTRIBUTES) {
            throw std::invalid_argument("Stop file already exists; choose a fresh path");
        }
        if (!payload.empty()) {
            randomize(payload);
        }
        // Bind this endpoint's URL group to its request queue. Keep configuration handles as
        // members so they remain valid through request processing and orderly shutdown.
        check(HttpCreateRequestQueue(HTTPAPI_VERSION{2, 0}, nullptr, nullptr, 0, &queue.value),
              "HttpCreateRequestQueue");
        check(HttpCreateServerSession(HTTPAPI_VERSION{2, 0}, &session.value, 0),
              "HttpCreateServerSession");
        check(HttpCreateUrlGroup(session.value, &group.value, 0), "HttpCreateUrlGroup");
        HTTP_BINDING_INFO binding{};
        binding.Flags.Present = 1;
        binding.RequestQueueHandle = queue.value;
        check(HttpSetUrlGroupProperty(group.value, HttpServerBindingProperty, &binding,
                                      sizeof(binding)),
              "Bind HTTP.sys request queue");
        // Apply limits in HTTP.sys itself, since the application does not accept TCP sockets.
        // Native timeouts also cover header/body receipt, queue waits, and idle connections.
        HTTP_CONNECTION_LIMIT_INFO limit{};
        limit.Flags.Present = 1;
        limit.MaxConnections = agent.config.connection_limit;
        HTTP_QOS_SETTING_INFO qos{HttpQosSettingTypeConnectionLimit, &limit};
        check(HttpSetUrlGroupProperty(group.value, HttpServerQosProperty, &qos, sizeof(qos)),
              "Set connection limit");
        ULONG queue_length = agent.config.connection_limit;
        check(HttpSetRequestQueueProperty(queue.value, HttpServerQueueLengthProperty, &queue_length,
                                          sizeof(queue_length), 0, nullptr),
              "Set request queue length");
        HTTP_TIMEOUT_LIMIT_INFO timeouts{};
        timeouts.Flags.Present = 1;
        timeouts.EntityBody = timeouts.DrainEntityBody = timeouts.RequestQueue = 60;
        timeouts.IdleConnection = timeouts.HeaderWait = 60;
        timeouts.MinSendRate = std::numeric_limits<ULONG>::max();
        check(HttpSetUrlGroupProperty(group.value, HttpServerTimeoutsProperty, &timeouts,
                                      sizeof(timeouts)),
              "Set HTTP.sys timeouts");
        const auto url = wide(std::string(agent.config.tls ? "https://" : "http://") + address +
                              ":" + std::to_string(port) + "/");
        check(HttpAddUrlToUrlGroup(group.value, url.c_str(), 0, 0),
              "Register HTTP.sys URL (check URL ACL and, for HTTPS, certificate binding)");
        // Deliver asynchronous queue operations to the shared completion port. Workers recover
        // the owning Request from each completed operation rather than polling socket readiness.
        completion_port.value =
            CreateIoCompletionPort(queue.value, nullptr, 0, agent.config.workers);
        if (!completion_port.value) {
            throw windows_error("CreateIoCompletionPort");
        }
    }

    // Cancel outstanding I/O and join workers before member destruction closes native handles.
    ~Runtime() {
        shutdown();
        threads.clear();
    }

    // Request shutdown once, even if both normal teardown and failure recovery call this method.
    // Cancellation does not free Request objects here; completion workers perform that cleanup.
    void shutdown() {
        if (!stopping.exchange(true)) {
            const auto result = HttpShutdownRequestQueue(queue.value);
            if (result != NO_ERROR) {
                log_warning(windows_error("HttpShutdownRequestQueue", result).what());
            }
            if (!CancelIoEx(queue.value, nullptr) && GetLastError() != ERROR_NOT_FOUND) {
                log_warning(windows_error("CancelIoEx").what());
            }
        }
    }

    // Preserve the first fatal worker error and wake the controller to begin shutdown. The
    // controller also checks failure periodically in case signalling the event fails.
    void fail(const std::string& message) {
        {
            std::lock_guard lock(failure_mutex);
            if (failure.empty()) {
                failure = message;
            }
        }
        if (!SetEvent(stopping_event.value)) {
            log_warning(
                windows_error("Cannot signal worker failure; controller will detect it on timeout")
                    .what());
        }
    }

    // Reuse a worker-local context when available, then post an asynchronous HTTP request receive,
    // not a TCP accept. Initial receives have no worker cache. Keep a caller reference until the
    // submission returns, because its IOCP completion may already be running on another worker.
    void accept(RequestCache* cache = nullptr) {
        if (!stopping) {
            auto* request = cache ? cache->take() : nullptr;
            if (!request) {
                request = new Request(*this);
            }
            request->prepare();
            const RequestReference reference(request, RequestReleaser{cache});
            request->receive();
        }
    }

    // Retrieve up to eight ready HTTP.sys completions per call, without waiting to fill a batch.
    // Keep batches small so one worker does not monopolize completion processing. During shutdown,
    // drain every dequeued entry: each still owns a reference even if an earlier entry stops I/O.
    void worker() {
        RequestCache cache;
        std::array<OVERLAPPED_ENTRY, 8> entries;
        while (!stopping || live.load() != 0) {
            ULONG count{};
            if (!GetQueuedCompletionStatusEx(completion_port.value, entries.data(),
                                             static_cast<ULONG>(entries.size()), &count, 100,
                                             FALSE)) {
                const auto error = GetLastError();
                if (error != WAIT_TIMEOUT) {
                    fail(windows_error("GetQueuedCompletionStatusEx", error).what());
                    return;
                }
                continue;
            }

            // Batch success describes dequeueing, not each operation's result. Decode native and
            // synthetic errors separately, preserving each packet's byte count and reference.
            for (ULONG index = 0; index < count; ++index) {
                const auto& entry = entries[index];
                if (!entry.lpOverlapped) {
                    continue;
                }
                auto* operation = reinterpret_cast<Request::Operation*>(entry.lpOverlapped);
                const RequestReference reference(operation->request, RequestReleaser{&cache});
                const auto error =
                    completion_error(queue.value, entry.lpOverlapped, operation->immediate_error);
                reference->complete(error, entry.dwNumberOfBytesTransferred, cache);
            }
        }
    }

    // Start completion workers, post initial request receives, and then announce readiness.
    // The calling controller thread waits for a stop event, stop file, or fatal worker failure.
    // A workload uses its readiness callback without replacing the control console handler.
    // On every exit path, cancel I/O and join workers before returning or propagating failure.
    void run(bool control = true, const std::function<void()>& listening = {}) {
        bool console_registered = false;
        try {
            for (unsigned i = 0; i < agent.config.workers; ++i) {
                threads.emplace_back([this] {
                    worker();
                });
            }
            // Keep several receives pending per worker so arrival processing is not limited to
            // waiting for the previous request's response. Receives share the same native queue.
            for (unsigned i = 0; i < agent.config.workers * 4; ++i) {
                accept();
            }
            {
                std::lock_guard lock(failure_mutex);
                if (!failure.empty()) {
                    throw std::runtime_error(failure);
                }
            }
            if (control) {
                stop_event = stopping_event.value;
                console_registered = SetConsoleCtrlHandler(on_console, TRUE);
                if (!console_registered) {
                    log_warning(
                        windows_error(
                            "Console handler unavailable; use --stop-file for headless shutdown")
                            .what());
                }
                std::cout << Json{{"event", "listening"},
                                  {"port", port},
                                  {"backend", agent.config.backend},
                                  {"workers", agent.config.workers}}
                                 .dump()
                          << std::endl;
            }
            if (listening) {
                listening();
            }
            for (;;) {
                const auto wait = WaitForSingleObject(stopping_event.value, 100);
                if (wait == WAIT_OBJECT_0 || stopping) {
                    break;
                }
                if (wait != WAIT_TIMEOUT) {
                    throw windows_error("WaitForSingleObject");
                }
                {
                    // A broken event signal must not leave the controller waiting after worker
                    // failure.
                    std::lock_guard lock(failure_mutex);
                    if (!failure.empty()) {
                        throw std::runtime_error(failure);
                    }
                }
                if (!stop_file.empty()) {
                    if (GetFileAttributesW(wide(stop_file).c_str()) != INVALID_FILE_ATTRIBUTES) {
                        if (!SetEvent(stopping_event.value)) {
                            throw windows_error("SetEvent");
                        }
                    } else {
                        const auto error = GetLastError();
                        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                            throw windows_error("Cannot inspect stop file", error);
                        }
                    }
                }
            }
            if (console_registered && !SetConsoleCtrlHandler(on_console, FALSE)) {
                log_warning(windows_error("Remove console handler").what());
            }
            console_registered = false;
            if (control) {
                stop_event = nullptr;
            }
            // Stop new receives and drain outstanding completions before inspecting the final
            // failure or allowing Runtime's resources to be destroyed.
            shutdown();
            threads.clear();
            if (!failure.empty()) {
                throw std::runtime_error(failure);
            }
        } catch (...) {
            if (console_registered && !SetConsoleCtrlHandler(on_console, FALSE)) {
                log_warning(windows_error("Remove console handler during shutdown").what());
            }
            if (control) {
                stop_event = nullptr;
            }
            shutdown();
            threads.clear();
            throw;
        }
    }
};

// Allocate receive/body storage once per context, not once per HTTP request on a warm cache.
// Native I/O keeps the same aligned buffer address until the context's final reference is released.
Request::Request(Runtime& owner)
    : runtime(owner), storage((65536 + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t)) {
    operation.request = this;
}

// Reset only per-request metadata after exclusive checkout. Do not clear the large receive/body
// buffers: HTTP.sys writes the returned bytes, and body consumers read only completed byte counts.
// Clear the native request ID explicitly so a failed receive cannot cancel a previous request.
void Request::prepare() {
    id = HTTP_NULL_ID;
    header()->RequestId = HTTP_NULL_ID;
    reply = AgentReply{};
    parsed_head = {};
    connection = {};
    control_body.clear();
    remaining = 0;
    content_length.clear();
    references.store(1, std::memory_order_relaxed);
    ++runtime.live;
}

// Return storage only after every submitting caller and completion has stopped using it.
// The final release may occur on a different worker; use that worker's cache, never a remote one.
// Keep live nonzero through cleanup so shutdown cannot mistake a retiring request for idle work.
void Request::release(RequestCache* cache) noexcept {
    if (references.fetch_sub(1, std::memory_order_acq_rel) != 1) {
        return;
    }
    auto& owner = runtime;
    if (owner.stopping || !cache || !cache->put(this)) {
        delete this;
    }
    --owner.live;
}

// Handle the submission result, not the eventual I/O result. Successful and pending operations
// already produce IOCP packets. An immediate failure has no native packet, so enqueue one to let
// complete() perform the same error handling and cleanup. If enqueueing also fails, no operation
// is pending: drop its completion reference and report a fatal runtime error. The caller still
// owns a reference until the submission returns, so this cannot recycle a context underneath it.
void Request::submitted(ULONG result) {
    if (result != NO_ERROR && result != ERROR_IO_PENDING) {
        RequestReference completion(this, RequestReleaser{});
        operation.immediate_error = result;
        if (PostQueuedCompletionStatus(runtime.completion_port.value, 0, 0,
                                       &operation.overlapped)) {
            completion.release();
        } else {
            runtime.fail("Cannot enqueue HTTP.sys I/O error");
        }
    }
}

// Submit a header receive for the next available request. The storage and operation remain owned
// by this Request until completion, even when the API reports immediate success.
void Request::receive() {
    state = State::receive;
    operation.overlapped = {};
    operation.immediate_error = 0;
    references.fetch_add(1, std::memory_order_relaxed);
    submitted(HttpReceiveHttpRequest(runtime.queue.value, HTTP_NULL_ID, 0, header(),
                                     static_cast<ULONG>(storage.size() * sizeof(std::max_align_t)),
                                     nullptr, &operation.overlapped));
}

// Read the declared body in bounded chunks. PUT bytes are discarded, while control JSON is kept
// for shared dispatch. Only after the complete body arrives may PUT counters advance or the
// control command execute; then submit the response.
void Request::read_body() {
    if (!remaining) {
        if (reply.kind == AgentReply::Kind::consume_control) {
            reply = runtime.agent.request(parsed_head, connection, control_body);
        } else {
            ++runtime.agent.puts;
            runtime.agent.put_bytes += reply.size;
            const auto close = reply.close;
            reply = AgentReply{};
            reply.close = close;
        }
        send();
        return;
    }
    state = State::body;
    operation.overlapped = {};
    operation.immediate_error = 0;
    references.fetch_add(1, std::memory_order_relaxed);
    submitted(
        HttpReceiveRequestEntityBody(runtime.queue.value, id, 0, body_buffer.data(),
                                     static_cast<ULONG>(std::min(body_buffer.size(), remaining)),
                                     nullptr, &operation.overlapped));
}

// Build a native HTTP_RESPONSE and submit it to HTTP.sys, which serializes the wire headers and
// performs the selected transport's send/TLS work. Do not assume the structure determines a fixed
// wire header length. GET data borrows Runtime's immutable payload; JSON data belongs to reply.
//
// Keep all referenced headers, body data, and OVERLAPPED storage alive until send completion.
// Disable caching both in the response and the HTTP.sys cache policy so repeated GETs still use
// the native request/response path rather than cached responses.
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
    const char* content_type =
        reply.kind == AgentReply::Kind::object ? "application/octet-stream" : "application/json";
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
        chunk.FromMemory.pBuffer =
            reply.kind == AgentReply::Kind::object ? runtime.payload.data() : reply.text.data();
        chunk.FromMemory.BufferLength = static_cast<ULONG>(size);
        response.EntityChunkCount = 1;
        response.pEntityChunks = &chunk;
    }
    operation.overlapped = {};
    operation.immediate_error = 0;
    references.fetch_add(1, std::memory_order_relaxed);
    submitted(HttpSendHttpResponse(
        runtime.queue.value, id, reply.close ? HTTP_SEND_RESPONSE_FLAG_DISCONNECT : 0, &response,
        &cache_policy, nullptr, nullptr, 0, &operation.overlapped, nullptr));
}

// Advance this request after one operation completes. Header completion dispatches through Agent,
// body completion consumes bytes and schedules another read or a response, and successful send
// completion records GET counters. The worker releases this callback's reference on return.
//
// Errors and shutdown also end the request, cancelling it in HTTP.sys when an ID is available.
// Catch exceptions here because they must reach the Runtime controller, not escape an IOCP worker.
// A caller reference prevents early reuse while submission unwinds, but does not permit reading
// mutable request fields after another operation is posted: another worker may already own them.
void Request::complete(ULONG error, DWORD bytes, RequestCache& cache) noexcept {
    try {
        if (state == State::receive) {
            // Replace a finished header receive promptly so new requests can arrive while this
            // one is processed. Fatal queue/resource errors instead wake the controller.
            id = header()->RequestId;
            if (error == ERROR_INVALID_PARAMETER || error == ERROR_INVALID_HANDLE ||
                error == ERROR_NOT_ENOUGH_MEMORY) {
                runtime.fail(windows_error("HttpReceiveHttpRequest", error).what());
            } else {
                runtime.accept(&cache);
            }
        }
        if (runtime.stopping || error != NO_ERROR) {
            // Cancellation packets arrive during normal shutdown too. Release this request only
            // now that its outstanding operation has completed; warn on unexpected I/O errors.
            if (!runtime.stopping) {
                log_warning(windows_error("HTTP.sys request I/O failed", error).what());
            }
            if (id) {
                const auto result = HttpCancelHttpRequest(runtime.queue.value, id, nullptr);
                if (result != NO_ERROR && result != ERROR_CONNECTION_INVALID) {
                    log_warning(windows_error("HttpCancelHttpRequest", result).what());
                }
            }
            return;
        }
        if (state == State::receive) {
            // HTTP.sys has parsed the native header. Adapt it to the shared protocol and verify
            // actual TLS metadata before deciding whether to read a body or send a reply.
            try {
                parsed_head = request_head(*header());
                connection =
                    runtime.agent.config.tls ? connection_info(*header()) : ConnectionInfo{};
                reply = runtime.agent.request(parsed_head, connection);
            } catch (const std::invalid_argument& failure) {
                reply = AgentReply::error(400, failure.what());
            }
            if (reply.kind == AgentReply::Kind::consume_put ||
                reply.kind == AgentReply::Kind::consume_control) {
                if (reply.kind == AgentReply::Kind::consume_control) {
                    if (reply.size > 65536) {
                        throw std::logic_error("Control body exceeds native receive limit");
                    }
                    control_body.reserve(reply.size);
                }
                remaining = reply.size;
                read_body();
            } else {
                send();
            }
        } else if (state == State::body) {
            // Reject an incomplete or oversized body chunk. Preserve control JSON, but discard
            // PUT contents after counting how many declared bytes remain.
            if (!bytes || bytes > remaining) {
                reply = AgentReply::error(400, "Incomplete request body");
                send();
            } else {
                // Successful send completion means HTTP.sys finished this response operation,
                // not that the client application has confirmed receipt.
                if (reply.kind == AgentReply::Kind::consume_control) {
                    control_body.append(body_buffer.data(), bytes);
                }
                remaining -= bytes;
                read_body();
            }
        } else {
            if (reply.kind == AgentReply::Kind::object) {
                ++runtime.agent.gets;
                runtime.agent.get_bytes += reply.size;
            }
        }
    } catch (const std::exception& failure) {
        runtime.fail(failure.what());
        if (id) {
            const auto result = HttpCancelHttpRequest(runtime.queue.value, id, nullptr);
            if (result != NO_ERROR && result != ERROR_CONNECTION_INVALID) {
                log_warning(windows_error("HttpCancelHttpRequest after failure", result).what());
            }
        }
    }
}

// Own the temporary Windows workload created by the shared benchmark controller.
// Its controller thread runs a separate Runtime, which in turn manages its IOCP worker threads.
// Construction waits for native readiness or startup failure before advertising the endpoint.
//
// Destruction signals only this workload's stop event and joins its controller before Runtime
// resources are released. The permanent control endpoint and its console handler remain intact.
// Telemetry checks stored controller/worker failures so a stopped workload cannot appear healthy.
class NativeBenchmark final : public BenchmarkInstance {
    Runtime runtime_;
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    bool ready_{}, finished_{};
    std::string error_;
    std::jthread thread_;

public:
    // Wait for either native readiness or failure so start never advertises an unusable listener.
    NativeBenchmark(AgentConfig config, const std::string& run_id, const std::string& address,
                    unsigned port)
        : runtime_(std::move(config), run_id, address, port), thread_([this] {
              try {
                  runtime_.run(false, [this] {
                      {
                          std::lock_guard lock(mutex_);
                          ready_ = true;
                      }
                      changed_.notify_all();
                  });
              } catch (const std::exception& failure) {
                  std::lock_guard lock(mutex_);
                  error_ = failure.what();
              }
              {
                  std::lock_guard lock(mutex_);
                  finished_ = true;
              }
              changed_.notify_all();
          }) {
        std::unique_lock lock(mutex_);
        changed_.wait(lock, [this] {
            return ready_ || finished_;
        });
        if (finished_) {
            throw BenchmarkError(500, "Workload startup failed: " + error_);
        }
    }

    // Stop only this data plane; the permanent control endpoint and console handler remain intact.
    ~NativeBenchmark() override {
        if (!SetEvent(runtime_.stopping_event.value)) {
            log_warning(windows_error("Signal workload shutdown").what());
            runtime_.shutdown();
        }
        thread_.join();
    }

    // Advertise the host-selected port, never a remotely supplied network address or credential.
    Json describe() const override {
        return {{"port", runtime_.port},
                {"transport", runtime_.agent.config.tls ? "https" : "http"},
                {"backend", runtime_.agent.config.backend}};
    }

    // Surface worker/controller failures instead of returning counters for a silently dead run.
    Json telemetry() const override {
        {
            std::lock_guard lock(mutex_);
            if (finished_) {
                throw BenchmarkError(500, "Workload stopped unexpectedly: " + error_);
            }
        }
        {
            std::lock_guard lock(runtime_.failure_mutex);
            if (!runtime_.failure.empty()) {
                throw BenchmarkError(500, "Workload runtime failed: " + runtime_.failure);
            }
        }
        try {
            return runtime_.agent.telemetry();
        } catch (const std::exception& failure) {
            throw BenchmarkError(500, "Workload telemetry failed: " + std::string(failure.what()));
        }
    }
};
}

// Start the permanent HTTP control endpoint and provide the shared controller with a factory for
// temporary native workloads. Keep Winsock, the exclusive guard, and controller alive through
// runtime shutdown. HTTPS certificate bindings are provisioned externally, not changed here.
int wmain(int argc, wchar_t** argv) {
    using namespace winlin;
    if (argc == 1 || (argc == 2 && std::wstring_view(argv[1]) == L"--help")) {
        std::cout << "winlin-server [--bind 127.0.0.1] [--port 38080]\n"
                     "  [--http-port 38444] [--https-port 38445]\n"
                     "  [--stop-file path]\n"
                     "Control uses plain HTTP; per-run workload TLS/cipher/workers are controlled "
                     "remotely.\n"
                     "Control runs one worker; workloads start only on client request.\n"
                     "Configure the HTTP.sys certificate bindings and URL ACLs using "
                     "scripts/setup-server.ps1 first.\n";
        return 0;
    }
    try {
        Winsock winsock;
        std::vector<std::string> values;
        for (int i = 0; i < argc; ++i) {
            values.push_back(utf8(argv[i]));
        }
        std::vector<char*> arguments;
        for (auto& value : values) {
            arguments.push_back(value.data());
        }
        Args args(argc, arguments.data());
        args.allow({"--bind", "--port", "--stop-file", "--http-port", "--https-port"});
        const auto control_port = number(args.get("--port", "38080"), 65535);
        const auto http_port =
            static_cast<unsigned>(number(args.get("--http-port", "38444"), 65535));
        const auto https_port =
            static_cast<unsigned>(number(args.get("--https-port", "38445"), 65535));
        if (!control_port || !http_port || !https_port || http_port == https_port ||
            control_port == http_port || control_port == https_port) {
            throw std::invalid_argument(
                "Control, HTTP and HTTPS ports must be nonzero and distinct");
        }
        ServerGuard instance_guard;
        reference_clock();
        const auto host_config = windows_config();
        const auto address = args.get("--bind", "127.0.0.1");
        BenchmarkController controller(
            issue_run_id, [&](const BenchmarkOptions& options, const std::string& run_id) {
                auto config = workload_config(host_config, options);
                try {
                    return std::make_unique<NativeBenchmark>(std::move(config), run_id, address,
                                                             options.tls == "off" ? http_port
                                                                                  : https_port);
                } catch (const BenchmarkError&) {
                    throw;
                } catch (const std::exception& failure) {
                    throw BenchmarkError(500, "Cannot start HTTP.sys workload: " +
                                                  std::string(failure.what()));
                }
            });
        Runtime server(args);
        server.agent.controller = &controller;
        server.run();
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << "winlin-server: FATAL: " << failure.what() << '\n';
        return 1;
    }
}
