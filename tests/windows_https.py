"""Privileged Windows control/workload tests, launched by windows_integration.ps1."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
from pathlib import Path
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time

from https_contract import exercise_request_reuse, exercise_single_instance, pending_puts, tls_context


SERVER, PORT, HTTP_PORT, HTTPS_PORT, PIN, STOP_FILE = sys.argv[1:]
PORT, HTTP_PORT, HTTPS_PORT = map(int, (PORT, HTTP_PORT, HTTPS_PORT))
LAUNCHER = Path(__file__).resolve().parents[1] / "scripts" / "run-server.ps1"


class Agent:
    """Own a permanent native control process and its provisioned endpoints."""

    def __init__(self):
        self.port = PORT
        arguments = [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(LAUNCHER),
            "-ServerExe", SERVER, "-Port", str(PORT), "-HttpPort", str(HTTP_PORT),
            "-HttpsPort", str(HTTPS_PORT),
            "-StopFile", STOP_FILE,
        ]
        self.process = subprocess.Popen(
            arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        lines = queue.Queue()
        threading.Thread(
            target=lambda: lines.put(self.process.stdout.readline()), daemon=True,
        ).start()
        try:
            line = lines.get(timeout=15)
            if not line:
                raise AssertionError(f"Server failed: {self.process.stderr.read()}")
            ready = json.loads(line)
            assert ready["backend"] == "httpsys"
            assert ready["workers"] == 1, ready
            self.connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
        except BaseException:
            self.stop()
            raise

    def stop(self):
        """Stop the complete native server tree, including any still-active workload."""
        if hasattr(self, "connection"):
            self.connection.close()
        if self.process.poll() is None:
            Path(STOP_FILE).write_text("stop\n")
        try:
            _, stderr = self.process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            cleanup = subprocess.run(
                ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                capture_output=True, text=True, timeout=10,
            )
            if cleanup.returncode != 0:
                print(f"WARNING: server-tree cleanup failed: {cleanup.stdout}{cleanup.stderr}",
                      file=sys.stderr)
                self.process.kill()
            self.process.communicate(timeout=5)
            raise AssertionError("HTTP.sys server did not stop gracefully")
        finally:
            Path(STOP_FILE).unlink(missing_ok=True)
        assert self.process.returncode == 0, stderr

    def request(self, method, path, body=None):
        """Send one control request, reconnecting automatically after an error response."""
        return request(self.connection, method, path, body=body)

    def start(self, settings):
        """Request one exclusive in-process workload with remotely selected tuning."""
        status, payload = self.request("POST", "/v1/benchmark/start", json.dumps(settings))
        assert status == 200, (status, payload)
        return json.loads(payload)


def request(connection, method, path, run_id=None, body=None):
    """Keep request body bytes and workload run selection explicit for both transports."""
    headers = {"X-Winlin-Run": run_id} if run_id else {}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    return response.status, response.read()


def data_connection(mode):
    """Select the advertised HTTP.sys transport without substituting TLS for plain HTTP."""
    if mode == "on":
        return http.client.HTTPSConnection(
            "127.0.0.1", HTTPS_PORT, context=tls_context(), timeout=5,
        )
    return http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=5)


def exercise_run(agent, cipher, mode, workers):
    """Switch transport/workers without restarting control; exercise actual leased data I/O."""
    settings = {"tls": mode, "cipher": cipher, "workers": workers}
    run = agent.start(settings)
    run_id = run["run_id"]
    assert len(run_id) == 64
    assert run["port"] == (HTTPS_PORT if mode == "on" else HTTP_PORT)
    assert run["transport"] == ("https" if mode == "on" else "http")
    assert run["backend"] == ("httpsys-schannel" if mode == "on" else "httpsys")
    assert run["settings"]["workers"] == workers
    assert run["settings"]["cipher"] == (cipher if mode == "on" else None)
    assert agent.request("POST", "/v1/benchmark/start", json.dumps(settings))[0] == 409
    assert agent.request("POST", "/v1/benchmark/stop?run_id=wrong")[0] == 409
    assert agent.request("GET", "/v1/benchmark/telemetry?run_id=wrong")[0] == 409
    assert agent.request("GET", "/v1/object?size=512")[0] == 404

    connection = data_connection(mode)
    try:
        assert request(connection, "GET", "/v1/capabilities")[0] == 404
        assert request(connection, "GET", "/v1/object?size=512", "0" * 64)[0] == 409
        assert request(connection, "GET", "/v1/capabilities", run_id)[0] == 404
        assert request(connection, "GET", "/v1/telemetry", run_id)[0] == 404
        assert request(connection, "POST", "/v1/pair", run_id)[0] == 404
        for size in (0, 256, 512, 4096, 16384, 65536, 1048576, 4194304):
            status, payload = request(connection, "GET", f"/v1/object?size={size}", run_id)
            assert status == 200 and len(payload) == size
            assert request(connection, "PUT", "/v1/object", run_id, b"x" * size) == (200, b"")
        # A partial PUT must not be acknowledged or counted before all bytes have arrived.
        connection.putrequest("PUT", "/v1/object")
        connection.putheader("X-Winlin-Run", run_id)
        connection.putheader("Content-Length", "512")
        connection.endheaders()
        connection.send(b"x" * 256)
        connection.sock.settimeout(0.1)
        try:
            connection.sock.recv(1)
            raise AssertionError("PUT acknowledged before body completion")
        except (TimeoutError, socket.timeout):
            pass
        connection.sock.settimeout(5)
        connection.send(b"x" * 256)
        response = connection.getresponse()
        assert response.status == 200 and response.read() == b""
    finally:
        connection.close()

    def load(index):
        """Exercise persistent IOCP GET/PUT chains from independent client connections."""
        connection = data_connection(mode)
        try:
            for operation in range(32):
                method = "GET" if (index + operation) % 2 else "PUT"
                size = (0, 256, 16384, 65536)[(index + operation // 2) % 4]
                path = f"/v1/object?size={size}" if method == "GET" else "/v1/object"
                body = None if method == "GET" else b"x" * size
                status, payload = request(connection, method, path, run_id, body)
                assert status == 200 and len(payload) == (size if method == "GET" else 0)
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(load, range(16)))

    status, payload = agent.request("GET", f"/v1/benchmark/telemetry?run_id={run_id}")
    assert status == 200, payload
    puts_before = json.loads(payload)["put_completed"]
    exercise_request_reuse(lambda: data_connection(mode), run_id)
    status, payload = agent.request("GET", f"/v1/benchmark/telemetry?run_id={run_id}")
    assert status == 200, payload
    assert json.loads(payload)["put_completed"] == puts_before + 39

    if mode == "off":
        # HTTP.sys may support HTTP/2 globally, but this benchmark must reject non-HTTP/1.1 data.
        with socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=5) as raw:
            raw.sendall(
                (f"GET /v1/object?size=512 HTTP/1.0\r\nHost: localhost\r\n"
                 f"X-Winlin-Run: {run_id}\r\n\r\n").encode()
            )
            assert raw.recv(4096).startswith(b"HTTP/1.1 400 ")

    status, payload = agent.request("GET", f"/v1/benchmark/telemetry?run_id={run_id}")
    telemetry = json.loads(payload)
    assert status == 200 and telemetry["get_completed"] >= 8 and telemetry["put_completed"] >= 9
    assert telemetry["active_connections"] is None and telemetry["tls_handshakes"] is None
    assert telemetry["process"]["voluntary_context_switches"] is None
    assert "System" in telemetry["process_cpu_scope"]
    assert telemetry["host"]["busy_cpu_seconds"] >= 0
    assert telemetry["host"]["processor_groups_sampled"] >= 1
    clock = telemetry["host"]["reference_clock"]
    assert clock["frequency_hz"] is not None or clock["unavailable_reason"]
    process = telemetry["process"]
    if process["cpu_cycles"] is None:
        assert process["cpu_cycles_unavailable_reason"]
    else:
        assert process["cpu_cycles"] > 0 and process["cpu_cycles_source"] == "QueryProcessCycleTime"
        assert process["cpu_cycles_unavailable_reason"] is None
    # Stop while real body operations are pending, not just idle header receives. Their cancelled
    # completions and all cached contexts must drain before the next Runtime can take the endpoint.
    pending = pending_puts(lambda: data_connection(mode), run_id, 6)
    try:
        assert agent.request("POST", f"/v1/benchmark/stop?run_id={run_id}")[0] == 200
    finally:
        for connection in pending:
            connection.close()
    assert agent.request("GET", f"/v1/benchmark/telemetry?run_id={run_id}")[0] == 409


agent = Agent()
try:
    exercise_single_instance([SERVER], PORT)
    probe = agent.start({"tls": "on", "workers": 1})
    connection = data_connection("on")
    try:
        connection.connect()
        assert hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest() == PIN
        cipher = connection.sock.cipher()[0]
    finally:
        connection.close()
        assert agent.request("POST", f"/v1/benchmark/stop?run_id={probe['run_id']}")[0] == 200
finally:
    agent.stop()
assert cipher in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"), cipher

agent = Agent()
try:
    assert agent.request("POST", "/v1/pair")[0] == 404
    status, payload = agent.request("GET", "/v1/capabilities")
    capabilities = json.loads(payload)
    assert status == 200
    assert "authentication" not in capabilities
    assert capabilities["supported_tls_modes"] == ["on", "off"]
    assert capabilities["environment"]["system_ram_bytes"] > 0
    assert capabilities["environment"]["fd_limit"]["soft"] is None
    for key in ("backend", "transport", "tls_version", "cipher", "workers", "run"):
        assert key not in capabilities
    status, payload = agent.request("POST", "/v1/benchmark/start", '{"tls":"ktls"}')
    assert status == 501 and b"kTLS" in payload, payload
    assert agent.request("POST", "/v1/benchmark/start", '{"tls":"on","cipher":"bad"}')[0] == 400
    assert agent.request("POST", "/v1/benchmark/start", " " * 65537)[0] == 400
    assert agent.request("POST", "/v1/benchmark/start", '{"max_connections":32}')[0] == 400

    # Split JSON across receives: no workload may start from a partial control body.
    body = json.dumps({"tls": "off", "workers": 1})
    connection = agent.connection
    connection.putrequest("POST", "/v1/benchmark/start")
    connection.putheader("Content-Length", str(len(body)))
    connection.endheaders()
    connection.send(body[:5].encode())
    connection.sock.settimeout(0.1)
    try:
        connection.sock.recv(1)
        raise AssertionError("Control request dispatched before body completion")
    except (TimeoutError, socket.timeout):
        pass
    connection.sock.settimeout(5)
    connection.send(body[5:].encode())
    response = connection.getresponse()
    run = json.loads(response.read())
    assert response.status == 200, run
    assert agent.request("POST", f"/v1/benchmark/stop?run_id={run['run_id']}")[0] == 200

    for mode, workers in (("off", 1), ("on", 3), ("off", 3), ("on", 1)):
        exercise_run(agent, cipher, mode, workers)

    # Changing the run cipher must change validation, not rewrite machine-wide Schannel policy.
    other_cipher = ("TLS_AES_256_GCM_SHA384" if cipher == "TLS_AES_128_GCM_SHA256"
                    else "TLS_AES_128_GCM_SHA256")
    mismatch = agent.start({"tls": "on", "cipher": other_cipher})
    connection = data_connection("on")
    try:
        status, payload = request(connection, "GET", "/v1/object?size=512", mismatch["run_id"])
        assert status == 400 and b"cipher" in payload, payload
    finally:
        connection.close()
    assert agent.request("POST", f"/v1/benchmark/stop?run_id={mismatch['run_id']}")[0] == 200

    expired = agent.start({"tls": "off", "lease_seconds": 1})
    time.sleep(2.2)
    assert agent.request("GET", f"/v1/benchmark/telemetry?run_id={expired['run_id']}")[0] == 409
    # Leaving a workload active also verifies whole-server shutdown joins its data-plane workers.
    agent.start({"tls": "on", "cipher": cipher})

    legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    legacy.check_hostname = False
    legacy.verify_mode = ssl.CERT_NONE
    legacy.minimum_version = legacy.maximum_version = ssl.TLSVersion.TLSv1_2
    for port in (HTTPS_PORT,):
        try:
            with legacy.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=3),
                                    server_hostname="127.0.0.1"):
                raise AssertionError("TLS 1.2 was not disabled")
        except (ssl.SSLError, ConnectionError):
            pass
finally:
    agent.stop()

agent = Agent()
try:
    assert agent.request("GET", "/v1/capabilities")[0] == 200
finally:
    agent.stop()

with socket.socket() as guard_owner:
    guard_owner.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    guard_owner.bind(("127.0.0.1", 8444))
    guard_owner.listen(1)
    exercise_single_instance([SERVER], PORT)

print(f"Windows HTTP.sys control, HTTP/HTTPS workload switching, leases and IOCP GET/PUT checks passed ({cipher}).")
