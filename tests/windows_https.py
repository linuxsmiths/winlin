"""Privileged Windows HTTP.sys loopback tests, launched by windows_integration.ps1."""

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

from https_contract import exercise_contract, tls_context


SERVER, PORT, TOKEN_FILE, PIN, STOP_FILE = sys.argv[1:]
PORT = int(PORT)


class Agent:
    """Own one native process while reusing the provisioned endpoint and persisted pairing state."""

    def __init__(self, cipher="TLS_AES_128_GCM_SHA256"):
        self.port = PORT
        self.process = subprocess.Popen(
            [SERVER, "--token-file", TOKEN_FILE, "--port", str(PORT),
             "--workers", "2", "--max-connections", "128", "--cipher", cipher,
             "--stop-file", STOP_FILE],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        lines = queue.Queue()
        threading.Thread(
            target=lambda: lines.put(self.process.stdout.readline()), daemon=True
        ).start()
        try:
            line = lines.get(timeout=15)
            if not line:
                raise AssertionError(f"Server failed: {self.process.stderr.read()}")
            assert json.loads(line)["backend"] == "httpsys-schannel"
            self.connection = http.client.HTTPSConnection(
                "127.0.0.1", PORT, context=tls_context(), timeout=3,
            )
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if hasattr(self, "connection"):
            self.connection.close()
        if self.process.poll() is None:
            Path(STOP_FILE).write_text("stop\n")
        try:
            _, stderr = self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()
            raise AssertionError("HTTP.sys server did not stop gracefully")
        finally:
            Path(STOP_FILE).unlink(missing_ok=True)
        assert self.process.returncode == 0, stderr

    def request(self, method, path, token=None, body=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.connection.request(method, path, body=body, headers=headers)
        response = self.connection.getresponse()
        return response.status, response.read()


bootstrap = Path(TOKEN_FILE).read_text().strip()
agent = Agent()
try:
    agent.connection.connect()
    assert hashlib.sha256(agent.connection.sock.getpeercert(binary_form=True)).hexdigest() == PIN
    cipher = agent.connection.sock.cipher()[0]
finally:
    agent.stop()
assert cipher in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"), cipher

agent = Agent(cipher)
try:
    assert agent.request("GET", "/v1/capabilities", bootstrap)[0] == 401
    status, payload = agent.request("POST", "/v1/pair", bootstrap)
    assert status == 200, payload
    token = json.loads(payload)["access_token"]
    exercise_contract(agent, bootstrap, token, "httpsys-schannel", cipher)
    status, payload = agent.request("GET", "/v1/telemetry", token)
    telemetry = json.loads(payload)
    assert telemetry["active_connections"] is None
    assert telemetry["tls_handshakes"] is None
    assert telemetry["process"]["voluntary_context_switches"] is None
    assert "System" in telemetry["process_cpu_scope"]
    for size in (256, 512, 1024, 4096, 8192, 16384, 65536, 262144, 1048576, 4194304):
        status, payload = agent.request("GET", f"/v1/object?size={size}", token)
        assert status == 200 and len(payload) == size
        assert agent.request("PUT", "/v1/object", token, b"x" * size) == (200, b"")

    def load(index):
        """Give each concurrent client its own persistent connection and alternate both body paths."""
        connection = http.client.HTTPSConnection("127.0.0.1", PORT, context=tls_context(), timeout=5)
        try:
            for operation in range(8):
                method = "GET" if (index + operation) % 2 else "PUT"
                path = "/v1/object?size=4096" if method == "GET" else "/v1/object"
                body = None if method == "GET" else b"x" * 4096
                connection.request(method, path, body=body, headers={"Authorization": f"Bearer {token}"})
                response = connection.getresponse()
                assert response.status == 200
                assert len(response.read()) == (4096 if method == "GET" else 0)
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(load, range(16)))
    legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    legacy.check_hostname = False
    legacy.verify_mode = ssl.CERT_NONE
    legacy.minimum_version = legacy.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        with legacy.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=3),
                                server_hostname="127.0.0.1"):
            raise AssertionError("TLS 1.2 was not disabled on the test binding")
    except (ssl.SSLError, ConnectionError):
        pass
finally:
    agent.stop()

agent = Agent(cipher)
try:
    assert agent.request("GET", "/v1/capabilities", token)[0] == 200
    assert agent.request("POST", "/v1/pair", bootstrap)[0] == 409
finally:
    agent.stop()

other = "TLS_AES_256_GCM_SHA384" if cipher == "TLS_AES_128_GCM_SHA256" else "TLS_AES_128_GCM_SHA256"
agent = Agent(other)
try:
    status, payload = agent.request("GET", "/v1/capabilities", token)
    assert status == 400 and b"cipher" in payload, payload
finally:
    agent.stop()

print(f"Windows HTTP.sys shared contract, persistent/concurrent GET/PUT, restart and TLS checks passed ({cipher}).")
