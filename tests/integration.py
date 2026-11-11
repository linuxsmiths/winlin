"""Loopback integration tests; all credentials and results live in a temporary directory."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
from https_contract import exercise_contract, exercise_single_instance, tls_context


SERVER, CLIENT = sys.argv[1:3]
SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def command(*args, expected=0, input_text=None, env=None):
    # Keep the existing end-to-end cases while exercising the launcher's stdin/argv/exit forwarding.
    arguments = [str(arg) for arg in args]
    if arguments[0] == CLIENT:
        arguments = [
            str(SCRIPTS / "run-client.sh"), "--build-dir", str(Path(CLIENT).parent),
            "--", *arguments[1:],
        ]
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        input=input_text,
        env=env,
        timeout=20,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"{args[0]} returned {result.returncode}, expected {expected}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result


def private_file(path, text):
    path.write_text(text)
    path.chmod(0o600)


class Agent:
    """Own a loopback Linux server and control connection; always reap it and retain diagnostics."""

    def __init__(self, directory, backend="openssl"):
        self.directory = directory
        self.process = subprocess.Popen(
            [
                str(SCRIPTS / "run-server.sh"),
                "--build-dir", str(Path(SERVER).parent), "--",
                "--cert", str(directory / "cert.pem"),
                "--key", str(directory / "private.key"),
                "--token-file", str(directory / "pairing"),
                "--session-file", str(directory / f"{backend}.session"),
                "--port", "0",
                "--workers", "2",
                "--backend", backend,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            readable, _, _ = select.select([self.process.stdout], [], [], 10)
            if not readable:
                raise AssertionError("Server startup timed out")
            line = self.process.stdout.readline()
            if not line:
                raise AssertionError(f"Server failed: {self.process.stderr.read()}")
            self.port = json.loads(line)["port"]
            self.connection = http.client.HTTPSConnection(
                "127.0.0.1", self.port, context=tls_context(), timeout=3
            )
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if hasattr(self, "connection"):
            self.connection.close()
        if self.process.poll() is None:
            self.process.terminate()
        try:
            _, stderr = self.process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()
            raise AssertionError("Server did not stop gracefully")
        if self.process.returncode != 0:
            raise AssertionError(f"Server failed: {stderr}")
        self.stderr = stderr

    def request(self, method, path, token=None, body=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.connection.request(method, path, body=body, headers=headers)
        response = self.connection.getresponse()
        return response.status, response.read()


def exercise_invalid_request_accounting(agent, token):
    """A parser rejection after a persistent GET must not inherit successful-workload accounting."""
    status, payload = agent.request("GET", "/v1/telemetry", token)
    assert status == 200
    before = json.loads(payload)
    with tls_context().wrap_socket(
        socket.create_connection(("127.0.0.1", agent.port), timeout=3),
        server_hostname="127.0.0.1",
    ) as raw:
        raw.sendall(
            (f"GET /v1/object?size=512 HTTP/1.1\r\nHost: 127.0.0.1:{agent.port}\r\n"
             f"Authorization: Bearer {token}\r\n\r\n").encode()
        )
        response = http.client.HTTPResponse(raw)
        response.begin()
        assert response.status == 200 and len(response.read()) == 512
        raw.sendall(
            (f"PUT /v1/object HTTP/1.1\r\nHost: 127.0.0.1:{agent.port}\r\n"
             f"Authorization: Bearer {token}\r\n"
             "Content-Length: 1\r\ncontent-length: 2\r\n\r\n").encode()
        )
        response = http.client.HTTPResponse(raw)
        response.begin()
        assert response.status == 400
        response.read()
        # EOF guarantees the server finished its close/accounting path before telemetry is sampled.
        assert raw.recv(1) == b""

    # Unlike an idle disconnect, EOF halfway through a declared PUT body must be diagnosed.
    with tls_context().wrap_socket(
        socket.create_connection(("127.0.0.1", agent.port), timeout=3),
        server_hostname="127.0.0.1",
    ) as raw:
        raw.sendall(
            (f"PUT /v1/object HTTP/1.1\r\nHost: 127.0.0.1:{agent.port}\r\n"
             f"Authorization: Bearer {token}\r\nContent-Length: 512\r\n\r\n").encode()
            + b"x" * 256
        )

    # Header reception is also active work once any bytes have arrived, even before framing completes.
    with tls_context().wrap_socket(
        socket.create_connection(("127.0.0.1", agent.port), timeout=3),
        server_hostname="127.0.0.1",
    ) as raw:
        raw.sendall(b"GET /v1/object?size=512 HTTP/1.1\r\n")
    status, payload = agent.request("GET", "/v1/telemetry", token)
    assert status == 200
    after = json.loads(payload)
    assert after["get_completed"] == before["get_completed"] + 1, after
    assert after["get_bytes"] == before["get_bytes"] + 512, after
    assert after["put_completed"] == before["put_completed"], after
    assert after["put_bytes"] == before["put_bytes"], after


def run_case(directory, target, name, *options):
    """Verify a persisted real-client repetition, including operation/latency/byte consistency."""
    output = directory / f"{name}.json"
    configuration = {
        "--connections": "4", "--workers": "2", "--warmup": "0.02",
        "--duration": "1", "--repetitions": "1", "--requests": "100",
    }
    # Merge overrides rather than repeating CLI flags, which the strict argument parser rejects.
    configuration.update(zip(options[::2], options[1::2]))
    arguments = [item for pair in configuration.items() for item in pair]
    command(
        CLIENT, "run", "--target", target,
        "--output", output, *arguments,
    )
    report = json.loads(output.read_text())
    assert report["status"] == "completed", report
    result = report["results"][0]
    assert result["errors"] == 0
    assert result["completed"] == result["issued"]
    assert result["latency"]["samples"] == result["completed"]
    assert result["latency_by_method"]["get"]["samples"] == result["get_completed"]
    assert result["latency_by_method"]["put"]["samples"] == result["put_completed"]
    assert sum(bucket["count"] for bucket in result["latency"]["histogram"]) == result["completed"]
    assert result["latency"]["p50_us"] <= result["latency"]["p99_us"]
    assert result["elapsed_seconds"] > 0
    assert result["requests_per_second"] > 0
    assert result["server_process"]["user_cpu_seconds"] >= 0
    assert result["client_process"]["system_cpu_seconds"] >= 0
    assert "access_token" not in output.read_text()
    return report, result


with tempfile.TemporaryDirectory(prefix="winlin-test-") as temporary:
    directory = Path(temporary)
    command(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", directory / "private.key", "-out", directory / "cert.pem",
        "-days", "1", "-subj", "/CN=winlin-test",
        "-addext", "subjectAltName=IP:127.0.0.1",
    )
    bootstrap = secrets.token_hex(32)
    private_file(directory / "pairing", bootstrap + "\n")
    certificate = ssl.PEM_cert_to_DER_cert((directory / "cert.pem").read_text())
    fingerprint = hashlib.sha256(certificate).hexdigest()
    server_arguments = [
        SERVER, "--cert", str(directory / "cert.pem"), "--key", str(directory / "private.key"),
        "--token-file", str(directory / "pairing"),
    ]
    agent = Agent(directory)
    try:
        exercise_single_instance(server_arguments, agent.port)
        assert agent.request("GET", "/v1/capabilities")[0] == 401
        assert agent.request("GET", "/v1/capabilities", bootstrap)[0] == 401
        target = directory / "target.json"
        pairing = (
            CLIENT, "pair", "--host", "127.0.0.1", "--port", str(agent.port),
            "--token-file", directory / "pairing", "--target", target,
        )
        result = command(*pairing, "--fingerprint", "0" * 64, expected=1)
        assert "certificate changed" in result.stderr
        assert not target.exists()
        paired = command(*pairing, "--fingerprint", fingerprint)
        target_json = json.loads(target.read_text())
        token = target_json["access_token"]
        assert bootstrap not in paired.stdout and token not in paired.stdout
        assert target.stat().st_mode & 0o777 == 0o600
        assert (directory / "openssl.session").stat().st_mode & 0o777 == 0o600
        assert agent.request("POST", "/v1/pair", bootstrap)[0] == 409
        assert agent.request("GET", "/v1/capabilities", bootstrap)[0] == 401
        inspected = command(CLIENT, "inspect", "--target", target)
        assert json.loads(inspected.stdout)["backend"] == "openssl"
        assert json.loads(inspected.stdout)["cipher"] == "TLS_AES_128_GCM_SHA256"
        assert json.loads(inspected.stdout)["ktls_tx"] is False
        target.chmod(0o644)
        command(CLIENT, "inspect", "--target", target, expected=1)
        target.chmod(0o600)

        exercise_contract(agent, bootstrap, token, "openssl", "TLS_AES_128_GCM_SHA256")
        exercise_invalid_request_accounting(agent, token)

        _, result = run_case(directory, target, "get")
        assert result["completed"] == 100
        assert result["received_object_bytes"] == 100 * 4096
        assert result["put_completed"] == 0
        _, result = run_case(directory, target, "put", "--method", "put", "--put-size", "512")
        assert result["sent_object_bytes"] == 100 * 512
        assert result["get_completed"] == 0
        _, result = run_case(
            directory, target, "mixed", "--method", "mixed",
            "--get-percent", "30", "--get-size", "512", "--put-size", "1KiB",
        )
        assert result["get_completed"] == 30 and result["put_completed"] == 70
        for method in ("get", "put"):
            for size in ("0", "4MiB"):
                _, result = run_case(
                    directory, target, f"{method}-{size}", "--method", method,
                    f"--{method}-size", size,
                )
                assert result["completed"] == 100
        report, result = run_case(directory, target, "repeated", "--repetitions", "2")
        assert len(report["results"]) == 2
        assert all(item["completed"] == 100 for item in report["results"])
        _, result = run_case(
            directory, target, "duration", "--duration", "0.1", "--requests", "0",
        )
        assert result["elapsed_seconds"] >= 0.1
        _, result = run_case(
            directory, target, "small-limit", "--connections", "64", "--requests", "7",
        )
        assert result["issued"] == result["completed"] == 7
        failed_output = directory / "failed-run.json"
        command(
            CLIENT, "run", "--target", target, "--connections", "4", "--workers", "2",
            "--timeout", "0.000000001", "--output", failed_output, expected=1,
        )
        failed = json.loads(failed_output.read_text())
        assert failed["status"] == "failed" and "timed out" in failed["failure"]
        original = (directory / "get.json").read_text()
        command(
            CLIENT, "run", "--target", target, "--output", directory / "get.json", expected=1,
        )
        assert (directory / "get.json").read_text() == original
        assert not list(directory.glob("*.tmp.*"))
        for option, value in (("--connections", "16385"), ("--duration", "nan"),
                              ("--get-percent", "101"), ("--get-size", "65MiB"),
                              ("--method", "invalid"), ("--workers", "0"),
                              ("--rate", "100")):
            rejected = command(CLIENT, "run", "--target", target, option, value, expected=1)
            assert "FATAL:" in rejected.stderr
        command(
            CLIENT, "run", "--target", target, "--cipher", "TLS_CHACHA20_POLY1305_SHA256",
            expected=1,
        )
        altered = dict(target_json, certificate_sha256="0" * 64)
        private_file(directory / "wrong-pin.json", json.dumps(altered))
        command(CLIENT, "inspect", "--target", directory / "wrong-pin.json", expected=1)
        menu = command(CLIENT, input_text="0\n")
        assert "Run HTTPS benchmark" in menu.stdout
        state = directory / "state"
        (state / "winlin").mkdir(parents=True)
        private_file(state / "winlin/test.json", json.dumps(target_json))
        menu_output = directory / "menu-result.json"
        menu_input = (
            "2\n1\n3\n1\nmixed\n512\n1KiB\n30\n4\n2\n0\n0.1\n20\n1\n"
            f"{menu_output}\n0\n"
        )
        command(CLIENT, input_text=menu_input, env=dict(os.environ, XDG_STATE_HOME=str(state)))
        assert json.loads(menu_output.read_text())["results"][0]["completed"] == 20
    finally:
        agent.stop()

    assert "WARNING: Rejected malformed HTTP header" in agent.stderr
    assert "WARNING: Peer closed an unfinished TLS request" in agent.stderr
    assert "WARNING: Peer closed an incomplete HTTP header" in agent.stderr
    assert bootstrap not in agent.stderr and token not in agent.stderr

    agent = Agent(directory)
    try:
        # A healthy persistent client may disconnect between requests without sending close_notify.
        assert agent.request("GET", "/v1/capabilities", token)[0] == 200
        agent.connection.close()
        target_json["port"] = str(agent.port)
        private_file(target, json.dumps(target_json))
        command(CLIENT, "inspect", "--target", target)
        assert agent.request("POST", "/v1/pair", bootstrap)[0] == 409
    finally:
        agent.stop()

    assert "Closing failed TLS session" not in agent.stderr, agent.stderr
    assert "Peer closed an unfinished TLS request" not in agent.stderr, agent.stderr

    # A forced process exit must release the guard without deleting state or cleaning a PID file.
    agent = Agent(directory)
    try:
        agent.connection.close()
        agent.process.kill()
        _, stderr = agent.process.communicate(timeout=5)
        assert agent.process.returncode == -signal.SIGKILL, stderr
    finally:
        if agent.process.poll() is None:
            agent.stop()

    agent = Agent(directory, "ktls")
    try:
        ktls_target = directory / "ktls-target.json"
        command(
            CLIENT, "pair", "--host", "127.0.0.1", "--port", agent.port,
            "--token-file", directory / "pairing", "--fingerprint", fingerprint,
            "--target", ktls_target,
        )
        capabilities = json.loads(command(CLIENT, "inspect", "--target", ktls_target).stdout)
        assert capabilities["backend"] == "openssl-ktls"
        print(f"Verified kTLS capability: TX={capabilities['ktls_tx']}, RX={capabilities['ktls_rx']}")
        for method, direction in (("get", "tx"), ("put", "rx")):
            if capabilities[f"ktls_{direction}"]:
                run_case(directory, ktls_target, f"ktls-{method}", "--method", method)
            else:
                result = command(
                    CLIENT, "run", "--target", ktls_target, "--method", method, expected=1,
                )
                assert "refusing userspace fallback" in result.stderr
    finally:
        agent.stop()

    # A non-Winlin listener occupying the reservation must also cause a clear startup failure.
    with socket.socket() as guard_owner:
        guard_owner.bind(("127.0.0.1", 8444))
        guard_owner.listen(1)
        exercise_single_instance(server_arguments, 8443)

print("HTTPS integration tests passed")
