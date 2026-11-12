"""Exercise the actual HTTPS controller and per-run Linux workload engines on temporary ports."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from https_contract import exercise_single_instance, tls_context


SERVER, CLIENT = sys.argv[1:3]
ROOT = Path(__file__).resolve().parents[1]


def command(*arguments, expected=0, **kwargs):
    result = subprocess.run(
        [str(argument) for argument in arguments],
        capture_output=True, text=True, timeout=30, **kwargs,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    return result


class Controller:
    """Own only test-created processes; keep their guard, credentials and diagnostics isolated."""

    def __init__(self, directory, bind=None, extra=()):
        self.directory = directory
        arguments = [
            str(ROOT / "scripts/run-server.sh"), "--build-dir", str(Path(SERVER).parent),
            "--state-dir", str(directory), "--port", "0", "--http-port", "0",
            "--https-port", "0", "--workers", "2", *extra,
        ]
        if bind is not None:
            arguments += ["--bind", bind]
        self.process = subprocess.Popen(
            arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            assert select.select([self.process.stdout], [], [], 10)[0], "Controller startup timed out"
            line = self.process.stdout.readline()
            assert line, self.process.stderr.read()
            self.ready = json.loads(line)
            self.port = self.ready["port"]
            self.token = None
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            _, stderr = self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()
            raise AssertionError("Controller or workload workers failed to stop")
        assert self.process.returncode == 0, stderr

    def request(self, method, path, body=None, host="127.0.0.1"):
        connection = http.client.HTTPSConnection(
            host, self.port, context=tls_context(), timeout=10,
        )
        try:
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            return response.status, json.loads(payload)
        finally:
            connection.close()

    def start(self, **settings):
        status, payload = self.request("POST", "/v1/benchmark/start", json.dumps(settings))
        assert status == 200, payload
        return payload

    def telemetry(self, lease):
        status, payload = self.request("GET", "/v1/benchmark/telemetry?run_id=" + lease["run_id"])
        assert status == 200, payload
        return payload

    def finish(self, lease):
        status, payload = self.request("POST", "/v1/benchmark/stop?run_id=" + lease["run_id"])
        assert status == 200, payload
        return payload


class Workload:
    """Connect only to the endpoint and automatic lease returned by the HTTPS controller."""

    def __init__(self, lease):
        self.lease = lease
        connection_type = (http.client.HTTPConnection if lease["transport"] == "http"
                           else http.client.HTTPSConnection)
        options = {} if lease["transport"] == "http" else {"context": tls_context()}
        self.connection = connection_type("127.0.0.1", lease["port"], timeout=10, **options)

    def request(self, method, path, body=None, authorized=True):
        headers = {"Authorization": f"Bearer {self.lease['run_id']}"} if authorized else {}
        self.connection.request(method, path, body=body, headers=headers)
        response = self.connection.getresponse()
        return response.status, response.read()


with tempfile.TemporaryDirectory(prefix="winlin-controlled-test-") as temporary:
    directory = Path(temporary)
    controller = Controller(directory)
    try:
        assert controller.ready["bind"] == "0.0.0.0"
        assert controller.request("GET", "/v1/capabilities", host="127.0.0.2")[0] == 200
        status, capabilities = controller.request("GET", "/v1/capabilities")
        assert status == 200 and capabilities["benchmark_control"]
        assert capabilities["benchmark_tls_modes"] == ["on", "off", "ktls"]
        assert controller.request("GET", "/v1/object?size=512")[0] == 404
        exercise_single_instance([SERVER], controller.port)

        target = directory / "client/target.json"
        command(
            CLIENT, "pair", "--host", "127.0.0.1", "--port", controller.port,
            "--target", target,
        )
        assert json.loads(target.read_text())["access_token"] == ""
        assert target.stat().st_mode & 0o777 == 0o600
        assert not (directory / "pairing-token").exists()
        bad_target = directory / "wrong-pin.json"
        refused = command(
            CLIENT, "pair", "--host", "127.0.0.1", "--port", controller.port,
            "--target", bad_target, "--fingerprint", "00" * 32, expected=1,
        )
        assert "certificate changed" in refused.stderr and not bad_target.exists()
        for invalid in ({"workers": 0}, {"workers": 1.5}, {"tls": "invalid"}, {"unknown": 1}):
            assert controller.request("POST", "/v1/benchmark/start", json.dumps(invalid))[0] == 400
        body = json.dumps({"tls": "off", "workers": 1})
        fragmented = http.client.HTTPSConnection(
            "127.0.0.1", controller.port, context=tls_context(), timeout=5,
        )
        try:
            fragmented.putrequest("POST", "/v1/benchmark/start")
            fragmented.putheader("Content-Length", str(len(body)))
            fragmented.endheaders()
            fragmented.send(body[:5].encode())
            fragmented.sock.settimeout(.1)
            try:
                fragmented.sock.recv(1)
                raise AssertionError("Server started a workload before settings were complete")
            except socket.timeout:
                pass
            fragmented.sock.settimeout(5)
            fragmented.send(body[5:].encode())
            response = fragmented.getresponse()
            started = json.loads(response.read())
            assert response.status == 200, started
            controller.finish(started)
        finally:
            fragmented.close()

        lease = controller.start(tls="off", workers=3, max_connections=32)
        assert lease["transport"] == "http"
        assert controller.request("POST", "/v1/benchmark/start", "{}")[0] == 409
        assert controller.request("POST", "/v1/benchmark/stop?run_id=wrong")[0] == 409
        data = Workload(lease)
        try:
            status, payload = data.request("GET", "/v1/capabilities")
            metadata = json.loads(payload)
            assert status == 200 and metadata["transport"] == "http"
            assert metadata["tls_version"] is None and metadata["cipher"] is None
            assert metadata["workers"] == 3 and metadata["max_connections"] == 32
            assert data.request("GET", "/v1/object?size=256", authorized=False)[0] == 401
            for size in (0, 256, 4096, 65536, 4194304):
                status, payload = data.request("GET", f"/v1/object?size={size}")
                assert status == 200 and len(payload) == size
                assert data.request("PUT", "/v1/object", body=b"x" * size) == (200, b"")
            before = controller.telemetry(lease)
            # A parser error after a GET must never reuse that GET's accounting state.
            with socket.create_connection(("127.0.0.1", lease["port"]), timeout=5) as raw:
                raw.sendall(
                    (f"GET /v1/object?size=512 HTTP/1.1\r\nHost: localhost\r\n"
                     f"Authorization: Bearer {lease['run_id']}\r\n\r\n").encode()
                )
                response = http.client.HTTPResponse(raw)
                response.begin()
                assert response.status == 200 and len(response.read()) == 512
                raw.sendall(
                    b"GET /v1/object?size=512 HTTP/1.1\r\nHost: localhost\r\n"
                    b"Content-Length: invalid\r\n\r\n"
                )
                response = http.client.HTTPResponse(raw)
                response.begin()
                assert response.status == 400
                response.read()
            after = controller.telemetry(lease)
            assert after["get_completed"] == before["get_completed"] + 1
            assert after["get_bytes"] == before["get_bytes"] + 512
            assert after["put_completed"] == 5
            assert after["tls_handshakes"] == 0
        finally:
            data.connection.close()
            controller.finish(lease)
        assert controller.request("GET", "/v1/benchmark/telemetry?run_id=" + lease["run_id"])[0] == 409

        for mode, workers in (("on", 1), ("off", 4), ("on", 2)):
            output = directory / f"{mode}-{workers}.json"
            invocation = command(
                CLIENT, "run", "--target", target, "--tls", mode, "--server-workers", workers,
                "--server-max-connections", "32", "--method", "mixed",
                "--get-size", "512", "--put-size", "256", "--connections", "4", "--workers", "2",
                "--warmup", "0.02", "--duration", "1", "--requests", "100", "--repetitions", "2",
                "--output", output,
            )
            report = json.loads(output.read_text())
            assert report["status"] == "completed" and len(report["results"]) == 2
            assert report["server_configuration"]["workers"] == workers
            assert report["server_capabilities"]["transport"] == ("http" if mode == "off" else "https")
            assert report["benchmark"] == ("http" if mode == "off" else "https")
            assert "Final telemetry summary" in invocation.stdout
            assert '"server_cpu_percent"' in invocation.stdout
            assert '"server_cycles_per_io"' in invocation.stdout
            assert "run_id" not in output.read_text() and "access_token" not in output.read_text()
            for repetition in report["results"]:
                assert repetition["completed"] == repetition["issued"] == 100
                assert repetition["errors"] == 0
                assert repetition["latency"]["samples"] == 100
                assert repetition["get_completed"] == repetition["put_completed"] == 50
                cpu = repetition["server_process"]
                if cpu["cpu_cycles"] is None:
                    assert repetition["server_cycles_per_request"] is None
                    assert cpu["cpu_cycles_unavailable_reason"]
                else:
                    assert repetition["server_cycles_per_request"] == cpu["cpu_cycles"] / 100
                for note in report["notes"]:
                    assert note not in invocation.stdout + invocation.stderr
                    assert note not in repetition["warnings"]
            # The next start also proves that the client relinquished ownership after completion.
            short = controller.start(tls="off", workers=1)
            controller.finish(short)

        output = directory / "ktls.json"
        ktls = subprocess.run(
            [CLIENT, "run", "--target", str(target), "--tls", "ktls", "--server-workers", "2",
             "--method", "get", "--get-size", "64KiB", "--connections", "2", "--workers", "1",
             "--warmup", "0", "--duration", "1", "--requests", "10", "--repetitions", "1",
             "--output", str(output)],
            capture_output=True, text=True, timeout=30,
        )
        report = json.loads(output.read_text())
        if ktls.returncode == 0:
            assert report["server_capabilities"]["backend"] == "openssl-ktls"
            assert report["server_capabilities"]["ktls_tx"]
        else:
            assert report["status"] == "failed"
            assert "kTLS" in ktls.stderr or "kTLS" in report["failure"]
        abandoned = controller.start(tls="off", workers=1, lease_seconds=1)
        time.sleep(2.2)
        assert controller.request("GET", "/v1/benchmark/telemetry?run_id=" + abandoned["run_id"])[0] == 409
        short = controller.start(tls="off", workers=2)
        controller.finish(short)
    finally:
        controller.stop()

    controller = Controller(directory, bind="127.0.0.1")
    try:
        try:
            with socket.create_connection(("127.0.0.2", controller.port), timeout=3):
                raise AssertionError("Explicit loopback override accepted another IPv4 address")
        except ConnectionRefusedError:
            pass
        # A fresh menu still needs no token, transport option, or certificate confirmation.
        menu_output = directory / "menu-result.json"
        menu = command(
            CLIENT, input=(f"1\n127.0.0.1\n{controller.port}\n\n2\n1\n"
                           f"3\n1\noff\n2\n32\nget\n256\n256\n1\n1\n0\n1\n2\n1\n{menu_output}\n0\n"),
            env=dict(os.environ, XDG_STATE_HOME=str(directory / "menu")),
        )
        assert "Paired target saved" in menu.stdout
        assert "pairing-token" not in menu.stdout and "Trust this certificate?" not in menu.stdout
        menu_report = json.loads(menu_output.read_text())
        assert menu_report["benchmark"] == "http"
        assert menu_report["server_configuration"]["workers"] == 2
    finally:
        controller.stop()

    # Optional host authentication must protect control without leaking its credential to data.
    authenticated = directory / "authenticated"
    authenticated.mkdir()
    token_file = authenticated / "bootstrap"
    token_file.write_text("ab" * 32 + "\n")
    token_file.chmod(0o600)
    controller = Controller(authenticated, extra=("--token-file", str(token_file)))
    try:
        assert controller.request("GET", "/v1/capabilities")[0] == 401
        target = authenticated / "target.json"
        command(CLIENT, "pair", "--host", "127.0.0.1", "--port", controller.port,
                "--target", target, "--token-file", token_file)
        command(CLIENT, "inspect", "--target", target)
        command(CLIENT, "run", "--target", target, "--tls", "off",
                "--connections", "1", "--workers", "1", "--warmup", "0", "--duration", "1",
                "--requests", "2", "--repetitions", "1", "--output", authenticated / "result.json")
    finally:
        controller.stop()
    controller = Controller(authenticated, extra=("--token-file", str(token_file)))
    try:
        saved = json.loads(target.read_text())
        saved["port"] = str(controller.port)
        target.write_text(json.dumps(saved))
        command(CLIENT, "inspect", "--target", target)
    finally:
        controller.stop()

    custom = directory / "custom"
    custom.mkdir()
    command(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=winlin-test", "-keyout", custom / "server.key", "-out", custom / "server.pem",
    )
    controller = Controller(custom)
    try:
        target = custom / "target.json"
        refused = command(
            CLIENT, "pair", "--host", "127.0.0.1", "--port", controller.port,
            "--target", target, expected=1,
        )
        assert "certificate changed" in refused.stderr and not target.exists()
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            (custom / "server.pem").read_text())).hexdigest()
        command(CLIENT, "pair", "--host", "127.0.0.1", "--port", controller.port,
                "--target", target, "--fingerprint", pin)
    finally:
        controller.stop()

print("HTTPS control, HTTP/TLS/kTLS workloads, exclusive leases, runtime tuning and telemetry passed.")
