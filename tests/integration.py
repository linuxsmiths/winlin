"""Exercise the HTTP controller and independent Linux HTTP/TLS workloads on temporary ports."""

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
    """Own only test-created processes; keep their guard and diagnostics isolated."""

    def __init__(self, directory, bind=None, extra=()):
        self.directory = directory
        arguments = [
            str(ROOT / "scripts/run-server.sh"), "--build-dir", str(Path(SERVER).parent),
            "--state-dir", str(directory), "--port", "0", "--http-port", "0",
            "--https-port", "0", *extra,
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
            assert self.ready["workers"] == 1, self.ready
            self.port = self.ready["port"]
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

    def listening_ports(self):
        """Inspect this test-owned process's listeners, not other servers in its network namespace."""
        socket_inodes = set()
        for descriptor in Path(f"/proc/{self.process.pid}/fd").iterdir():
            try:
                target = str(descriptor.readlink())
            except FileNotFoundError:
                # A completed control connection can close between listing and reading its fd.
                continue
            if target.startswith("socket:["):
                socket_inodes.add(target[8:-1])
        ports = []
        for line in Path(f"/proc/{self.process.pid}/net/tcp").read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == "0A" and fields[9] in socket_inodes:
                ports.append(int(fields[1].split(":")[1], 16))
        return sorted(ports)

    def request(self, method, path, body=None, host="127.0.0.1"):
        connection = http.client.HTTPConnection(host, self.port, timeout=10)
        try:
            connection.request(method, path, body=body)
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
    """Connect only to the endpoint and automatic lease returned by the HTTP controller."""

    def __init__(self, lease):
        self.lease = lease
        connection_type = (http.client.HTTPConnection if lease["transport"] == "http"
                           else http.client.HTTPSConnection)
        options = {} if lease["transport"] == "http" else {"context": tls_context()}
        self.connection = connection_type("127.0.0.1", lease["port"], timeout=10, **options)

    def request(self, method, path, body=None, include_run=True):
        headers = {"X-Winlin-Run": self.lease['run_id']} if include_run else {}
        self.connection.request(method, path, body=body, headers=headers)
        response = self.connection.getresponse()
        return response.status, response.read()


def exercise_session_events(lease):
    """Keep event pointers valid across ownership-map growth, rearming, and connection turnover."""
    connections = [Workload(lease) for _ in range(32)]
    try:
        for iteration in range(3):
            # Keep surviving sessions active while replacing peers and reusing server descriptors.
            if iteration == 1:
                for index in range(0, len(connections), 2):
                    connections[index].connection.close()
                    connections[index] = Workload(lease)

            # Leave requests outstanding together so batches can mix listener and session events.
            # The first pass grows the session map; later passes exercise saved pointers after
            # rehashing and EPOLL_CTL_MOD, which must retain the pointer rather than an fd.
            for data in connections:
                data.connection.request(
                    "GET", "/v1/object?size=256", headers={"X-Winlin-Run": lease["run_id"]},
                )
            for data in connections:
                response = data.connection.getresponse()
                assert response.status == 200 and len(response.read()) == 256
    finally:
        for data in connections:
            data.connection.close()


def exercise_receive_buffer(lease):
    """Keep request/body boundaries intact across fragmented and pipelined HTTP/TLS input."""
    raw = socket.create_connection(("127.0.0.1", lease["port"]), timeout=5)
    if lease["transport"] == "https":
        raw = tls_context().wrap_socket(raw, server_hostname="localhost")
    try:
        with raw.makefile("rb") as reader:
            def read_response(size):
                """Use one reader for the pipeline so prefetched responses are not lost."""
                assert reader.readline().startswith(b"HTTP/1.1 200 ")
                headers = {}
                while True:
                    line = reader.readline()
                    assert line, "Connection closed inside a response header"
                    if line == b"\r\n":
                        break
                    name, value = line.split(b":", 1)
                    headers[name.lower()] = value.strip()
                assert int(headers[b"content-length"]) == size
                assert len(reader.read(size)) == size

            run_header = f"Host: localhost\r\nX-Winlin-Run: {lease['run_id']}\r\n".encode()
            get = b"GET /v1/object?size=256 HTTP/1.1\r\n" + run_header + b"\r\n"
            prefix = (b"PUT /v1/object HTTP/1.1\r\n" + run_header +
                      b"Content-Length: 65536\r\nX-Pad: ")
            put = prefix + b"x" * (16384 - len(prefix) - 4) + b"\r\n\r\n"

            # Leave a partial next header after the first request. Completing an exactly
            # maximum-sized header then requires recovering space from the consumed prefix.
            raw.sendall(get + put[:30])
            read_response(256)
            raw.sendall(put[30:] + b"x" * 65536 + get)
            read_response(0)
            read_response(256)

            # Delimiter bytes can arrive separately, including across TLS records.
            for split in (1, 2, 3):
                raw.sendall(get[:-split])
                time.sleep(.005)
                raw.sendall(get[-split:])
                read_response(256)

            # Repeated pipelined requests retain unread bytes when each response completes.
            raw.sendall(get * 128)
            for _ in range(128):
                read_response(256)

            # A full buffer without a delimiter must still close instead of reading beyond
            # the header limit or treating the following bytes as a valid request.
            oversized_prefix = b"GET /v1/object HTTP/1.1\r\nX-Pad: "
            raw.sendall(oversized_prefix + b"x" * (16384 - len(oversized_prefix)))
            assert reader.read(1) == b""
    finally:
        raw.close()


with tempfile.TemporaryDirectory(prefix="winlin-controlled-test-") as temporary:
    directory = Path(temporary)
    controller = Controller(directory)
    try:
        assert controller.ready["bind"] == "0.0.0.0"
        assert controller.ready["backend"] == "http"
        # Startup owns only the exclusive guard and one control listener, not a workload pool.
        assert controller.listening_ports() == sorted([8444, controller.port])
        rejected = command(SERVER, "--workers", "8", expected=1)
        assert "Unknown option: --workers" in rejected.stderr
        assert controller.request("GET", "/v1/capabilities", host="127.0.0.2")[0] == 200
        status, capabilities = controller.request("GET", "/v1/capabilities")
        assert status == 200
        assert "authentication" not in capabilities
        assert next(iter(capabilities)) == "environment"
        assert list(capabilities["environment"])[:2] == ["os", "kernel"]
        assert controller.request("POST", "/v1/pair")[0] == 404
        assert capabilities["supported_tls_modes"] == ["on", "off", "ktls"]
        assert capabilities["supported_transports"] == ["http", "https"]
        assert [backend["name"] for backend in capabilities["supported_backends"]] == [
            "http", "openssl", "openssl-ktls"]
        for key in ("backend", "transport", "cipher", "tls_version", "workers",
                    "max_connections", "ktls_tx", "ktls_rx", "benchmark_control", "run"):
            assert key not in capabilities, key
        host = capabilities["environment"]
        assert host["system_ram_bytes"] == os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
        assert host["fd_limit"]["soft"] == "unlimited" or host["fd_limit"]["soft"] >= 524288
        assert host["machine"]["type"] in ("unknown", "bare_metal", "virtual_machine")
        assert capabilities["limits"]["max_connections"] == 65536
        assert controller.request("GET", "/v1/object?size=512")[0] == 404
        exercise_single_instance([SERVER], controller.port)

        target = directory / "client/target.json"
        command(
            CLIENT, "add", "--host", "127.0.0.1", "--port", controller.port,
            "--target", target,
        )
        assert "access_token" not in json.loads(target.read_text())
        assert target.stat().st_mode & 0o777 == 0o600
        bad_target = directory / "wrong-pin.json"
        refused = command(
            CLIENT, "add", "--host", "127.0.0.1", "--port", controller.port,
            "--target", bad_target, "--fingerprint", "00" * 32,
        )
        # A workload pin has no role in HTTP discovery, but HTTPS must still reject mismatches.
        refused = command(
            CLIENT, "run", "--target", bad_target, "--tls", "on", "--connections", "1",
            "--workers", "1", "--server-workers", "1", "--warmup", "0", "--duration", "1",
            "--requests", "1", "--repetitions", "1", "--output", directory / "wrong-pin-result.json",
            expected=1,
        )
        assert "certificate changed" in refused.stderr
        for invalid in ({"workers": 0}, {"workers": 1.5}, {"tls": "invalid"}, {"unknown": 1},
                        {"max_connections": 32}):
            assert controller.request("POST", "/v1/benchmark/start", json.dumps(invalid))[0] == 400
        body = json.dumps({"tls": "off", "workers": 1})
        fragmented = http.client.HTTPConnection("127.0.0.1", controller.port, timeout=5)
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

        lease = controller.start(tls="off", workers=3)
        assert lease["transport"] == "http"
        # The requested workload pool is separate; control stays at one listener during the run.
        assert controller.listening_ports() == sorted([8444, controller.port] + [lease["port"]] * 3)
        assert controller.request("POST", "/v1/benchmark/start", "{}")[0] == 409
        assert controller.request("POST", "/v1/benchmark/stop?run_id=wrong")[0] == 409
        data = Workload(lease)
        try:
            assert lease["settings"] == {"tls": "off", "cipher": None, "workers": 3}
            assert data.request("GET", "/v1/capabilities")[0] == 404
            assert data.request("GET", "/v1/capabilities", include_run=False)[0] == 404
            assert data.request("GET", "/v1/object?size=256", include_run=False)[0] == 409
            for size in (0, 256, 4096, 65536, 4194304):
                status, payload = data.request("GET", f"/v1/object?size={size}")
                assert status == 200 and len(payload) == size
                assert data.request("PUT", "/v1/object", body=b"x" * size) == (200, b"")
            before = controller.telemetry(lease)
            # A parser error after a GET must never reuse that GET's accounting state.
            with socket.create_connection(("127.0.0.1", lease["port"]), timeout=5) as raw:
                raw.sendall(
                    (f"GET /v1/object?size=512 HTTP/1.1\r\nHost: localhost\r\n"
                     f"X-Winlin-Run: {lease['run_id']}\r\n\r\n").encode()
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

        for mode in ("off", "on"):
            lease = controller.start(tls=mode, workers=1)
            try:
                exercise_receive_buffer(lease)
                measured = controller.telemetry(lease)
                assert measured["get_completed"] == 133, measured
                assert measured["put_completed"] == 1, measured
                assert measured["put_bytes"] == 65536, measured
                exercise_session_events(lease)
            finally:
                controller.finish(lease)

        for mode, workers in (("on", 1), ("off", 4), ("on", 2)):
            output = directory / f"{mode}-{workers}.json"
            invocation = command(
                CLIENT, "run", "--target", target, "--tls", mode, "--server-workers", workers,
                "--method", "mixed",
                "--get-size", "512", "--put-size", "256", "--connections", "4", "--workers", "2",
                "--warmup", "0.02", "--duration", "1", "--requests", "100", "--repetitions", "2",
                "--output", output,
            )
            report = json.loads(output.read_text())
            assert report["status"] == "completed" and len(report["results"]) == 2
            assert (report["client_environment"]["allocator"] ==
                    report["server_capabilities"]["environment"]["allocator"] ==
                    capabilities["environment"]["allocator"])
            assert report["server_configuration"]["workers"] == workers
            assert report["server_run"]["transport"] == ("http" if mode == "off" else "https")
            assert "control_capabilities" not in report
            assert report["benchmark"] == ("http" if mode == "off" else "https")
            assert "Ref CPIO" in invocation.stdout
            assert "{" not in invocation.stdout
            assert "run_id" not in output.read_text() and "access_token" not in output.read_text()
            assert "authentication" not in invocation.stdout + output.read_text()
            assert next(iter(report["server_capabilities"])) == "environment"
            assert list(report["server_capabilities"]["environment"])[:2] == ["os", "kernel"]
            for repetition in report["results"]:
                assert repetition["completed"] == repetition["issued"] == 100
                assert repetition["errors"] == 0
                assert repetition["latency"]["samples"] == 100
                assert repetition["get_completed"] == repetition["put_completed"] == 50
                cpu = repetition["server_host"]
                if cpu["reference_cycles"] is None:
                    assert repetition["server_reference_cycles_per_io"] is None
                    assert cpu["reference_cycles_unavailable_reason"]
                    assert ("Reference CPIO unavailable: " +
                            cpu["reference_cycles_unavailable_reason"]
                            in invocation.stderr)
                else:
                    before, after = (repetition[key]["host"]
                                     for key in ("server_before", "server_after"))
                    clock = cpu["reference_clock"]
                    assert clock["calibration_samples"] >= 3
                    assert clock["frequency_hz"] > 0
                    assert cpu["busy_cpu_seconds"] == (
                        after["busy_cpu_seconds"] - before["busy_cpu_seconds"])
                    assert cpu["reference_cycles"] == (
                        cpu["busy_cpu_seconds"] * clock["frequency_hz"])
                    assert repetition["server_reference_cycles_per_io"] == (
                        cpu["reference_cycles"] / 100)
                    assert cpu["cpu_utilization_percent"] >= 0
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
            assert report["server_run"]["backend"] == "openssl-ktls"
            assert report["server_final_telemetry"]["ktls_tx_connections"] >= 2
        else:
            assert report["status"] in ("failed", "completed_with_errors")
            assert ("kTLS" in ktls.stderr or "kTLS" in report.get("failure", "") or
                    any("kTLS" in result["first_error"] for result in report["results"]))
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
        # A fresh menu discovers control without transport options or fixture confirmation.
        menu_output = directory / "menu-result.json"
        menu = command(
            CLIENT, input=(f"1\n127.0.0.1\n{controller.port}\n2\n1\n"
                           f"3\n1\noff\n2\nget\n256\n1\n1\n0\n1\n2\n1\n{menu_output}\n0\n"),
            env=dict(os.environ, XDG_STATE_HOME=str(directory / "menu")),
        )
        assert "Target saved" in menu.stdout
        assert "authentication" not in menu.stdout and "Trust this certificate?" not in menu.stdout
        assert "Server connection limit" not in menu.stdout
        assert "TLS 1.3 cipher" not in menu.stdout
        assert "GET size" in menu.stdout and "PUT size" not in menu.stdout
        menu_report = json.loads(menu_output.read_text())
        assert menu_report["benchmark"] == "http"
        assert menu_report["server_configuration"]["workers"] == 2
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
        default_target = custom / "default-pin.json"
        command(
            CLIENT, "add", "--host", "127.0.0.1", "--port", controller.port,
            "--target", default_target,
        )
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            (custom / "server.pem").read_text())).hexdigest()
        command(CLIENT, "add", "--host", "127.0.0.1", "--port", controller.port,
                "--target", target, "--fingerprint", pin)
        for selected, expected in ((default_target, 1), (target, 0)):
            result = command(
                CLIENT, "run", "--target", selected, "--tls", "on", "--connections", "1",
                "--workers", "1", "--server-workers", "1", "--warmup", "0", "--duration", "1",
                "--requests", "2", "--repetitions", "1",
                "--output", custom / f"{selected.stem}-result.json", expected=expected,
            )
            if expected:
                assert "certificate changed" in result.stderr
    finally:
        controller.stop()

print("HTTP control, HTTP/TLS/kTLS workloads, exclusive leases, workload pinning and telemetry passed.")
