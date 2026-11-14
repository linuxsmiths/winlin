"""Exercise onboarding, benchmark reports and errors without the native server's guard port."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


client = sys.argv[1]
with tempfile.TemporaryDirectory(prefix="winlin-client-errors-") as temporary:
    directory = Path(temporary)
    target = directory / "unreachable.json"

    # A bound but non-listening socket guarantees refusal without racing another process for a port.
    with socket.socket() as refused:
        refused.bind(("127.0.0.1", 0))
        port = refused.getsockname()[1]
        cases = [
            ([client, "add", "--host", "127.0.0.1", "--port", str(port),
              "--target", str(target)], None, 1),
            ([client], f"1\n127.0.0.1\n{port}\n2\n0\n", 0),
        ]
        for arguments, input_text, expected in cases:
            result = subprocess.run(
                arguments, input=input_text, capture_output=True, text=True, timeout=15,
                env=dict(os.environ, XDG_STATE_HOME=str(directory / "state")),
            )
            assert result.returncode == expected, result.stdout + result.stderr
            assert "Connection refused" in result.stderr, result.stderr
            assert f"127.0.0.1:{port}" in result.stderr, result.stderr
            assert "error:00000000" not in result.stderr, result.stderr
            assert not target.exists()
            if input_text:
                assert "No registered targets" in result.stderr, result.stderr


class RegistrationHandler(BaseHTTPRequestHandler):
    """Provide HTTP control and independent HTTP/HTTPS workloads without the native guard port."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.server.is_workload and not self.path.startswith("/v1/object?size="):
            self.server.metadata_requests.append(self.path)
            self.respond({"error": "Use HTTP control for metadata"}, status=404)
            return
        if self.path.startswith("/v1/object?size="):
            self.respond(b"x" * int(self.path.split("=")[1]),
                         status=503 if self.server.fail_workload else None)
        elif self.path.startswith("/v1/benchmark/telemetry?run_id="):
            self.server.telemetry_samples += 1
            self.respond({
                "process": {
                    "user_cpu_seconds": self.server.telemetry_samples * 0.000123456789,
                    "system_cpu_seconds": 0, "peak_rss_bytes": 0,
                    "voluntary_context_switches": None, "involuntary_context_switches": None,
                    "cpu_cycles": (self.server.telemetry_samples * 10001
                                   if self.server.cycles_available else None),
                    "cpu_cycles_source": "fixture hardware counter",
                    "cpu_cycles_unavailable_reason": (None if self.server.cycles_available
                                                     else "fixture counter access denied"),
                },
                "host": {
                    "busy_cpu_seconds": (self.server.telemetry_samples * 0.5
                                         if self.server.host_cpu_available else None),
                    "sampled_at_monotonic_seconds": self.server.telemetry_samples * 0.25,
                    "reference_clock": {
                        "frequency_hz": 20002 if self.server.reference_available else None,
                        "source": "fixture invariant TSC",
                        "unavailable_reason": (None if self.server.reference_available
                                               else "fixture invariant TSC unavailable"),
                    },
                },
                "network": {
                    "source": "fixture interface counters",
                    "interface_id": "fixture-1",
                    "interface_name": "fixture-nic",
                    "received_bytes": (self.server.telemetry_samples * 125000000
                                       if self.server.network_available else None),
                    "transmitted_bytes": (self.server.telemetry_samples * 62500000
                                          if self.server.network_available else None),
                    "sampled_at_monotonic_seconds": self.server.telemetry_samples * 0.25,
                    "unavailable_reason": (None if self.server.network_available
                                           else "fixture interface counters unavailable"),
                },
            })
        else:
            self.server.capability_queries += 1
            payload = {
                "supported_tls_modes": ["on", "off"],
                "supported_ciphers": ["TLS_AES_128_GCM_SHA256"],
                "server_workers": {"min": 1, "max": 256},
                "limits": {"max_connections": 65536},
                "telemetry": {
                    "process_cpu_scope": "application process only; excludes work charged to System",
                    "unavailable_metrics": ["voluntary_context_switches"],
                },
            }
            self.respond(payload)

    def do_POST(self):
        if self.path == "/v1/benchmark/start":
            settings = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert "max_connections" not in settings
            if settings["tls"] == "off":
                settings["cipher"] = None
            data = self.server.plain if settings["tls"] == "off" else self.server.secure
            self.respond({
                "run_id": "aa" * 32, "port": data.server_port,
                "transport": "http" if settings["tls"] == "off" else "https",
                "backend": "test",
                "settings": (dict(settings, workers=settings["workers"] + 1)
                             if self.server.misreport_workers else settings),
            })
        elif self.path.startswith("/v1/benchmark/stop?run_id="):
            self.respond({"stopped": True})
        else:
            self.respond({"error": "Unsupported route"}, status=404)

    def do_PUT(self):
        """Consume the complete dummy PUT before acknowledging an interactive workload."""
        self.rfile.read(int(self.headers["Content-Length"]))
        self.respond(b"")

    def respond(self, payload, status=None):
        self.server.authorizations.append(self.headers.get("Authorization"))
        self.server.run_ids.append(self.headers.get("X-Winlin-Run"))
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        if self.server.is_workload and self.server.raw_response_parts:
            for part in self.server.raw_response_parts:
                self.wfile.write(part)
            return
        self.send_response(self.server.response_status if status is None else status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


fixtures = Path(__file__).resolve().parents[1] / "certs/benchmark"
with tempfile.TemporaryDirectory(prefix="winlin-client-registration-") as temporary:
    directory = Path(temporary)
    menu_client = directory / "menu client 'quoted' $literal"
    menu_client.symlink_to(Path(client).resolve())
    menu_environment = dict(os.environ, XDG_STATE_HOME=str(directory / "state 'quoted' $literal"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), RegistrationHandler)
    plain = ThreadingHTTPServer(("127.0.0.1", 0), RegistrationHandler)
    secure = ThreadingHTTPServer(("127.0.0.1", 0), RegistrationHandler)
    server.plain, server.secure = plain, secure
    for endpoint in (server, plain, secure):
        endpoint.authorizations = []
        endpoint.run_ids = []
        endpoint.response_status = 200
        endpoint.fail_workload = False
        endpoint.raw_response_parts = ()
        endpoint.is_workload = endpoint is not server
        endpoint.metadata_requests = []
        endpoint.capability_queries = 0
        endpoint.telemetry_samples = 0
        endpoint.cycles_available = False
        endpoint.reference_available = False
        endpoint.host_cpu_available = True
        endpoint.network_available = True
    server.authorizations = []
    server.response_status = 200
    server.fail_workload = False
    server.misreport_workers = False
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(fixtures / "server.pem", fixtures / "server.key")
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever)
    plain_worker = threading.Thread(target=plain.serve_forever)
    secure_worker = threading.Thread(target=secure.serve_forever)
    worker.start()
    plain_worker.start()
    secure_worker.start()
    try:
        port = str(server.server_port)
        for index in range(2):
            target = directory / f"client-{index}.json"
            result = subprocess.run(
                [client, "add", "--host", "127.0.0.1", "--port", port,
                 "--target", str(target)],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert "PUBLIC benchmark certificate" not in result.stderr
            assert "access_token" not in json.loads(target.read_text())
            assert "cipher" not in json.loads(target.read_text())
            assert "authentication" not in result.stdout

        # Older target metadata remains readable, but obsolete values never reach the wire.
        saved = json.loads(target.read_text())
        saved["access_token"] = "obsolete"
        saved["cipher"] = "ignored-legacy-control-cipher"
        target.write_text(json.dumps(saved))

        result = subprocess.run(
            [client], input=f"1\n127.0.0.1\n{port}\n2\n1\n0\n",
            capture_output=True, text=True, timeout=15,
            env=menu_environment,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Target saved" in result.stdout, result.stdout + result.stderr
        assert "PUBLIC benchmark certificate" not in result.stderr
        assert "authentication" not in result.stdout
        assert "TLS 1.3 cipher" not in result.stdout
        assert server.authorizations and all(value is None for value in server.authorizations)

        for method, tls, size_input, expected_gets, expected_puts in (
            ("get", "off", "512\n", 2, 0),
            ("put", "off", "256\n", 0, 2),
            ("mixed", "on", "512\n256\n50\n", 1, 1),
        ):
            output = directory / f"menu-{method} 'quoted' $literal.json"
            tls_input = f"{tls}\n" + ("\n" if tls != "off" else "")
            result = subprocess.run(
                [str(menu_client)],
                input=(f"3\n1\n{tls_input}1\n{method}\n{size_input}"
                       f"1\n1\n0\n0.12345678912345678\n2\n1\n{output}\n0\n"),
                capture_output=True, text=True, timeout=15,
                env=menu_environment,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert ("GET size" in result.stdout) == (method != "put")
            assert ("PUT size" in result.stdout) == (method != "get")
            report = json.loads(output.read_text())
            assert report["status"] == "completed", report
            if method != "put":
                assert report["configuration"]["get_size_bytes"] == 512
            if method != "get":
                assert report["configuration"]["put_size_bytes"] == 256
            assert report["results"][0]["get_completed"] == expected_gets
            assert report["results"][0]["put_completed"] == expected_puts

            # The printed command must retain every setting and preserve literal shell arguments.
            displayed = re.search(r"Noninteractive command:\n([^\n]+)", result.stdout)
            assert displayed, result.stdout
            assert result.stdout.index("Noninteractive command:") < result.stdout.index("Run  ")
            replay_arguments = shlex.split(displayed.group(1))
            assert replay_arguments[:2] == [str(menu_client), "run"]
            assert replay_arguments[replay_arguments.index("--output") + 1] == str(output)
            assert "state 'quoted' $literal" in replay_arguments[
                replay_arguments.index("--target") + 1]
            assert ("--cipher" in replay_arguments) == (tls != "off")
            assert all(option in replay_arguments for option in (
                "--tls", "--server-workers", "--method", "--get-size", "--put-size",
                "--get-percent", "--connections", "--workers", "--warmup", "--duration",
                "--requests", "--repetitions", "--timeout",
            ))
            replay_output = directory / f"replay-{method}.json"
            replay_arguments[replay_arguments.index("--output") + 1] = str(replay_output)
            replay = subprocess.run(
                replay_arguments, capture_output=True, text=True, timeout=15,
            )
            assert replay.returncode == 0, replay.stdout + replay.stderr
            replay_report = json.loads(replay_output.read_text())
            assert replay_report["configuration"] == report["configuration"]
            assert replay_report["results"][0]["get_completed"] == expected_gets
            assert replay_report["results"][0]["put_completed"] == expected_puts
            assert "Noninteractive command:" not in replay.stdout

        benchmark = [
            client, "run", "--target", str(target), "--get-size", "256",
            "--connections", "1", "--workers", "1", "--warmup", "0",
            "--duration", "1", "--requests", "2", "--repetitions", "2",
        ]
        output = directory / "benchmark.json"
        queries_before = server.capability_queries
        result = subprocess.run(
            [*benchmark, "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert server.capability_queries == queries_before + 1
        report = json.loads(output.read_text())
        table_row = re.compile(
            r"^\s*(\d+)\s+(\d+\.\d{2})\s+(\d+\.\d{2})\s+"
            r"(\d+\.\d{2})\s+(\d+\.\d{2})\s+(\d+)\s+"
            r"(N/A|\d+\.\d{2})\s+(\d+\.\d{2})\s+(N/A|\d+\.\d{2})\s+"
            r"(N/A|\d+\.\d{2})\s*$", re.MULTILINE,
        )
        assert "Ref CPIO" in result.stdout
        assert "Avg CPU(%)" in result.stdout
        assert "p90(us)" in result.stdout
        assert "Net Gbps" in result.stdout
        assert "Client CPU(%)" in result.stdout
        assert "{" not in result.stdout, result.stdout
        rows = table_row.findall(result.stdout)
        assert [(row[0], row[-1]) for row in rows] == [("1", "N/A"), ("2", "N/A")]
        assert [row[-2] for row in rows] == ["200.00", "200.00"]
        assert [row[-4] for row in rows] == ["6.00", "6.00"]
        assert result.stderr.count(
            "Reference CPIO unavailable: fixture invariant TSC unavailable") == 1
        assert report["schema_version"] == 5
        assert len(report["results"]) == 2
        for row, repetition in zip(rows, report["results"]):
            assert row[3] == f'{repetition["latency"]["p90_us"]:.2f}'
            assert row[-3] == f'{repetition["client_process"]["cpu_utilization_percent"]:.2f}'
            assert repetition["server_network"]["gigabits_per_second"] == 6
            assert repetition["server_network"]["interface_name"] == "fixture-nic"
            assert repetition["server_reference_cycles_per_io"] is None
            assert repetition["server_host"]["cpu_utilization_percent"] == 200
            assert "server_cpu_seconds_per_request" not in repetition
            for process in ("server_process", "client_process"):
                assert "cpu_utilization_percent" in repetition[process]
                assert "cpu_core_equivalents" not in repetition[process]
            assert 0 < repetition["server_process"]["user_cpu_seconds"] < 0.001
            assert "server_before" in repetition and "server_after" in repetition
        notes = report["notes"]
        assert notes and len(notes) == len(set(notes))
        assert any("Closed-loop" in note for note in notes)
        assert any("System" in note for note in notes)
        assert any("null is not zero" in note for note in notes)
        for note in notes:
            assert note not in result.stdout + result.stderr
            assert all(note not in repetition["warnings"] for repetition in report["results"])

        # Reference CPIO must work even when hardware counters remain denied.
        server.reference_available = True
        output = directory / "plain-benchmark.json"
        result = subprocess.run(
            [*benchmark, "--tls", "off", "--server-workers", "3", "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(output.read_text())
        rows = table_row.findall(result.stdout)
        assert [(row[0], row[-1]) for row in rows] == [("1", "5000.50"), ("2", "5000.50")]
        assert [row[-2] for row in rows] == ["200.00", "200.00"]
        assert "CPIO unavailable" not in result.stderr, result.stderr
        assert "{" not in result.stdout, result.stdout
        assert all(repetition["server_reference_cycles_per_io"] == 5000.5
                   for repetition in report["results"])
        assert all(repetition["server_process"]["cpu_cycles"] is None
                   for repetition in report["results"])
        assert report["benchmark"] == "http"
        assert report["workload_endpoint"]["transport"] == "http"
        assert report["configuration"]["tls_version"] is None
        assert report["server_run"]["workers"] == 3
        assert "control_capabilities" not in report
        assert plain.run_ids and all(value == "aa" * 32 for value in plain.run_ids)
        assert all(value is None for value in plain.authorizations)

        # Missing whole-server counters must not appear as zero CPU utilization.
        server.host_cpu_available = False
        output = directory / "unavailable-cpu-benchmark.json"
        result = subprocess.run(
            [*benchmark, "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        rows = table_row.findall(result.stdout)
        assert [(row[-2], row[-1]) for row in rows] == [("N/A", "N/A"), ("N/A", "N/A")]
        report = json.loads(output.read_text())
        assert all(repetition["server_host"]["cpu_utilization_percent"] is None
                   for repetition in report["results"])
        server.host_cpu_available = True

        # Interface-counter failures must not fall back to successful object payload goodput.
        server.network_available = False
        output = directory / "unavailable-network-benchmark.json"
        result = subprocess.run(
            [*benchmark, "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert [row[-4] for row in table_row.findall(result.stdout)] == ["N/A", "N/A"]
        assert result.stderr.count(
            "Server network throughput unavailable: fixture interface counters unavailable") == 1
        report = json.loads(output.read_text())
        assert all(repetition["server_network"]["gigabits_per_second"] is None
                   and repetition["object_goodput_bytes_per_second"] > 0
                   for repetition in report["results"])
        server.network_available = True

        # Header fragments and preloaded bodies must work across repeated responses on the same
        # connection. Separate writes also split the header across TLS records.
        for mode, endpoint in (("off", plain), ("on", secure)):
            for size in (256, 65536):
                endpoint.raw_response_parts = (
                    b"HTTP/1.1 200 OK\r\ncOnTeNt-Leng",
                    f"Th: {size}\r\nConnection: keep-alive\r\n\r".encode(),
                    b"\n" + b"x" * size,
                )
                arguments = benchmark.copy()
                arguments[arguments.index("--get-size") + 1] = str(size)
                output = directory / f"fragmented-{mode}-{size}.json"
                result = subprocess.run(
                    [*arguments, "--tls", mode, "--output", str(output)],
                    capture_output=True, text=True, timeout=15,
                )
                assert result.returncode == 0, result.stdout + result.stderr
                report = json.loads(output.read_text())
                assert all(repetition["completed"] == 2 and repetition["errors"] == 0 and
                           repetition["received_object_bytes"] == 2 * size
                           for repetition in report["results"])
                endpoint.raw_response_parts = ()

        # Optimizing response parsing must not turn malformed framing into successful I/O.
        for index, response in enumerate((
            b"HTTP/1.1 200 OK\r\nServer: fixture\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 257\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 256\r\ncontent-length: 256\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-Fill: " + b"x" * 16384,
        )):
            secure.raw_response_parts = (response[:16384],)
            output = directory / f"malformed-{index}.json"
            result = subprocess.run(
                [*benchmark, "--output", str(output)],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 2, result.stdout + result.stderr
            report = json.loads(output.read_text())
            assert report["status"] == "completed_with_errors"
            assert all(repetition["completed"] == 0 and repetition["errors"] > 0
                       for repetition in report["results"])
            assert result.stderr.count("became dead:") == sum(
                repetition["errors"] for repetition in report["results"]
            ), result.stderr
        secure.raw_response_parts = ()

        secure.fail_workload = True
        output = directory / "failed-benchmark.json"
        result = subprocess.run(
            [*benchmark, "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 2, result.stdout + result.stderr
        report = json.loads(output.read_text())
        assert report["status"] == "completed_with_errors"
        assert result.stderr.count("became dead:") == sum(
            repetition["errors"] for repetition in report["results"]
        ), result.stderr
        for repetition in report["results"]:
            assert repetition["errors"] > 0
            assert repetition["server_reference_cycles_per_io"] is None
            assert repetition["warnings"], repetition
            for warning in repetition["warnings"]:
                assert warning in result.stderr
        assert [row[-1] for row in table_row.findall(result.stdout)] == ["N/A", "N/A"]
        for note in report["notes"]:
            assert note not in result.stdout + result.stderr
        secure.fail_workload = False

        # Validate the HTTP start response rather than asking the data endpoint for settings.
        server.misreport_workers = True
        output = directory / "mismatched-settings.json"
        result = subprocess.run(
            [*benchmark, "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1, result.stdout + result.stderr
        report = json.loads(output.read_text())
        assert report["status"] == "failed"
        assert "did not apply the requested benchmark settings" in report["failure"]
        server.misreport_workers = False
        assert not plain.metadata_requests and not secure.metadata_requests

        rejected = directory / "rejected.json"
        server.response_status = 503
        result = subprocess.run(
            [client, "add", "--host", "127.0.0.1", "--port", port, "--target", str(rejected)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1, result.stdout + result.stderr
        assert "Server rejected control request (HTTP 503)" in result.stderr, result.stderr
        assert not rejected.exists()
    finally:
        server.shutdown()
        plain.shutdown()
        secure.shutdown()
        worker.join(timeout=5)
        plain_worker.join(timeout=5)
        secure_worker.join(timeout=5)
        server.server_close()
        plain.server_close()
        secure.server_close()

print("Client registration, benchmark notes, run-specific warnings and error diagnostics passed.")
