"""Exercise onboarding, benchmark reports and errors without the native server's guard port."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
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
                    "busy_cpu_seconds": self.server.telemetry_samples * 0.5,
                    "sampled_at_monotonic_seconds": self.server.telemetry_samples * 0.25,
                    "reference_clock": {
                        "frequency_hz": 20002 if self.server.reference_available else None,
                        "source": "fixture invariant TSC",
                        "unavailable_reason": (None if self.server.reference_available
                                               else "fixture invariant TSC unavailable"),
                    },
                },
            })
        else:
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
            if self.headers.get("X-Winlin-Run"):
                payload["run"] = {
                    "backend": "test", "transport": "https" if self.server.encrypted else "http",
                    "tls_version": "TLSv1.3" if self.server.encrypted else None,
                    "cipher": self.server.settings["cipher"] if self.server.encrypted else None,
                    "workers": self.server.settings["workers"],
                }
            self.respond(payload)

    def do_POST(self):
        if self.path == "/v1/benchmark/start":
            settings = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert "max_connections" not in settings
            self.server.settings = settings
            self.server.plain.settings = settings
            self.server.secure.settings = settings
            data = self.server.plain if settings["tls"] == "off" else self.server.secure
            self.respond({
                "run_id": "aa" * 32, "port": data.server_port,
                "transport": "http" if settings["tls"] == "off" else "https",
                "backend": "test", "settings": settings,
            })
        elif self.path.startswith("/v1/benchmark/stop?run_id="):
            self.respond({"stopped": True})
        else:
            self.respond({"error": "Unsupported route"}, status=404)

    def respond(self, payload, status=None):
        self.server.authorizations.append(self.headers.get("Authorization"))
        self.server.run_ids.append(self.headers.get("X-Winlin-Run"))
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(self.server.response_status if status is None else status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


fixtures = Path(__file__).resolve().parents[1] / "certs/benchmark"
with tempfile.TemporaryDirectory(prefix="winlin-client-registration-") as temporary:
    directory = Path(temporary)
    server = ThreadingHTTPServer(("127.0.0.1", 0), RegistrationHandler)
    plain = ThreadingHTTPServer(("127.0.0.1", 0), RegistrationHandler)
    secure = ThreadingHTTPServer(("127.0.0.1", 0), RegistrationHandler)
    server.plain, server.secure = plain, secure
    for endpoint, encrypted in ((server, False), (plain, False), (secure, True)):
        endpoint.authorizations = []
        endpoint.run_ids = []
        endpoint.response_status = 200
        endpoint.fail_workload = False
        endpoint.settings = {}
        endpoint.encrypted = encrypted
        endpoint.telemetry_samples = 0
        endpoint.cycles_available = False
        endpoint.reference_available = False
    server.authorizations = []
    server.response_status = 200
    server.fail_workload = False
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
            env=dict(os.environ, XDG_STATE_HOME=str(directory / "state")),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Target saved" in result.stdout, result.stdout + result.stderr
        assert "authentication" not in result.stdout
        assert "TLS 1.3 cipher" not in result.stdout
        assert server.authorizations and all(value is None for value in server.authorizations)

        benchmark = [
            client, "run", "--target", str(target), "--get-size", "256",
            "--connections", "1", "--workers", "1", "--warmup", "0",
            "--duration", "1", "--requests", "2", "--repetitions", "2",
        ]
        output = directory / "benchmark.json"
        result = subprocess.run(
            [*benchmark, "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(output.read_text())
        table_row = re.compile(
            r"^\s*(\d+)\s+(\d+\.\d{2})\s+(\d+\.\d{2})\s+"
            r"(\d+\.\d{2})\s+(\d+)\s+(N/A|\d+\.\d{2})\s*$", re.MULTILINE,
        )
        assert "Ref CPIO" in result.stdout
        assert "{" not in result.stdout, result.stdout
        rows = table_row.findall(result.stdout)
        assert [(row[0], row[-1]) for row in rows] == [("1", "N/A"), ("2", "N/A")]
        assert result.stderr.count(
            "Reference CPIO unavailable: fixture invariant TSC unavailable") == 1
        assert report["schema_version"] == 4
        assert len(report["results"]) == 2
        for repetition in report["results"]:
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

        secure.fail_workload = True
        output = directory / "failed-benchmark.json"
        result = subprocess.run(
            [*benchmark, "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 2, result.stdout + result.stderr
        report = json.loads(output.read_text())
        assert report["status"] == "completed_with_errors"
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
