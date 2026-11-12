"""Exercise onboarding, benchmark reports and errors without the native server's guard port."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


client = sys.argv[1]
with tempfile.TemporaryDirectory(prefix="winlin-client-errors-") as temporary:
    directory = Path(temporary)
    token = directory / "token"
    token.write_text("00" * 32 + "\n")
    token.chmod(0o600)
    target = directory / "unreachable.json"

    # A bound but non-listening socket guarantees refusal without racing another process for a port.
    with socket.socket() as refused:
        refused.bind(("127.0.0.1", 0))
        port = refused.getsockname()[1]
        cases = [
            ([client, "pair", "--host", "127.0.0.1", "--port", str(port),
              "--token-file", str(token), "--target", str(target)], None, 1),
            ([client], f"1\n127.0.0.1\n{port}\n\n2\n0\n", 0),
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
    """Provide control and tiny workload responses over TLS without the native guard port."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path.startswith("/v1/object?size="):
            self.respond(b"x" * int(self.path.split("=")[1]),
                         status=503 if self.server.fail_workload else None)
        elif self.path.startswith("/v1/benchmark/telemetry?run_id="):
            self.respond({
                "process": {
                    "user_cpu_seconds": 0, "system_cpu_seconds": 0, "peak_rss_bytes": 0,
                    "voluntary_context_switches": None, "involuntary_context_switches": None,
                },
            })
        else:
            self.respond({
                "authentication": "none", "backend": "test", "benchmark_control": True,
                "benchmark_tls_modes": ["on", "off"],
                "transport": "https" if self.server.encrypted else "http",
                "workers": self.server.settings.get("workers", 8),
                "max_connections": self.server.settings.get("max_connections", 32768),
                "process_cpu_scope": "application process only; excludes work charged to System",
                "unavailable_metrics": ["voluntary_context_switches"],
            })

    def do_POST(self):
        if self.path == "/v1/benchmark/start":
            settings = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.server.settings = settings
            self.server.peer.settings = settings
            data = self.server.peer if settings["tls"] == "off" else self.server
            self.respond({
                "run_id": "aa" * 32, "port": data.server_port,
                "transport": "http" if settings["tls"] == "off" else "https",
                "backend": "test", "settings": settings,
            })
        elif self.path.startswith("/v1/benchmark/stop?run_id="):
            self.respond({"stopped": True})
        else:
            self.respond({"access_token": ""})

    def respond(self, payload, status=None):
        self.server.authorizations.append(self.headers.get("Authorization"))
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
    plain.peer, server.peer = server, plain
    for endpoint, encrypted in ((server, True), (plain, False)):
        endpoint.authorizations = []
        endpoint.response_status = 200
        endpoint.fail_workload = False
        endpoint.settings = {}
        endpoint.encrypted = encrypted
    server.authorizations = []
    server.response_status = 200
    server.fail_workload = False
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(fixtures / "server.pem", fixtures / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever)
    plain_worker = threading.Thread(target=plain.serve_forever)
    worker.start()
    plain_worker.start()
    try:
        port = str(server.server_port)
        for index in range(2):
            target = directory / f"client-{index}.json"
            result = subprocess.run(
                [client, "pair", "--host", "127.0.0.1", "--port", port,
                 "--target", str(target)],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert json.loads(target.read_text())["access_token"] == ""

        result = subprocess.run(
            [client], input=f"1\n127.0.0.1\n{port}\n\n2\n1\n0\n",
            capture_output=True, text=True, timeout=15,
            env=dict(os.environ, XDG_STATE_HOME=str(directory / "state")),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Paired target saved" in result.stdout, result.stdout + result.stderr
        assert result.stdout.count('"authentication": "none"') == 2, result.stdout
        assert "pairing-token" not in result.stdout
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
        assert "Final telemetry summary" in result.stdout
        assert '"server_cpu_percent"' in result.stdout
        assert '"server_cycles_per_io": null' in result.stdout
        assert len(report["results"]) == 2
        notes = report["notes"]
        assert notes and len(notes) == len(set(notes))
        assert any("Closed-loop" in note for note in notes)
        assert any("System" in note for note in notes)
        assert any("null is not zero" in note for note in notes)
        for note in notes:
            assert note not in result.stdout + result.stderr
            assert all(note not in repetition["warnings"] for repetition in report["results"])

        output = directory / "plain-benchmark.json"
        result = subprocess.run(
            [*benchmark, "--tls", "off", "--server-workers", "3", "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(output.read_text())
        assert report["benchmark"] == "http"
        assert report["workload_endpoint"]["transport"] == "http"
        assert report["configuration"]["tls_version"] is None
        assert report["server_capabilities"]["workers"] == 3
        assert plain.authorizations and all(value == "Bearer " + "aa" * 32
                                            for value in plain.authorizations)

        server.fail_workload = True
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
            assert repetition["warnings"], repetition
            for warning in repetition["warnings"]:
                assert warning in result.stderr
        for note in report["notes"]:
            assert note not in result.stdout + result.stderr
        server.fail_workload = False

        token = directory / "optional-token"
        token.write_text("00" * 32 + "\n")
        token.chmod(0o600)
        rejected = directory / "rejected.json"
        result = subprocess.run(
            [client, "pair", "--host", "127.0.0.1", "--port", port,
             "--target", str(rejected), "--token-file", str(token)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1, result.stdout + result.stderr
        assert "Server authentication is disabled" in result.stderr, result.stderr
        assert not rejected.exists()

        server.response_status = 401
        result = subprocess.run(
            [client, "pair", "--host", "127.0.0.1", "--port", port, "--target", str(rejected)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1, result.stdout + result.stderr
        assert "Restart it without --token-file" in result.stderr, result.stderr
        assert not rejected.exists()
    finally:
        server.shutdown()
        plain.shutdown()
        worker.join(timeout=5)
        plain_worker.join(timeout=5)
        server.server_close()
        plain.server_close()

print("Client registration, benchmark notes, run-specific warnings and error diagnostics passed.")
