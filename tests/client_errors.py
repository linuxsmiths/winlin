"""Exercise client onboarding and errors without using the native server's fixed guard port."""

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
    """Provide the no-auth control contract over real TLS for client onboarding regressions."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond({"authentication": "none"})

    def do_POST(self):
        self.respond({"access_token": ""})

    def respond(self, payload):
        self.server.authorizations.append(self.headers.get("Authorization"))
        body = json.dumps(payload).encode()
        self.send_response(self.server.response_status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


fixtures = Path(__file__).resolve().parents[1] / "certs/benchmark"
with tempfile.TemporaryDirectory(prefix="winlin-client-registration-") as temporary:
    directory = Path(temporary)
    server = ThreadingHTTPServer(("127.0.0.1", 0), RegistrationHandler)
    server.authorizations = []
    server.response_status = 200
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(fixtures / "server.pem", fixtures / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
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
        worker.join(timeout=5)
        server.server_close()

print("CLI and interactive automatic registration and connection-error diagnostics passed.")
