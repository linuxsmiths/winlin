"""The HTTP/TLS workload contract exercised against both native backends."""

import ssl
import subprocess


def exercise_single_instance(server_arguments, running_port):
    """Reject duplicate native servers before readiness, including on a different HTTPS endpoint."""
    for port in (running_port, 1 if running_port != 1 else 2):
        result = subprocess.run(
            [*server_arguments, "--port", str(port)],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 1, result.stdout + result.stderr
        assert not result.stdout, result.stdout
        assert "exclusive server guard on 127.0.0.1:8444" in result.stderr, result.stderr


def tls_context():
    """Use ephemeral loopback certificates without CA validation; production client pinning is separate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context
