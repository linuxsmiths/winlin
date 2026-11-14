"""The HTTP/TLS workload contract exercised against both native backends."""

import ssl
import subprocess


def exercise_single_instance(server_arguments, running_port):
    """Reject duplicate native servers before readiness, including on a different control endpoint."""
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


def pending_puts(connect, run_id, count):
    """Keep body reads outstanding until the caller supplies the rest or cancels them."""
    connections = []
    try:
        for _ in range(count):
            connection = connect()
            connections.append(connection)
            connection.putrequest("PUT", "/v1/object")
            connection.putheader("X-Winlin-Run", run_id)
            connection.putheader("Content-Length", "32769")
            connection.endheaders()
            connection.send(b"x")
        return connections
    except BaseException:
        for connection in connections:
            connection.close()
        raise


def exercise_request_reuse(connect, run_id):
    """Exercise context turnover, multi-read bodies, cancellation, and clean metadata on reuse."""
    # Exceed a Windows worker's idle-cache capacity without changing the active-request limit.
    # Abandon one body, then verify subsequent nonempty and empty responses have clean framing.
    connections = pending_puts(connect, run_id, 40)
    try:
        connections[0].close()
        for connection in connections[1:]:
            connection.send(b"x" * 32768)
            response = connection.getresponse()
            assert response.status == 200 and response.read() == b""
            for size in (512, 0):
                connection.request(
                    "GET", f"/v1/object?size={size}", headers={"X-Winlin-Run": run_id},
                )
                response = connection.getresponse()
                assert response.status == 200 and len(response.read()) == size
    finally:
        for connection in connections:
            connection.close()
