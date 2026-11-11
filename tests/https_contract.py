"""The HTTP/TLS workload contract exercised against both native backends."""

import json
import socket
import ssl


def tls_context():
    """Use ephemeral loopback certificates without CA validation; production client pinning is separate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context


def exercise_contract(agent, bootstrap, token, backend, cipher):
    """Require the same workload semantics even when native parsers format rejected requests differently."""
    assert agent.request("GET", "/v1/capabilities")[0] == 401
    assert agent.request("GET", "/v1/capabilities", bootstrap)[0] == 401
    assert agent.request("GET", "/v1/object?size=512", "0" * 64)[0] == 401
    status, payload = agent.request("GET", "/v1/capabilities", token)
    capabilities = json.loads(payload)
    assert status == 200 and capabilities["protocol_version"] == 1
    assert capabilities["backend"] == backend and capabilities["cipher"] == cipher
    assert capabilities["tls_version"] == "TLSv1.3" and capabilities["http_version"] == "1.1"
    assert agent.request("POST", "/v1/pair", bootstrap)[0] == 409
    status, first = agent.request("GET", "/v1/object?size=512", token)
    assert status == 200 and len(first) == 512
    assert agent.request("GET", "/v1/object?size=512", token)[1] == first
    assert agent.request("PUT", "/v1/object", token, b"x" * 4096) == (200, b"")
    assert agent.request("GET", "/v1/object?size=67108865", token)[0] == 400
    assert agent.request("GET", "/v1/object?size=0", token) == (200, b"")
    assert agent.request("PUT", "/v1/object", token, b"") == (200, b"")
    connection = agent.connection
    connection.request("PUT", "/v1/object", body=b"x" * 256,
                       headers={"Authorization": f"Bearer {token}", "Connection": "close"})
    response = connection.getresponse()
    assert response.status == 200 and response.will_close and response.read() == b""

    connection = agent.connection
    connection.putrequest("PUT", "/v1/object")
    connection.putheader("Authorization", f"Bearer {token}")
    connection.putheader("Content-Length", "512")
    connection.endheaders()
    connection.send(b"x" * 256)
    connection.sock.settimeout(0.1)
    try:
        connection.sock.recv(1)
        raise AssertionError("PUT was acknowledged before its body was consumed")
    except (TimeoutError, socket.timeout):
        pass
    connection.sock.settimeout(3)
    connection.send(b"x" * 256)
    response = connection.getresponse()
    assert response.status == 200 and response.read() == b""
    assert agent.request("GET", "/v1/object?size=256", token)[0] == 200

    with tls_context().wrap_socket(
        socket.create_connection(("127.0.0.1", agent.port), timeout=3),
        server_hostname="127.0.0.1",
    ) as raw:
        raw.sendall(
            (f"PUT /v1/object HTTP/1.1\r\nHost: 127.0.0.1:{agent.port}\r\n"
             f"Authorization: Bearer {token}\r\n"
             "Content-Length: 1\r\ncontent-length: 2\r\n\r\n").encode()
        )
        assert raw.recv(4096).startswith(b"HTTP/1.1 400 ")

    status, payload = agent.request("GET", "/v1/telemetry", token)
    telemetry = json.loads(payload)
    assert status == 200 and telemetry["get_completed"] >= 4
    assert telemetry["put_completed"] >= 4
    assert telemetry["process"]["user_cpu_seconds"] >= 0
    assert telemetry["process"]["system_cpu_seconds"] >= 0
    assert telemetry["process"]["peak_rss_bytes"] > 0
