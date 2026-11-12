"""Verify connection diagnostics without starting a server or using the fixed server guard port."""

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


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

print("CLI and interactive connection-error diagnostics passed.")
