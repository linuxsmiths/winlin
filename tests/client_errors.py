"""Exercise onboarding, benchmark reports and errors without the native server's guard port."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
import os
from pathlib import Path
import re
import resource
import shlex
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time


class StalledHandshake(socketserver.BaseRequestHandler):
    """Receive ClientHello but never reply, so cancellation must escape TLS setup polling."""

    def handle(self):
        """Keep the test-owned transport open until the interrupted client closes it."""
        if self.request.recv(16384):
            self.server.hello_received.set()
            while self.request.recv(16384):
                pass


class LocalControllerHandler(BaseHTTPRequestHandler):
    """Exercise server-local CLI dispatch without acquiring the native server guard."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        """Keep fixture diagnostics out of console result assertions."""
        pass

    def respond(self, payload):
        """Send a bounded control JSON reply and close this fixture connection."""
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Advertise local workloads or return completed and failed repetition snapshots."""
        if self.server.oversized_response:
            self.send_response(200)
            self.send_header("Content-Length", str(16 * 1024 * 1024 + 1))
            self.end_headers()
            return
        if self.path == "/v1/capabilities":
            self.respond({"supported_benchmarks": ["context-switch", "syscall", "allocation",
                                                   "page-fault", "thread-create"]})
        else:
            self.server.poll_seen.set()
            self.respond(self.snapshot())

    def snapshot(self):
        """Include full repetition history so telemetry and stop exercise large response bodies."""
        repetitions = self.server.settings[-1]["repetitions"] if self.server.long_run else 1
        results = []
        if not self.server.running:
            for repetition in range(1, repetitions + 1):
                result = {
                    "repetition": repetition, "operations": 100, "operations_per_second": 1000,
                    "mean_operation_ns": 1000000, "reference_cycles_per_operation": 2000,
                    "mean_round_trip_ns": 123456, "mean_ring_lap_ns": 654321,
                    "observed_page_faults": {"total": 7},
                    "server_host": {"cpu_utilization_percent": 100}, "errors": 0,
                }
                if self.server.long_run:
                    result["fixture_telemetry"] = "x" * 2048
                if self.server.settings[-1]["benchmark"] == "thread-create":
                    result["thread_startup_latency"] = {
                        "mean_us": 10, "p50_us": 8, "p99_us": 20,
                    }
                    result["thread_lifecycle_latency"] = {
                        "mean_us": 30, "p50_us": 25, "p99_us": 50,
                    }
                results.append(result)
        return {
            "status": ("running" if self.server.running else
                       "failed" if self.server.fail_run else "completed"),
            "failure": "fixture native failure" if self.server.fail_run else None,
            "results": results,
        }

    def do_POST(self):
        """Retain submitted parameters and verify the client releases its owned lease."""
        if self.path == "/v1/benchmark/start":
            settings = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.server.settings.append(settings)
            self.respond({
                "run_id": "ab" * 32, "settings": settings, "transport": "server-local",
                "operation_unit": "fixture operation", "benchmark": settings["benchmark"],
                "server_cpu": settings.get("server_cpu", 0),
                "execution_threads": settings.get("threads", settings["workers"]),
            })
        else:
            self.server.stops += 1
            self.respond(self.snapshot() if self.server.long_run else {"status": "stopped"})


client = sys.argv[1]
faults = str(Path(sys.argv[2]).resolve()) if len(sys.argv) > 2 else None
native_server = str(Path(sys.argv[3]).resolve()) if len(sys.argv) > 3 else None

# Set limits in a separate, single-threaded child before exec, never in the test runner or a
# preexec_fn used after the HTTP fixture has started threads.
limited_client = [
    sys.executable, "-c",
    "import os, resource, sys\n"
    "resource.setrlimit(resource.RLIMIT_NOFILE, (int(sys.argv[1]), int(sys.argv[2])))\n"
    "os.execv(sys.argv[3], sys.argv[3:])\n",
]

for arguments, input_text in ((["inspect", "--target", "/nonexistent-winlin-target"], None),
                              ([], "0\n")):
    result = subprocess.run(
        [*limited_client, "16", "64", client, *arguments], input=input_text,
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "winlin: FATAL:" in result.stderr, result.stderr
    assert "524288 file descriptors; soft=16, hard=64" in result.stderr, result.stderr
    assert "Raise the hard nofile limit" in result.stderr, result.stderr

# Help stays available even when the process cannot obtain benchmark descriptor capacity.
for command in ("--help", "help"):
    result = subprocess.run(
        [*limited_client, "16", "64", client, command],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "winlin run" in result.stdout, result.stdout

if native_server:
    # Failure must precede guard/listener acquisition, so these checks coexist with a live server.
    result = subprocess.run(
        [*limited_client, "16", "64", native_server, "--port", "0"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "winlin-server: FATAL:" in result.stderr, result.stderr
    assert "524288 file descriptors; soft=16, hard=64" in result.stderr, result.stderr
    for arguments in ([], ["--help"]):
        result = subprocess.run(
            [*limited_client, "16", "64", native_server, *arguments],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "winlin-server" in result.stdout, result.stdout

if faults:
    # Verify real kernel limits after native startup without binding any server sockets. Invalid
    # arguments stop both executables before discovery or guard acquisition.
    hard_fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    higher_soft_limit = (524289 if hard_fd_limit == resource.RLIM_INFINITY
                         else min(524289, hard_fd_limit))
    executables = [(client, ["winlin-test-invalid"])]
    if native_server:
        executables.append((native_server, ["--winlin-test-invalid", "1"]))
    for executable, invalid_arguments in executables:
        for soft_limit in (16, higher_soft_limit):
            result = subprocess.run(
                [*limited_client, str(soft_limit), str(hard_fd_limit), executable,
                 *invalid_arguments],
                capture_output=True, text=True, timeout=15,
                env=dict(os.environ, LD_PRELOAD=faults, WINLIN_TEST_VERIFY_FD_LIMIT="1"),
            )
            assert result.returncode == 1, result.stdout + result.stderr
            assert "Unknown" in result.stderr, result.stderr
            assert ("verified native descriptor-limit increase" in result.stderr) == (
                soft_limit < 524288), result.stderr

with tempfile.TemporaryDirectory(prefix="winlin-local-client-") as temporary:
    directory = Path(temporary)
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalControllerHandler)
    server.settings, server.stops, server.fail_run = [], 0, False
    server.running = False
    server.long_run = server.oversized_response = False
    server.poll_seen = threading.Event()
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    target = directory / "local.json"
    target.write_text(json.dumps({
        "host": "127.0.0.1", "port": str(server.server_port),
        "certificate_sha256": "ab" * 32,
    }))
    target.chmod(0o600)
    try:
        for benchmark, parameters in (
            ("context-switch", ["--server-cpu", "2", "--threads", "32"]),
            ("syscall", ["--operation", "minimal-query"]),
            ("allocation", ["--allocation-size", "512B", "--live-allocations", "4",
                            "--memory-touch", "pages", "--server-workers", "2"]),
        ):
            output = directory / f"{benchmark}.json"
            result = subprocess.run(
                [client, "run", "--target", str(target), "--benchmark", benchmark,
                 "--duration", "0.02", "--repetitions", "1", "--output", str(output), *parameters],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert f"Server-local {benchmark}" in result.stdout
            if benchmark == "context-switch":
                assert "mean lap(ns)" in result.stdout and "654321.00" in result.stdout
                assert "execution threads=32" in result.stdout
            report = json.loads(output.read_text())
            assert report["status"] == "completed" and len(report["results"]) == 1
            assert "ab" * 32 not in output.read_text()
            assert not {"tls", "cipher", "get_response_data"} & server.settings[-1].keys()
        assert server.settings[0]["server_cpu"] == 2
        assert server.settings[0]["threads"] == 32
        assert server.settings[2]["allocation_size"] == 512
        assert server.stops == 3
        server.fail_run = True
        output = directory / "failed-local.json"
        result = subprocess.run(
            [client, "run", "--target", str(target), "--benchmark", "syscall",
             "--repetitions", "2", "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1 and "fixture native failure" in result.stderr
        report = json.loads(output.read_text())
        assert report["status"] == "failed" and len(report["results"]) == 1
        assert server.stops == 4
        result = subprocess.run(
            [client, "run", "--target", str(target), "--benchmark", "syscall", "--tls", "on"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1 and "Unknown option: --tls" in result.stderr
        assert len(server.settings) == 4
        server.fail_run = False
        # The local menu emits a replayable command without changing existing network prompts.
        state = directory / "state" / "winlin"
        state.mkdir(parents=True, mode=0o700)
        saved_target = state / "target.json"
        saved_target.write_text(target.read_text())
        saved_target.chmod(0o600)
        result = subprocess.run(
            [client], input="4\nsyscall\n1\nauto\n0.02\n1\nno\n0\n",
            capture_output=True, text=True, timeout=15,
            env=dict(os.environ, XDG_STATE_HOME=str(state.parent)),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        displayed = re.search(r"Noninteractive command:\n([^\n]+)", result.stdout)
        assert displayed and "--benchmark 'syscall'" in displayed.group(1), result.stdout
        replay = subprocess.run(shlex.split(displayed.group(1)),
                                capture_output=True, text=True, timeout=15)
        assert replay.returncode == 0, replay.stdout + replay.stderr
        assert server.stops == 6
        # Cancellation while polling must release the owned lease and keep reports bearer-free.
        server.running = True
        for signal_number in (signal.SIGINT, signal.SIGTERM):
            server.poll_seen.clear()
            output = directory / f"local-cancel-{signal_number}.json"
            process = subprocess.Popen(
                [client, "run", "--target", str(target), "--benchmark", "context-switch",
                 "--output", str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                assert server.poll_seen.wait(5), "Local client did not start telemetry polling"
                process.send_signal(signal_number)
                stdout, stderr = process.communicate(timeout=10)
                assert process.returncode == 128 + signal_number, stdout + stderr
                assert json.loads(output.read_text())["status"] == "interrupted"
                assert "ab" * 32 not in output.read_text()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        assert server.stops == 8
        server.running = False
        output = directory / "page-fault.json"
        result = subprocess.run(
            [client, "run", "--target", str(target), "--benchmark", "page-fault",
             "--region-size", "128MiB", "--repetitions", "1", "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert server.settings[-1]["region_size"] == 128 * 1024 * 1024
        assert "duration" not in server.settings[-1]
        assert "Observed faults" in result.stdout
        assert re.search(r"\s7\n", result.stdout), result.stdout
        result = subprocess.run(
            [client, "run", "--target", str(target), "--benchmark", "page-fault",
             "--duration", "10"], capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1 and "Unknown option: --duration" in result.stderr
        result = subprocess.run(
            [client], input="4\npage-fault\n1\n64MiB\nauto\n1\nno\n0\n",
            capture_output=True, text=True, timeout=15,
            env=dict(os.environ, XDG_STATE_HOME=str(state.parent)),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        displayed = re.search(r"Noninteractive command:\n([^\n]+)", result.stdout)
        assert displayed and "--region-size 67108864" in displayed.group(1), result.stdout
        assert "--duration" not in displayed.group(1)
        replay = subprocess.run(shlex.split(displayed.group(1)),
                                capture_output=True, text=True, timeout=15)
        assert replay.returncode == 0, replay.stdout + replay.stderr
        result = subprocess.run(
            [client], input="4\ncontext-switch\n1\n8\nauto\n0.02\n1\nno\n0\n",
            capture_output=True, text=True, timeout=15,
            env=dict(os.environ, XDG_STATE_HOME=str(state.parent)),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        displayed = re.search(r"Noninteractive command:\n([^\n]+)", result.stdout)
        assert displayed and "--threads 8" in displayed.group(1), result.stdout
        replay = subprocess.run(shlex.split(displayed.group(1)),
                                capture_output=True, text=True, timeout=15)
        assert replay.returncode == 0, replay.stdout + replay.stderr
        assert server.settings[-1]["threads"] == 8
        for benchmark, parameters in (
            ("context-switch", ["--threads", "1"]),
            ("context-switch", ["--threads", "1025"]),
            ("syscall", ["--threads", "8"]),
        ):
            result = subprocess.run(
                [client, "run", "--target", str(target), "--benchmark", benchmark, *parameters],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 1, result.stdout + result.stderr
        # Thread creation has no affinity or parallelism prompts, and prints both distributions.
        output = directory / "thread-create.json"
        result = subprocess.run(
            [client, "run", "--target", str(target), "--benchmark", "thread-create",
             "--duration", "0.02", "--repetitions", "1", "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "one unpinned creator" in result.stdout and "start p99(us)" in result.stdout
        assert "life mean(us)" in result.stdout and "50.00" in result.stdout
        assert "server_cpu" not in server.settings[-1]
        report = json.loads(output.read_text())
        assert report["results"][0]["thread_startup_latency"]["mean_us"] == 10
        assert report["results"][0]["thread_lifecycle_latency"]["mean_us"] == 30
        result = subprocess.run(
            [client], input="4\nthread-create\n1\n0.02\n1\nno\n0\n",
            capture_output=True, text=True, timeout=15,
            env=dict(os.environ, XDG_STATE_HOME=str(state.parent)),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        displayed = re.search(r"Noninteractive command:\n([^\n]+)", result.stdout)
        assert displayed and "--benchmark 'thread-create'" in displayed.group(1), result.stdout
        assert "--server-cpu" not in displayed.group(1)
        replay = subprocess.run(shlex.split(displayed.group(1)),
                                capture_output=True, text=True, timeout=15)
        assert replay.returncode == 0, replay.stdout + replay.stderr
        for option in ("--server-cpu", "--server-workers", "--threads", "--tls"):
            result = subprocess.run(
                [client, "run", "--target", str(target), "--benchmark", "thread-create", option, "1"],
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 1 and "Unknown option" in result.stderr
        # Both polling and stop return histories above 64 KiB, including the supported maximum.
        server.long_run = True
        for repetitions in (100, 1000):
            arguments = [
                client, "run", "--target", str(target), "--benchmark", "page-fault",
                "--repetitions", str(repetitions),
            ]
            output = directory / "long-page-fault.json"
            if repetitions == 100:
                arguments.extend(["--output", str(output)])
            stops_before = server.stops
            result = subprocess.run(arguments, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, result.stdout + result.stderr
            assert server.stops == stops_before + 1
            assert not result.stderr, result.stderr
            if repetitions == 100:
                report = json.loads(output.read_text())
                assert report["status"] == "completed" and len(report["results"]) == 100
                assert output.stat().st_size > 65536
        # A header advertising an excessive body must fail before any body is received.
        server.oversized_response = True
        result = subprocess.run(
            [client, "run", "--target", str(target), "--benchmark", "page-fault"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1 and "Control response body exceeds 16 MiB limit" in result.stderr
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

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

    def setup(self):
        """Track live workload connections across the client's final telemetry boundary."""
        super().setup()
        if self.server.is_workload:
            with self.server.connection_condition:
                self.server.open_connections += 1
                self.server.connections_created += 1
                self.server.connection_condition.notify_all()

    def finish(self):
        """Notify control-side assertions once a workload connection is actually torn down."""
        try:
            super().finish()
        finally:
            if self.server.is_workload:
                with self.server.connection_condition:
                    self.server.open_connections -= 1
                    self.server.connection_condition.notify_all()

    def do_GET(self):
        if self.server.is_workload and not self.path.startswith("/v1/object?size="):
            self.server.metadata_requests.append(self.path)
            self.respond({"error": "Use HTTP control for metadata"}, status=404)
            return
        if self.path.startswith("/v1/object?size="):
            measuring, pause = self.observe_workload()
            if pause:
                self.server.request_paused.set()
                assert self.server.release_request.wait(10), "Paused workload was not released"
                # Deliberately leave this response unfinished after the client cancels it.
                return
            self.respond(b"x" * int(self.path.split("=")[1]),
                         status=503 if self.server.fail_workload and
                         (measuring or self.server.fail_warmup) else None)
        elif self.path.startswith("/v1/benchmark/telemetry?run_id="):
            self.server.telemetry_in_run += 1
            data = self.server.current_workload
            self.server.warmup_samples.append(data.warmup_requests)
            if self.server.telemetry_in_run == 1:
                self.server.warmup_elapsed = time.monotonic() - data.first_warmup_request
                if self.server.measurement_marker is not None:
                    self.server.measurement_marker.touch()
            if self.server.telemetry_in_run == self.server.fail_telemetry_at:
                self.respond({"error": "fixture telemetry failed"}, status=503)
                return
            if self.server.expected_live_connections:
                data = self.server.current_workload
                with data.connection_condition:
                    if self.server.telemetry_in_run == 1:
                        # TCP setup may finish before the fixture starts both handler threads.
                        data.connection_condition.wait_for(
                            lambda: data.open_connections == self.server.expected_live_connections,
                            timeout=1,
                        )
                    else:
                        # Give EOF handlers time to observe a prematurely closed client.
                        # Correctly parked workers keep these sockets open throughout the wait.
                        data.connection_condition.wait_for(
                            lambda: data.open_connections == 0, timeout=0.1,
                        )
                    self.server.sampled_connections.append(data.open_connections)
            self.server.telemetry_samples += 1
            self.respond({
                "get_response_data": self.server.current_get_response_data,
                "get_response_source_access": ("hot-prefix" if self.server.current_get_response_data
                                               == "shared" else "rotating-objects"),
                "get_response_source_pool_bytes": (64 * 1024 * 1024
                                                  if self.server.current_get_response_data
                                                  == "shared" else 1024 * 1024 * 1024),
                "process": {
                    "sampled_at_monotonic_seconds": self.server.telemetry_samples * 0.25,
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
            if self.server.pause_capabilities:
                self.server.capabilities_seen.set()
                assert self.server.release_capabilities.wait(10)
                self.respond({"error": "fixture discovery failed"}, status=503)
                return
            payload = {
                "supported_tls_modes": ["on", "off"],
                "supported_get_response_data_modes": self.server.get_response_data_modes,
                "supported_ciphers": ["TLS_AES_128_GCM_SHA256"],
                "server_workers": {"min": 1, "max": 256},
                "limits": {"max_connections": 65536},
                "telemetry": {
                    "process_cpu_scope": "application process only; excludes work charged to System",
                    "unavailable_metrics": ["voluntary_context_switches"],
                },
            }
            if self.server.copy_working_set_bytes is not None:
                payload["copy_get_working_set_bytes"] = self.server.copy_working_set_bytes
            self.respond(payload)

    def do_POST(self):
        if self.path == "/v1/benchmark/start":
            settings = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            with self.server.lease_condition:
                if self.server.enforce_leases and self.server.active_run is not None:
                    self.respond({"error": "A benchmark is already active on this server"},
                                 status=409)
                    return
                run_id = "aa" * 32
                if self.server.enforce_leases:
                    self.server.run_sequence += 1
                    run_id = f"{self.server.run_sequence:064x}"
                    self.server.active_run = run_id
            assert "max_connections" not in settings
            assert settings["get_response_data"] in ("shared", "copy")
            self.server.current_get_response_data = settings["get_response_data"]
            if settings["tls"] == "off":
                settings["cipher"] = None
            data = self.server.plain if settings["tls"] == "off" else self.server.secure
            self.server.current_workload = data
            self.server.telemetry_in_run = 0
            data.first_warmup_request = None
            applied = dict(settings)
            if self.server.misreport_workers:
                applied["workers"] += 1
            if self.server.misreport_get_response_data:
                applied["get_response_data"] = "shared"
            self.server.start_seen.set()
            if self.server.pause_start:
                assert self.server.release_start.wait(10), "Paused start was not released"
            self.respond({
                "run_id": run_id,
                "port": self.server.workload_port_override or data.server_port,
                "transport": "http" if settings["tls"] == "off" else "https",
                "backend": "test",
                "settings": applied,
            })
        elif self.path.startswith("/v1/benchmark/stop?run_id="):
            if self.server.fail_stop:
                self.respond({"error": "fixture stop failed"}, status=503)
                return
            with self.server.lease_condition:
                if (self.server.enforce_leases and
                        self.path.split("run_id=", 1)[1] != self.server.active_run):
                    self.respond({"error": "Workload run ID does not match active lease"}, status=409)
                    return
                if self.server.enforce_leases:
                    self.server.active_run = None
            self.server.stop_requests += 1
            self.server.stop_seen.set()
            self.respond({"stopped": True})
        else:
            self.respond({"error": "Unsupported route"}, status=404)

    def do_PUT(self):
        """Consume the complete dummy PUT before acknowledging an interactive workload."""
        self.observe_workload()
        size = int(self.headers["Content-Length"])
        body = self.rfile.read(size)
        if self.server.verify_put:
            assert len(body) == size
            digest = hashlib.sha256(body).digest()
            with self.server.connection_condition:
                if self.server.put_digest is None:
                    self.server.put_digest = digest
                assert self.server.put_digest == digest, "PUT body changed across requests"
                self.server.puts_verified += 1
        self.respond(b"")

    def observe_workload(self):
        """Separate warmup from measurement to make lifecycle assertions independent of rate."""
        with self.server.connection_condition:
            measuring = self.server.control.telemetry_in_run > 0
            if measuring:
                self.server.workload_requests += 1
                self.server.measurement_request_seen.set()
            else:
                self.server.warmup_requests += 1
                if self.server.first_warmup_request is None:
                    self.server.first_warmup_request = time.monotonic()
            pause = measuring and self.server.workload_requests == self.server.pause_request_at
        self.server.request_seen.set()
        return measuring, pause

    def respond(self, payload, status=None):
        self.server.authorizations.append(self.headers.get("Authorization"))
        self.server.run_ids.append(self.headers.get("X-Winlin-Run"))
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        if (self.server.is_workload and self.server.raw_response_parts and
                self.server.control.telemetry_in_run > 0):
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
        endpoint.fail_warmup = False
        endpoint.verify_put = False
        endpoint.put_digest = None
        endpoint.puts_verified = 0
        endpoint.raw_response_parts = ()
        endpoint.is_workload = endpoint is not server
        endpoint.metadata_requests = []
        endpoint.capability_queries = 0
        endpoint.telemetry_samples = 0
        endpoint.connection_condition = threading.Condition()
        endpoint.open_connections = 0
        endpoint.connections_created = 0
        endpoint.warmup_requests = 0
        endpoint.first_warmup_request = None
        endpoint.workload_requests = 0
        endpoint.pause_request_at = 0
        endpoint.request_seen = threading.Event()
        endpoint.measurement_request_seen = threading.Event()
        endpoint.request_paused = threading.Event()
        endpoint.release_request = threading.Event()
        endpoint.cycles_available = False
        endpoint.reference_available = False
        endpoint.host_cpu_available = True
        endpoint.network_available = True
        endpoint.get_response_data_modes = ["shared", "copy"]
        endpoint.current_get_response_data = "shared"
        endpoint.copy_working_set_bytes = 1024 * 1024 * 1024
    server.authorizations = []
    server.response_status = 200
    server.fail_workload = False
    server.misreport_workers = False
    server.misreport_get_response_data = False
    server.telemetry_in_run = 0
    server.warmup_samples = []
    server.measurement_marker = None
    plain.control = secure.control = server
    server.fail_telemetry_at = 0
    server.expected_live_connections = 0
    server.sampled_connections = []
    server.workload_port_override = None
    server.stop_requests = 0
    server.fail_stop = False
    server.enforce_leases = False
    server.active_run = None
    server.run_sequence = 0
    server.lease_condition = threading.Condition()
    server.start_seen = threading.Event()
    server.stop_seen = threading.Event()
    server.pause_start = False
    server.release_start = threading.Event()
    server.pause_capabilities = False
    server.capabilities_seen = threading.Event()
    server.release_capabilities = threading.Event()
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

        for method, tls, data_mode, size_input, expected_gets, expected_puts in (
            ("get", "off", "copy", "512\n\n", 2, 0),
            ("get", "on", "shared", "512\nshared\n", 2, 0),
            ("put", "off", "copy", "256\n", 0, 2),
            ("mixed", "on", "copy", "512\ncopy\n256\n50\n", 1, 1),
        ):
            output = directory / f"menu-{method}-{tls}-{data_mode} 'quoted' $literal.json"
            tls_input = f"{tls}\n" + ("\n" if tls != "off" else "")
            result = subprocess.run(
                [str(menu_client)],
                input=(f"3\n1\n{tls_input}1\n{method}\n{size_input}"
                       f"1\n1\n0.12345678912345678\n2\n1\nyes\n{output}\n0\n"),
                capture_output=True, text=True, timeout=15,
                env=menu_environment,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert result.stdout.index("Save detailed telemetry?") < result.stdout.index("Result file")
            assert ("GET size" in result.stdout) == (method != "put")
            assert ("PUT size" in result.stdout) == (method != "get")
            assert ("GET response data:" in result.stdout) == (method != "put")
            assert "Warmup seconds" not in result.stdout
            report = json.loads(output.read_text())
            assert report["status"] == "completed", report
            if method != "put":
                assert report["configuration"]["get_size_bytes"] == 512
            if method != "get":
                assert report["configuration"]["put_size_bytes"] == 256
            assert report["results"][0]["get_completed"] == expected_gets
            assert report["results"][0]["put_completed"] == expected_puts
            assert report["configuration"]["get_response_data"] == data_mode
            assert report["server_run"]["get_response_data"] == data_mode

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
            assert ("--get-percent" in replay_arguments) == (method == "mixed")
            if method == "mixed":
                assert replay_arguments[replay_arguments.index("--get-percent") + 1] == "50"
            assert all(option in replay_arguments for option in (
                "--tls", "--server-workers", "--method", "--get-response-data",
                "--get-size", "--put-size",
                "--connections", "--workers", "--duration",
                "--requests", "--repetitions", "--timeout",
            ))
            assert "--warmup" not in replay_arguments
            replay_output = directory / f"replay-{method}-{tls}-{data_mode}.json"
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
            "--connections", "1", "--workers", "1",
            "--duration", "1", "--requests", "2", "--repetitions", "2",
        ]
        output = directory / "benchmark.json"
        queries_before = server.capability_queries
        connections_before = secure.connections_created
        server.warmup_samples = []
        result = subprocess.run(
            [*benchmark, "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert server.capability_queries == queries_before + 1
        report = json.loads(output.read_text())
        assert report["configuration"]["get_response_data"] == "copy"
        assert report["server_configuration"]["get_response_data"] == "copy"
        table_row = re.compile(
            r"^\s*(\d+)\s+(\d+\.\d{2})\s+(\d+\.\d{2})\s+"
            r"(\d+\.\d{2})\s+(\d+\.\d{2})\s+(\d+)\s+"
            r"(N/A|\d+\.\d{2})\s+(\d+\.\d{2})\s+(N/A|\d+\.\d{2})\s+"
            r"(N/A|\d+\.\d{2}K)\s*$", re.MULTILINE,
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
        # Warmup lasts two seconds once; both measurements reuse the same warmed connection.
        assert secure.connections_created == connections_before + 1
        assert server.warmup_elapsed >= 1.9, server.warmup_elapsed
        assert len(server.warmup_samples) == 4
        assert server.warmup_samples[0] > 0
        assert len(set(server.warmup_samples)) == 1, server.warmup_samples
        assert all(repetition["issued"] == 2 and repetition["completed"] == 2
                   for repetition in report["results"])
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

        # Multiple workers must stay live at every boundary, with independent measured limits.
        server.expected_live_connections = 2
        server.sampled_connections = []
        server.warmup_samples = []
        connections_before = plain.connections_created
        output = directory / "persistent-workers.json"
        arguments = benchmark.copy()
        for option in ("--connections", "--workers"):
            arguments[arguments.index(option) + 1] = "2"
        arguments[arguments.index("--repetitions") + 1] = "3"
        result = subprocess.run(
            [*arguments, "--tls", "off", "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        server.expected_live_connections = 0
        assert result.returncode == 0, result.stdout + result.stderr
        persistent = json.loads(output.read_text())
        assert plain.connections_created == connections_before + 2
        assert server.sampled_connections == [2] * 6, server.sampled_connections
        assert len(set(server.warmup_samples)) == 1, server.warmup_samples
        assert [entry["repetition"] for entry in persistent["results"]] == [1, 2, 3]
        assert all(entry["issued"] == 2 and entry["completed"] == 2 and entry["errors"] == 0
                   for entry in persistent["results"])

        notes = report["notes"]
        assert notes and len(notes) == len(set(notes))
        assert any("Closed-loop" in note for note in notes)
        assert any("System" in note for note in notes)
        assert any("null is not zero" in note for note in notes)
        for note in notes:
            assert note not in result.stdout + result.stderr
            assert all(note not in repetition["warnings"] for repetition in report["results"])

        # Console-only runs must keep metrics and warnings without creating even a results directory.
        console_directory = directory / "console-only"
        console_directory.mkdir()
        result = subprocess.run(
            benchmark, cwd=console_directory,
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert len(table_row.findall(result.stdout)) == 2
        assert "Results saved" not in result.stdout
        assert "Reference CPIO unavailable:" in result.stderr
        assert not list(console_directory.iterdir())

        # Both an explicit no and the default answer omit --output from the reproducible command.
        for answer in ("no", ""):
            result = subprocess.run(
                [str(menu_client)],
                input=(f"3\n1\noff\n1\nget\n512\nshared\n1\n1\n1\n2\n1\n"
                       f"{answer}\n0\n"),
                cwd=console_directory, env=menu_environment,
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert "Save detailed telemetry?" in result.stdout
            assert "Result file" not in result.stdout
            assert len(table_row.findall(result.stdout)) == 1
            displayed = re.search(r"Noninteractive command:\n([^\n]+)", result.stdout)
            assert displayed, result.stdout
            assert "--output" not in shlex.split(displayed.group(1))
            assert "Results saved" not in result.stdout
            assert not list(console_directory.iterdir())

        # Reject invalid or unadvertised modes before creating a workload or report.
        result = subprocess.run(
            [*benchmark, "--warmup", "0"], capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1 and "Unknown option: --warmup" in result.stderr, result.stderr
        result = subprocess.run(
            [*benchmark, "--get-response-data", "generated"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1
        assert "GET response data mode must be shared or copy" in result.stderr
        server.get_response_data_modes = ["shared"]
        result = subprocess.run(
            [*benchmark, "--get-response-data", "copy"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1
        assert "does not support requested GET response data mode" in result.stderr
        server.get_response_data_modes = ["shared", "copy"]
        for advertised_size in (None, 64 * 1024 * 1024):
            server.copy_working_set_bytes = advertised_size
            result = subprocess.run(
                [*benchmark, "--get-response-data", "copy"], cwd=console_directory,
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 1
            assert "Copy-mode source capabilities are outdated" in result.stderr
            assert not list(console_directory.iterdir())
        server.copy_working_set_bytes = 1024 * 1024 * 1024

        # An explicitly empty filename is an error, not an implicit request to disable saving.
        result = subprocess.run(
            [*benchmark, "--output", ""], cwd=console_directory,
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1
        assert "Missing --output" in result.stderr
        assert not list(console_directory.iterdir())

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
        assert [(row[0], row[-1]) for row in rows] == [("1", "5.00K"), ("2", "5.00K")]
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

        single_repetition = benchmark.copy()
        single_repetition[single_repetition.index("--repetitions") + 1] = "1"
        multiple_workers = single_repetition.copy()
        for option in ("--connections", "--workers"):
            multiple_workers[multiple_workers.index(option) + 1] = "2"

        # Launch the native binary without its shell wrapper. Sixteen workload sockets plus
        # control/epoll descriptors exceed the inherited soft limit unless startup raises it.
        output = directory / "native-fd-limit.json"
        arguments = benchmark.copy()
        for option, value in (("--connections", "16"), ("--workers", "1"), ("--requests", "8")):
            arguments[arguments.index(option) + 1] = value
        hard_fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        result = subprocess.run(
            [*limited_client, "16", str(hard_fd_limit), *arguments,
             "--tls", "off", "--output", str(output)],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(output.read_text())
        assert all(entry["issued"] == 8 and entry["completed"] == 8 and entry["errors"] == 0
                   for entry in report["results"])

        if faults:
            # A syscall-level probe rejects pre-write EPOLLOUT and repeated interest masks.
            # Force both a blocked write and a partial header; framing and request limits
            # must remain correct across connections and consecutive repetitions.
            output = directory / "optimistic-epoll.json"
            arguments = benchmark.copy()
            for option, value in (("--connections", "2"), ("--workers", "1"),
                                  ("--requests", "8")):
                arguments[arguments.index(option) + 1] = value
            result = subprocess.run(
                [*arguments, "--tls", "off", "--output", str(output)],
                capture_output=True, text=True, timeout=15,
                env=dict(os.environ, LD_PRELOAD=faults,
                         WINLIN_TEST_DATA_PORT=str(plain.server_port),
                         WINLIN_TEST_OPTIMISTIC_WRITES="1"),
            )
            assert result.returncode == 0, result.stdout + result.stderr
            for marker in ("injected blocked optimistic write", "injected partial request write",
                           "verified optimistic request write"):
                assert marker in result.stderr, result.stderr
            optimistic = json.loads(output.read_text())
            assert all(entry["issued"] == 8 and entry["completed"] == 8 and entry["errors"] == 0
                       for entry in optimistic["results"])

            # Check the TLS write itself and exact body framing through retries, multiple
            # connections/repetitions, and mixed requests. Include empty and multi-record PUTs.
            for size in (0, 256, 16384, 65536):
                secure.verify_put = True
                secure.put_digest = None
                secure.puts_verified = 0
                output = directory / f"tls-put-prefix-{size}.json"
                arguments = benchmark.copy()
                for option, value in (("--connections", "2"), ("--workers", "2"),
                                      ("--requests", "4")):
                    arguments[arguments.index(option) + 1] = value
                result = subprocess.run(
                    [*arguments, "--method", "mixed", "--get-percent", "50",
                     "--put-size", str(size), "--output", str(output)],
                    capture_output=True, text=True, timeout=15,
                    env=dict(os.environ, LD_PRELOAD=faults,
                             WINLIN_TEST_DATA_PORT=str(secure.server_port),
                             WINLIN_TEST_TLS_PUT_SIZE=str(size)),
                )
                secure.verify_put = False
                assert result.returncode == 0, result.stdout + result.stderr
                assert "verified combined TLS PUT prefix" in result.stderr, result.stderr
                assert "preserved TLS retry buffer" in result.stderr, result.stderr
                report = json.loads(output.read_text())
                assert all(entry["put_completed"] == 2 and entry["get_completed"] == 2 and
                           entry["sent_object_bytes"] == 2 * size and entry["errors"] == 0
                           for entry in report["results"])
                assert secure.puts_verified > 4

            # Inject delay at the two distinct boundaries that previously admitted expired I/O.
            for variable, marker in (
                ("WINLIN_TEST_LATE_READY", "delayed ready response"),
                ("WINLIN_TEST_LATE_RECV", "delayed received response"),
            ):
                output = directory / f"{variable}.json"
                server.measurement_marker = directory / f"{variable}.ready"
                result = subprocess.run(
                    [*single_repetition, "--tls", "off", "--timeout", "0.05",
                     "--output", str(output)],
                    capture_output=True, text=True, timeout=15,
                    env=dict(os.environ, LD_PRELOAD=faults, WINLIN_TEST_DATA_PORT=str(plain.server_port),
                             WINLIN_TEST_MEASUREMENT_MARKER=str(server.measurement_marker),
                             **{variable: "1"}),
                )
                server.measurement_marker = None
                assert result.returncode == 2, result.stdout + result.stderr
                assert marker in result.stderr, result.stderr
                repetition = json.loads(output.read_text())["results"][0]
                assert repetition["completed"] == 0 and repetition["errors"] == 1, repetition
                assert repetition["first_error"] == "Request timed out", repetition
                assert repetition["latency"]["samples"] == 0, repetition
                assert result.stderr.count("became dead:") == 1, result.stderr

            # Teardown has a known injected CPU cost. Neither final process counters nor the
            # final control sample may include it; both workload connections must still be live.
            with plain.connection_condition:
                assert plain.connection_condition.wait_for(
                    lambda: plain.open_connections == 0, timeout=1,
                )
            server.expected_live_connections = 2
            server.sampled_connections = []
            output = directory / "measurement-boundary.json"
            result = subprocess.run(
                [*multiple_workers, "--tls", "off", "--output", str(output)],
                capture_output=True, text=True, timeout=15,
                env=dict(os.environ, LD_PRELOAD=faults, WINLIN_TEST_DATA_PORT=str(plain.server_port),
                         WINLIN_TEST_TEARDOWN_CPU="1"),
            )
            server.expected_live_connections = 0
            assert result.returncode == 0, result.stdout + result.stderr
            assert result.stderr.count("accounted teardown CPU") == 2, result.stderr
            assert server.sampled_connections == [2, 2], server.sampled_connections
            repetition = json.loads(output.read_text())["results"][0]
            assert repetition["client_process"]["user_cpu_seconds"] < 5, repetition
            assert repetition["client_process"]["elapsed_seconds"] >= repetition["elapsed_seconds"]
            assert repetition["server_process"]["elapsed_seconds"] == 0.25, repetition

            # A never-created worker must not leave the new measurement latch waiting forever.
            output = directory / "worker-creation-failure.json"
            result = subprocess.run(
                [*multiple_workers, "--tls", "off", "--output", str(output)],
                capture_output=True, text=True, timeout=15,
                env=dict(os.environ, LD_PRELOAD=faults, WINLIN_TEST_FAIL_THREAD_CREATE="1"),
            )
            assert result.returncode == 1, result.stdout + result.stderr
            report = json.loads(output.read_text())
            assert report["status"] == "failed"
            assert "Cannot start load workers" in report["failure"], report

        # Every failure stage must release parked workers and stop the benchmark lease.
        for stage in ("setup", "warmup", "baseline", "final", "later-baseline", "later-final"):
            output = directory / f"{stage}-failure.json"
            stops_before = server.stop_requests
            arguments = [*multiple_workers, "--tls", "off", "--output", str(output)]
            with socket.socket() as refused:
                refused.bind(("127.0.0.1", 0))
                if stage == "setup":
                    server.workload_port_override = refused.getsockname()[1]
                elif stage == "warmup":
                    plain.fail_workload = True
                    plain.fail_warmup = True
                else:
                    server.fail_telemetry_at = {
                        "baseline": 1, "final": 2, "later-baseline": 3, "later-final": 4,
                    }[stage]
                    if stage.startswith("later-"):
                        arguments[arguments.index("--repetitions") + 1] = "2"
                result = subprocess.run(
                    arguments, capture_output=True, text=True, timeout=15,
                )
            server.workload_port_override = None
            plain.fail_workload = False
            plain.fail_warmup = False
            server.fail_telemetry_at = 0
            assert result.returncode == 1, result.stdout + result.stderr
            report = json.loads(output.read_text())
            assert report["status"] == "failed", report
            assert len(report["results"]) == (1 if stage.startswith("later-") else 0), report
            assert server.stop_requests == stops_before + 1
            if stage not in ("setup", "warmup"):
                assert "Server rejected control request (HTTP 503)" in report["failure"], report
            with plain.connection_condition:
                assert plain.connection_condition.wait_for(
                    lambda: plain.open_connections == 0, timeout=1,
                ), stage

        # Signals must unwind every worker phase, stop only the owned lease, and allow an
        # immediate restart. Pausing the start reply also tests cancellation before ID receipt.
        for cancellation in (signal.SIGINT, signal.SIGTERM):
            for menu_mode in (False, True):
                server.pause_capabilities = True
                server.capabilities_seen.clear()
                server.release_capabilities.clear()
                stops_before = server.stop_requests
                process = subprocess.Popen(
                    [client] if menu_mode else [*single_repetition, "--tls", "off"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, env=menu_environment,
                )
                try:
                    if menu_mode:
                        process.stdin.write(
                            "3\n1\noff\n1\nget\n256\ncopy\n1\n1\n1\n2\n1\nno\n0\n")
                        process.stdin.flush()
                    assert server.capabilities_seen.wait(5)
                    process.send_signal(cancellation)
                    server.release_capabilities.set()
                    stdout, stderr = process.communicate(timeout=5)
                finally:
                    server.release_capabilities.set()
                    server.pause_capabilities = False
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                expected = 0 if menu_mode and cancellation == signal.SIGINT else 128 + cancellation
                assert process.returncode == expected, stdout + stderr
                assert "Server rejected control request (HTTP 503)" in stderr, stderr
                assert ("SIGINT" if cancellation == signal.SIGINT else "SIGTERM") in stderr
                assert server.stop_requests == stops_before

        server.enforce_leases = True
        handshake = socketserver.ThreadingTCPServer(("127.0.0.1", 0), StalledHandshake)
        handshake.hello_received = threading.Event()
        handshake_worker = threading.Thread(target=handshake.serve_forever)
        handshake_worker.start()
        try:
            for stage, cancellation in (
                ("start", signal.SIGINT), ("setup", signal.SIGINT),
                ("warmup", signal.SIGINT), ("measurement", signal.SIGINT),
                ("measurement", signal.SIGTERM), ("later-repetition", signal.SIGINT),
                ("cleanup-failure", signal.SIGINT),
            ):
                output = directory / f"interrupted-{stage}-{cancellation}.json"
                arguments = [*multiple_workers, "--tls", "off", "--output", str(output)]
                arguments[arguments.index("--requests") + 1] = "0"
                arguments[arguments.index("--duration") + 1] = "30"
                server.start_seen.clear()
                server.stop_seen.clear()
                server.release_start.clear()
                plain.request_seen.clear()
                plain.measurement_request_seen.clear()
                plain.request_paused.clear()
                plain.release_request.clear()
                plain.workload_requests = 0
                server.pause_start = stage == "start"
                server.fail_stop = stage == "cleanup-failure"
                if stage == "setup":
                    arguments[arguments.index("--tls") + 1] = "on"
                    server.workload_port_override = handshake.server_address[1]
                    handshake.hello_received.clear()
                elif stage == "later-repetition":
                    arguments[arguments.index("--requests") + 1] = "2"
                    arguments[arguments.index("--repetitions") + 1] = "2"
                    plain.pause_request_at = 3
                stops_before = server.stop_requests
                process = subprocess.Popen(
                    arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    assert server.start_seen.wait(5), "Client never acquired a run"
                    if stage == "setup":
                        assert handshake.hello_received.wait(5), "TLS setup did not start"
                    elif stage == "later-repetition":
                        assert plain.request_paused.wait(5), "Second repetition did not start"
                    elif stage == "warmup":
                        assert plain.request_seen.wait(5), "Load phase did not start"
                    elif stage in ("measurement", "cleanup-failure"):
                        assert plain.measurement_request_seen.wait(5), "Measurement did not start"
                    process.send_signal(cancellation)
                    server.release_start.set()
                    stdout, stderr = process.communicate(timeout=5)
                finally:
                    server.release_start.set()
                    plain.release_request.set()
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                    server.pause_start = False
                    server.fail_stop = False
                    server.workload_port_override = None
                    plain.pause_request_at = 0
                assert process.returncode == 128 + cancellation, stdout + stderr
                report = json.loads(output.read_text())
                assert report["status"] == "interrupted", report
                assert len(report["results"]) == (1 if stage == "later-repetition" else 0)
                if stage == "later-repetition":
                    assert report["results"][0]["completed"] == 2
                assert "run_id" not in output.read_text()
                expected_signal = "SIGINT" if cancellation == signal.SIGINT else "SIGTERM"
                assert expected_signal in stderr
                if stage == "cleanup-failure":
                    assert "bounded lease will expire" in stderr, stderr
                    assert "HTTP 503" in report["cleanup_failure"], report
                    assert server.active_run is not None
                    # A cleanup failure cannot authorize stealing or silently resetting the run.
                    retry = subprocess.run(
                        [*single_repetition, "--tls", "off"],
                        capture_output=True, text=True, timeout=10,
                    )
                    assert retry.returncode == 1 and "HTTP 409" in retry.stderr
                    server.active_run = None
                    assert server.stop_requests == stops_before
                else:
                    assert server.stop_requests == stops_before + 1
                assert server.active_run is None
                restarted = subprocess.run(
                    [*single_repetition, "--tls", "off"],
                    capture_output=True, text=True, timeout=10,
                )
                assert restarted.returncode == 0, restarted.stdout + restarted.stderr
                assert server.active_run is None

            # A conflicting run is never ours to stop, including when start itself returns 409.
            server.active_run = "bb" * 32
            stops_before = server.stop_requests
            refused = subprocess.run(
                [*single_repetition, "--tls", "off"],
                capture_output=True, text=True, timeout=10,
            )
            assert refused.returncode == 1, refused.stdout + refused.stderr
            assert "HTTP 409" in refused.stderr
            assert server.stop_requests == stops_before
            assert server.active_run == "bb" * 32
            server.active_run = None

            # The interactive process must restore/reset cancellation state before another run.
            plain.request_seen.clear()
            server.stop_seen.clear()
            menu = subprocess.Popen(
                [client], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=menu_environment,
            )
            try:
                menu.stdin.write("3\n1\noff\n1\nget\n256\ncopy\n2\n2\n30\n0\n1\nno\n")
                menu.stdin.flush()
                assert plain.request_seen.wait(5), "Interactive workload did not start"
                menu.send_signal(signal.SIGINT)
                assert server.stop_seen.wait(5), "Interactive cancellation did not stop its run"
                stdout, stderr = menu.communicate(
                    input="3\n1\noff\n1\nget\n256\ncopy\n2\n2\n1\n2\n1\nno\n0\n",
                    timeout=10,
                )
            finally:
                if menu.poll() is None:
                    menu.kill()
                    menu.communicate()
            assert menu.returncode == 0, stdout + stderr
            assert "SIGINT" in stderr
            assert server.active_run is None
        finally:
            server.enforce_leases = False
            server.active_run = None
            handshake.shutdown()
            handshake.server_close()
            handshake_worker.join()

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
            assert report["results"][0]["errors"] > 0
            assert all(repetition["completed"] == 0 for repetition in report["results"])
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
            assert repetition["completed"] == 0
            assert repetition["server_reference_cycles_per_io"] is None
            assert repetition["warnings"], repetition
            for warning in repetition["warnings"]:
                assert warning in result.stderr
        assert report["results"][0]["errors"] > 0
        assert [row[-1] for row in table_row.findall(result.stdout)] == ["N/A", "N/A"]
        for note in report["notes"]:
            assert note not in result.stdout + result.stderr
        result = subprocess.run(
            benchmark, cwd=console_directory,
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 2, result.stdout + result.stderr
        assert len(table_row.findall(result.stdout)) == 2
        assert "Benchmark completed with errors" in result.stderr
        assert "Results saved" not in result.stdout
        assert not list(console_directory.iterdir())
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
        result = subprocess.run(
            benchmark, cwd=console_directory,
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1, result.stdout + result.stderr
        assert "did not apply the requested benchmark settings" in result.stderr
        assert not list(console_directory.iterdir())
        server.misreport_workers = False
        server.misreport_get_response_data = True
        result = subprocess.run(
            [*benchmark, "--get-response-data", "copy"], cwd=console_directory,
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1, result.stdout + result.stderr
        assert "did not apply the requested benchmark settings" in result.stderr
        assert not list(console_directory.iterdir())
        server.misreport_get_response_data = False
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
