"""Verify script behavior without installing packages or changing the host."""

import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MOCK = r"""
import json
import os
from pathlib import Path
import resource
import sys

name = Path(sys.argv[0]).name
arguments = sys.argv[1:]
with open(os.environ["WINLIN_TEST_LOG"], "a") as log:
    log.write(json.dumps([name, *arguments]) + "\n")
if name == "sudo":
    os.execvp(arguments[0], arguments)
if name == "cmake":
    if arguments == ["--version"]:
        print("cmake version 3.28.3")
    else:
        sys.exit(int(os.environ.get("WINLIN_TEST_CMAKE_EXIT", "0")))
elif name == "dpkg-query":
    if arguments[-2] == "-f=${Version}":
        print("3.11.3")
    elif os.environ.get("WINLIN_TEST_QUERY_EXIT"):
        print("simulated package database failure", file=sys.stderr)
        sys.exit(int(os.environ["WINLIN_TEST_QUERY_EXIT"]))
    elif (arguments[-1] == os.environ.get("WINLIN_TEST_MISSING")
          and not Path(os.environ["WINLIN_TEST_INSTALLED"]).exists()):
        sys.exit(1)
    else:
        print("installed")
elif name == "apt-get":
    code = int(os.environ.get("WINLIN_TEST_APT_EXIT", "0"))
    if code:
        sys.exit(code)
    if arguments[0] == "install":
        Path(os.environ["WINLIN_TEST_INSTALLED"]).touch()
elif name in ("winlin", "winlin-server"):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(json.dumps({
        "arguments": arguments, "cwd": str(Path.cwd()), "pid": os.getpid(),
        "soft_fd_limit": soft, "hard_fd_limit": hard,
    }))
    sys.exit(int(os.environ.get("WINLIN_TEST_NATIVE_EXIT", "0")))
"""


class Scripts(unittest.TestCase):
    """Intercept package/build tools so script failure paths never mutate the shared host."""

    def setUp(self):
        # Retain actual OS/compiler probes while mocking commands that install packages or build code.
        self.temporary = tempfile.TemporaryDirectory(prefix="winlin-scripts-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.log = self.directory / "calls.jsonl"
        for name in ("cmake", "dpkg-query", "apt-get", "sudo"):
            path = self.bin / name
            path.write_text(f"#!{sys.executable}\n" + MOCK)
            path.chmod(0o755)
        self.env = dict(
            os.environ,
            PATH=f"{self.bin}:{os.environ['PATH']}",
            WINLIN_TEST_LOG=str(self.log),
            WINLIN_TEST_INSTALLED=str(self.directory / "installed"),
            CMAKE_BUILD_PARALLEL_LEVEL="2",
        )
        # A separate checkout exercises repository-relative defaults without starting real binaries.
        self.checkout = self.directory / "checkout with spaces"
        (self.checkout / "scripts").mkdir(parents=True)
        (self.checkout / "build").mkdir()
        (self.checkout / ".winlin-local").mkdir()
        for script in ("run-client.sh", "run-server.sh"):
            shutil.copy2(ROOT / "scripts" / script, self.checkout / "scripts" / script)
        for name in ("winlin", "winlin-server"):
            executable = self.checkout / "build" / name
            executable.write_text(f"#!{sys.executable}\n" + MOCK)
            executable.chmod(0o755)
        for name in ("server.pem", "server.key", "pairing-token"):
            (self.checkout / ".winlin-local" / name).write_text("launcher fixture, not a credential")

    def run_script(self, script, *arguments, expected=0, fd_limits=None, **environment):
        """Run from outside the repository to catch accidental working-directory assumptions."""
        root = self.checkout if script in ("run-client.sh", "run-server.sh") else ROOT
        result = subprocess.run(
            ["bash", str(root / "scripts" / script), *arguments],
            cwd=self.directory,
            env=dict(self.env, **environment),
            text=True,
            capture_output=True,
            timeout=10,
            # Limit only this single-threaded test's child, never the test runner or shared host.
            preexec_fn=(lambda: resource.setrlimit(resource.RLIMIT_NOFILE, fd_limits))
            if fd_limits else None,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def calls(self, program):
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        calls = []
        for line in lines:
            call = json.loads(line)
            if call[0] == program:
                calls.append(call[1:])
        return calls

    def test_components_and_paths(self):
        for component, client, server in (("client", "ON", "OFF"), ("server", "OFF", "ON"),
                                          ("all", "ON", "ON")):
            with self.subTest(component=component):
                result = self.run_script(
                    "build.sh", component, "--jobs", "3", "--build-dir", "build with spaces",
                )
                configure, build = self.calls("cmake")[-2:]
                self.assertIn(str(ROOT), configure)
                self.assertIn("build with spaces", configure)
                self.assertIn(f"-DWINLIN_BUILD_CLIENT={client}", configure)
                self.assertIn(f"-DWINLIN_BUILD_SERVER={server}", configure)
                self.assertEqual(build, ["--build", "build with spaces", "--parallel", "3"])
                self.assertEqual("Client:" in result.stdout, client == "ON")
                self.assertEqual("Server:" in result.stdout, server == "ON")

    def test_build_defaults_and_invalid_arguments(self):
        self.run_script("build.sh")
        self.assertIn(str(ROOT / "build"), self.calls("cmake")[0])
        before = len(self.calls("cmake"))
        for arguments in (("other",), ("client", "--jobs", "0"), ("--build-dir",),
                          ("--jobs", "-2"), ("--unexpected",), ("--jobs", "abc")):
            with self.subTest(arguments=arguments):
                self.run_script("build.sh", *arguments, expected=2)
        self.assertEqual(len(self.calls("cmake")), before)

    def test_configure_failure_stops_build(self):
        result = self.run_script("build.sh", "server", expected=23, WINLIN_TEST_CMAKE_EXIT="23")
        self.assertIn("FATAL:", result.stderr)
        self.assertEqual(len(self.calls("cmake")), 1)

    def test_prep_check_never_installs(self):
        self.run_script("prep.sh", "--check")
        result = self.run_script(
            "prep.sh", "--check", expected=1, WINLIN_TEST_MISSING="nlohmann-json3-dev",
        )
        self.assertIn("nlohmann-json3-dev", result.stderr)
        self.assertFalse(self.calls("apt-get"))
        self.assertFalse(self.calls("sudo"))

    def test_prep_installs_only_missing_packages_and_is_idempotent(self):
        environment = {"WINLIN_TEST_MISSING": "nlohmann-json3-dev"}
        self.run_script("prep.sh", **environment)
        self.assertEqual(self.calls("apt-get"), [
            ["update"], ["install", "-y", "--no-install-recommends", "nlohmann-json3-dev"],
        ])
        self.run_script("prep.sh", **environment)
        self.assertEqual(len(self.calls("apt-get")), 2)

    def test_prep_failure_propagates(self):
        result = self.run_script(
            "prep.sh", expected=42, WINLIN_TEST_MISSING="nlohmann-json3-dev",
            WINLIN_TEST_APT_EXIT="42",
        )
        self.assertIn("FATAL:", result.stderr)
        self.assertEqual(self.calls("apt-get"), [["update"]])

    def test_prep_query_failure_does_not_install(self):
        result = self.run_script("prep.sh", expected=42, WINLIN_TEST_QUERY_EXIT="42")
        self.assertIn("FATAL:", result.stderr)
        self.assertIn("simulated package database failure", result.stderr)
        self.assertFalse(self.calls("apt-get"))

    def test_client_launcher_defaults_and_argument_boundaries(self):
        """Forward menu startup and opaque client arguments without changing the caller's directory."""
        interactive = self.run_script("run-client.sh")
        self.assertEqual(json.loads(interactive.stdout)["arguments"], [])
        result = self.run_script(
            "run-client.sh", "--", "run", "--target", "target with spaces.json", "--output", "",
        )
        invocation = json.loads(result.stdout)
        self.assertEqual(
            invocation["arguments"],
            ["run", "--target", "target with spaces.json", "--output", ""],
        )
        self.assertEqual(invocation["cwd"], str(self.directory))

    def test_server_launcher_defaults_and_overrides(self):
        """Reuse state files and allow individual overrides without duplicating native options."""
        result = self.run_script("run-server.sh", "--bind", "10.0.0.4")
        arguments = json.loads(result.stdout)["arguments"]
        state = self.checkout / ".winlin-local"
        self.assertEqual(arguments, [
            "--cert", str(state / "server.pem"), "--key", str(state / "server.key"),
            "--token-file", str(state / "pairing-token"), "--bind", "10.0.0.4",
        ])
        custom = self.directory / "private state"
        shutil.copytree(state, custom)
        result = self.run_script(
            "run-server.sh", "--state-dir", "private state", "--cert", str(custom / "server.pem"),
        )
        self.assertEqual(json.loads(result.stdout)["arguments"], [
            "--key", "private state/server.key", "--token-file", "private state/pairing-token",
            "--cert", str(custom / "server.pem"),
        ])
        result = self.run_script(
            "run-server.sh", "--state-dir", "private state", "--",
            "--cert", str(custom / "server.pem"), "--key", str(custom / "server.key"),
            "--token-file", str(custom / "pairing-token"), "--backend", "ktls",
        )
        arguments = json.loads(result.stdout)["arguments"]
        for option in ("--cert", "--key", "--token-file"):
            self.assertEqual(arguments.count(option), 1)
        self.assertEqual(arguments[-2:], ["--backend", "ktls"])

    def test_launcher_custom_build_paths_and_native_exit_codes(self):
        """Locate caller-relative builds with spaces and preserve application failure statuses."""
        custom = self.directory / "custom build"
        shutil.copytree(self.checkout / "build", custom)
        for script in ("run-client.sh", "run-server.sh"):
            with self.subTest(script=script):
                result = self.run_script(
                    script, "--build-dir", "custom build",
                    expected=23, WINLIN_TEST_NATIVE_EXIT="23",
                )
                self.assertIn("arguments", json.loads(result.stdout))

    def test_launcher_preflight_errors_and_help(self):
        """Reject incomplete launch settings before execution while keeping help available."""
        before = len(self.calls("winlin-server"))
        for script in ("run-client.sh", "run-server.sh"):
            with self.subTest(script=script):
                self.run_script(script, "--build-dir", expected=2)
                self.run_script(script, "--build-dir", "missing build", expected=1)
                self.assertIn("Usage:", self.run_script(script, "--help").stdout)
        self.run_script("run-server.sh", "--state-dir", "missing state", expected=1)
        self.run_script("run-server.sh", "--workers", expected=2)
        self.assertEqual(len(self.calls("winlin-server")), before)
        # Native help must not require a certificate or pairing state.
        result = self.run_script("run-server.sh", "--state-dir", "missing state", "--", "--help")
        self.assertEqual(json.loads(result.stdout)["arguments"], ["--help"])

    def test_launchers_replace_shell_process(self):
        """Keep the caller-visible PID so signals reach the real foreground application."""
        for script in ("run-client.sh", "run-server.sh"):
            with self.subTest(script=script):
                process = subprocess.Popen(
                    ["bash", str(self.checkout / "scripts" / script)],
                    cwd=self.directory, env=self.env, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                )
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(json.loads(stdout)["pid"], process.pid)

    def test_launchers_raise_soft_fd_limit_without_lowering_hard_limit(self):
        """Verify the actual limits inherited by each application, not just a shell command string."""
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        for script in ("run-client.sh", "run-server.sh"):
            with self.subTest(script=script):
                result = self.run_script(script, fd_limits=(1024, hard))
                invocation = json.loads(result.stdout)
                self.assertEqual(invocation["soft_fd_limit"], 524288)
                self.assertEqual(invocation["hard_fd_limit"], hard)
                if hard == resource.RLIM_INFINITY or hard > 524288:
                    result = self.run_script(script, fd_limits=(524289, hard))
                    self.assertEqual(json.loads(result.stdout)["soft_fd_limit"], 524289)

    def test_launchers_reject_insufficient_hard_fd_limit(self):
        """Fail before execution when the process cannot reach 512K; help remains accessible."""
        for script, binary in (("run-client.sh", "winlin"), ("run-server.sh", "winlin-server")):
            with self.subTest(script=script):
                before = len(self.calls(binary))
                result = self.run_script(script, fd_limits=(1024, 4096), expected=1)
                self.assertIn("FATAL:", result.stderr)
                self.assertIn("524288", result.stderr)
                self.assertIn("hard=4096", result.stderr)
                self.assertIn("Raise the hard nofile limit", result.stderr)
                self.assertEqual(len(self.calls(binary)), before)
                self.run_script(script, "--", "--help", fd_limits=(1024, 4096))


if __name__ == "__main__":
    unittest.main()
