"""Verify script behavior without installing packages or changing the host."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MOCK = r"""
import json
import os
from pathlib import Path
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
"""


class Scripts(unittest.TestCase):
    def setUp(self):
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

    def run_script(self, script, *arguments, expected=0, **environment):
        result = subprocess.run(
            ["bash", str(ROOT / "scripts" / script), *arguments],
            cwd=self.directory,
            env=dict(self.env, **environment),
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def calls(self, program):
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        return [call[1:] for line in lines if (call := json.loads(line))[0] == program]

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
        self.run_script("build.sh", "server", expected=23, WINLIN_TEST_CMAKE_EXIT="23")
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
        self.run_script(
            "prep.sh", expected=42, WINLIN_TEST_MISSING="nlohmann-json3-dev",
            WINLIN_TEST_APT_EXIT="42",
        )
        self.assertEqual(self.calls("apt-get"), [["update"]])


if __name__ == "__main__":
    unittest.main()
