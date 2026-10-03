#!/usr/bin/env python3
"""Startup rollback checks; every network/module command runs against a fake."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MOCK = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
path = Path(os.environ["TEST_STATE"])
state = json.loads(path.read_text())
state["calls"].append([name, *args])
code = 0
if name == "modprobe":
    if "-r" in args:
        code = int(os.environ.get("TEST_UNLOAD_ERROR", "0"))
        if not code: state["loaded"] = False
    else:
        code = int(os.environ.get("TEST_LOAD_ERROR", "0"))
        if not code: state["loaded"] = True
elif name == "ip" and args[:2] == ["link", "show"]:
    code = 0 if state["loaded"] else 1
elif name == "ip" and args[:3] == ["route", "show", "default"]:
    print("default via 192.0.2.1 dev eth0")
elif name == "ip" and args[:3] == ["-o", "route", "get"]:
    print("1.1.1.1 via 192.0.2.1 dev eth0")
else:
    state["steps"] += 1
    if state["steps"] == int(os.environ.get("TEST_FAIL_STEP", "0")):
        code = 23
path.write_text(json.dumps(state))
sys.exit(code)
'''


class StartupTests(unittest.TestCase):
    def run_script(self, script_name, **options):
        with tempfile.TemporaryDirectory(prefix="tnet-startup-") as directory:
            directory = Path(directory)
            mock = directory / "mock"
            mock.write_text(MOCK)
            mock.chmod(0o755)
            for command in ("ip", "modprobe", "sysctl", "iptables"):
                (directory / command).symlink_to(mock)
            source = (ROOT / script_name).read_text()
            guard = 'if [ "$EUID" -ne 0 ]; then'
            self.assertEqual(source.count(guard), 1)
            # Remove only the privilege guard in the test copy; host commands are mocked.
            script = directory / script_name
            script.write_text(source.replace(guard, "if false; then"))
            state = directory / "state.json"
            state.write_text(json.dumps({"loaded": False, "steps": 0, "calls": []}))
            env = os.environ.copy()
            env.update({"PATH": str(directory) + os.pathsep + env["PATH"], "TEST_STATE": str(state)})
            for key in ("TEST_FAIL_STEP", "TEST_LOAD_ERROR", "TEST_UNLOAD_ERROR"):
                env.pop(key, None)
            env.update({key: str(value) for key, value in options.items()})
            result = subprocess.run(["bash", str(script), "c"], env=env, capture_output=True, text=True)
            return result, json.loads(state.read_text())

    def test_each_add_rules_failure_unloads_and_stops(self):
        for script, steps in (("client.sh", 5), ("server.sh", 4)):
            for step in range(1, steps + 1):
                with self.subTest(script=script, failed_step=step):
                    result, state = self.run_script(script, TEST_FAIL_STEP=step)
                    self.assertEqual(result.returncode, 23, result.stderr)
                    self.assertFalse(state["loaded"])
                    self.assertEqual(state["steps"], step)
                    self.assertEqual(state["calls"][-1], ["modprobe", "-r", "tnet"])

    def test_success_keeps_module_loaded(self):
        for script in ("client.sh", "server.sh"):
            with self.subTest(script=script):
                result, state = self.run_script(script)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(state["loaded"])
                self.assertNotIn(["modprobe", "-r", "tnet"], state["calls"])

    def test_load_failure_does_not_attempt_unload(self):
        for script in ("client.sh", "server.sh"):
            with self.subTest(script=script):
                result, state = self.run_script(script, TEST_LOAD_ERROR=17)
                self.assertEqual(result.returncode, 17)
                self.assertEqual(state["steps"], 0)
                self.assertNotIn(["modprobe", "-r", "tnet"], state["calls"])

    def test_unload_failure_reports_error_and_preserves_original_status(self):
        for script in ("client.sh", "server.sh"):
            with self.subTest(script=script):
                result, state = self.run_script(script, TEST_FAIL_STEP=2, TEST_UNLOAD_ERROR=19)
                self.assertEqual(result.returncode, 23)
                self.assertEqual(state["steps"], 2)
                self.assertTrue(state["loaded"])
                self.assertIn("failed to unload module tnet", result.stderr)
                self.assertEqual(state["calls"].count(["modprobe", "-r", "tnet"]), 1)


if __name__ == "__main__":
    unittest.main()
