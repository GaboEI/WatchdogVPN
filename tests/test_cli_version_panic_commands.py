from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliVersionPanicCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "PYTHONPATH": str(ROOT_DIR),
        }
        result = subprocess.run(
            [str(WATCHDOG), *args],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        if check and result.returncode != 0:
            self.fail(f"command failed: {result.stderr}\nstdout={result.stdout}")
        return result

    def test_version_human_matches_published_cli_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["version"], tmp)

        self.assertEqual(result.stdout.strip(), "WatchdogVPN v0.3.1")

    def test_version_json_uses_stable_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["version", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertEqual(
            data,
            {
                "product": "WatchdogVPN",
                "version": "v0.3.1",
                "python_cli": True,
            },
        )

    def test_panic_passthrough_uses_argv_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "panic-argv.txt"
            script = Path(tmp) / "watchdog_panic"
            script.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$@\" > \"$WATCHDOGVPN_PANIC_TEST_LOG\"\n"
                "printf 'panic %s\\n' \"$1\"\n",
                encoding="utf-8",
            )
            script.chmod(0o755)

            result = subprocess.run(
                [
                    str(WATCHDOG),
                    "panic",
                    "status",
                    "--panic-script",
                    str(script),
                ],
                text=True,
                capture_output=True,
                env={
                    "WATCHDOGVPN_CONFIG_DIR": tmp,
                    "WATCHDOGVPN_PANIC_TEST_LOG": str(log),
                    "PYTHONPATH": str(ROOT_DIR),
                },
                check=False,
            )
            argv_log = log.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "panic status\n")
        self.assertEqual(argv_log, "status\n")

    def test_nested_command_requires_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["profile"], tmp, check=False)

        self.assertEqual(result.returncode, 2)
        self.assertIn("profile_command", result.stderr)
        self.assertNotIn("WatchdogVPN command line", result.stdout)


if __name__ == "__main__":
    unittest.main()
