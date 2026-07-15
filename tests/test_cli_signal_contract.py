from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import cli.main


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliSignalContractTests(unittest.TestCase):
    def test_keyboard_interrupt_before_argument_parsing_is_clean(self) -> None:
        with (
            patch("cli.main._build_parser", side_effect=KeyboardInterrupt),
            redirect_stdout(StringIO()) as stdout,
            redirect_stderr(StringIO()) as stderr,
        ):
            result = cli.main.main(["version"])

        self.assertEqual(result, 130)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "error: operation cancelled\n")
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_keyboard_interrupt_before_argument_parsing_uses_json_contract(self) -> None:
        with (
            patch("cli.main._build_parser", side_effect=KeyboardInterrupt),
            redirect_stdout(StringIO()) as stdout,
            redirect_stderr(StringIO()) as stderr,
        ):
            result = cli.main.main(["version", "--json"])

        self.assertEqual(result, 130)
        self.assertEqual(stderr.getvalue(), "")
        data = json.loads(stdout.getvalue())
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "operation cancelled")

    def test_broken_pipe_before_argument_parsing_is_silent(self) -> None:
        with (
            patch("cli.main._build_parser", side_effect=BrokenPipeError),
            redirect_stdout(StringIO()) as stdout,
            redirect_stderr(StringIO()) as stderr,
        ):
            result = cli.main.main(["version"])

        self.assertEqual(result, 141)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_broken_pipe_during_handler_output_is_silent(self) -> None:
        with (
            patch("cli.main._version", side_effect=BrokenPipeError),
            redirect_stdout(StringIO()) as stdout,
            redirect_stderr(StringIO()) as stderr,
        ):
            result = cli.main.main(["version"])

        self.assertEqual(result, 141)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_signal_return_codes_use_shell_convention(self) -> None:
        self.assertEqual(cli.main._normalize_exit_code(-2), 130)
        self.assertEqual(cli.main._normalize_exit_code(-13), 141)
        self.assertEqual(cli.main._normalize_exit_code(0), 0)
        self.assertEqual(cli.main._normalize_exit_code(70), 70)

    def test_doctor_pipeline_returns_documented_sigpipe_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = tmp / "doctor.sh"
            script.write_text("#!/usr/bin/env bash\nexec yes doctor-line\n", encoding="utf-8")
            script.chmod(0o755)
            env = os.environ.copy()
            env.update(
                {
                    "WATCHDOGVPN_CONFIG_DIR": str(tmp / "config"),
                    "PYTHONPATH": str(ROOT_DIR),
                }
            )

            result = subprocess.run(
                [
                    "bash",
                    "-o",
                    "pipefail",
                    "-c",
                    '"$1" doctor --doctor-script "$2" | head -n 5 >/dev/null',
                    "watchdog-pipe-test",
                    str(WATCHDOG),
                    str(script),
                ],
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )

        self.assertEqual(result.returncode, 141)
        self.assertEqual(result.stderr, "")

    def test_python_output_pipeline_has_no_shutdown_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            runner = tmp / "emit_cli_output.py"
            runner.write_text(
                "\n".join(
                    [
                        "import cli.main",
                        "",
                        "def emit_output(_args):",
                        "    for index in range(1_000_000):",
                        "        print(f'line {index}')",
                        "    return 0",
                        "",
                        "cli.main._version = emit_output",
                        "raise SystemExit(cli.main.main(['version']))",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT_DIR)
            result = subprocess.run(
                [
                    "bash",
                    "-o",
                    "pipefail",
                    "-c",
                    'python3 "$1" | head -n 5 >/dev/null',
                    "watchdog-python-pipe-test",
                    str(runner),
                ],
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )

        self.assertEqual(result.returncode, 141)
        self.assertEqual(result.stderr, "")

    def test_doctor_json_normalizes_signal_terminated_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._make_sigpipe_script(tmp, "doctor.sh")
            result = self._run_watchdog(
                ["doctor", "--doctor-script", str(script), "--json"],
                tmp,
            )

        self.assertEqual(result.returncode, 141)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["doctor_exit_code"], 141)

    def test_uninstall_json_normalizes_signal_terminated_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._make_sigpipe_script(tmp, "uninstall.sh")
            result = self._run_watchdog(
                [
                    "uninstall",
                    "--keep-data",
                    "--yes",
                    "--uninstall-script",
                    str(script),
                    "--json",
                ],
                tmp,
            )

        self.assertEqual(result.returncode, 141)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["uninstall_exit_code"], 141)

    def test_panic_normalizes_signal_terminated_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._make_sigpipe_script(tmp, "watchdog_panic")
            result = self._run_watchdog(
                ["panic", "status", "--panic-script", str(script)],
                tmp,
            )

        self.assertEqual(result.returncode, 141)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def _run_watchdog(self, args: list[str], tmp: Path) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "WATCHDOGVPN_CONFIG_DIR": str(tmp / "config"),
                "PYTHONPATH": str(ROOT_DIR),
            }
        )
        return subprocess.run(
            [str(WATCHDOG), *args],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    @staticmethod
    def _make_sigpipe_script(tmp: Path, name: str) -> Path:
        script = tmp / name
        script.write_text('#!/usr/bin/env bash\nkill -PIPE "$$"\n', encoding="utf-8")
        script.chmod(0o755)
        return script


if __name__ == "__main__":
    unittest.main()
