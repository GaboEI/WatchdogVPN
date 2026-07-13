from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cli.main as cli_main


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"
WATCHDOGVPN = ROOT_DIR / "bin" / "watchdogvpn"


class CliEntrypointConsolidationTests(unittest.TestCase):
    def run_command(
        self,
        command: list[str],
        tmp: Path,
        *,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "WATCHDOGVPN_CONFIG_DIR": str(tmp / "config"),
                "PYTHONPATH": str(ROOT_DIR),
            }
        )
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    def test_compatibility_alias_uses_canonical_root_help(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            canonical = self.run_command([str(WATCHDOG), "--help"], tmp)
            alias = self.run_command([str(WATCHDOGVPN), "--help"], tmp)

        self.assertEqual(canonical.returncode, 0)
        self.assertEqual(alias.returncode, 0)
        self.assertEqual(alias.stdout, canonical.stdout)
        self.assertIn("watchdogvpn is deprecated; use watchdog", alias.stderr)
        self.assertIn("maintenance", alias.stdout)

    def test_compatibility_alias_uses_canonical_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            canonical = self.run_command([str(WATCHDOG), "version"], tmp)
            alias = self.run_command([str(WATCHDOGVPN), "version"], tmp)
            dash_alias = self.run_command([str(WATCHDOGVPN), "--version"], tmp)

        self.assertEqual(alias.returncode, 0)
        self.assertEqual(dash_alias.returncode, 0)
        self.assertEqual(alias.stdout, canonical.stdout)
        self.assertEqual(dash_alias.stdout, canonical.stdout)

    def test_compatibility_alias_routes_runtime_and_maintenance_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            fake_canonical = tmp / "watchdog"
            fake_canonical.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\"\n",
                encoding="utf-8",
            )
            fake_canonical.chmod(0o755)
            env = {
                "WATCHDOGVPN_CANONICAL_CLI": str(fake_canonical),
                "WATCHDOGVPN_SUPPRESS_DEPRECATION_WARNING": "1",
            }
            cases = [
                (["status", "--json"], "status --json\n"),
                (["doctor", "--json"], "doctor --json\n"),
                (["backend", "status"], "maintenance backend status\n"),
                (["config", "get", "language.current"], "maintenance config get language.current\n"),
                (["profile", "list", "--json"], "profile list --json\n"),
            ]

            for args, expected in cases:
                with self.subTest(args=args):
                    result = self.run_command([str(WATCHDOGVPN), *args], tmp, extra_env=env)
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, expected)
                    self.assertEqual(result.stderr, "")

    def test_compatibility_help_routes_topics_to_one_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            fake_canonical = tmp / "watchdog"
            fake_canonical.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\"\n",
                encoding="utf-8",
            )
            fake_canonical.chmod(0o755)
            env = {
                "WATCHDOGVPN_CANONICAL_CLI": str(fake_canonical),
                "WATCHDOGVPN_SUPPRESS_DEPRECATION_WARNING": "1",
            }
            maintenance = self.run_command(
                [str(WATCHDOGVPN), "help", "logs"],
                tmp,
                extra_env=env,
            )
            canonical = self.run_command(
                [str(WATCHDOGVPN), "help", "profile"],
                tmp,
                extra_env=env,
            )

        self.assertEqual(maintenance.stdout, "maintenance logs --help\n")
        self.assertEqual(canonical.stdout, "profile --help\n")

    def test_maintenance_namespace_invokes_internal_backend_without_shell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            backend = tmp / "maintenance-backend"
            backend.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'internal=%s\\n' \"${WATCHDOGVPN_MAINTENANCE_INTERNAL:-}\"\n"
                "printf 'args=%s\\n' \"$*\"\n"
                "exit 23\n",
                encoding="utf-8",
            )
            backend.chmod(0o755)
            result = self.run_command(
                [str(WATCHDOG), "maintenance", "logs", "events", "5"],
                tmp,
                extra_env={"WATCHDOGVPN_MAINTENANCE_CLI": str(backend)},
            )

        self.assertEqual(result.returncode, 23)
        self.assertEqual(result.stdout, "internal=1\nargs=logs events 5\n")
        self.assertEqual(result.stderr, "")

    def test_maintenance_override_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            result = self.run_command(
                [str(WATCHDOG), "maintenance", "logs"],
                tmp,
                extra_env={"WATCHDOGVPN_MAINTENANCE_CLI": str(tmp / "missing")},
            )

        self.assertEqual(result.returncode, 66)
        self.assertIn("maintenance backend not found", result.stderr)

    def test_internal_marker_cannot_restore_legacy_runtime_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            marker = tmp / "legacy-status-marker"
            fake_vpnctl = tmp / "vpnctl"
            fake_vpnctl.write_text(
                "#!/usr/bin/env bash\n"
                'touch "$WATCHDOGVPN_TEST_MARKER"\n',
                encoding="utf-8",
            )
            fake_vpnctl.chmod(0o755)
            result = self.run_command(
                [str(WATCHDOGVPN), "status"],
                tmp,
                extra_env={
                    "WATCHDOGVPN_MAINTENANCE_INTERNAL": "1",
                    "WATCHDOGVPN_TEST_MARKER": str(marker),
                    "WATCHDOGVPN_VPNCTL_BIN": str(fake_vpnctl),
                },
            )
            marker_was_created = marker.exists()

        self.assertEqual(result.returncode, 64)
        self.assertIn("unsupported internal command: status", result.stderr)
        self.assertFalse(marker_was_created)

    def test_maintenance_backend_resolves_from_installed_runtime_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            runtime_root = tmp / "installed-runtime"
            runtime_cli = runtime_root / "cli" / "main.py"
            backend = runtime_root / "bin" / "watchdogvpn"
            marker = tmp / "maintenance-marker"
            backend.parent.mkdir(parents=True)
            backend.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'internal=%s\\n' "
                '"${WATCHDOGVPN_MAINTENANCE_INTERNAL:-}" '
                '>> "$WATCHDOGVPN_TEST_MARKER"\n'
                "printf 'args=%s\\n' \"$*\" "
                '>> "$WATCHDOGVPN_TEST_MARKER"\n',
                encoding="utf-8",
            )
            backend.chmod(0o755)
            env = os.environ.copy()
            env.pop("WATCHDOGVPN_MAINTENANCE_CLI", None)
            env["WATCHDOGVPN_TEST_MARKER"] = str(marker)

            with (
                patch.object(cli_main, "__file__", str(runtime_cli)),
                patch.dict(os.environ, env, clear=True),
            ):
                return_code = cli_main.main(
                    ["maintenance", "backend", "status"]
                )
            marker_text = marker.read_text(encoding="utf-8")

        self.assertEqual(return_code, 0)
        self.assertEqual(marker_text, "internal=1\nargs=backend status\n")

    def test_update_target_does_not_override_maintenance_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            target = tmp / "target-checkout"
            (target / "bin").mkdir(parents=True)
            wrong_backend = target / "bin" / "watchdogvpn"
            wrong_backend.write_text(
                "#!/usr/bin/env bash\nprintf 'wrong backend\\n'\nexit 42\n",
                encoding="utf-8",
            )
            wrong_backend.chmod(0o755)
            result = self.run_command(
                [str(WATCHDOG), "maintenance", "update-check"],
                tmp,
                extra_env={"WATCHDOGVPN_REPO_DIR": str(target)},
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn("WatchdogVPN update check", result.stdout)
        self.assertNotIn("wrong backend", result.stdout)

    def test_maintenance_help_lists_preserved_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            result = self.run_command(
                [str(WATCHDOG), "maintenance", "--help"],
                Path(tmp_name),
            )

        self.assertEqual(result.returncode, 0)
        for command in (
            "backend",
            "config",
            "logs",
            "report",
            "runtime-update",
            "tui",
            "update-check",
            "update-plan",
        ):
            self.assertIn(command, result.stdout)


if __name__ == "__main__":
    unittest.main()
