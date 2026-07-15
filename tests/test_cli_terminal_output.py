from __future__ import annotations

import argparse
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
from cli.terminal import terminal_safe_text, truncate_to_width, visible_width
from config.persistence import dump_json
from config.provider_store import ProviderStore
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class TtyStringIO(StringIO):
    def isatty(self) -> bool:
        return True


class CliTerminalOutputTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        *,
        columns: int = 80,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "COLUMNS": str(columns),
                "NO_COLOR": "1",
                "PYTHONPATH": str(ROOT_DIR),
                "WATCHDOGVPN_CONFIG_DIR": tmp,
                "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
                "WATCHDOGVPN_PROVIDERS_FILE": str(Path(tmp) / "providers.json"),
            }
        )
        return subprocess.run(
            [str(WATCHDOG), *args],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    def write_profiles(self, tmp: str, profiles: list[Profile]) -> None:
        dump_json(
            Path(tmp) / "profiles.json",
            [profile.to_dict() for profile in profiles],
        )

    def assert_output_fits(self, output: str, columns: int) -> None:
        for line_number, line in enumerate(output.splitlines(), start=1):
            with self.subTest(columns=columns, line_number=line_number, line=line):
                self.assertLessEqual(visible_width(line), columns)

    def test_root_help_fits_40_80_and_120_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for columns in (40, 80, 120):
                result = self.run_watchdog(["--help"], tmp, columns=columns)

                with self.subTest(columns=columns):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assert_output_fits(result.stdout, columns)
                    self.assertIn("Use: watchdog <command> --help", result.stdout)

    def test_profile_list_help_fits_40_80_and_120_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for columns in (40, 80, 120):
                result = self.run_watchdog(
                    ["profile", "list", "--help"],
                    tmp,
                    columns=columns,
                )

                with self.subTest(columns=columns):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assert_output_fits(result.stdout, columns)
                    self.assertIn("--protocol PROTOCOL", result.stdout)
                    self.assertIn("--wide", result.stdout)

    def test_every_argparse_help_route_fits_40_columns(self) -> None:
        inventory = json.loads(
            (ROOT_DIR / "docs" / "generated" / "cli-command-inventory.json").read_text(
                encoding="utf-8"
            )
        )
        routes = [
            route
            for route in inventory["routes"]
            if route["source"] == "argparse"
        ]
        with patch.dict(os.environ, {"COLUMNS": "40", "NO_COLOR": "1"}):
            for route in routes:
                stdout = StringIO()
                stderr = StringIO()
                with self.subTest(command=route["command"]):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        try:
                            rc = cli.main.main([*route["path"], "--help"])
                        except SystemExit as exc:
                            rc = int(exc.code or 0)
                    self.assertEqual(rc, 0, stderr.getvalue())
                    self.assertEqual(stderr.getvalue(), "")
                    self.assert_output_fits(stdout.getvalue(), 40)

    def test_large_profile_list_fits_40_80_and_120_columns(self) -> None:
        profiles = [
            Profile(
                id=f"profile-{index:03d}-identifier-with-long-provider-style-suffix",
                name=f"Profile {index:03d} with a long descriptive provider node name",
                protocol=(
                    ProtocolType.VLESS
                    if index % 2 == 0
                    else ProtocolType.OPENVPN_CLOAK
                ),
                config={
                    "host": "example.invalid",
                    "port": 443,
                    "uuid": f"test-only-{index}",
                },
                source=ProfileSource.MANUAL,
                health_status="unknown",
            )
            for index in range(127)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            self.write_profiles(tmp, profiles)
            for columns in (40, 80, 120):
                result = self.run_watchdog(
                    ["profile", "list"],
                    tmp,
                    columns=columns,
                )

                with self.subTest(columns=columns):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assert_output_fits(result.stdout, columns)
                    self.assertIn("Total: 127", result.stdout)
                    self.assertIn("Use --wide or --json for", result.stdout)

    def test_profile_list_wide_is_explicit_untruncated_overflow(self) -> None:
        profile = Profile(
            id="manual-profile-with-a-full-identifier-that-must-remain-visible",
            name="Manual profile with a full descriptive name that must remain visible",
            protocol=ProtocolType.VLESS,
            config={"host": "example.invalid", "port": 443, "uuid": "test-only"},
            source=ProfileSource.MANUAL,
        )
        with tempfile.TemporaryDirectory() as tmp:
            self.write_profiles(tmp, [profile])
            result = self.run_watchdog(
                ["profile", "list", "--wide"],
                tmp,
                columns=40,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(profile.id, result.stdout)
        self.assertIn(profile.name, result.stdout)
        self.assertTrue(
            any(visible_width(line) > 40 for line in result.stdout.splitlines())
        )

    def test_profile_filters_compose_and_preserve_full_json_values(self) -> None:
        manual = Profile(
            id="manual-vless",
            name="Manual VLESS",
            protocol=ProtocolType.VLESS,
            config={"host": "manual.invalid", "port": 443, "uuid": "manual-test"},
            source=ProfileSource.MANUAL,
            health_status="ok",
        )
        provider_profile = Profile(
            id="provider-one:disabled-trojan-node-with-full-id",
            name="Provider Trojan Node With Full Name",
            protocol=ProtocolType.TROJAN,
            config={"host": "provider.invalid", "port": 443, "password": "test-only"},
            source=ProfileSource.SUBSCRIPTION,
            provider_id="provider-one",
            enabled=False,
            health_status="down",
        )
        with tempfile.TemporaryDirectory() as tmp:
            self.write_profiles(tmp, [manual, provider_profile])
            ProviderStore(Path(tmp) / "providers.json").add(
                Provider(
                    id="provider-one",
                    name="Provider One",
                    url="https://provider.invalid/subscription",
                    profiles=[provider_profile.id],
                )
            )
            filters = [
                "--source",
                "provider",
                "--protocol",
                "trojan",
                "--health",
                "down",
                "--provider",
                "provider-one",
                "--disabled-only",
            ]
            json_result = self.run_watchdog(
                ["profile", "list", *filters, "--json"],
                tmp,
                columns=40,
            )
            human_result = self.run_watchdog(
                ["profile", "list", *filters],
                tmp,
                columns=40,
            )
            invalid_result = self.run_watchdog(
                [
                    "profile",
                    "list",
                    "--source",
                    "manual",
                    "--provider",
                    "provider-one",
                ],
                tmp,
                columns=40,
            )

        payload = json.loads(json_result.stdout)
        self.assertEqual(json_result.returncode, 0, json_result.stderr)
        self.assertEqual([item["id"] for item in payload], [provider_profile.id])
        self.assertEqual(payload[0]["name"], provider_profile.name)
        self.assertEqual(human_result.returncode, 0, human_result.stderr)
        self.assertIn("Showing 1 of 2", human_result.stdout)
        self.assert_output_fits(human_result.stdout, 40)
        self.assertEqual(invalid_result.returncode, 65)
        self.assertIn(
            "--provider cannot be combined with --source manual",
            invalid_result.stderr,
        )

    def test_human_profile_output_neutralizes_control_sequences(self) -> None:
        profile = Profile(
            id="unsafe-profile-id",
            name=(
                "Unsafe\x1b[31m\nInjected "
                "\x1b]52;c;U0VDUkVU\x07"
                "\x1bPterminal-action\x1b\\Name\x9b31m"
            ),
            protocol=ProtocolType.VLESS,
            config={"host": "example.invalid", "port": 443, "uuid": "test-only"},
            source=ProfileSource.MANUAL,
        )
        with tempfile.TemporaryDirectory() as tmp:
            self.write_profiles(tmp, [profile])
            result = self.run_watchdog(
                ["profile", "list"],
                tmp,
                columns=40,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("\x1b", result.stdout)
        self.assertNotIn("\x9b", result.stdout)
        self.assertNotIn("U0VDUkVU", result.stdout)
        self.assertNotIn("terminal-action", result.stdout)
        self.assertIn("Unsafe Injected Name", result.stdout)
        self.assert_output_fits(result.stdout, 40)

    def test_human_provider_output_neutralizes_terminal_actions(self) -> None:
        provider = Provider(
            id="unsafe-provider",
            name=(
                "Provider界\x1b]0;owned\x07 "
                "\x1bPpayload\x1b\\e\u0301 👨\u200d👩\u200d👧\u200d👦"
            ),
            url="https://provider.invalid/private-token",
        )
        with tempfile.TemporaryDirectory() as tmp:
            ProviderStore(Path(tmp) / "providers.json").add(provider)
            result = self.run_watchdog(
                ["provider", "list"],
                tmp,
                columns=120,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("\x1b", result.stdout)
        self.assertNotIn("owned", result.stdout)
        self.assertNotIn("payload", result.stdout)
        self.assertIn("Provider界 e\u0301", result.stdout)
        self.assert_output_fits(result.stdout, 120)

    def test_common_command_typos_suggest_without_changing_exit_code(self) -> None:
        cases = (
            (["statu"], "watchdog status"),
            (["profile", "lst"], "watchdog profile list"),
            (["dns", "statsu"], "watchdog dns status"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            for args, expected in cases:
                result = self.run_watchdog(args, tmp, columns=40)

                with self.subTest(args=args):
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(f"Did you mean '{expected}'?", result.stderr)
                    self.assert_output_fits(result.stderr, 40)

    def test_typo_suggestions_are_bounded_and_json_aware(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            distant = self.run_watchdog(["totally-unrelated"], tmp, columns=40)
            json_result = self.run_watchdog(
                ["profile", "lst", "--json"],
                tmp,
                columns=40,
            )

        self.assertEqual(distant.returncode, 2)
        self.assertNotIn("Did you mean", distant.stderr)
        self.assertIn("Run 'watchdog --help'", distant.stderr)
        self.assertEqual(json_result.returncode, 2)
        self.assertEqual(json_result.stderr, "")
        payload = json.loads(json_result.stdout)
        self.assertFalse(payload["ok"])
        self.assertIn("watchdog profile list", payload["error"])

    def test_typo_suggestion_strips_leaked_root_usage_metavariables(self) -> None:
        parser = argparse.ArgumentParser(
            prog="watchdog <command> [options] profile"
        )

        rendered = cli.main._command_error_text(parser, "lst", "list")

        self.assertEqual(
            rendered,
            "watchdog profile: error: invalid command 'lst'\n"
            "Did you mean 'watchdog profile list'?\n"
            "Run 'watchdog profile --help' to list available commands.",
        )

    def test_typo_suggestion_never_executes_the_suggested_handler(self) -> None:
        with (
            patch("cli.main._connection_status") as status_handler,
            patch.dict(os.environ, {"COLUMNS": "40", "NO_COLOR": "1"}),
            redirect_stdout(StringIO()),
            redirect_stderr(StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            cli.main.main(["statu"])

        self.assertEqual(raised.exception.code, 2)
        status_handler.assert_not_called()

    def test_terminal_helpers_use_display_width_and_safe_text(self) -> None:
        self.assertEqual(visible_width("abc界"), 5)
        self.assertEqual(visible_width("\x1b[31mred\x1b[0m"), 3)
        self.assertEqual(visible_width("e\u0301"), 1)
        self.assertEqual(visible_width("👨\u200d👩\u200d👧\u200d👦"), 2)
        self.assertEqual(visible_width("🇩🇰"), 2)
        self.assertEqual(terminal_safe_text("a\x1b[31m\nb"), "a b")
        rendered = truncate_to_width("alpha界omega", 8)
        self.assertLessEqual(visible_width(rendered), 8)
        self.assertTrue(rendered.endswith("..."))

    def test_colored_tty_output_keeps_visible_width_contract(self) -> None:
        profile = Profile(
            id="colored-profile-with-a-long-id",
            name="Colored Profile With A Long Name",
            protocol=ProtocolType.VLESS,
            config={"host": "example.invalid", "port": 443, "uuid": "test-only"},
            source=ProfileSource.MANUAL,
            health_status="ok",
        )
        with tempfile.TemporaryDirectory() as tmp:
            self.write_profiles(tmp, [profile])
            env = {
                "COLUMNS": "40",
                "PYTHONPATH": str(ROOT_DIR),
                "WATCHDOGVPN_CONFIG_DIR": tmp,
                "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
                "WATCHDOGVPN_PROVIDERS_FILE": str(Path(tmp) / "providers.json"),
            }
            profile_stdout = TtyStringIO()
            help_stdout = TtyStringIO()
            with patch.dict(os.environ, env, clear=True), redirect_stdout(
                profile_stdout
            ):
                profile_rc = cli.main.main(["profile", "list"])
            with (
                patch.dict(os.environ, env, clear=True),
                redirect_stdout(help_stdout),
                self.assertRaises(SystemExit) as help_exit,
            ):
                cli.main.main(["--help"])
            help_rc = help_exit.exception.code

        self.assertEqual(profile_rc, 0)
        self.assertEqual(help_rc, 0)
        self.assertIn("\x1b[", profile_stdout.getvalue())
        self.assertIn("\x1b[", help_stdout.getvalue())
        self.assert_output_fits(profile_stdout.getvalue(), 40)
        self.assert_output_fits(help_stdout.getvalue(), 40)


if __name__ == "__main__":
    unittest.main()
