from __future__ import annotations

import argparse
import json
import os
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from cli.command_inventory import (
    _normalized_usage,
    _public_arguments,
    build_command_inventory,
    render_inventory_json,
    render_inventory_markdown,
)
from cli.main import MAINTENANCE_COMMAND_HELP, _build_parser


ROOT_DIR = Path(__file__).resolve().parents[1]
JSON_SNAPSHOT = ROOT_DIR / "docs" / "generated" / "cli-command-inventory.json"
MARKDOWN_SNAPSHOT = ROOT_DIR / "docs" / "generated" / "cli-command-inventory.md"
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliCommandInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = build_command_inventory(_build_parser())
        self.routes = self.inventory["routes"]

    def test_inventory_covers_every_current_route(self) -> None:
        self.assertEqual(self.inventory["route_count"], 143)
        self.assertEqual(self.inventory["command_route_count"], 142)
        self.assertEqual(self.inventory["parser_route_count"], 135)
        self.assertEqual(self.inventory["passthrough_route_count"], 8)
        self.assertEqual(self.inventory["group_route_count"], 20)
        self.assertEqual(self.inventory["leaf_route_count"], 123)
        commands = [route["command"] for route in self.routes]
        self.assertEqual(len(commands), len(set(commands)))

        parser_paths: set[tuple[str, ...]] = set()

        def collect_parser_paths(
            parser: argparse.ArgumentParser,
            path: tuple[str, ...],
        ) -> None:
            parser_paths.add(path)
            for action in parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    for name, child in action.choices.items():
                        collect_parser_paths(child, (*path, name))

        collect_parser_paths(_build_parser(), ())
        inventory_parser_paths = {
            tuple(route["path"])
            for route in self.routes
            if route["source"] == "argparse"
        }
        self.assertEqual(inventory_parser_paths, parser_paths)

    def test_inventory_expands_all_maintenance_routes(self) -> None:
        maintenance_routes = {
            route["command"]
            for route in self.routes
            if route["source"] == "documented-passthrough-choice"
        }
        self.assertEqual(
            maintenance_routes,
            {f"watchdog maintenance {name}" for name in MAINTENANCE_COMMAND_HELP},
        )

    def test_inventory_uses_structural_required_mutex_contract(self) -> None:
        route = next(
            route
            for route in self.routes
            if route["command"] == "watchdog provider update"
        )
        self.assertEqual(
            route["mutually_exclusive_groups"],
            [{"required": True, "members": ["provider_id", "--all"]}],
        )

    def test_inventory_derives_optional_positional_mutex_usage_without_argparse_renderer(
        self,
    ) -> None:
        parser = _build_parser()
        provider_parser = next(
            action.choices["provider"]
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        update_parser = next(
            action.choices["update"]
            for action in provider_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        with patch.object(
            argparse.ArgumentParser,
            "format_usage",
            side_effect=AssertionError("provider update must not use argparse usage text"),
        ):
            usage = _normalized_usage(
                update_parser,
                command="watchdog provider update",
            )

        self.assertEqual(usage, "usage: watchdog provider update [-h] [--json] (--all | provider_id)")

    def test_inventory_derives_empty_positional_requiredness_from_nargs(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("zero_or_more", nargs="*")
        parser.add_argument("remainder", nargs=argparse.REMAINDER)

        arguments = _public_arguments(parser)

        self.assertEqual(
            [(argument["name"], argument["required"]) for argument in arguments],
            [("zero_or_more", False), ("remainder", False)],
        )

    def test_wdcli_020_previously_missing_contracts_are_documented(self) -> None:
        commands = {route["command"] for route in self.routes}
        previously_missing_routes = {
            "watchdog dns channel add",
            "watchdog dns channel remove",
            "watchdog dns resolver add",
            "watchdog dns resolver remove",
            "watchdog dns resolver enable",
            "watchdog dns resolver disable",
            "watchdog dns rule add",
            "watchdog dns rule remove",
            "watchdog dns rule enable",
            "watchdog dns rule disable",
            "watchdog dns static-ip add",
            "watchdog dns static-ip remove",
            "watchdog rules set-priority",
            "watchdog rules enable-rule",
            "watchdog rules disable-rule",
            "watchdog ruleset add",
            "watchdog ruleset remove",
            "watchdog node-group add-provider",
            "watchdog node-group remove-provider",
            "watchdog node-group exclude",
            "watchdog node-group unexclude",
            "watchdog node-group resilience",
            "watchdog node-group enable",
            "watchdog node-group disable",
            "watchdog chain list",
            "watchdog chain show",
            "watchdog chain create",
            "watchdog chain add-hop",
            "watchdog chain remove-hop",
            "watchdog chain enable",
            "watchdog chain disable",
            "watchdog chain remove",
        }
        self.assertTrue(previously_missing_routes.issubset(commands))

        app_policy_add = next(
            route
            for route in self.routes
            if route["command"] == "watchdog app-policy add"
        )
        argument_names = {argument["name"] for argument in app_policy_add["arguments"]}
        self.assertTrue(
            {"--process-path-regex", "--user", "--user-id"}.issubset(argument_names)
        )

    def test_every_route_has_discoverable_help_and_summary(self) -> None:
        for route in self.routes:
            with self.subTest(command=route["command"]):
                self.assertTrue(route["summary"].strip())
                self.assertTrue(route["usage"].startswith("usage:"))
                self.assertEqual(route["help_command"], f"{route['command']} --help")
                self.assertNotIn("Undocumented parser route", route["summary"])

    def test_every_documented_help_route_exits_zero(self) -> None:
        parser = _build_parser()
        for route in self.routes:
            path = route["path"]
            if route["source"] == "argparse":
                with self.subTest(command=route["command"]):
                    stdout = StringIO()
                    stderr = StringIO()
                    with (
                        redirect_stdout(stdout),
                        redirect_stderr(stderr),
                        self.assertRaises(SystemExit) as raised,
                    ):
                        parser.parse_args([*path, "--help"])
                    self.assertEqual(raised.exception.code, 0)
                    self.assertTrue(stdout.getvalue().strip())
                    self.assertEqual(stderr.getvalue(), "")
                continue

            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT_DIR)
            result = subprocess.run(
                [str(WATCHDOG), *path, "--help"],
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            with self.subTest(command=route["command"]):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.strip())
                self.assertEqual(result.stderr, "")

    def test_generated_snapshots_match_current_parser(self) -> None:
        self.assertEqual(
            json.loads(JSON_SNAPSHOT.read_text(encoding="utf-8")),
            self.inventory,
        )
        self.assertEqual(
            JSON_SNAPSHOT.read_text(encoding="utf-8"),
            render_inventory_json(self.inventory),
        )
        self.assertEqual(
            MARKDOWN_SNAPSHOT.read_text(encoding="utf-8"),
            render_inventory_markdown(self.inventory),
        )

    def test_inventory_normalizes_leaked_root_usage_metavariables(self) -> None:
        parser = _build_parser()
        root_subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        profile_parser = root_subparsers.choices["profile"]
        profile_parser.prog = "watchdog <command> [options] profile"

        inventory = build_command_inventory(parser)
        profile_route = next(
            route
            for route in inventory["routes"]
            if route["command"] == "watchdog profile"
        )

        self.assertTrue(profile_route["usage"].startswith("usage: watchdog profile"))
        self.assertNotIn("<command> [options]", profile_route["usage"])

    def test_inventory_excludes_suppressed_internal_overrides(self) -> None:
        rendered = render_inventory_json(self.inventory)
        for internal_argument in (
            "--doctor-script",
            "--panic-script",
            "--uninstall-script",
            "--version-source",
        ):
            self.assertNotIn(internal_argument, rendered)
        self.assertNotIn("/home/", rendered)

    def test_primary_cli_documentation_links_generated_snapshots(self) -> None:
        cli_docs = (ROOT_DIR / "docs" / "cli.md").read_text(encoding="utf-8")
        self.assertIn("generated/cli-command-inventory.md", cli_docs)
        self.assertIn("generated/cli-command-inventory.json", cli_docs)
        self.assertIn("generate_cli_inventory.py --check", cli_docs)

    def test_primary_cli_documentation_covers_wdcli_020_safety_contracts(self) -> None:
        cli_docs = (ROOT_DIR / "docs" / "cli.md").read_text(encoding="utf-8")
        required_contracts = (
            "watchdog dns channel add",
            "watchdog dns resolver disable",
            "watchdog dns rule enable",
            "watchdog dns static-ip remove",
            "watchdog rules set-priority",
            "watchdog rules enable-rule",
            "watchdog app-policy add --process-path-regex",
            "watchdog app-policy add --user-id",
            "watchdog app-policy disable-rule",
            "watchdog split-tunnel",
            "watchdog split-tunnel add --process-path-regex",
            "watchdog split-tunnel disable-rule",
            "watchdog node-group add-provider",
            "watchdog node-group exclude",
            "watchdog node-group resilience",
            "watchdog chain create",
            "watchdog chain remove-hop",
            "watchdog chain enable",
            "watchdog ruleset add",
            "watchdog ruleset remove",
            "commands do not activate the policy",
            "never silently falls back",
            "an exact SHA-256",
        )
        for contract in required_contracts:
            with self.subTest(contract=contract):
                self.assertIn(contract, cli_docs)


if __name__ == "__main__":
    unittest.main()
