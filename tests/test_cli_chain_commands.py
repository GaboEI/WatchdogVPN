from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from route_chains.models import ChainHop, RouteChain
from route_chains.store import RouteChainStore


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliChainCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
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

    def test_create_list_show(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            created = self.run_watchdog(
                [
                    "chain",
                    "create",
                    "work-safe",
                    "--hop",
                    "profile:profile-one",
                    "--hop",
                    "group:resilient-exit",
                    "--description",
                    "Local operator label",
                    "--json",
                ],
                tmp,
            )
            created_data = json.loads(created.stdout)

            list_data = json.loads(self.run_watchdog(["chain", "list", "--json"], tmp).stdout)
            show_data = json.loads(self.run_watchdog(["chain", "show", "work-safe", "--json"], tmp).stdout)
            backup_exists = Path(created_data["backup_path"]).exists()

        self.assertEqual(created_data["chain"]["id"], "work-safe")
        self.assertFalse(created_data["chain"]["enabled"])
        self.assertTrue(backup_exists)
        self.assertIsNotNone(created_data["chain"]["created_at"])
        self.assertEqual(created_data["chain"]["updated_at"], created_data["chain"]["created_at"])
        self.assertEqual(len(list_data), 1)
        self.assertEqual(list_data[0]["id"], "work-safe")
        self.assertEqual(len(show_data["hops"]), 2)
        self.assertEqual(show_data["hops"][0], {"type": "profile", "target": "profile-one", "required": True})
        self.assertEqual(
            show_data["hops"][1],
            {
                "type": "group",
                "target": "resilient-exit",
                "required": True,
                "selection_policy": "group_policy",
            },
        )

    def test_create_rejects_existing_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["chain", "create", "work-safe", "--hop", "profile:p1"], tmp)

            result = self.run_watchdog(
                ["chain", "create", "work-safe", "--hop", "profile:p2"], tmp, check=False
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("route chain already exists: work-safe", result.stderr)

    def test_create_rejects_malformed_hop_spec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["chain", "create", "work-safe", "--hop", "not-a-hop"], tmp, check=False
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid --hop value", result.stderr)

    def test_add_hop_and_remove_hop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["chain", "create", "work-safe", "--hop", "profile:p1"], tmp)

            added = self.run_watchdog(
                ["chain", "add-hop", "work-safe", "--type", "profile", "--target", "p2", "--json"],
                tmp,
            )
            added_data = json.loads(added.stdout)
            self.assertEqual(len(added_data["chain"]["hops"]), 2)
            self.assertTrue(Path(added_data["backup_path"]).exists())

            removed = self.run_watchdog(
                ["chain", "remove-hop", "work-safe", "--index", "1", "--json"], tmp
            )
            removed_data = json.loads(removed.stdout)
            self.assertEqual(len(removed_data["chain"]["hops"]), 1)
            self.assertEqual(removed_data["chain"]["hops"][0]["target"], "p2")

    def test_remove_hop_rejects_last_hop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["chain", "create", "work-safe", "--hop", "profile:p1"], tmp)

            result = self.run_watchdog(
                ["chain", "remove-hop", "work-safe", "--index", "1"], tmp, check=False
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("cannot remove the last hop", result.stderr)

    def test_remove_hop_rejects_out_of_range_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(
                ["chain", "create", "work-safe", "--hop", "profile:p1", "--hop", "profile:p2"], tmp
            )

            result = self.run_watchdog(
                ["chain", "remove-hop", "work-safe", "--index", "5"], tmp, check=False
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("chain hop index out of range", result.stderr)

    def test_add_hop_group_selection_policy_rejected_for_profile_hop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["chain", "create", "work-safe", "--hop", "profile:p1"], tmp)

            result = self.run_watchdog(
                [
                    "chain",
                    "add-hop",
                    "work-safe",
                    "--type",
                    "profile",
                    "--target",
                    "p2",
                    "--selection-policy",
                    "group_policy",
                ],
                tmp,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)

    def test_enable_disable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["chain", "create", "work-safe", "--hop", "profile:p1"], tmp)

            enabled = self.run_watchdog(["chain", "enable", "work-safe", "--json"], tmp)
            self.assertTrue(json.loads(enabled.stdout)["chain"]["enabled"])

            disabled = self.run_watchdog(["chain", "disable", "work-safe", "--json"], tmp)
            self.assertFalse(json.loads(disabled.stdout)["chain"]["enabled"])

    def test_mutations_preserve_chain_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "chains.json"
            store = RouteChainStore(path)
            store.add(
                RouteChain(
                    id="work-safe",
                    hops=[ChainHop(type="profile", target="p1")],
                    created_at="2026-07-09T00:00:00+00:00",
                    updated_at="2026-07-09T00:00:00+00:00",
                )
            )

            result = self.run_watchdog(["chain", "enable", "work-safe", "--json"], tmp)
            chain = json.loads(result.stdout)["chain"]

        self.assertTrue(chain["enabled"])
        self.assertEqual(chain["created_at"], "2026-07-09T00:00:00+00:00")
        self.assertNotEqual(chain["updated_at"], "2026-07-09T00:00:00+00:00")

    def test_remove_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["chain", "create", "work-safe", "--hop", "profile:p1"], tmp)

            removed = self.run_watchdog(["chain", "remove", "work-safe", "--json"], tmp)
            self.assertEqual(json.loads(removed.stdout)["removed"], "work-safe")

            list_data = json.loads(self.run_watchdog(["chain", "list", "--json"], tmp).stdout)
            self.assertEqual(list_data, [])

    def test_show_missing_chain_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["chain", "show", "missing"], tmp, check=False)

            self.assertEqual(result.returncode, 65)
            self.assertIn("route chain not found: missing", result.stderr)

    def test_created_chain_is_usable_as_rule_action(self) -> None:
        # Regression guard for the original defect: a chain: route action
        # must resolve to a chain that the CLI itself can create end to end.
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["chain", "create", "work-safe", "--hop", "profile:p1"], tmp)
            self.run_watchdog(["chain", "enable", "work-safe"], tmp)

            document = RouteChainStore(Path(tmp) / "chains.json").load()
            chain = document.chains[0]

        self.assertEqual(chain.id, "work-safe")
        self.assertTrue(chain.enabled)


if __name__ == "__main__":
    unittest.main()
