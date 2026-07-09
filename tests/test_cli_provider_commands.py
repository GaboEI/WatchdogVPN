from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import cli.main
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


def _provider() -> Provider:
    return Provider(
        id="netz.tg",
        name="netz",
        url="https://netz.tg/private-token",
        last_updated=datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc),
        profiles=["netz.tg:austria", "netz.tg:belgium"],
        rotation_enabled=True,
        metadata={
            "traffic_used": "51.6 GB",
            "traffic_limit": "1000.0 GB",
            "expires_at": "2026-09-17",
        },
    )


def _profile(profile_id: str, provider_id: str = "netz.tg") -> Profile:
    return Profile(
        id=profile_id,
        name=profile_id,
        protocol=ProtocolType.TROJAN,
        config={"host": "example.com", "port": 443},
        source=ProfileSource.SUBSCRIPTION,
        provider_id=provider_id,
        in_rotation_pool=True,
    )


class CliProviderCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        input_text: str | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_PROVIDERS_FILE": str(Path(tmp) / "providers.json"),
            "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
            "PYTHONPATH": str(ROOT_DIR),
        }
        result = subprocess.run(
            [str(WATCHDOG), *args],
            input=input_text,
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        if check and result.returncode != 0:
            self.fail(f"command failed: {result.stderr}\nstdout={result.stdout}")
        return result

    def seed_provider(self, tmp: str) -> None:
        ProviderStore(Path(tmp) / "providers.json").add(_provider())
        store = ProfileStore(Path(tmp) / "profiles.json")
        store.add(_profile("netz.tg:austria"))
        store.add(_profile("netz.tg:belgium"))

    def test_provider_list_json_redacts_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_provider(tmp)

            result = self.run_watchdog(["provider", "list", "--json"], tmp)

            providers = json.loads(result.stdout)
            self.assertEqual(providers[0]["id"], "netz.tg")
            self.assertEqual(providers[0]["url"], "https://netz.tg/<redacted>")
            self.assertEqual(providers[0]["traffic"], "51.6 GB/1000.0 GB")
            self.assertEqual(providers[0]["expires_at"], "2026-09-17")
            self.assertFalse(providers[0]["metadata_included"])
            self.assertNotIn("private-token", result.stdout)
            self.assertNotIn("metadata", providers[0])

    def test_provider_stats_json_counts_nodes_and_protocols(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_provider(tmp)

            result = self.run_watchdog(["provider", "stats", "netz.tg", "--json"], tmp)

            stats = json.loads(result.stdout)
            self.assertEqual(stats["node_count"], 2)
            self.assertEqual(stats["enabled_nodes"], 2)
            self.assertEqual(stats["rotation_nodes"], 2)
            self.assertEqual(stats["protocols"], {"trojan": 2})
            self.assertEqual(stats["url"], "https://netz.tg/<redacted>")
            self.assertFalse(stats["metadata_included"])
            self.assertNotIn("private-token", result.stdout)

    def test_provider_edit_rotation_node_and_remove(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_provider(tmp)

            edited = self.run_watchdog(
                [
                    "provider",
                    "edit",
                    "netz.tg",
                    "--name",
                    "new name",
                    "--url",
                    "https://netz.tg/new-token",
                    "--json",
                ],
                tmp,
            )
            rotation = self.run_watchdog(["provider", "rotation", "netz.tg", "--disable", "--json"], tmp)
            node = self.run_watchdog(
                [
                    "provider",
                    "node",
                    "netz.tg",
                    "netz.tg:austria",
                    "--rotation",
                    "--disable",
                    "--json",
                ],
                tmp,
            )

            self.assertNotIn("new-token", edited.stdout)
            self.assertFalse(json.loads(rotation.stdout)["provider"]["rotation_enabled"])
            self.assertFalse(json.loads(node.stdout)["node"]["in_rotation_pool"])

            provider = ProviderStore(Path(tmp) / "providers.json").get("netz.tg")
            profile = ProfileStore(Path(tmp) / "profiles.json").get("netz.tg:austria")
            self.assertIsNotNone(provider)
            self.assertIsNotNone(profile)
            assert provider is not None
            assert profile is not None
            self.assertEqual(provider.name, "new name")
            self.assertEqual(provider.url, "https://netz.tg/new-token")
            self.assertFalse(provider.rotation_enabled)
            self.assertFalse(profile.in_rotation_pool)

            removed = self.run_watchdog(["provider", "remove", "netz.tg", "--json"], tmp)
            removed_data = json.loads(removed.stdout)
            self.assertEqual(removed_data["removed"]["id"], "netz.tg")
            self.assertFalse(removed_data["rollback_point"]["subscription_url_included"])
            self.assertNotIn("new-token", removed.stdout)
            self.assertIsNone(ProviderStore(Path(tmp) / "providers.json").get("netz.tg"))
            self.assertEqual(ProfileStore(Path(tmp) / "profiles.json").list(), [])

    def test_provider_add_uses_subscription_provider(self) -> None:
        provider = _provider()
        with patch("cli.main.SubscriptionProvider") as provider_cls:
            manager = provider_cls.return_value
            manager.add.return_value = provider

            with redirect_stdout(StringIO()):
                result = cli.main.main(["provider", "add", "https://netz.tg/private-token", "--name", "netz", "--json"])

        self.assertEqual(result, 0)
        manager.add.assert_called_once_with("https://netz.tg/private-token", "netz")

    def test_provider_update_all_uses_subscription_provider(self) -> None:
        with patch("cli.main.SubscriptionProvider") as provider_cls:
            manager = provider_cls.return_value
            manager.update_all.return_value = {"netz.tg": 2}

            with redirect_stdout(StringIO()):
                result = cli.main.main(["provider", "update", "--all", "--json"])

        self.assertEqual(result, 0)
        manager.update_all.assert_called_once_with()

    def test_provider_update_single_json_uses_subscription_provider(self) -> None:
        with patch("cli.main.SubscriptionProvider") as provider_cls:
            manager = provider_cls.return_value
            manager.update.return_value = 3

            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["provider", "update", "netz.tg", "--json"])

        self.assertEqual(result, 0)
        manager.update.assert_called_once_with("netz.tg")
        self.assertEqual(json.loads(stdout.getvalue()), {"changes": 3, "provider_id": "netz.tg"})

    def test_provider_add_json_redacts_subscription_url(self) -> None:
        provider = _provider()
        with patch("cli.main.SubscriptionProvider") as provider_cls:
            manager = provider_cls.return_value
            manager.add.return_value = provider

            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["provider", "add", "https://netz.tg/private-token", "--name", "netz", "--json"])

        self.assertEqual(result, 0)
        self.assertNotIn("private-token", stdout.getvalue())
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["provider"]["url"], "https://netz.tg/<redacted>")

    def test_provider_missing_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["provider", "stats", "missing"], tmp, check=False)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("provider not found: missing", result.stderr)
            self.assertIn("watchdog provider list", result.stderr)

    def test_provider_add_invalid_url_fails_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["provider", "add", "TU_URL_REAL_DEL_PROVIDER", "--name", "netz.tg"],
                tmp,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid subscription URL: TU_URL_REAL_DEL_PROVIDER", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_provider_edit_requires_name_or_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_provider(tmp)

            result = self.run_watchdog(["provider", "edit", "netz.tg"], tmp, check=False)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("provider edit requires --name or --url", result.stderr)

    def test_provider_node_rejects_node_from_other_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_provider(tmp)
            profile_store = ProfileStore(Path(tmp) / "profiles.json")
            profile_store.add(_profile("other-provider:node", provider_id="other-provider"))

            result = self.run_watchdog(
                ["provider", "node", "netz.tg", "other-provider:node", "--rotation", "--disable"],
                tmp,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("node does not belong to provider", result.stderr)


if __name__ == "__main__":
    unittest.main()
