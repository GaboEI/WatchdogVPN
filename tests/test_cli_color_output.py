from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from contextlib import contextmanager
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import cli.main
from config.dns_policy_store import DNSPolicyStore
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from daemon.protocol import Response
from dns.models import DNSChannel, DNSChannelName, DNSPolicy, Resolver
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class TtyStringIO(StringIO):
    def isatty(self) -> bool:
        return True


def has_ansi(text: str) -> bool:
    return bool(ANSI_RE.search(text))


@contextmanager
def without_no_color():
    previous = os.environ.pop("NO_COLOR", None)
    try:
        yield
    finally:
        if previous is not None:
            os.environ["NO_COLOR"] = previous


class CliColorOutputTests(unittest.TestCase):
    def test_root_help_uses_color_only_for_tty_without_no_color(self) -> None:
        with without_no_color(), redirect_stdout(TtyStringIO()):
            colored = cli.main._build_parser().format_help()

        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False), redirect_stdout(TtyStringIO()):
            plain = cli.main._build_parser().format_help()

        self.assertTrue(has_ansi(colored))
        self.assertIn("watchdog status", colored)
        self.assertFalse(has_ansi(plain))

    def test_status_human_colors_semantic_values_and_json_stays_plain(self) -> None:
        response = Response(
            ok=True,
            payload={
                "state": {
                    "status": "connected",
                    "mode": "global",
                    "active_profile_id": "demo",
                    "tun_active": True,
                    "proxy_active": False,
                    "kill_switch_active": False,
                }
            },
        )
        with without_no_color(), patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.return_value = response
            with redirect_stdout(TtyStringIO()) as stdout:
                rc = cli.main.main(["status"])

        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.status.return_value = response
            with redirect_stdout(TtyStringIO()) as stdout_json:
                json_rc = cli.main.main(["status", "--json"])

        self.assertEqual(rc, 0)
        self.assertTrue(has_ansi(stdout.getvalue()))
        self.assertIn("Status:", stdout.getvalue())
        self.assertEqual(json_rc, 0)
        self.assertFalse(has_ansi(stdout_json.getvalue()))
        self.assertEqual(json.loads(stdout_json.getvalue())["payload"]["state"]["status"], "connected")

    def test_profile_list_tty_color_respects_no_color_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profiles.json"
            ProfileStore(profile_path).add(
                Profile(
                    id="demo",
                    name="Demo",
                    protocol=ProtocolType.VLESS,
                    config={"host": "example.com", "port": 443, "uuid": "secret"},
                    source=ProfileSource.MANUAL,
                    health_status="ok",
                    in_rotation_pool=True,
                )
            )
            env = {
                "WATCHDOGVPN_CONFIG_DIR": tmp,
                "WATCHDOGVPN_PROFILES_FILE": str(profile_path),
            }
            with without_no_color(), patch.dict(os.environ, env, clear=False), redirect_stdout(TtyStringIO()) as colored:
                rc = cli.main.main(["profile", "list"])
            with patch.dict(os.environ, env, clear=False), redirect_stdout(TtyStringIO()) as no_color:
                plain_rc = cli.main.main(["profile", "list", "--no-color"])
            with without_no_color(), patch.dict(os.environ, env, clear=False), redirect_stdout(TtyStringIO()) as json_out:
                json_rc = cli.main.main(["profile", "list", "--json"])

        self.assertEqual(rc, 0)
        self.assertEqual(plain_rc, 0)
        self.assertEqual(json_rc, 0)
        self.assertTrue(has_ansi(colored.getvalue()))
        self.assertFalse(has_ansi(no_color.getvalue()))
        self.assertFalse(has_ansi(json_out.getvalue()))

    def test_provider_list_and_dns_status_color_human_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider_path = Path(tmp) / "providers.json"
            ProviderStore(provider_path).add(
                Provider(
                    id="netz.tg",
                    name="netz",
                    url="https://netz.tg/private-token",
                    profiles=["netz.tg:austria"],
                    rotation_enabled=True,
                )
            )
            policy_path = Path(tmp) / "dns-policy.json"
            DNSPolicyStore(policy_path).save(
                DNSPolicy(
                    channels={
                        DNSChannelName.PROXY: DNSChannel(
                            name=DNSChannelName.PROXY,
                            resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                        )
                    }
                )
            )
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")
            env = {
                "WATCHDOGVPN_CONFIG_DIR": tmp,
                "WATCHDOGVPN_PROVIDERS_FILE": str(provider_path),
                "WATCHDOGVPN_DNS_POLICY_FILE": str(policy_path),
            }

            with without_no_color(), patch.dict(os.environ, env, clear=False), redirect_stdout(TtyStringIO()) as provider_out:
                provider_rc = cli.main.main(["provider", "list"])
            with without_no_color(), patch.dict(os.environ, env, clear=False), redirect_stdout(TtyStringIO()) as provider_json:
                provider_json_rc = cli.main.main(["provider", "list", "--json"])
            with without_no_color(), patch.dict(os.environ, env, clear=False), redirect_stdout(TtyStringIO()) as dns_out:
                dns_rc = cli.main.main(["dns", "status", "--resolv-conf-path", str(resolv_conf)])
            with without_no_color(), patch.dict(os.environ, env, clear=False), redirect_stdout(TtyStringIO()) as dns_json:
                dns_json_rc = cli.main.main(["dns", "status", "--json", "--resolv-conf-path", str(resolv_conf)])

        self.assertEqual(provider_rc, 0)
        self.assertEqual(provider_json_rc, 0)
        self.assertEqual(dns_rc, 0)
        self.assertEqual(dns_json_rc, 0)
        self.assertTrue(has_ansi(provider_out.getvalue()))
        self.assertTrue(has_ansi(dns_out.getvalue()))
        self.assertFalse(has_ansi(provider_json.getvalue()))
        self.assertFalse(has_ansi(dns_json.getvalue()))


if __name__ == "__main__":
    unittest.main()
