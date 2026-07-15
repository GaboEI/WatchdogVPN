#!/usr/bin/env python3
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tui"))

from watchdogvpn import actions
from watchdogvpn import commands
from watchdogvpn import dns
from watchdogvpn import render
from watchdogvpn import state
from watchdogvpn.constants import MENU, MENU_ITEMS
from watchdogvpn.formatting import display_vpn_status, format_span, strip_ansi
from watchdogvpn.parsers import parse_event_line, parse_trace_line
from watchdogvpn.validators import valid_domain, valid_location_hint, valid_timer_interval


class TuiModuleTests(unittest.TestCase):
    def test_menu_labels_match_items(self):
        self.assertEqual(MENU, [item["label"] for item in MENU_ITEMS])
        self.assertIn("Dashboard", MENU)
        self.assertIn("Backend", MENU)
        self.assertIn("Exclusiones", MENU)
        self.assertIn("DNS", MENU)
        self.assertIn("Settings", MENU)
        self.assertIn("Update", MENU)

    def test_formatting_helpers(self):
        self.assertEqual(strip_ansi("\x1b[31mred\x1b[0m"), "red")
        self.assertEqual(format_span(65), "1m 05s")
        self.assertEqual(format_span(3661), "1h 01m 01s")
        self.assertEqual(display_vpn_status("up"), "ACTIVO")
        self.assertEqual(display_vpn_status("degraded"), "DEGRADADO")

    def test_render_helpers(self):
        self.assertEqual(render.fit("abcdef", 4), "abc…")
        self.assertEqual(render.display_label("Auth"), "Sesion")
        self.assertEqual(render.display_value("Location", "DK"), "🇩🇰 DK")
        self.assertEqual(render.flag_from_iso("bad"), "")
        self.assertIn("\x1b[", render.semantic_style("VPN", "ACTIVO"))

    def test_event_parser_new_trace_format(self):
        event = parse_event_line(
            "2026-05-09T01:02:03+03:00 | notify | INFO | vpn_activa | "
            "title='VPN conectada' urgency='normal' body='Conectado a Dinamarca.'"
        )
        self.assertEqual(event["format"], "trace")
        self.assertEqual(event["title"], "VPN conectada")
        self.assertEqual(event["urgency"], "normal")
        self.assertEqual(event["body"], "Conectado a Dinamarca.")

    def test_event_parser_legacy_format(self):
        event = parse_event_line("[old] VPN prueba | low | Mensaje")
        self.assertEqual(event["format"], "legacy")
        self.assertEqual(event["title"], "VPN prueba")
        self.assertEqual(event["urgency"], "low")
        self.assertEqual(event["body"], "Mensaje")

    def test_trace_parser(self):
        parsed = parse_trace_line("2026-05-09T01:02:03+03:00 | watchdog | WARN | soft_fail | count=1")
        self.assertEqual(parsed["component"], "watchdog")
        self.assertEqual(parsed["level"], "WARN")
        self.assertEqual(parsed["event"], "soft_fail")
        self.assertIsNone(parse_trace_line("bad | line"))

    def test_validators(self):
        self.assertEqual(valid_domain("https://example.com")[0], False)
        self.assertEqual(valid_domain("*.example.com"), (True, "example.com"))
        self.assertEqual(valid_timer_interval("3h"), (True, "3h"))
        self.assertEqual(valid_timer_interval("0h")[0], False)
        self.assertTrue(valid_location_hint("Berlin"))
        self.assertFalse(valid_location_hint("sin valor"))

    def test_command_runner_contract(self):
        self.assertEqual(commands.run("printf ok"), "ok")
        self.assertEqual(commands.run_args(["printf", "ok"]), "ok")
        proc = commands.run_process("printf ok")
        self.assertIsNotNone(proc)
        self.assertEqual(proc.stdout, "ok")
        self.assertEqual(proc.returncode, 0)
        proc = commands.run_process_args(["printf", "ok"])
        self.assertIsNotNone(proc)
        self.assertEqual(proc.stdout, "ok")
        self.assertEqual(proc.returncode, 0)

    def test_action_command_builders(self):
        self.assertEqual(actions.restart_vpn_command("DK"), "/usr/local/bin/vpnctl restart")
        self.assertEqual(actions.restart_vpn_command("sin valor"), "/usr/local/bin/vpnctl restart")
        self.assertEqual(actions.disconnect_vpn_command(), "/usr/local/bin/vpnctl disconnect")
        self.assertIn("/usr/local/bin/watchdog rotate --force", actions.rotate_now_command())
        self.assertEqual(actions.real_status_command(), "/usr/local/bin/vpnctl status")
        self.assertFalse(hasattr(actions, "dns_current_command"))
        self.assertFalse(hasattr(actions, "dns_apply_command"))
        self.assertEqual(actions.add_bypass_domain_command("example.com"), "sudo -n /usr/local/bin/no_vpn example.com")
        self.assertIn("sin rutas", actions.add_bypass_domain_command("bad/domain"))

        timer_cmd = actions.set_timer_interval_command("myvpn-logrotate.timer", "3h")
        self.assertIn("OnUnitInactiveSec=", timer_cmd)
        self.assertIn("systemctl restart myvpn-logrotate.timer", timer_cmd)
        self.assertIn("timer no permitido", actions.set_timer_interval_command("bad.timer", "3h"))
        self.assertIn("Usa formato", actions.set_timer_interval_command("myvpn-logrotate.timer", "bad"))

        self.assertIn("dominio invalido", actions.remove_bypass_domain_command("bad/domain"))
        self.assertIn("Quitado: example.com", actions.remove_bypass_domain_command("example.com"))

    def test_dns_tui_helpers_read_policy_and_build_real_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = pathlib.Path(tmp) / "config"
            policy_path = config_dir / "dns-policy.json"
            snapshot_path = config_dir / "dns-state.json"
            policy_path.parent.mkdir(parents=True)
            policy_path.write_text(
                """
{
  "mode": "advanced",
  "test_domain": "example.com",
  "ttl": "6h",
  "tun_hijack": true,
  "channels": {
    "direct": {
      "name": "direct",
      "resolvers": [
        {"uri": "local", "enabled": true},
        {"uri": "https://1.1.1.1/dns-query", "enabled": false}
      ]
    }
  },
  "static_ip_enabled": true,
  "static_ips": [{"domain": "example.com", "ip": "203.0.113.10"}],
  "rules_enabled": true,
  "rules": [{"id": "r1", "pattern": "suffix:example.com", "channel": "direct"}],
  "ecs_direct_enabled": true,
  "ecs_direct_subnet": "203.0.113.0/24"
}
""",
                encoding="utf-8",
            )
            with patch.dict(
                "os.environ",
                {
                    "WATCHDOGVPN_DNS_POLICY_FILE": str(policy_path),
                    "WATCHDOGVPN_DNS_SNAPSHOT_FILE": str(snapshot_path),
                    "WATCHDOGVPN_REPO": str(ROOT),
                },
            ):
                rows = dict(dns.policy_rows())
                channels = dict(dns.channel_rows())
                status_cmd = dns.status_command(json_output=True)
                apply_cmd = dns.apply_command("tun0")

            self.assertEqual(rows["Mode"], "advanced")
            self.assertEqual(rows["Test domain"], "example.com")
            self.assertEqual(rows["TTL"], "6h")
            self.assertEqual(rows["Static IP"], "on (1 entries)")
            self.assertEqual(rows["Rules"], "on (1 rules)")
            self.assertEqual(rows["ECS direct"], "on (203.0.113.0/24)")
            self.assertEqual(channels["direct"], "1/2 enabled")
            self.assertIn("bin/watchdog dns status --json", status_cmd)
            self.assertIn("sudo -n env", apply_cmd)
            self.assertIn("--systemd-link tun0", apply_cmd)

    def test_dns_tui_helpers_report_missing_core_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"WATCHDOGVPN_REPO": tmp}), \
                 patch.object(dns.os, "getcwd", return_value=tmp), \
                 patch.object(dns.Path, "home", return_value=pathlib.Path(tmp)):
                self.assertFalse(dns.core_available())
                self.assertIn("core CLI not found", dns.test_command())

    def test_systemd_helpers_parse_mocked_output(self):
        with patch.object(commands, "run_args", return_value="active"):
            self.assertEqual(commands.service_state("myvpn-logrotate.timer"), "active")
        with patch.object(commands, "run", return_value="3h"):
            self.assertEqual(commands.timer_interval("myvpn-logrotate.timer"), "3h")
        with patch.object(commands, "run", return_value="2h"):
            self.assertEqual(commands.timer_countdown("myvpn-logrotate.timer"), "2h")

    def test_state_key_value_parsing(self):
        truth_raw = "STATUS=UP\nTUN=UP\nROUTE=TUN\nIP=OK\nIP_ADDR=198.51.100.10\n"
        with patch.object(state, "run", return_value=truth_raw):
            parsed = state.truth_data()
            self.assertEqual(parsed["STATUS"], "UP")
            self.assertEqual(parsed["ROUTE"], "TUN")

    def test_settings_snapshot_reads_persistent_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.toml"
            path.write_text(
                "\n".join(
                    [
                        "[language]",
                        'current = "es"',
                        "auto_detect = true",
                        "",
                        "[tui]",
                        'theme = "high_contrast"',
                        "color = false",
                        "unicode = true",
                        "",
                        "[reporting]",
                        "sanitize_ipv4 = true",
                        "sanitize_ipv6 = true",
                        "sanitize_email = false",
                        "sanitize_home = true",
                    ]
                ),
                encoding="utf-8",
            )
            with patch.dict("os.environ", {"WATCHDOGVPN_CONFIG_FILE": str(path)}):
                snapshot = dict(state.settings_snapshot())
            self.assertEqual(snapshot["Estado"], "readable")
            self.assertEqual(snapshot["Idioma"], "es")
            self.assertEqual(snapshot["Tema"], "high_contrast")
            self.assertEqual(snapshot["Color"], "false")

    def test_backend_snapshot_reads_persistent_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.toml"
            path.write_text(
                "\n".join(
                    [
                        "[backend]",
                        'mode = "custom-vps"',
                        'active = "custom-vps"',
                        "",
                        "[custom_vps]",
                        "enabled = true",
                        'name = "Paris"',
                        'host = "203.0.113.10"',
                        'ssh_user = "ubuntu"',
                        "ssh_port = 22",
                        'protocol = "awg"',
                        'profile_path = "/etc/watchdogvpn/custom.conf"',
                        'service_name = "custom-vpn.service"',
                        'interface = "awg0"',
                    ]
                ),
                encoding="utf-8",
            )
            runtime = {
                "MODE": "custom-vps",
                "BACKEND": "custom-vps",
                "CUSTOM_VPS_ENABLED": "true",
                "IMPLEMENTED": "true",
                "SUPPORTS_ROTATION": "false",
                "TRUTH_INTERFACE": "tun0",
                "CUSTOM_VPS_INTERFACE": "awg0",
            }
            with patch.dict("os.environ", {"WATCHDOGVPN_CONFIG_FILE": str(path)}), \
                 patch.object(state, "backend_data", return_value=runtime):
                snapshot = dict(state.backend_snapshot())
            self.assertEqual(snapshot["Modo"], "custom-vps")
            self.assertEqual(snapshot["Custom VPS"], "true")
            self.assertEqual(snapshot["Host"], "203.0.113.10")
            self.assertEqual(snapshot["Interfaz VPS"], "awg0")

    def test_state_snapshots_with_mocks(self):
        with patch.object(state, "run", return_value="example.com\nexample.org\n# ignored\n"):
            self.assertEqual(state.bypass_domains(), ["example.com", "example.org"])

        with patch.object(state, "logrotate_policy", return_value={"interval": "hourly"}), \
             patch.object(state, "log_size", return_value="1.0K"), \
             patch.object(state, "rotated_log_count", return_value=2), \
             patch.object(state, "service_state", return_value="active"), \
             patch.object(state, "timer_enabled", return_value="enabled"), \
             patch.object(state, "timer_trigger", return_value="soon"), \
             patch.object(state, "timer_countdown", return_value="5min"):
            snapshot = state.housekeeping_snapshot()
            self.assertEqual(snapshot["timer_state"], "active")
            self.assertEqual(snapshot["logs"][0]["size"], "1.0K")

        with patch.object(state, "tail_plain_lines", return_value=[
            "2026-05-09T01:02:03+03:00 | watchdog | WARN | soft_fail | count=1",
            "legacy line",
        ]):
            snapshot = state.trace_snapshot()
            self.assertEqual(snapshot["counts"]["WARN"], 2)
            self.assertEqual(snapshot["legacy"], 2)


if __name__ == "__main__":
    unittest.main()
