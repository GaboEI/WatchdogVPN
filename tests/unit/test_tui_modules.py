#!/usr/bin/env python3
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tui"))

from watchdogvpn import actions
from watchdogvpn import commands
from watchdogvpn import render
from watchdogvpn import state
from watchdogvpn.constants import MENU, MENU_ITEMS
from watchdogvpn.formatting import display_auth_status, display_vpn_status, format_span, strip_ansi
from watchdogvpn.parsers import parse_event_line, parse_trace_line
from watchdogvpn.validators import valid_domain, valid_location_hint, valid_timer_interval


class TuiModuleTests(unittest.TestCase):
    def test_menu_labels_match_items(self):
        self.assertEqual(MENU, [item["label"] for item in MENU_ITEMS])
        self.assertIn("Dashboard", MENU)
        self.assertIn("Exclusiones", MENU)

    def test_formatting_helpers(self):
        self.assertEqual(strip_ansi("\x1b[31mred\x1b[0m"), "red")
        self.assertEqual(format_span(65), "1m 05s")
        self.assertEqual(format_span(3661), "1h 01m 01s")
        self.assertEqual(display_vpn_status("up"), "ACTIVO")
        self.assertEqual(display_vpn_status("degraded"), "DEGRADADO")
        self.assertEqual(display_auth_status("expired"), "SESION EXPIRADA")
        self.assertEqual(display_auth_status("unknown", "sudo_required"), "SIN SUDO")

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
        proc = commands.run_process("printf ok")
        self.assertIsNotNone(proc)
        self.assertEqual(proc.stdout, "ok")
        self.assertEqual(proc.returncode, 0)

    def test_action_command_builders(self):
        self.assertIn("/usr/local/sbin/vpn_set DK", actions.restart_vpn_command("DK"))
        self.assertIn("systemctl restart adguardvpn.service", actions.restart_vpn_command("sin valor"))
        self.assertIn("VPN_ROTATE_FORCE=1", actions.rotate_now_command())
        self.assertEqual(actions.real_status_command(), "/usr/local/bin/vpnctl status")
        self.assertEqual(actions.dns_apply_command("quad9-doh"), "sudo -n /usr/local/bin/vpn_dnsctl apply quad9-doh")
        self.assertEqual(actions.add_bypass_domain_command("example.com"), "sudo -n /usr/local/bin/no_vpn example.com")

        timer_cmd = actions.set_timer_interval_command("vpn-rotate.timer", "3h")
        self.assertIn("OnUnitInactiveSec=", timer_cmd)
        self.assertIn("systemctl restart vpn-rotate.timer", timer_cmd)

        self.assertIn('-v val="15"', actions.set_rotate_top_n_command("15"))
        self.assertIn("ERROR: TOP_N", actions.set_rotate_top_n_command("0"))
        self.assertIn("dominio invalido", actions.remove_bypass_domain_command("bad/domain"))
        self.assertIn("Quitado: example.com", actions.remove_bypass_domain_command("example.com"))

    def test_systemd_helpers_parse_mocked_output(self):
        with patch.object(commands, "run", return_value="active"):
            self.assertEqual(commands.service_state("vpn-watchdog.timer"), "active")
        with patch.object(commands, "run", return_value="3h"):
            self.assertEqual(commands.timer_interval("vpn-rotate.timer"), "3h")
        with patch.object(commands, "run", return_value="2h"):
            self.assertEqual(commands.timer_countdown("vpn-rotate.timer"), "2h")

    def test_state_key_value_parsing(self):
        truth_raw = "STATUS=UP\nTUN=UP\nROUTE=TUN\nIP=OK\nIP_ADDR=198.51.100.10\n"
        auth_raw = "AUTH=OK\nREASON=ok\nCLI_RC=0\nDETAIL=\n"
        with patch.object(state, "run", return_value=truth_raw):
            parsed = state.truth_data()
            self.assertEqual(parsed["STATUS"], "UP")
            self.assertEqual(parsed["ROUTE"], "TUN")
        with patch.object(state, "run", return_value=auth_raw):
            parsed = state.auth_data()
            self.assertEqual(parsed["AUTH"], "OK")
            self.assertEqual(parsed["REASON"], "ok")

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
            self.assertEqual(snapshot["counts"]["WARN"], 4)
            self.assertEqual(snapshot["legacy"], 4)


if __name__ == "__main__":
    unittest.main()
