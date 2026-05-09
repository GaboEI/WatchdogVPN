#!/usr/bin/env python3
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tui"))

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


if __name__ == "__main__":
    unittest.main()
