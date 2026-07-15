from __future__ import annotations

import importlib.machinery
import importlib.util
from io import StringIO
import os
from pathlib import Path
import re
import signal
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tui"))

from watchdogvpn import render as render_module
from watchdogvpn.formatting import terminal_safe_text, visible_width
from watchdogvpn.terminal import (
    MIN_COLUMNS,
    MIN_ROWS,
    detect_terminal,
    plain_terminal_message,
)


class FakeStream:
    def __init__(self, tty: bool):
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def load_launcher():
    loader = importlib.machinery.SourceFileLoader("watchdogvpn_tui_r25", str(ROOT / "tui" / "VPN"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class TuiTerminalCapabilitiesTests(unittest.TestCase):
    HOSTILE_TEXT = (
        "safe界e\u0301👨\u200d👩\u200d👧\u200d👦 "
        "\x00\x07\x1b[2J\x1b]52;c;U0VDUkVU\x07"
        "\x1bPterminal-action\x1b\\\x9dtitle\x9c end"
    )

    def assert_hostile_controls_removed(self, output: str) -> None:
        self.assertNotIn("\x1b]", output)
        self.assertNotIn("\x1bP", output)
        self.assertNotIn("\x9d", output)
        self.assertNotIn("U0VDUkVU", output)
        self.assertNotIn("terminal-action", output)

    def assert_cursor_writes_fit(self, output: str, rows: int, columns: int) -> None:
        moves = re.findall(r"\x1b\[(\d+);(\d+)H", output)
        self.assertTrue(moves, "render emitted no cursor-addressed writes")
        for y, x in moves:
            with self.subTest(y=y, x=x, rows=rows, columns=columns):
                self.assertGreaterEqual(int(y), 1)
                self.assertLessEqual(int(y), rows)
                self.assertGreaterEqual(int(x), 1)
                self.assertLessEqual(int(x), columns)

    def test_capability_detection_covers_dumb_and_redirected_sessions(self):
        dumb = detect_terminal(
            stdin=FakeStream(True),
            stdout=FakeStream(True),
            environ={"TERM": "dumb"},
            size_getter=lambda fallback: os.terminal_size((80, 24)),
        )
        redirected = detect_terminal(
            stdin=FakeStream(False),
            stdout=FakeStream(False),
            environ={"TERM": "xterm-256color"},
            size_getter=lambda fallback: os.terminal_size((80, 24)),
        )

        self.assertFalse(dumb.ansi)
        self.assertEqual(dumb.layout, "plain")
        self.assertFalse(redirected.interactive)
        self.assertEqual(redirected.layout, "plain")
        self.assertNotIn("\x1b", plain_terminal_message(dumb))
        self.assertEqual(plain_terminal_message(redirected), "VPN requiere una terminal interactiva.")

        launcher = load_launcher()
        for capabilities in (dumb, redirected):
            output = StringIO()
            with self.subTest(layout=capabilities.layout, ansi=capabilities.ansi), \
                 patch.object(launcher, "detect_terminal", return_value=capabilities), \
                 patch("sys.stdout", output):
                launcher.main()
            self.assertNotIn("\x1b", output.getvalue())

    def test_narrow_and_wide_dashboard_never_address_outside_viewport(self):
        launcher = load_launcher()
        dashboard = [
            ("VPN", "ACTIVO"),
            ("Tun", "ACTIVO"),
            ("Route", "tun0"),
            ("IP", "OK"),
            ("Country", "DK"),
            ("DNS", "OK"),
            ("Bypass", "0"),
        ]
        for rows, columns in ((24, 40), (30, 120)):
            output = StringIO()
            with self.subTest(columns=columns), \
                 patch.object(launcher, "get_size", return_value=(rows, columns)), \
                 patch.object(render_module, "get_size", return_value=(rows, columns)), \
                 patch("sys.stdout", output):
                launcher.render(0, dashboard)
            self.assert_cursor_writes_fit(output.getvalue(), rows, columns)
            if columns == 40:
                self.assertIn("Enter abrir", output.getvalue())

    def test_write_clamps_stale_layout_coordinates_after_resize(self):
        output = StringIO()
        with patch.object(render_module, "get_size", return_value=(12, MIN_COLUMNS)), patch("sys.stdout", output):
            render_module.write(25, 90, "stale")
            render_module.write(12, MIN_COLUMNS - 2, "too-long-for-the-new-width")
        self.assert_cursor_writes_fit(output.getvalue(), 12, MIN_COLUMNS)

    def test_shared_geometry_handles_cjk_combining_flags_and_emoji_clusters(self):
        self.assertEqual(visible_width("界" * 20), 40)
        self.assertEqual(visible_width("e\u0301"), 1)
        self.assertEqual(visible_width("🇩🇰"), 2)
        self.assertEqual(visible_width("👨\u200d👩\u200d👧\u200d👦"), 2)
        fitted = render_module.fit("界" * 20, 20)
        self.assertLessEqual(visible_width(fitted), 20)
        self.assertTrue(fitted.endswith("…"))

    def test_final_write_boundary_strips_controls_and_clips_by_cells(self):
        output = StringIO()
        with patch.object(render_module, "get_size", return_value=(12, 12)), \
             patch.object(render_module, "RESET", ""), \
             patch("sys.stdout", output):
            render_module.write(4, 5, self.HOSTILE_TEXT)

        rendered = output.getvalue()
        self.assertTrue(rendered.startswith("\x1b[4;5H"))
        payload = rendered.removeprefix("\x1b[4;5H")
        self.assertLessEqual(visible_width(payload), 8)
        self.assert_hostile_controls_removed(rendered)
        self.assertIn("safe界e\u0301", payload)

    def test_dashboard_and_text_surfaces_neutralize_hostile_runtime_values(self):
        launcher = load_launcher()
        dashboard = [
            ("VPN", "ACTIVO"),
            ("Event", self.HOSTILE_TEXT),
            ("Country", "DK"),
        ]
        output = StringIO()
        with patch.object(launcher, "get_size", return_value=(24, 40)), \
             patch.object(render_module, "get_size", return_value=(24, 40)), \
             patch("sys.stdout", output):
            launcher.render(0, dashboard)
        self.assert_hostile_controls_removed(output.getvalue())

        for title in ("Eventos", "Logs", "Perfiles", "Proveedores"):
            output = StringIO()
            with self.subTest(surface=title), \
                 patch.object(launcher, "get_size", return_value=(24, 40)), \
                 patch.object(render_module, "get_size", return_value=(24, 40)), \
                 patch.object(launcher, "read_key", return_value="q"), \
                 patch("sys.stdout", output):
                launcher.show_output(title, self.HOSTILE_TEXT)
            self.assert_hostile_controls_removed(output.getvalue())
            self.assert_cursor_writes_fit(output.getvalue(), 24, 40)
            self.assertEqual(
                terminal_safe_text(self.HOSTILE_TEXT),
                "safe界e\u0301👨\u200d👩\u200d👧\u200d👦 end",
            )

    def test_resize_notification_wakes_input_without_keyboard(self):
        launcher = load_launcher()
        previous = launcher.install_resize_handler()
        try:
            launcher.RESIZE_PENDING = False
            os.kill(os.getpid(), signal.SIGWINCH)
            with patch.object(launcher.select, "select", return_value=([], [], [])):
                self.assertEqual(launcher.read_key(timeout=None), "resize")
            self.assertFalse(launcher.RESIZE_PENDING)
        finally:
            launcher.restore_resize_handler(previous)

    def test_narrow_subview_keeps_open_and_return_controls_visible(self):
        launcher = load_launcher()
        output = StringIO()
        items = [("Estado real", "command"), ("Rotar ahora", "command")]
        with patch.object(launcher, "get_size", return_value=(24, 40)), \
             patch.object(render_module, "get_size", return_value=(24, 40)), \
             patch.object(launcher, "read_key", return_value="q"), \
             patch("sys.stdout", output):
            self.assertIsNone(launcher.section_panel("Acciones rapidas", items))
        self.assert_cursor_writes_fit(output.getvalue(), 24, 40)
        self.assertIn("Enter abrir", output.getvalue())
        self.assertIn("q volver", output.getvalue())

    def test_too_small_terminal_has_literal_recovery_message(self):
        capabilities = detect_terminal(
            stdin=FakeStream(True),
            stdout=FakeStream(True),
            environ={"TERM": "xterm-256color"},
            size_getter=lambda fallback: os.terminal_size((MIN_COLUMNS - 1, MIN_ROWS - 1)),
        )
        message = plain_terminal_message(capabilities)
        self.assertEqual(capabilities.layout, "too-small")
        self.assertNotIn("\x1b", message)
        self.assertIn("al menos", message)


if __name__ == "__main__":
    unittest.main()
