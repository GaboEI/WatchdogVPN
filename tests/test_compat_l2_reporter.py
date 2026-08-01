"""Tests for tools/compat_l2_reporter.py."""

from __future__ import annotations

import json
import unittest
import unittest.mock
from pathlib import Path
from tempfile import TemporaryDirectory

from tools import compat_l2_reporter as reporter


class MatrixReportTests(unittest.TestCase):
    def _sample_results(self):
        return [
            {
                "target": "ubuntu_24_04",
                "image": "ubuntu:24.04",
                "runtime": "docker",
                "overall_status": "available",
                "probe_aggregate": "available",
                "pull": {"status": "available"},
                "os_release": {"status": "available"},
                "package_manager": {"status": "available"},
                "metadata_refresh": {"status": "available"},
                "cleanup": {"status": "cleaned", "residual_possible": False},
                "limitations": [],
                "dependency_decisions": [],
                "resolver_package_queries": [],
            },
            {
                "target": "ubuntu_26_04",
                "image": "ubuntu:26.04",
                "runtime": "docker",
                "overall_status": "image_not_found",
                "probe_aggregate": "image_not_found",
                "pull": {"status": "image_not_found"},
                "os_release": {"status": "not_run"},
                "package_manager": {"status": "not_run"},
                "metadata_refresh": {"status": "not_run"},
                "cleanup": {"status": "not_needed", "residual_possible": False},
                "limitations": ["image pull failed: image_not_found"],
                "dependency_decisions": [],
                "resolver_package_queries": [],
            },
        ]

    def test_build_matrix_report_summary(self) -> None:
        report = reporter.build_matrix_report(self._sample_results())
        self.assertEqual(report["report_kind"], "compat_l2_matrix")
        self.assertEqual(report["schema_version"], "1.0.0")
        self.assertEqual(report["summary"]["total_targets"], 2)
        self.assertEqual(report["summary"]["available"], 1)
        self.assertEqual(report["summary"]["unavailable"], 0)
        self.assertEqual(report["summary"]["image_not_found"], 1)
        self.assertEqual(report["targets"][0]["cleanup_status"], "cleaned")
        self.assertFalse(report["targets"][0]["residual_possible"])

    def test_render_matrix_markdown_contains_summary_and_table(self) -> None:
        report = reporter.build_matrix_report(self._sample_results())
        md = reporter.render_matrix_markdown(report)
        self.assertIn("L2 Compatibility Matrix Report", md)
        self.assertIn("| Total targets | Available | Unavailable | Image not found |", md)
        self.assertIn("| ubuntu_24_04 |", md)
        self.assertIn("image pull failed: image_not_found", md)

    def test_matrix_cli_writes_json_and_markdown(self) -> None:
        with TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "raw.json"
            json_path = Path(tmp) / "matrix.json"
            md_path = Path(tmp) / "matrix.md"
            input_path.write_text(json.dumps(self._sample_results()), encoding="utf-8")
            rc = reporter.main(["matrix", "--input", str(input_path), "--json-output", str(json_path), "--markdown-output", str(md_path)])
            self.assertEqual(rc, 0)
            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["available"], 1)

    def test_matrix_cli_rejects_non_array_input(self) -> None:
        with TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "raw.json"
            json_path = Path(tmp) / "matrix.json"
            input_path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
            rc = reporter.main(["matrix", "--input", str(input_path), "--json-output", str(json_path)])
            self.assertEqual(rc, 1)


class CronReportTests(unittest.TestCase):
    def test_summarize_cron_counts(self) -> None:
        checks = [
            {"category": "container_image", "name": "a", "status": "available"},
            {"category": "artifact", "name": "b", "status": "unavailable"},
            {"category": "source", "name": "c", "status": "unknown"},
        ]
        summary = reporter._summarize_cron(checks)
        self.assertEqual(summary, {"total": 3, "available": 1, "unavailable": 1, "unknown": 1})

    def test_render_cron_markdown(self) -> None:
        report = {
            "schema_version": "1.0.0",
            "report_kind": "repo_availability",
            "generated_at": "2026-01-01T00:00:00Z",
            "summary": {"total": 1, "available": 1, "unavailable": 0, "unknown": 0},
            "checks": [
                {"category": "artifact", "name": "sing_box", "status": "available", "url": "https://example.com", "evidence": "HEAD 200"},
            ],
        }
        md = reporter.render_cron_markdown(report)
        self.assertIn("Repository Availability Report", md)
        self.assertIn("| artifact | sing_box | available |", md)

    def test_cron_cli_rejects_non_report_input(self) -> None:
        with TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "raw.json"
            json_path = Path(tmp) / "cron.json"
            input_path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
            rc = reporter.main(["cron", "--input", str(input_path), "--json-output", str(json_path)])
            self.assertEqual(rc, 1)

    def test_cron_cli_fails_on_unavailable(self) -> None:
        with TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "raw.json"
            json_path = Path(tmp) / "cron.json"
            report = {
                "schema_version": "1.0.0",
                "report_kind": "repo_availability",
                "generated_at": "2026-01-01T00:00:00Z",
                "summary": {"total": 1, "available": 0, "unavailable": 1, "unknown": 0},
                "checks": [
                    {"category": "artifact", "name": "x", "status": "unavailable", "url": "https://example.com", "evidence": "HEAD 404"},
                ],
            }
            input_path.write_text(json.dumps(report), encoding="utf-8")
            rc = reporter.main(["cron", "--input", str(input_path), "--json-output", str(json_path), "--fail-on-unavailable"])
            self.assertEqual(rc, 1)


class HeadUrlTests(unittest.TestCase):
    def test_head_url_200_is_available(self) -> None:
        fake_response = unittest.mock.MagicMock()
        fake_response.status = 200
        fake_context = unittest.mock.MagicMock()
        fake_context.__enter__ = unittest.mock.MagicMock(return_value=fake_response)
        fake_context.__exit__ = unittest.mock.MagicMock(return_value=False)
        with unittest.mock.patch("urllib.request.urlopen", return_value=fake_context):
            result = reporter._head_url("https://example.com/ok")
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["http_status"], 200)

    def test_head_url_404_is_unavailable(self) -> None:
        from urllib.error import HTTPError
        with unittest.mock.patch(
            "urllib.request.urlopen",
            side_effect=HTTPError("https://example.com/missing", 404, "Not Found", None, None),
        ):
            result = reporter._head_url("https://example.com/missing")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["http_status"], 404)

    def test_head_url_invalid_url_is_unknown(self) -> None:
        from urllib.error import URLError
        with unittest.mock.patch(
            "urllib.request.urlopen",
            side_effect=URLError("Name or service not known"),
        ):
            result = reporter._head_url("https://this-is-not-a-valid-host.invalid")
        self.assertEqual(result["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
