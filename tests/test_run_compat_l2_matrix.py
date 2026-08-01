"""Tests for tools/run_compat_l2_matrix.py without requiring a real container runtime."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import tools.run_compat_l2_matrix as l2_runner


class RunMatrixCliTests(unittest.TestCase):
    def _mock_cases(self):
        return [
            {"target": "ubuntu_24_04", "image": "ubuntu:24.04", "manager": "apt-get", "kind": "apt", "packages": ()},
            {"target": "ubuntu_26_04", "image": "ubuntu:26.04", "manager": "apt-get", "kind": "apt", "packages": (), "optional_image": True},
        ]

    def _mock_result(self, target, *, pull_status, overall_status):
        return {
            "target": target,
            "image": "image",
            "runtime": "docker",
            "pull": {"status": pull_status},
            "overall_status": overall_status,
            "limitations": [],
            "dependency_decisions": [],
            "resolver_package_queries": [],
        }

    def _run_with_mock_results(self, results, cases=None):
        cases = cases or self._mock_cases()
        with tempfile.TemporaryDirectory() as tmp:
            raw_path = Path(tmp) / "raw.json"
            json_path = Path(tmp) / "matrix.json"
            md_path = Path(tmp) / "matrix.md"
            with unittest.mock.patch.object(l2_runner.l2, "execute_l2_matrix_case", side_effect=results), \
                 unittest.mock.patch.object(l2_runner.l2, "CASES", cases), \
                 unittest.mock.patch.object(l2_runner, "_detect_runtime", return_value="docker"):
                return l2_runner.main([
                    "--raw-output", str(raw_path),
                    "--json-output", str(json_path),
                    "--markdown-output", str(md_path),
                    "--fail-on-red",
                ])

    def test_fail_on_red_passes_when_all_available(self) -> None:
        results = [
            self._mock_result("ubuntu_24_04", pull_status="available", overall_status="available"),
            self._mock_result("ubuntu_26_04", pull_status="available", overall_status="available"),
        ]
        self.assertEqual(self._run_with_mock_results(results), 0)

    def test_fail_on_red_fails_for_non_optional_unavailable(self) -> None:
        results = [
            self._mock_result("ubuntu_24_04", pull_status="timeout", overall_status="timeout"),
            self._mock_result("ubuntu_26_04", pull_status="available", overall_status="available"),
        ]
        self.assertEqual(self._run_with_mock_results(results), 1)

    def test_fail_on_red_excuses_optional_image_not_found(self) -> None:
        results = [
            self._mock_result("ubuntu_24_04", pull_status="available", overall_status="available"),
            self._mock_result("ubuntu_26_04", pull_status="image_not_found", overall_status="image_not_found"),
        ]
        self.assertEqual(self._run_with_mock_results(results), 0)

    def test_fail_on_red_does_not_excuse_optional_other_failure(self) -> None:
        results = [
            self._mock_result("ubuntu_24_04", pull_status="available", overall_status="available"),
            self._mock_result("ubuntu_26_04", pull_status="timeout", overall_status="timeout"),
        ]
        self.assertEqual(self._run_with_mock_results(results), 1)

    def test_runtime_error_produces_artifact_and_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw_path = Path(tmp) / "raw.json"
            json_path = Path(tmp) / "matrix.json"
            md_path = Path(tmp) / "matrix.md"
            with unittest.mock.patch.object(l2_runner, "_detect_runtime", return_value=None):
                rc = l2_runner.main([
                    "--raw-output", str(raw_path),
                    "--json-output", str(json_path),
                    "--markdown-output", str(md_path),
                    "--fail-on-red",
                ])
            self.assertEqual(rc, 1)
            self.assertTrue(raw_path.exists())
            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            self.assertEqual(raw[0]["overall_status"], "runtime_error")
            self.assertEqual(raw[0]["pull"]["status"], "runtime_error")


if __name__ == "__main__":
    unittest.main()
