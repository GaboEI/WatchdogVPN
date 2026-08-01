"""Tests for tools/compat_l2_reporter.py."""

from __future__ import annotations

import json
import subprocess
import sys
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


class CronUrlTests(unittest.TestCase):
    def test_cron_urls_derive_from_manifest(self) -> None:
        manifest = reporter._load_manifest_for_cron()
        checks = reporter._collect_cron_urls_from_manifest(manifest)
        urls = {check["url"] for check in checks}
        names = {check["name"] for check in checks}
        # External repositories.
        self.assertIn("https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/noble/Release", urls)
        self.assertIn("https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/repodata/repomd.xml", urls)
        self.assertIn("https://dl.fedoraproject.org/pub/epel/9/Everything/aarch64/repodata/repomd.xml", urls)
        self.assertNotIn("https://dl.fedoraproject.org/pub/epel/epel9/Everything/x86_64/repodata/repomd.xml", urls)
        self.assertNotIn("https://dl.fedoraproject.org/pub/epel/epel9/Everything/aarch64/repodata/repomd.xml", urls)
        # Artifact assets.
        self.assertIn(
            "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-linux-amd64-glibc.tar.gz",
            urls,
        )
        self.assertIn(
            "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-linux-arm64.tar.gz",
            urls,
        )
        self.assertIn(
            "https://github.com/cbeuw/Cloak/releases/download/v2.12.0/ck-client-linux-amd64-v2.12.0",
            urls,
        )
        # Source-build tags.
        self.assertIn(
            "https://github.com/amnezia-vpn/amneziawg-tools/releases/tag/v1.0.20260618-2",
            urls,
        )
        self.assertIn(
            "https://github.com/amnezia-vpn/amneziawg-go/releases/tag/v3.0.2",
            urls,
        )
        self.assertIn("sing_box_official_artifact_stable_x86_64", names)
        self.assertIn("sing_box_official_artifact_stable_aarch64", names)
        self.assertIn("ck_client_official_artifact_stable_x86_64", names)

    def test_container_runtime_uses_executable_lookup(self) -> None:
        with unittest.mock.patch.object(reporter.shutil, "which", side_effect=lambda name: "/usr/bin/docker" if name == "docker" else None):
            self.assertEqual(reporter._container_runtime(), "docker")

    def test_reporter_script_entrypoint_can_import_tools_package(self) -> None:
        result = subprocess.run(
            [sys.executable, "tools/compat_l2_reporter.py", "--help"],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cron_urls_update_when_manifest_changes(self) -> None:
        manifest = {
            "dependency_requirements": {
                "dep_sing_box_runtime": {
                    "capability_id": "proto_sing_box_runtime",
                    "description": "fixture",
                    "method_chain": [
                        {
                            "id": "sing_box_official_artifact_stable",
                            "kind": "official_artifact_pinned",
                            "method_ref": "official_artifact_pinned",
                            "official_download_base": "https://github.com/SagerNet/sing-box/releases/download/v9.9.9",
                            "version": "9.9.9",
                            "assets": [
                                {
                                    "architecture": "x86_64",
                                    "archive_or_binary_kind": "tar.gz",
                                    "asset_name": "sing-box-9.9.9-linux-amd64.tar.gz",
                                    "official_download_base": "https://github.com/SagerNet/sing-box/releases/download/v9.9.9",
                                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                },
                            ],
                        },
                    ],
                }
            }
        }
        checks = reporter._collect_cron_urls_from_manifest(manifest)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["category"], "artifact")
        self.assertEqual(
            checks[0]["url"],
            "https://github.com/SagerNet/sing-box/releases/download/v9.9.9/sing-box-9.9.9-linux-amd64.tar.gz",
        )

    def test_cron_deduplicates_duplicate_urls(self) -> None:
        manifest = {
            "dependency_requirements": {
                "dep_amneziawg_runtime": {
                    "capability_id": "proto_amneziawg_runtime",
                    "description": "fixture",
                    "method_chain": [
                        {
                            "id": "amneziawg_ubuntu_ppa_exact",
                            "kind": "external_repo_exact",
                            "method_ref": "external_repo_exact",
                            "package_manager": "apt",
                            "repository": {
                                "id": "amnezia_ubuntu_ppa_noble",
                                "series": "noble",
                                "url": "https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu",
                            },
                        },
                        {
                            "id": "amneziawg_mint_base_ppa_exact",
                            "kind": "external_repo_exact",
                            "method_ref": "external_repo_exact",
                            "package_manager": "apt",
                            "repository": {
                                "id": "amnezia_ubuntu_ppa_noble_for_mint",
                                "series": "noble",
                                "url": "https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu",
                            },
                        },
                    ],
                }
            }
        }
        checks = reporter._collect_cron_urls_from_manifest(manifest)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["url"], "https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/noble/Release")


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
