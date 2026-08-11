from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import installed_provenance


class InstalledProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.source_root = self.root / "source"
        self.installed_root = self.root / "installed"
        (self.source_root / "daemon").mkdir(parents=True)
        (self.source_root / "tools").mkdir(parents=True)
        (self.source_root / "daemon" / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.source_root / "tools" / "helper.py").write_text("HELPER = 1\n", encoding="utf-8")
        shutil.copytree(self.source_root / "daemon", self.installed_root / "daemon")
        shutil.copytree(self.source_root / "tools", self.installed_root / "tools")
        self.manifest_path = self.installed_root / "installed-provenance.json"
        self.marker_path = self.installed_root / "installed-version"
        self.daemon_wrapper = self.root / "watchdogvpn-daemon"
        self.daemon_unit = self.root / "watchdogvpn.service"
        self.daemon_wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
        self.daemon_unit.write_text("[Service]\n", encoding="utf-8")
        self.deployment_paths = (self.daemon_wrapper, self.daemon_unit)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def build_manifest(self, *, source_state: str = "clean") -> dict[str, object]:
        identity = installed_provenance.SourceIdentity(
            commit="a" * 40,
            state=source_state,
        )
        with patch.object(installed_provenance, "source_identity", return_value=identity):
            manifest = installed_provenance.build_manifest(
                source_root=self.source_root,
                installed_root=self.installed_root,
                includes=("daemon", "tools"),
                deployment_paths=self.deployment_paths,
                installed_at="2026-08-11T00:00:00Z",
            )
        installed_provenance.write_manifest(self.manifest_path, manifest)
        manifest_sha256 = hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        self.marker_path.write_text(
            "schema_version=2\n"
            f"commit={'a' * 40}\n"
            "installed_at=2026-08-11T00:00:00Z\n"
            f"manifest_sha256={manifest_sha256}\n",
            encoding="utf-8",
        )
        return manifest

    def test_clean_source_and_matching_runtime_verify(self) -> None:
        manifest = self.build_manifest()

        result = installed_provenance.verify_installation(
            marker_path=self.marker_path,
            manifest_path=self.manifest_path,
            installed_root=self.installed_root,
        )

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["commit"], "a" * 40)
        self.assertEqual(result["tree_sha256"], manifest["tree_sha256"])

    def test_dirty_source_is_recorded_without_claiming_attributable_commit(self) -> None:
        self.build_manifest(source_state="dirty")

        result = installed_provenance.verify_installation(
            marker_path=self.marker_path,
            manifest_path=self.manifest_path,
            installed_root=self.installed_root,
        )

        self.assertEqual(result["status"], "tree_verified_source_unattributed")
        self.assertEqual(result["source_state"], "dirty")

    def test_modified_installed_file_is_rejected(self) -> None:
        self.build_manifest()
        (self.installed_root / "daemon" / "main.py").write_text("VALUE = 2\n", encoding="utf-8")

        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "installed runtime tree differs"):
            installed_provenance.verify_installation(
                marker_path=self.marker_path,
                manifest_path=self.manifest_path,
                installed_root=self.installed_root,
            )

    def test_added_installed_file_is_rejected(self) -> None:
        self.build_manifest()
        (self.installed_root / "daemon" / "injected.py").write_text("INJECTED = True\n", encoding="utf-8")

        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "installed runtime tree differs"):
            installed_provenance.verify_installation(
                marker_path=self.marker_path,
                manifest_path=self.manifest_path,
                installed_root=self.installed_root,
            )

    def test_changed_deployed_wrapper_is_rejected(self) -> None:
        self.build_manifest()
        self.daemon_wrapper.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")

        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "deployed runtime files differ"):
            installed_provenance.verify_installation(
                marker_path=self.marker_path,
                manifest_path=self.manifest_path,
                installed_root=self.installed_root,
            )

    def test_prepublication_deployment_tamper_is_rejected(self) -> None:
        expected = {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.deployment_paths
        }
        self.daemon_wrapper.write_text("#!/bin/sh\nexit 4\n", encoding="utf-8")
        identity = installed_provenance.SourceIdentity(commit="b" * 40, state="clean")

        with patch.object(installed_provenance, "source_identity", return_value=identity):
            with self.assertRaisesRegex(installed_provenance.ProvenanceError, "expected generation"):
                installed_provenance.build_manifest(
                    source_root=self.source_root,
                    installed_root=self.installed_root,
                    includes=("daemon", "tools"),
                    deployment_paths=self.deployment_paths,
                    expected_deployment_sha256=expected,
                    installed_at="2026-08-11T00:00:00Z",
                )

    def test_changed_deployed_unit_is_rejected(self) -> None:
        self.build_manifest()
        self.daemon_unit.write_text("[Service]\nExecStart=/bin/false\n", encoding="utf-8")

        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "deployed runtime files differ"):
            installed_provenance.verify_installation(
                marker_path=self.marker_path,
                manifest_path=self.manifest_path,
                installed_root=self.installed_root,
            )

    def test_deployed_file_replacement_during_hash_is_rejected(self) -> None:
        original_hash = installed_provenance._sha256_open_fd

        def replace_after_hash(
            fd: int,
            path: Path,
        ) -> tuple[str, int, int, int, int, int, int]:
            result = original_hash(fd, path)
            replacement = self.root / "replacement-wrapper"
            replacement.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
            os.replace(replacement, self.daemon_wrapper)
            return result

        with patch.object(installed_provenance, "_sha256_open_fd", side_effect=replace_after_hash):
            with self.assertRaisesRegex(installed_provenance.ProvenanceError, "changed while hashing set"):
                installed_provenance._collect_deployment(self.daemon_wrapper)

    def test_deployment_set_holds_all_files_until_final_validation(self) -> None:
        original_hash = installed_provenance._sha256_open_fd
        calls = 0

        def replace_first_while_hashing_second(
            fd: int,
            path: Path,
        ) -> tuple[str, int, int, int, int, int, int]:
            nonlocal calls
            calls += 1
            result = original_hash(fd, path)
            if calls == 2:
                replacement = self.root / "replacement-first"
                replacement.write_text("changed set member\n", encoding="utf-8")
                os.replace(replacement, self.daemon_wrapper)
            return result

        with patch.object(
            installed_provenance,
            "_sha256_open_fd",
            side_effect=replace_first_while_hashing_second,
        ):
            with self.assertRaisesRegex(installed_provenance.ProvenanceError, "changed while hashing set"):
                installed_provenance.collect_deployments(self.deployment_paths)

    def test_changed_runtime_directory_mode_is_rejected(self) -> None:
        self.build_manifest()
        (self.installed_root / "daemon").chmod(0o777)

        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "installed runtime tree differs"):
            installed_provenance.verify_installation(
                marker_path=self.marker_path,
                manifest_path=self.manifest_path,
                installed_root=self.installed_root,
            )

    def test_changed_runtime_root_mode_is_rejected(self) -> None:
        self.build_manifest()
        self.installed_root.chmod(0o777)

        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "runtime root metadata differs"):
            installed_provenance.verify_installation(
                marker_path=self.marker_path,
                manifest_path=self.manifest_path,
                installed_root=self.installed_root,
            )

    def test_insecure_installed_metadata_refuses_publication(self) -> None:
        (self.installed_root / "daemon").chmod(0o777)
        identity = installed_provenance.SourceIdentity(commit="b" * 40, state="clean")

        with patch.object(installed_provenance, "source_identity", return_value=identity):
            with self.assertRaisesRegex(installed_provenance.ProvenanceError, "writable by group or others"):
                installed_provenance.build_manifest(
                    source_root=self.source_root,
                    installed_root=self.installed_root,
                    includes=("daemon", "tools"),
                    deployment_paths=self.deployment_paths,
                    installed_at="2026-08-11T00:00:00Z",
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                )

    def test_publication_rejects_generation_changed_after_daemon_smoke(self) -> None:
        approved_generation = installed_provenance.fingerprint_generation(
            self.installed_root,
            self.deployment_paths,
        )
        (self.installed_root / "daemon" / "main.py").chmod(0o600)
        identity = installed_provenance.SourceIdentity(commit="b" * 40, state="clean")

        with patch.object(installed_provenance, "source_identity", return_value=identity):
            with self.assertRaisesRegex(installed_provenance.ProvenanceError, "daemon-approved smoke digest"):
                installed_provenance.build_manifest(
                    source_root=self.source_root,
                    installed_root=self.installed_root,
                    includes=("daemon", "tools"),
                    deployment_paths=self.deployment_paths,
                    expected_generation_sha256=approved_generation,
                    installed_at="2026-08-11T00:00:00Z",
                )

    def test_source_and_installed_tree_must_match_before_publication(self) -> None:
        (self.installed_root / "tools" / "helper.py").write_text("HELPER = 2\n", encoding="utf-8")
        identity = installed_provenance.SourceIdentity(commit="b" * 40, state="clean")

        with patch.object(installed_provenance, "source_identity", return_value=identity):
            with self.assertRaisesRegex(installed_provenance.ProvenanceError, "source and installed runtime differ"):
                installed_provenance.build_manifest(
                    source_root=self.source_root,
                    installed_root=self.installed_root,
                    includes=("daemon", "tools"),
                    deployment_paths=self.deployment_paths,
                    installed_at="2026-08-11T00:00:00Z",
                )

    def test_runtime_include_replacement_during_hash_is_rejected(self) -> None:
        target = self.source_root / "daemon" / "main.py"
        original_hash = installed_provenance._sha256_file

        def replace_after_hash(
            path: Path,
            *,
            dir_fd: int | None = None,
            name: str | None = None,
        ) -> tuple[str, int, int, int, int, int, int]:
            result = original_hash(path, dir_fd=dir_fd, name=name)
            if path == target:
                replacement = self.root / "replacement-main.py"
                replacement.write_text("VALUE = 9\n", encoding="utf-8")
                os.replace(replacement, target)
            return result

        with patch.object(installed_provenance, "_sha256_file", side_effect=replace_after_hash):
            with self.assertRaisesRegex(installed_provenance.ProvenanceError, "replaced while hashing"):
                installed_provenance.collect_tree(
                    self.source_root,
                    ("daemon", "tools"),
                    exclude_python_cache=True,
                )

    def test_manifest_tamper_is_rejected_by_marker_digest(self) -> None:
        self.build_manifest()
        data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        data["source_commit"] = "b" * 40
        self.manifest_path.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "manifest digest differs"):
            installed_provenance.verify_installation(
                marker_path=self.marker_path,
                manifest_path=self.manifest_path,
                installed_root=self.installed_root,
            )

    def test_python_cache_in_installed_runtime_changes_fingerprint_and_fails_verification(self) -> None:
        self.build_manifest()
        cache_dir = self.installed_root / "daemon" / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "main.cpython-313.pyc").write_bytes(b"dynamic")

        first = installed_provenance.fingerprint_tree(self.installed_root)
        (cache_dir / "main.cpython-313.pyc").write_bytes(b"changed")
        second = installed_provenance.fingerprint_tree(self.installed_root)

        self.assertNotEqual(first, second)
        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "installed runtime tree differs"):
            installed_provenance.verify_installation(
                marker_path=self.marker_path,
                manifest_path=self.manifest_path,
                installed_root=self.installed_root,
            )

    def test_unsafe_include_is_rejected(self) -> None:
        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "unsafe include path"):
            installed_provenance.build_manifest(
                source_root=self.source_root,
                installed_root=self.installed_root,
                includes=("../outside",),
                installed_at="2026-08-11T00:00:00Z",
            )

    def test_symlink_outside_runtime_tree_is_rejected(self) -> None:
        (self.installed_root / "daemon" / "escape.py").symlink_to("../../../escape.py")

        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "symlink escapes"):
            installed_provenance.fingerprint_tree(self.installed_root)

    def test_daemon_digest_must_match_installed_manifest(self) -> None:
        manifest = self.build_manifest()
        status_payload = {
            "ok": True,
            "payload": {
                "state": {"status": "standby"},
                "runtime_provenance": {
                    "status": "captured",
                    "generation_sha256": manifest["generation_sha256"],
                },
            },
        }

        result = installed_provenance.verify_daemon_status(
            status_payload=status_payload,
            manifest_path=self.manifest_path,
        )

        self.assertEqual(result["status"], "verified")

    def test_daemon_digest_mismatch_is_rejected(self) -> None:
        self.build_manifest()
        status_payload = {
            "ok": True,
            "payload": {
                "runtime_provenance": {
                    "status": "captured",
                    "generation_sha256": "f" * 64,
                },
            },
        }

        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "daemon generation digest differs"):
            installed_provenance.verify_daemon_status(
                status_payload=status_payload,
                manifest_path=self.manifest_path,
            )

    def test_running_generation_must_match_current_installed_files(self) -> None:
        digest = installed_provenance.fingerprint_generation(
            self.installed_root,
            self.deployment_paths,
        )
        status_payload = {
            "payload": {
                "runtime_provenance": {
                    "status": "captured",
                    "generation_sha256": digest,
                }
            }
        }

        result = installed_provenance.verify_running_generation(
            status_payload=status_payload,
            runtime_root=self.installed_root,
            deployment_paths=self.deployment_paths,
        )
        self.assertEqual(result["generation_sha256"], digest)

        self.daemon_wrapper.write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(installed_provenance.ProvenanceError, "differs from current"):
            installed_provenance.verify_running_generation(
                status_payload=status_payload,
                runtime_root=self.installed_root,
                deployment_paths=self.deployment_paths,
            )

    def test_process_identity_rejects_invalid_environment_digest(self) -> None:
        with patch.dict(
            os.environ,
            {installed_provenance.RUNTIME_GENERATION_SHA256_ENV: "invalid"},
            clear=False,
        ):
            identity = installed_provenance.process_runtime_identity()

        self.assertEqual(identity["status"], "unavailable")
        self.assertNotIn("generation_sha256", identity)

    def test_process_identity_recomputes_generation_before_capture(self) -> None:
        digest = "a" * 64
        with patch.dict(
            os.environ,
            {installed_provenance.RUNTIME_GENERATION_SHA256_ENV: digest},
            clear=False,
        ):
            with patch.object(installed_provenance, "fingerprint_generation", return_value=digest):
                identity = installed_provenance.process_runtime_identity()

        self.assertEqual(identity, {"status": "captured", "generation_sha256": digest})

    def test_launch_daemon_parser_preserves_daemon_arguments(self) -> None:
        args = installed_provenance._build_parser().parse_args(
            [
                "launch-daemon",
                "--runtime-root",
                str(self.installed_root),
                "--deployment",
                str(self.daemon_wrapper),
                "--",
                "--standalone",
                "--socket-path",
                "/tmp/control.sock",
            ]
        )

        self.assertEqual(args.command, "launch-daemon")
        self.assertEqual(
            args.daemon_args,
            ["--", "--standalone", "--socket-path", "/tmp/control.sock"],
        )

    def test_daemon_launcher_fingerprints_before_and_after_import(self) -> None:
        with patch.object(
            installed_provenance,
            "fingerprint_generation",
            side_effect=["a" * 64, "a" * 64],
        ) as fingerprint:
            with patch("daemon.main.main", return_value=7) as daemon_main:
                result = installed_provenance.launch_daemon(
                    self.installed_root,
                    self.deployment_paths,
                    ("--standalone",),
                )

        self.assertEqual(result, 7)
        self.assertEqual(fingerprint.call_count, 2)
        daemon_main.assert_called_once_with(["--standalone"])

    def test_daemon_launcher_rejects_generation_change_during_import(self) -> None:
        with patch.object(
            installed_provenance,
            "fingerprint_generation",
            side_effect=["a" * 64, "b" * 64],
        ):
            with patch("daemon.main.main") as daemon_main:
                with self.assertRaisesRegex(installed_provenance.ProvenanceError, "changed while importing"):
                    installed_provenance.launch_daemon(
                        self.installed_root,
                        self.deployment_paths,
                        (),
                    )

        daemon_main.assert_not_called()

    def test_real_git_checkout_attributes_only_clean_tracked_source(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.source_root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.source_root), "config", "user.name", "Provenance Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.source_root), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", str(self.source_root), "add", "daemon", "tools"], check=True)
        subprocess.run(
            ["git", "-C", str(self.source_root), "commit", "-q", "-m", "test provenance"],
            check=True,
        )

        manifest = installed_provenance.build_manifest(
            source_root=self.source_root,
            installed_root=self.installed_root,
            includes=("daemon", "tools"),
            deployment_paths=self.deployment_paths,
            installed_at="2026-08-11T00:00:00Z",
        )
        self.assertEqual(manifest["source_state"], "clean")

        (self.source_root / "daemon" / "main.py").write_text("VALUE = 2\n", encoding="utf-8")
        (self.installed_root / "daemon" / "main.py").write_text("VALUE = 2\n", encoding="utf-8")
        dirty_manifest = installed_provenance.build_manifest(
            source_root=self.source_root,
            installed_root=self.installed_root,
            includes=("daemon", "tools"),
            deployment_paths=self.deployment_paths,
            installed_at="2026-08-11T00:00:00Z",
        )
        self.assertEqual(dirty_manifest["source_state"], "dirty")


if __name__ == "__main__":
    unittest.main()
