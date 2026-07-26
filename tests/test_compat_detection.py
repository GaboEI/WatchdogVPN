"""L1 tests for Phase 23.7.5.4 read-only detection and capabilities."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import stat
from datetime import datetime
from pathlib import Path
from unittest import mock

from compat import detection
from compat.support_model import CoreCapabilityStatus, ProtocolRuntimeStatus


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "compat_probe.py"


def product_manifest():
    return detection.load_product_manifest()


def osr(text: str) -> detection.OsReleaseData:
    return detection.parse_os_release_text(text.strip() + "\n")


def facts(manifest, text: str) -> detection.DistroFacts:
    return detection.distro_facts_from_os_release(
        osr(text),
        manifest,
        kernel_release="6.8.0-test",
        machine_architecture="x86_64",
    )


def fixture_env(*, runner=None, files=None, paths=None, py=(3, 11, 0)):
    env = detection.ProbeEnvironment(
        runner=runner or detection.FakeCommandRunner(),
        files=files or {},
        existing_paths=paths or set(),
        machine_architecture="x86_64",
        kernel_release="6.8.0-test",
        python_version=py,
        allow_host_fallback=False,
    )
    env.manifest = product_manifest()
    return env


class OsReleaseParserTests(unittest.TestCase):
    def test_valid_quoting_and_ordered_id_like(self) -> None:
        parsed = osr(
            """
            ID=ubuntu
            ID_LIKE="debian ubuntu"
            PRETTY_NAME='Ubuntu 24.04 LTS'
            VERSION_CODENAME=noble
            """
        )
        self.assertEqual(parsed.values["PRETTY_NAME"], "Ubuntu 24.04 LTS")
        manifest = product_manifest()
        distro = detection.distro_facts_from_os_release(
            parsed,
            manifest,
            kernel_release="6.8.0-test",
            machine_architecture="x86_64",
        )
        self.assertEqual(distro.id_like_ordered, ("debian", "ubuntu"))

    def test_rejects_malformed_duplicate_bad_escape_and_empty_key_value_cases(self) -> None:
        bad_inputs = [
            "ID=ubuntu\nID=debian\n",
            "ID ubuntu\n",
            "id=ubuntu\n",
            'ID="unterminated\n',
            r'ID="bad\n"',
            "ID=ubuntu linux\n",
        ]
        for text in bad_inputs:
            with self.subTest(text=text):
                with self.assertRaises(detection.DetectionError):
                    detection.parse_os_release_text(text)
        self.assertEqual(detection.parse_os_release_text("ID=\n").values["ID"], "")

    def test_rejects_command_and_variable_expansion_without_running_it(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "watchdogvpn-pwn"
            for text in (
                "ID=$(touch %s)\n" % marker,
                "ID=`touch %s`\n" % marker,
                "ID=$HOME\n",
                'ID="$(touch %s)"\n' % marker,
                'ID="`touch %s`"\n' % marker,
                'ID="$HOME"\n',
            ):
                with self.subTest(text=text):
                    with self.assertRaises(detection.DetectionError):
                        detection.parse_os_release_text(text)
            self.assertFalse(marker.exists())

    def test_read_os_release_fallback_symlink_limits_and_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            base = Path(tempdir)
            etc = base / "etc-os-release"
            usr = base / "usr-os-release"
            with self.assertRaises(detection.DetectionError):
                detection.read_os_release(etc_path=etc, usr_path=usr)
            usr.write_text("ID=debian\nVERSION_ID=13\n", encoding="utf-8")
            self.assertEqual(detection.read_os_release(etc_path=etc, usr_path=usr).values["ID"], "debian")

            etc.symlink_to(usr)
            self.assertEqual(detection.read_os_release(etc_path=etc, usr_path=usr).values["ID"], "debian")
            etc.unlink()
            outside = base / "outside"
            outside.write_text("ID=ubuntu\n", encoding="utf-8")
            etc.symlink_to(outside)
            with self.assertRaises(detection.DetectionError):
                detection.read_os_release(etc_path=etc, usr_path=usr)

            etc.unlink()
            etc.write_bytes(b"\xff")
            with self.assertRaises(detection.DetectionError):
                detection.read_os_release(etc_path=etc, usr_path=usr)
            etc.write_bytes(b" " * (detection.MAX_OS_RELEASE_BYTES + 1))
            with self.assertRaises(detection.DetectionError):
                detection.read_os_release(etc_path=etc, usr_path=usr)
            etc.unlink()
            etc.mkdir()
            with self.assertRaises(detection.DetectionError):
                detection.read_os_release(etc_path=etc, usr_path=usr)
            etc.rmdir()
            broken = base / "missing-target"
            etc.symlink_to(broken)
            with self.assertRaises(detection.DetectionError):
                detection.read_os_release(etc_path=etc, usr_path=usr)

            etc.unlink()
            etc.write_text("ID=ubuntu\n", encoding="utf-8")
            os.chmod(etc, 0)
            try:
                with self.assertRaises(detection.DetectionError):
                    detection.read_os_release(etc_path=etc, usr_path=usr)
            finally:
                os.chmod(etc, stat.S_IRUSR | stat.S_IWUSR)

    def test_read_os_release_cli_error_has_exit_2_without_traceback(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("ID=$(touch /tmp/watchdogvpn-pwn)\n")
            handle.flush()
            result = subprocess.run(
                [sys.executable, str(TOOL), "--os-release", handle.name, "detect"],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("error:", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_read_os_release_atomic_descriptor_errors_are_detection_errors(self) -> None:
        good_stat = os.stat_result((stat.S_IFREG | 0o644, 1, 10, 1, 1000, 1000, 8, 0, 0, 0))
        changed_stat = os.stat_result((stat.S_IFREG | 0o644, 2, 10, 1, 1000, 1000, 8, 0, 0, 0))
        dir_stat = os.stat_result((stat.S_IFDIR | 0o755, 1, 10, 1, 1000, 1000, 8, 0, 0, 0))
        path = Path("/tmp/watchdogvpn-os-release")
        cases = (
            {"name": "os.open", "open": OSError("open failed"), "fstat": good_stat, "read": b"ID=ubuntu\n"},
            {"name": "fstat", "open": 3, "fstat": OSError("fstat failed"), "read": b"ID=ubuntu\n"},
            {"name": "read", "open": 3, "fstat": good_stat, "read": OSError("read failed")},
            {"name": "inode", "open": 3, "fstat": changed_stat, "read": b"ID=ubuntu\n"},
            {"name": "nonregular", "open": 3, "fstat": dir_stat, "read": b"ID=ubuntu\n"},
        )
        for case in cases:
            with self.subTest(name=case["name"]):
                with mock.patch.object(Path, "stat", return_value=good_stat), \
                    mock.patch("compat.detection.os.open", side_effect=case["open"] if isinstance(case["open"], OSError) else None, return_value=case["open"] if not isinstance(case["open"], OSError) else mock.DEFAULT), \
                    mock.patch("compat.detection.os.fstat", side_effect=case["fstat"] if isinstance(case["fstat"], OSError) else None, return_value=case["fstat"] if not isinstance(case["fstat"], OSError) else mock.DEFAULT), \
                    mock.patch("compat.detection.os.read", side_effect=case["read"] if isinstance(case["read"], OSError) else None, return_value=case["read"] if not isinstance(case["read"], OSError) else mock.DEFAULT), \
                    mock.patch("compat.detection.os.close"):
                    with self.assertRaises(detection.DetectionError):
                        detection._read_regular_file_atomically(path)

    def test_read_os_release_resolve_errors_are_detection_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            base = Path(tempdir)
            etc = base / "etc-os-release"
            usr = base / "usr-os-release"
            etc.write_text("ID=ubuntu\n", encoding="utf-8")
            usr.write_text("ID=ubuntu\n", encoding="utf-8")
            original = Path.resolve

            def failing_usr_resolve(path, *args, **kwargs):
                if path == usr:
                    raise OSError("resolve failed")
                return original(path, *args, **kwargs)

            with mock.patch.object(Path, "resolve", failing_usr_resolve):
                with self.assertRaises(detection.DetectionError):
                    detection.read_os_release(etc_path=etc, usr_path=usr)


class DistributionResolutionTests(unittest.TestCase):
    FIXTURES = {
        "arch": ('ID=arch\nID_LIKE=arch\n', "arch", None, "certified"),
        "cachyos": ('ID=cachyos\nID_LIKE="arch"\n', "cachyos", None, "certified"),
        "debian": ('ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n', "debian", "debian_13", "certified"),
        "fedora": ("ID=fedora\nVERSION_ID=44\n", "fedora", "fedora_44", "certified"),
        "rocky": ("ID=rocky\nVERSION_ID=9\n", "rocky", "rocky_9", "certified"),
        "ubuntu_24": ("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "ubuntu", "ubuntu_24_04", "certified"),
        "mint": (
            "ID=linuxmint\nID_LIKE=ubuntu\nVERSION_ID=22.3\nVERSION_CODENAME=zena\nUBUNTU_CODENAME=zena\n",
            "linuxmint",
            "linuxmint_22_3",
            "certified",
        ),
        "leap": ("ID=opensuse-leap\nVERSION_ID=15.6\n", "opensuse_leap", "opensuse_leap_15_6", "certified"),
        "alma": ("ID=almalinux\nVERSION_ID=9\n", "almalinux", "almalinux_9", "family_inferred"),
        "centos": ("ID=centos\nVERSION_ID=9\nPRETTY_NAME=\"CentOS Stream 9\"\n", "centos_stream", "centos_stream_9", "family_inferred"),
        "rhel": ("ID=rhel\nVERSION_ID=9\n", "rhel", "rhel_9", "family_inferred"),
        "tumbleweed": ("ID=opensuse-tumbleweed\nID_LIKE=opensuse\n", "opensuse_tumbleweed", None, "family_inferred"),
        "kali": ("ID=kali\nID_LIKE=debian\nVERSION_ID=2026.2\n", "kali", None, "experimental"),
        "ubuntu_26": ("ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n", "ubuntu", "ubuntu_26_04", "experimental"),
    }

    def test_productive_fixtures_derive_expected_classifications(self) -> None:
        manifest = product_manifest()
        for name, (text, distro_id, release_id, expected) in self.FIXTURES.items():
            with self.subTest(name=name):
                distro = facts(manifest, text)
                self.assertEqual(distro.resolved_distribution, distro_id)
                self.assertEqual(distro.resolved_release, release_id)
                report = detection.evaluate(manifest, distro, ready_core(manifest, distro), present_protocols(manifest), now=datetime(2026, 7, 26))
                self.assertEqual(report.support_classification, expected)

    def test_mint_requires_exact_codename_mapping(self) -> None:
        manifest = product_manifest()
        distro = facts(
            manifest,
            "ID=linuxmint\nVERSION_ID=22.3\nVERSION_CODENAME=unknown\nUBUNTU_CODENAME=unknown\n",
        )
        self.assertEqual(distro.resolution_status, "derivative_mapping_unknown")
        self.assertIsNone(distro.resolved_release)

    def test_kali_and_cachyos_do_not_borrow_parent_versions(self) -> None:
        manifest = product_manifest()
        kali = facts(manifest, "ID=kali\nID_LIKE=debian\nVERSION_ID=13\n")
        cachy = facts(manifest, "ID=cachyos\nID_LIKE=arch\nVERSION_ID=999\n")
        self.assertEqual(kali.release_model, "rolling")
        self.assertIsNone(kali.resolved_release)
        self.assertEqual(cachy.release_model, "rolling")
        self.assertIsNone(cachy.resolved_release)

    def test_known_distribution_unknown_release_is_experimental(self) -> None:
        manifest = product_manifest()
        distro = facts(manifest, "ID=ubuntu\nVERSION_ID=25.04\nVERSION_CODENAME=plucky\n")
        self.assertEqual(distro.resolution_status, "release_unknown")
        report = detection.evaluate(manifest, distro, ready_core(manifest, distro), present_protocols(manifest), now=datetime(2026, 7, 26))
        self.assertEqual(report.support_classification, "experimental")

    def test_stable_release_identity_requires_anchor_consensus(self) -> None:
        manifest = product_manifest()
        cases = (
            ("ID=ubuntu\nVERSION_ID=99.99\nVERSION_CODENAME=noble\n", "release_identity_conflict"),
            ("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=incorrecto\n", "release_identity_conflict"),
            ("ID=linuxmint\nVERSION_ID=99\nVERSION_CODENAME=zena\nUBUNTU_CODENAME=zena\n", "release_identity_conflict"),
        )
        for text, expected_status in cases:
            with self.subTest(text=text):
                distro = facts(manifest, text)
                self.assertEqual(distro.resolution_status, expected_status)
                self.assertIsNone(distro.resolved_release)
                self.assertTrue(distro.identity_conflicts)
                report = detection.evaluate(manifest, distro, ready_core(manifest, distro), present_protocols(manifest), now=datetime(2026, 7, 26))
                self.assertEqual(report.support_classification, "unsupported")

    def test_stable_release_identity_allows_single_exact_anchor(self) -> None:
        manifest = product_manifest()
        by_version = facts(manifest, "ID=ubuntu\nVERSION_ID=24.04\n")
        self.assertEqual(by_version.resolved_release, "ubuntu_24_04")
        by_codename = facts(manifest, "ID=ubuntu\nVERSION_CODENAME=noble\n")
        self.assertEqual(by_codename.resolved_release, "ubuntu_24_04")
        self.assertEqual(by_codename.identity_evidence["version_codename"], "ubuntu_24_04")

    def test_mint_mapping_is_preserved_and_conflicts_are_explicit(self) -> None:
        manifest = product_manifest()
        mint = facts(manifest, "ID=linuxmint\nVERSION_ID=22.3\nVERSION_CODENAME=zena\nUBUNTU_CODENAME=zena\n")
        self.assertEqual(mint.resolved_release, "linuxmint_22_3")
        self.assertEqual(mint.mapped_base_release, "ubuntu_24_04")
        self.assertEqual(mint.identity_evidence["derivative_mapping"], "ubuntu_24_04")

        unknown = facts(manifest, "ID=linuxmint\nVERSION_ID=22.3\nVERSION_CODENAME=unknown\nUBUNTU_CODENAME=unknown\n")
        self.assertEqual(unknown.resolution_status, "derivative_mapping_unknown")

        mutated = json.loads(json.dumps(manifest))
        mutated["derivatives"]["linuxmint_ubuntu_codename"]["codename_map"]["zena"] = "ubuntu_26_04"
        conflict = facts(mutated, "ID=linuxmint\nVERSION_ID=22.3\nVERSION_CODENAME=zena\nUBUNTU_CODENAME=zena\n")
        self.assertEqual(conflict.resolution_status, "release_identity_conflict")
        self.assertEqual(conflict.mapped_base_release, "ubuntu_26_04")

    def test_identity_conflict_cli_reports_json_without_promotion(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("ID=ubuntu\nVERSION_ID=99.99\nVERSION_CODENAME=noble\n")
            handle.flush()
            result = subprocess.run(
                [sys.executable, str(TOOL), "--os-release", handle.name, "--fixture-host", "evaluate"],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["distro_facts"]["resolution_status"], "release_identity_conflict")
            self.assertEqual(payload["support_classification"], "unsupported")
            self.assertNotIn("Traceback", result.stderr)

    def test_unknown_id_like_preserves_family_but_not_distribution_support(self) -> None:
        manifest = product_manifest()
        distro = facts(manifest, "ID=unknownos\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=24.04\n")
        self.assertIsNone(distro.resolved_distribution)
        self.assertEqual(distro.technical_family, "ubuntu_apt")
        report = detection.evaluate(manifest, distro, ready_core(manifest, distro), present_protocols(manifest), now=datetime(2026, 7, 26))
        self.assertEqual(report.support_classification, "unsupported")


class CapabilityProbeTests(unittest.TestCase):
    def test_core_capabilities_are_complete_and_never_empty(self) -> None:
        manifest = product_manifest()
        distro = facts(manifest, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        env = fixture_env(
            runner=detection.FakeCommandRunner(
                {
                    ("apt-get", "--version"): detection.CommandResult(("apt-get", "--version"), "ok", 0, "apt\n", ""),
                    ("sudo", "-V"): detection.CommandResult(("sudo", "-V"), "ok", 0, "sudo\n", ""),
                    ("pkaction", "--version"): detection.CommandResult(("pkaction", "--version"), "ok", 0, "polkit\n", ""),
                    ("nmcli", "-t", "-f", "RUNNING", "general"): detection.CommandResult(("nmcli", "-t", "-f", "RUNNING", "general"), "ok", 0, "running\n", ""),
                    ("nft", "--version"): detection.CommandResult(("nft", "--version"), "ok", 0, "nft\n", ""),
                    ("ip", "rule", "show"): detection.CommandResult(("ip", "rule", "show"), "ok", 0, "0: from all lookup local\n", ""),
                }
            ),
            files={"/proc/1/comm": "systemd\n", "/etc/resolv.conf": "# systemd-resolved\n"},
            paths={"/dev/net/tun"},
        )
        results = detection.probe_core_capabilities(manifest, distro, env)
        by_id = {item.capability_id: item for item in results}
        self.assertEqual(set(by_id), set(manifest["technical_families"]["ubuntu_apt"]["core_capabilities"]))
        self.assertEqual(by_id["cap_systemd"].domain_status, "present")
        self.assertEqual(by_id["cap_network_manager"].domain_status, "present")
        self.assertEqual(by_id["cap_kernel"].domain_status, "provisionable")
        self.assertEqual(by_id["cap_package_manager"].domain_status, "provisionable")
        self.assertEqual(by_id["cap_sudo"].domain_status, "provisionable")
        self.assertEqual(by_id["cap_polkit"].domain_status, "provisionable")
        self.assertEqual(by_id["cap_persistence"].domain_status, "provisionable")
        self.assertEqual(by_id["cap_rollback"].domain_status, "provisionable")
        self.assertEqual(by_id["cap_tun"].domain_status, "provisionable")
        self.assertEqual(by_id["cap_nftables"].domain_status, "provisionable")

    def test_command_errors_map_to_controlled_domain_results(self) -> None:
        cases = {
            "command_missing": CoreCapabilityStatus.PROVISIONABLE.value,
            "timeout": CoreCapabilityStatus.PROVISIONABLE.value,
            "permission_denied": CoreCapabilityStatus.PROVISIONABLE.value,
            "nonzero_exit": CoreCapabilityStatus.PROVISIONABLE.value,
            "malformed_output": CoreCapabilityStatus.PROVISIONABLE.value,
        }
        for status, expected in cases.items():
            with self.subTest(status=status):
                result = detection._command_cap("cap_sudo", detection.CommandResult(("sudo", "-V"), status, 1, "", "err"), "test")
                self.assertEqual(result.domain_status, expected)

    def test_python_arch_systemd_networkmanager_and_security_diagnostics(self) -> None:
        manifest = product_manifest()
        distro = facts(manifest, "ID=fedora\nVERSION_ID=44\n")
        inactive = fixture_env(
            runner=detection.FakeCommandRunner(
                {
                    ("nmcli", "-t", "-f", "RUNNING", "general"): detection.CommandResult(("nmcli", "-t", "-f", "RUNNING", "general"), "ok", 0, "stopped\n", ""),
                    ("getenforce",): detection.CommandResult(("getenforce",), "ok", 0, "Enforcing\n", ""),
                }
            ),
            files={"/proc/1/comm": "init\n"},
            py=(3, 9, 18),
        )
        self.assertEqual(detection._probe_core("cap_python310", distro, inactive).domain_status, "provisionable")
        self.assertEqual(detection._probe_core("cap_architecture", distro, inactive).domain_status, "present")
        self.assertEqual(detection._probe_core("cap_kernel", distro, inactive).domain_status, "provisionable")
        self.assertEqual(detection._probe_core("cap_systemd", distro, inactive).domain_status, "provisionable")
        self.assertEqual(detection._probe_core("cap_network_manager", distro, inactive).domain_status, "provisionable")
        self.assertEqual(detection._probe_core("cap_selinux", distro, inactive).domain_status, "present")
        self.assertEqual(detection._probe_core("cap_firewalld", distro, inactive).domain_status, "provisionable")
        self.assertEqual(detection._probe_core("cap_apparmor", distro, inactive).domain_status, "provisionable")
        distro_unknown_arch = detection.distro_facts_from_os_release(
            osr("ID=fedora\nVERSION_ID=44\n"),
            manifest,
            kernel_release="6.8.0-test",
            machine_architecture="mips",
        )
        self.assertEqual(detection._probe_core("cap_architecture", distro_unknown_arch, inactive).domain_status, "provisionable")

    def test_architecture_policy_comes_from_manifest(self) -> None:
        manifest = product_manifest()
        distro = detection.distro_facts_from_os_release(
            osr("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n"),
            manifest,
            kernel_release="6.8.0-test",
            machine_architecture="amd64",
        )
        env = fixture_env()
        env.manifest = manifest
        self.assertEqual(distro.machine_architecture, "x86_64")
        self.assertEqual(detection._probe_core("cap_architecture", distro, env).domain_status, "present")

        restricted = json.loads(json.dumps(manifest))
        restricted["capabilities"]["core_host_capabilities"]["cap_architecture"]["supported_values"] = ["aarch64"]
        env.manifest = restricted
        self.assertEqual(detection._probe_core("cap_architecture", distro, env).domain_status, "provisionable")

    def test_protocol_runtime_results_are_orthogonal(self) -> None:
        manifest = product_manifest()
        runner = detection.FakeCommandRunner(
            {
                ("sing-box", "version"): detection.CommandResult(("sing-box", "version"), "ok", 0, "sing-box\n", ""),
                ("openvpn", "--version"): detection.CommandResult(("openvpn", "--version"), "command_missing"),
                ("ck-client", "-v"): detection.CommandResult(("ck-client", "-v"), "command_missing"),
                ("awg", "--version"): detection.CommandResult(("awg", "--version"), "ok", 0, "awg\n", ""),
                ("amneziawg-go", "--version"): detection.CommandResult(("amneziawg-go", "--version"), "command_missing"),
            }
        )
        protocol_caps = detection.probe_protocol_capabilities(manifest, fixture_env(runner=runner))
        by_id = {item.capability_id: item for item in protocol_caps}
        self.assertEqual(by_id["proto_sing_box_runtime"].domain_status, ProtocolRuntimeStatus.PRESENT.value)
        self.assertEqual(by_id["proto_openvpn_runtime"].domain_status, ProtocolRuntimeStatus.PROVISIONABLE.value)
        self.assertEqual(by_id["proto_ck_client_runtime"].domain_status, ProtocolRuntimeStatus.PROVISIONABLE.value)
        self.assertEqual(by_id["proto_amneziawg_runtime"].domain_status, ProtocolRuntimeStatus.PROVISIONABLE.value)
        distro = facts(manifest, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        report = detection.evaluate(manifest, distro, ready_core(manifest, distro), protocol_caps, now=datetime(2026, 7, 26))
        self.assertEqual(report.host_readiness, "ready")
        self.assertEqual(report.protocol_readiness["vless"], "operable")
        self.assertEqual(report.protocol_readiness["amneziawg"], "provisionable")

    def test_permission_denied_is_provisionable_not_failed_or_impossible(self) -> None:
        manifest = product_manifest()
        distro = facts(manifest, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        denied = detection.CommandResult(("cmd",), "permission_denied", reason="denied")
        runner = detection.FakeCommandRunner(
            {
                ("sudo", "-V"): detection.CommandResult(("sudo", "-V"), "permission_denied", reason="denied"),
                ("apt-get", "--version"): detection.CommandResult(("apt-get", "--version"), "permission_denied", reason="denied"),
                ("nft", "--version"): detection.CommandResult(("nft", "--version"), "permission_denied", reason="denied"),
                ("openvpn", "--version"): detection.CommandResult(("openvpn", "--version"), "permission_denied", reason="denied"),
                ("sing-box", "version"): detection.CommandResult(("sing-box", "version"), "permission_denied", reason="denied"),
                ("ck-client", "-v"): detection.CommandResult(("ck-client", "-v"), "permission_denied", reason="denied"),
                ("awg", "--version"): detection.CommandResult(("awg", "--version"), "permission_denied", reason="denied"),
                ("amneziawg-go", "--version"): detection.CommandResult(("amneziawg-go", "--version"), "command_missing"),
            }
        )
        env = fixture_env(runner=runner)
        for cap_id in ("cap_sudo", "cap_package_manager", "cap_nftables"):
            with self.subTest(cap_id=cap_id):
                result = detection._probe_core(cap_id, distro, env)
                self.assertEqual(result.domain_status, "provisionable")
                self.assertEqual(result.error_kind, "permission_denied")
        protocol = {item.capability_id: item for item in detection.probe_protocol_capabilities(manifest, env)}
        for cap_id in ("proto_openvpn_runtime", "proto_sing_box_runtime", "proto_ck_client_runtime", "proto_amneziawg_runtime"):
            with self.subTest(cap_id=cap_id):
                self.assertEqual(protocol[cap_id].domain_status, "provisionable")
                self.assertNotEqual(protocol[cap_id].domain_status, "impossible")

    def test_evaluate_rejects_incomplete_or_invalid_core_contract(self) -> None:
        manifest = product_manifest()
        distro = facts(manifest, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        one_core = (detection.CapabilityResult("cap_systemd", "present", "present", "", "", ""),)
        for core in (
            (),
            one_core,
            ready_core(manifest, distro) + (detection.CapabilityResult("cap_systemd", "present", "present", "", "", ""),),
            ready_core(manifest, distro) + (detection.CapabilityResult("cap_not_real", "present", "present", "", "", ""),),
            tuple([detection.CapabilityResult("", "present", "present", "", "", "")] + list(ready_core(manifest, distro))[1:]),
            tuple([object()] + list(ready_core(manifest, distro))[1:]),
            tuple([detection.CapabilityResult("cap_systemd", "present", "bogus", "", "", "")] + list(ready_core(manifest, distro))[1:]),
        ):
            with self.subTest(core=core):
                with self.assertRaises(detection.DetectionError):
                    detection.evaluate(manifest, distro, core, present_protocols(manifest), now=datetime(2026, 7, 26))

    def test_evaluate_rejects_incomplete_or_invalid_protocol_contract(self) -> None:
        manifest = product_manifest()
        distro = facts(manifest, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        protocols = present_protocols(manifest)
        for proto in (
            (),
            protocols[:-1],
            protocols + (protocols[0],),
            protocols + (detection.CapabilityResult("proto_not_real", "present", "present", "", "", ""),),
            tuple([detection.CapabilityResult("proto_sing_box_runtime", "present", "bogus", "", "", "")] + list(protocols)[1:]),
        ):
            with self.subTest(proto=proto):
                with self.assertRaises(detection.DetectionError):
                    detection.evaluate(manifest, distro, ready_core(manifest, distro), proto, now=datetime(2026, 7, 26))

    def test_host_readiness_not_ready_with_partial_required_capabilities(self) -> None:
        manifest = product_manifest()
        distro = facts(manifest, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        env = fixture_env(files={"/proc/1/comm": "systemd\n"}, paths={"/dev/net/tun"})
        core = detection.probe_core_capabilities(manifest, distro, env)
        report = detection.evaluate(manifest, distro, core, present_protocols(manifest), now=datetime(2026, 7, 26))
        self.assertEqual(report.host_readiness, "needs_preparation")

    def test_capability_types_control_host_readiness_participation(self) -> None:
        manifest = product_manifest()
        distro = facts(manifest, "ID=fedora\nVERSION_ID=44\n")
        core = list(ready_core(manifest, distro))
        by_id = {cap.capability_id: index for index, cap in enumerate(core)}
        core[by_id["cap_selinux"]] = detection.CapabilityResult("cap_selinux", "unknown", "provisionable", "", "", "")
        report = detection.evaluate(manifest, distro, tuple(core), present_protocols(manifest), now=datetime(2026, 7, 26))
        self.assertEqual(report.host_readiness, "ready")

        mutated = json.loads(json.dumps(manifest))
        mutated["capabilities"]["core_host_capabilities"]["cap_optional_probe"] = {
            "type": "optional",
            "description": "optional probe",
        }
        mutated["technical_families"]["redhat_dnf"]["core_capabilities"].append("cap_optional_probe")
        distro_optional = facts(mutated, "ID=fedora\nVERSION_ID=44\n")
        optional_core = tuple(
            detection.CapabilityResult("cap_optional_probe", "absent", "provisionable", "", "", "")
            if cap.capability_id == "cap_optional_probe"
            else cap
            for cap in ready_core(mutated, distro_optional)
        )
        report = detection.evaluate(mutated, distro_optional, optional_core, present_protocols(mutated), now=datetime(2026, 7, 26))
        self.assertEqual(report.host_readiness, "ready")

        required_core = list(ready_core(manifest, distro))
        required_core[by_id["cap_kernel"]] = detection.CapabilityResult("cap_kernel", "partial", "provisionable", "", "", "")
        report = detection.evaluate(manifest, distro, tuple(required_core), present_protocols(manifest), now=datetime(2026, 7, 26))
        self.assertEqual(report.host_readiness, "needs_preparation")

        alt = json.loads(json.dumps(manifest))
        alt["capabilities"]["core_host_capabilities"]["cap_kernel"]["type"] = "alternative"
        with self.assertRaises(detection.DetectionError):
            detection.evaluate(alt, distro, ready_core(alt, distro), present_protocols(alt), now=datetime(2026, 7, 26))

    def test_fixture_without_host_fallback_does_not_observe_host_files(self) -> None:
        env = detection.ProbeEnvironment(
            runner=detection.FakeCommandRunner(),
            allow_host_fallback=False,
        )
        self.assertIsNone(env.read_file("/proc/modules"))
        self.assertIsNone(env.read_file("/sys/module/apparmor/parameters/enabled"))
        self.assertFalse(env.exists("/dev/net/tun"))


class ToolAndSecurityTests(unittest.TestCase):
    def test_internal_tool_outputs_deterministic_json_for_all_operations(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
            handle.flush()
            for command in ("detect", "capabilities", "evaluate", "report"):
                result = subprocess.run(
                    [sys.executable, str(TOOL), "--os-release", handle.name, "--fixture-host", command],
                    cwd=str(ROOT),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                json.loads(result.stdout)

    def test_internal_tool_reports_detection_errors_without_traceback(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("ID ubuntu\n")
            handle.flush()
            result = subprocess.run(
                [sys.executable, str(TOOL), "--os-release", handle.name, "detect"],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("error:", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_no_forbidden_execution_patterns_in_detection_layer(self) -> None:
        for path in (ROOT / "compat" / "detection.py", TOOL):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("shell" + "=True", text)
            self.assertNotRegex(text, r"\b" + "eval" + r"\s*\(")
            self.assertNotRegex(text, r"\b" + "exec" + r"\s*\(")
            self.assertNotRegex(text, r"\bos\." + "system" + r"\s*\(")
            self.assertNotRegex(text, r"(^|[;&|])\s*source\s+")
            mutators = (
                r"\bnft\s+" + "add" + r"\b",
                r"\bip\s+rule\s+" + "add" + r"\b",
                "nmcli connection " + "modify",
                "resolvectl " + "dns",
            )
            self.assertNotRegex(text, "|".join(mutators))

    def test_detect_current_accepts_injected_paths_env_and_clock(self) -> None:
        manifest = product_manifest()
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
            handle.flush()
            env = fixture_env(files={"/proc/1/comm": "systemd\n"})
            report = detection.detect_current(
                manifest=manifest,
                env=env,
                etc_os_release_path=Path(handle.name),
                usr_os_release_path=Path(handle.name),
                now_provider=lambda: datetime(2026, 7, 26),
            )
            self.assertEqual(report.distro_facts.resolved_distribution, "ubuntu")
            self.assertEqual(report.support_classification, "certified")

    def test_detect_current_rejects_invalid_clock(self) -> None:
        manifest = product_manifest()
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
            handle.flush()
            with self.assertRaises(detection.DetectionError):
                detection.detect_current(
                    manifest=manifest,
                    env=fixture_env(),
                    etc_os_release_path=Path(handle.name),
                    usr_os_release_path=Path(handle.name),
                    now_provider=lambda: "2026-07-26",
                )


class SafeCommandRunnerTests(unittest.TestCase):
    def test_runner_limits_output_and_marks_truncation(self) -> None:
        runner = detection.SafeCommandRunner(output_limit=8)
        result = runner.run([sys.executable, "-c", "import sys; sys.stdout.write('x'*100); sys.stderr.write('e'*100)"], timeout=5)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.stdout, "x" * 8)
        self.assertEqual(result.stderr, "e" * 8)
        self.assertTrue(result.stdout_truncated)
        self.assertTrue(result.stderr_truncated)

    def test_runner_timeout_missing_permission_invalid_stdout_stderr_and_nonzero(self) -> None:
        timeout = detection.SafeCommandRunner().run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.1)
        self.assertEqual(timeout.status, "timeout")
        missing = detection.SafeCommandRunner().run(["definitely-missing-watchdogvpn-command"], timeout=1)
        self.assertEqual(missing.status, "command_missing")
        streams = detection.SafeCommandRunner().run(
            [sys.executable, "-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"],
            timeout=5,
        )
        self.assertEqual(streams.stdout, "out")
        self.assertEqual(streams.stderr, "err")
        nonzero = detection.SafeCommandRunner().run([sys.executable, "-c", "import sys; sys.exit(7)"], timeout=5)
        self.assertEqual(nonzero.status, "nonzero_exit")
        invalid = detection.SafeCommandRunner().run([str(Path(tempfile.gettempdir()))], timeout=1)
        self.assertEqual(invalid.status, "invalid_executable")
        with mock.patch("compat.detection.shutil.which", side_effect=OSError("boom")):
            oserror = detection.SafeCommandRunner().run(["probe"], timeout=1)
        self.assertEqual(oserror.status, "unknown")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nexit 0\n")
            handle.flush()
            os.chmod(handle.name, stat.S_IRUSR | stat.S_IWUSR)
            permission = detection.SafeCommandRunner().run([handle.name], timeout=1)
            self.assertIn(permission.status, ("permission_denied", "unknown"))

    def test_runner_kills_child_process_group_on_timeout(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as marker:
            marker_path = marker.name
        os.unlink(marker_path)
        code = (
            "import os, subprocess, sys, time\n"
            "marker = sys.argv[1]\n"
            "subprocess.Popen([sys.executable, '-c', "
            "\"import pathlib, sys, time; time.sleep(1); pathlib.Path(sys.argv[1]).write_text('alive')\", marker])\n"
            "time.sleep(5)\n"
        )
        result = detection.SafeCommandRunner().run([sys.executable, "-c", code, marker_path], timeout=0.2)
        self.assertEqual(result.status, "timeout")
        import time as _time

        _time.sleep(1.3)
        self.assertFalse(Path(marker_path).exists())

    def test_runner_does_not_use_unbounded_temporary_files(self) -> None:
        layer_text = (ROOT / "compat" / "detection.py").read_text(encoding="utf-8")
        self.assertNotIn("TemporaryFile", layer_text)
        self.assertNotIn("tempfile", layer_text)


def ready_core(manifest, distro):
    return tuple(
        detection.CapabilityResult(cap_id, "present", "present", "fixture", "fixture", "fixture")
        for cap_id in manifest["technical_families"][distro.technical_family]["core_capabilities"]
    )


def present_protocols(manifest):
    return tuple(
        detection.CapabilityResult(cap_id, "present", "present", "fixture", "fixture", "fixture")
        for cap_id in manifest["capabilities"]["protocol_capabilities"]
    )


if __name__ == "__main__":
    unittest.main()
