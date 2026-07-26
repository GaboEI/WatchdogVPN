"""L1 tests for Phase 23.7.5.4 read-only detection and capabilities."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

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
    return detection.ProbeEnvironment(
        runner=runner or detection.FakeCommandRunner(),
        files=files or {},
        existing_paths=paths or set(),
        machine_architecture="x86_64",
        kernel_release="6.8.0-test",
        python_version=py,
    )


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
        self.assertEqual(by_id["cap_tun"].domain_status, "provisionable")
        self.assertEqual(by_id["cap_nftables"].domain_status, "provisionable")

    def test_command_errors_map_to_controlled_domain_results(self) -> None:
        cases = {
            "command_missing": CoreCapabilityStatus.PROVISIONABLE.value,
            "timeout": CoreCapabilityStatus.PROVISIONABLE.value,
            "permission_denied": CoreCapabilityStatus.PREPARATION_FAILED.value,
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
        self.assertEqual(detection._probe_core("cap_systemd", distro, inactive).domain_status, "provisionable")
        self.assertEqual(detection._probe_core("cap_network_manager", distro, inactive).domain_status, "provisionable")
        self.assertEqual(detection._probe_core("cap_selinux", distro, inactive).domain_status, "present")
        self.assertEqual(detection._probe_core("cap_firewalld", distro, inactive).domain_status, "present")
        self.assertEqual(detection._probe_core("cap_apparmor", distro, inactive).domain_status, "present")
        distro_unknown_arch = detection.distro_facts_from_os_release(
            osr("ID=fedora\nVERSION_ID=44\n"),
            manifest,
            kernel_release="6.8.0-test",
            machine_architecture="mips",
        )
        self.assertEqual(detection._probe_core("cap_architecture", distro_unknown_arch, inactive).domain_status, "provisionable")

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
