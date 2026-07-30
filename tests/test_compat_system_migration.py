"""L1 coherency tests for Task 23.7.5.7 system migration.

Verifies that lib/distro.sh stays aligned with the manifest+engine output from
tools/compat_distro_classify.py, and that the pure-Bash fallback never reclaims
support decisions when the engine is unavailable.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
from pathlib import Path
from typing import Mapping

import unittest


ROOT_DIR = Path(__file__).resolve().parents[1]
LIB_DISTRO_SH = ROOT_DIR / "lib" / "distro.sh"
CLASSIFY = ROOT_DIR / "tools" / "compat_distro_classify.py"


FIXTURES: Mapping[str, str] = {
    "arch": textwrap.dedent(
        '''\
        ID=arch
        PRETTY_NAME="Arch Linux"
        '''
    ),
    "cachyos": textwrap.dedent(
        '''\
        ID=cachyos
        ID_LIKE="arch"
        PRETTY_NAME="CachyOS"
        '''
    ),
    "ubuntu_24_04": textwrap.dedent(
        '''\
        ID=ubuntu
        PRETTY_NAME="Ubuntu 24.04 LTS"
        VERSION_ID="24.04"
        VERSION_CODENAME=noble
        UBUNTU_CODENAME=noble
        '''
    ),
    "ubuntu_26_04": textwrap.dedent(
        '''\
        ID=ubuntu
        PRETTY_NAME="Ubuntu 26.04 LTS"
        VERSION_ID="26.04"
        VERSION_CODENAME=resolute
        UBUNTU_CODENAME=resolute
        '''
    ),
    "debian_13": textwrap.dedent(
        '''\
        ID=debian
        PRETTY_NAME="Debian GNU/Linux 13"
        VERSION_ID="13"
        VERSION_CODENAME=trixie
        '''
    ),
    "debian_12": textwrap.dedent(
        '''\
        ID=debian
        PRETTY_NAME="Debian GNU/Linux 12"
        VERSION_ID="12"
        VERSION_CODENAME=bookworm
        '''
    ),
    "fedora_44": textwrap.dedent(
        '''\
        ID=fedora
        PRETTY_NAME="Fedora Linux 44"
        VERSION_ID="44"
        '''
    ),
    "rocky_9": textwrap.dedent(
        '''\
        ID=rocky
        ID_LIKE="rhel centos fedora"
        PRETTY_NAME="Rocky Linux 9.6"
        VERSION_ID="9.6"
        '''
    ),
    "almalinux_9": textwrap.dedent(
        '''\
        ID=almalinux
        ID_LIKE="rhel centos fedora"
        PRETTY_NAME="AlmaLinux 9.6"
        VERSION_ID="9.6"
        '''
    ),
    "centos_stream_9": textwrap.dedent(
        '''\
        ID=centos
        ID_LIKE="rhel centos fedora"
        PRETTY_NAME="CentOS Stream 9"
        VERSION_ID="9"
        '''
    ),
    "opensuse_leap_15_6": textwrap.dedent(
        '''\
        ID=opensuse-leap
        ID_LIKE="suse opensuse"
        PRETTY_NAME="openSUSE Leap 15.6"
        VERSION_ID="15.6"
        '''
    ),
    "opensuse_tumbleweed": textwrap.dedent(
        '''\
        ID=opensuse-tumbleweed
        ID_LIKE="suse opensuse"
        PRETTY_NAME="openSUSE Tumbleweed"
        '''
    ),
    "linuxmint_22_3": textwrap.dedent(
        '''\
        ID=linuxmint
        ID_LIKE="ubuntu debian"
        PRETTY_NAME="Linux Mint 22.3"
        VERSION_ID="22.3"
        VERSION_CODENAME=zena
        UBUNTU_CODENAME=noble
        '''
    ),
    "kali": textwrap.dedent(
        '''\
        ID=kali
        ID_LIKE="debian"
        PRETTY_NAME="Kali GNU/Linux Rolling"
        VERSION_ID="2024.4"
        VERSION_CODENAME=kali-rolling
        '''
    ),
    "unknown": textwrap.dedent(
        '''\
        ID=exampleos
        PRETTY_NAME="ExampleOS"
        '''
    ),
}


class CompatSystemMigrationTest(unittest.TestCase):
    def _classify_with_engine(self, os_release_path: Path) -> dict:
        result = subprocess.run(
            ["python3", str(CLASSIFY), "--os-release", str(os_release_path), "classify"],
            cwd=ROOT_DIR,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def _detect_with_shell(self, os_release_path: Path, *, empty_path: bool = False) -> dict:
        script = [
            f'source "{LIB_DISTRO_SH}"',
        ]
        if empty_path:
            script.append('export PATH=""')
        script.extend([
            f'OS_RELEASE_FILE="{os_release_path}" detect_distro',
            'printf "%s\n" "$DISTRO_ID"',
            'printf "%s\n" "$DISTRO_ADAPTER_ID"',
            'printf "%s\n" "$DISTRO_FAMILY"',
            'printf "%s\n" "$DISTRO_SUPPORTED"',
            'printf "%s\n" "$DISTRO_FUTURE"',
            'printf "%s\n" "$DISTRO_UNSUPPORTED"',
            'printf "%s\n" "$DISTRO_UNDETERMINED"',
        ])
        result = subprocess.run(
            ["bash", "-c", "; ".join(script)],
            cwd=ROOT_DIR,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.strip().splitlines()
        return {
            "distro_id": lines[0],
            "adapter_id": lines[1],
            "family": lines[2],
            "supported": lines[3],
            "future": lines[4],
            "unsupported": lines[5],
            "undetermined": lines[6],
        }

    def test_shell_matches_engine_for_all_fixtures(self):
        for name, content in FIXTURES.items():
            with self.subTest(name=name):
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = Path(tmp.name)
                try:
                    engine = self._classify_with_engine(tmp_path)
                    shell = self._detect_with_shell(tmp_path)

                    self.assertEqual(shell["distro_id"], engine["distro_id"], "distro_id mismatch")
                    self.assertEqual(shell["adapter_id"], engine["adapter_id"], "adapter_id mismatch")
                    self.assertEqual(
                        shell["family"],
                        _family_short(engine["family_id"]),
                        "family mismatch",
                    )

                    if engine["support_classification"] == "experimental":
                        self.assertEqual(shell["future"], "1", "future mismatch")
                        self.assertEqual(shell["supported"], "0", "supported mismatch")
                        self.assertEqual(shell["unsupported"], "0", "unsupported mismatch")
                    elif engine["support_classification"] == "unsupported":
                        self.assertEqual(shell["future"], "0", "future mismatch")
                        self.assertEqual(shell["supported"], "0", "supported mismatch")
                        self.assertEqual(shell["unsupported"], "1", "unsupported mismatch")
                    else:
                        self.assertEqual(shell["future"], "0", "future mismatch")
                        self.assertEqual(shell["supported"], "1", "supported mismatch")
                        self.assertEqual(shell["unsupported"], "0", "unsupported mismatch")
                finally:
                    tmp_path.unlink(missing_ok=True)

    def test_future_iff_experimental(self):
        for name, content in FIXTURES.items():
            with self.subTest(name=name):
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = Path(tmp.name)
                try:
                    engine = self._classify_with_engine(tmp_path)
                    shell = self._detect_with_shell(tmp_path)
                    self.assertEqual(
                        shell["future"] == "1",
                        engine["support_classification"] == "experimental",
                        "DISTRO_FUTURE must be 1 exactly when support_classification is experimental",
                    )
                finally:
                    tmp_path.unlink(missing_ok=True)

    def test_fallback_never_claims_support(self):
        for name, content in FIXTURES.items():
            with self.subTest(name=name):
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = Path(tmp.name)
                try:
                    shell = self._detect_with_shell(tmp_path, empty_path=True)
                    self.assertEqual(shell["distro_id"], shell["distro_id"])
                    self.assertEqual(shell["supported"], "0")
                    self.assertEqual(shell["future"], "0")
                    self.assertEqual(shell["unsupported"], "0")
                    self.assertEqual(shell["undetermined"], "1")
                finally:
                    tmp_path.unlink(missing_ok=True)

    def test_classify_exit_code_on_invalid_manifest(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            tmp.write("{not valid json")
            manifest_path = Path(tmp.name)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write(FIXTURES["ubuntu_24_04"])
            os_release_path = Path(tmp.name)
        try:
            result = subprocess.run(
                ["python3", str(CLASSIFY), "--manifest", str(manifest_path),
                 "--os-release", str(os_release_path), "classify"],
                cwd=ROOT_DIR,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 2, "invalid manifest must exit 2")
            self.assertIn("error:", result.stderr.lower())
        finally:
            manifest_path.unlink(missing_ok=True)
            os_release_path.unlink(missing_ok=True)

    def test_classify_exit_code_on_usage_error(self):
        result = subprocess.run(
            ["python3", str(CLASSIFY)],
            cwd=ROOT_DIR,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 1, "usage error must exit 1")

    def test_classify_exit_code_on_missing_os_release(self):
        missing_path = ROOT_DIR / "nonexistent_os_release_for_test.txt"
        result = subprocess.run(
            ["python3", str(CLASSIFY), "--os-release", str(missing_path), "classify"],
            cwd=ROOT_DIR,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2, "missing os-release must exit 2")


def _family_short(family_id: str) -> str:
    return {
        "arch_pacman": "arch",
        "debian_apt": "debian",
        "ubuntu_apt": "ubuntu",
        "redhat_dnf": "redhat",
        "suse_zypper": "suse",
    }.get(family_id, family_id)


if __name__ == "__main__":
    unittest.main()
