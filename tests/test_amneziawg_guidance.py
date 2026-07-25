from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from diagnostics.amneziawg_guidance import ROOT_DIR, dependency_guidance


class AmneziaWGGuidanceTests(unittest.TestCase):
    def test_cli_bridge_returns_the_shared_shell_contract(self) -> None:
        guidance = dependency_guidance()

        self.assertIn("available", guidance)
        self.assertIn("distro_adapter", guidance)
        self.assertIn("commands", guidance)
        self.assertIn("message", guidance)
        self.assertIn("AmneziaWG profile saved", str(guidance["message"]))

    def test_arch_derivative_uses_existing_distro_adapter_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os_release = Path(tmp) / "os-release"
            os_release.write_text("ID=manjaro\nID_LIKE=arch\nNAME=Manjaro\n", encoding="utf-8")
            script = (
                'source "$1/lib/common.sh"; '
                'source "$1/lib/distro.sh"; '
                'OS_RELEASE_FILE="$2"; detect_distro; '
                'adapter="$(distro_adapter_path "$1")"; source "$adapter"; '
                'source "$1/lib/amneziawg.sh"; amneziawg_import_guidance_json'
            )
            result = subprocess.run(
                ["bash", "-c", script, "test", str(ROOT_DIR), str(os_release)],
                text=True,
                capture_output=True,
                check=True,
            )

        guidance = json.loads(result.stdout)
        self.assertEqual(guidance["distro"], "manjaro")
        self.assertEqual(guidance["distro_adapter"], "arch")
        self.assertIn("amneziawg-dkms", "\n".join(guidance["commands"]))

    def test_unknown_distro_offers_links_without_guessed_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os_release = Path(tmp) / "os-release"
            # opensuse-tumbleweed used to be this fixture's stand-in for an
            # unsupported distro, but Task 23.6.6 gave openSUSE its own real
            # adapter with guidance commands - it is no longer "unknown".
            # slackware has neither a native case nor a matching ID_LIKE, so
            # it stays genuinely adapter-less.
            os_release.write_text("ID=slackware\nNAME=Slackware\n", encoding="utf-8")
            script = (
                'source "$1/lib/common.sh"; '
                'source "$1/lib/distro.sh"; '
                'OS_RELEASE_FILE="$2"; detect_distro; '
                'adapter="$(distro_adapter_path "$1")"; '
                'if [[ -r "$adapter" ]]; then source "$adapter"; fi; '
                'source "$1/lib/amneziawg.sh"; amneziawg_import_guidance_json'
            )
            result = subprocess.run(
                ["bash", "-c", script, "test", str(ROOT_DIR), str(os_release)],
                text=True,
                capture_output=True,
                check=True,
            )

        guidance = json.loads(result.stdout)
        self.assertEqual(guidance["commands"], [])
        self.assertIn("Official sources", guidance["message"])

    def test_ubuntu_offers_from_source_fallback_for_unpackaged_releases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os_release = Path(tmp) / "os-release"
            # Ubuntu 26.04 "resolute" has no AmneziaWG PPA series yet, so the
            # packaged path 404s; the adapter must still offer a from-source
            # userspace fallback so the release is not stranded.
            os_release.write_text(
                'ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\nNAME=Ubuntu\n',
                encoding="utf-8",
            )
            script = (
                'source "$1/lib/common.sh"; '
                'source "$1/lib/distro.sh"; '
                'OS_RELEASE_FILE="$2"; detect_distro; '
                'adapter="$(distro_adapter_path "$1")"; source "$adapter"; '
                'source "$1/lib/amneziawg.sh"; amneziawg_import_guidance_json'
            )
            result = subprocess.run(
                ["bash", "-c", script, "test", str(ROOT_DIR), str(os_release)],
                text=True,
                capture_output=True,
                check=True,
            )

        guidance = json.loads(result.stdout)
        self.assertEqual(guidance["distro_adapter"], "ubuntu")
        self.assertIn("fallback_commands", guidance)
        self.assertIn("amneziawg-go", "\n".join(guidance["fallback_commands"]))
        self.assertIn("from source", guidance["message"])


if __name__ == "__main__":
    unittest.main()
