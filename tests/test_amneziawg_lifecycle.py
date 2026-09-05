"""Unit tests for the AmneziaWG lifecycle guidance module and its CLI wiring."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Callable
from unittest import mock

from cli.main import (
    _awg_profile_count,
    _awg_repair,
    _awg_rollback,
    _awg_setup,
    _awg_status,
    _awg_update,
    _awg_verify,
)
from diagnostics import amneziawg_lifecycle as lifecycle
from diagnostics.amneziawg_lifecycle import (
    AMNEZIAWG_TRANSPORT_REPO,
    AMNEZIAWG_TRANSPORT_URL,
    AMNEZIAWG_TOOLS_REPO,
    AMNEZIAWG_TOOLS_URL,
    CERTIFIED_PINS,
    OfficialReleaseResolver,
    ReleaseResolutionError,
    ResolvedRelease,
    RuntimeComponent,
    RuntimeProbe,
    build_recipe,
    import_guidance_payload,
    lifecycle_state,
    previous_installed_release,
    probe_runtime,
    recipe_for_certified_pins,
    record_installed_release,
    store_pending_releases,
    verification_report,
)


def _component(
    name: str,
    *,
    present: bool,
    provenance: str = "missing",
    version: str | None = None,
    sha256: str | None = None,
) -> RuntimeComponent:
    return RuntimeComponent(
        name=name,
        present=present,
        path=f"/usr/local/bin/{name}" if present else None,
        version=version,
        sha256=sha256,
        mode="0o755" if present else None,
        uid=0 if present else None,
        gid=0 if present else None,
        provenance=provenance,
    )


def _probe(*, awg: bool = False, awg_quick: bool = False, amneziawg_go: bool = False) -> RuntimeProbe:
    """Build a RuntimeProbe from underscore-named flags."""
    mapping = {"awg": awg, "awg-quick": awg_quick, "amneziawg-go": amneziawg_go}
    components = {
        name: _component(name, present=mapping[name], provenance="supported", version="v1", sha256=("aa" * 32))
        for name in ("awg", "awg-quick", "amneziawg-go")
    }
    all_present = all(components[name].present for name in ("awg", "awg-quick", "amneziawg-go"))
    runtime_available = all_present and components["awg"].present
    return RuntimeProbe(components=components, all_present=all_present, runtime_available=runtime_available)


def _probe_sha(sha: str) -> RuntimeProbe:
    components = {
        name: _component(name, present=True, provenance="unknown", version="v1", sha256=sha)
        for name in ("awg", "awg-quick", "amneziawg-go")
    }
    return RuntimeProbe(components=components, all_present=True, runtime_available=True)


def _certified_releases() -> list[ResolvedRelease]:
    now = "2026-09-05T00:00:00Z"
    return [
        ResolvedRelease(
            AMNEZIAWG_TOOLS_REPO,
            CERTIFIED_PINS[AMNEZIAWG_TOOLS_REPO]["tag"],
            CERTIFIED_PINS[AMNEZIAWG_TOOLS_REPO]["commit"],
            now,
        ),
        ResolvedRelease(
            AMNEZIAWG_TRANSPORT_REPO,
            CERTIFIED_PINS[AMNEZIAWG_TRANSPORT_REPO]["tag"],
            CERTIFIED_PINS[AMNEZIAWG_TRANSPORT_REPO]["commit"],
            now,
        ),
    ]


class LifecycleStateTests(unittest.TestCase):
    def test_context_absent_without_profiles_even_if_runtime_missing(self) -> None:
        probe = _probe()
        self.assertEqual(lifecycle_state(awg_profiles=0, probe=probe), lifecycle.STATE_CONTEXT_ABSENT)

    def test_available_state_when_profile_and_runtime(self) -> None:
        probe = _probe(awg=True, awg_quick=True, amneziawg_go=True)
        self.assertEqual(lifecycle_state(awg_profiles=1, probe=probe), lifecycle.STATE_PROFILE_AVAILABLE)

    def test_imported_missing_state(self) -> None:
        probe = _probe()
        self.assertEqual(lifecycle_state(awg_profiles=1, probe=probe, just_imported=True), lifecycle.STATE_IMPORTED_MISSING)

    def test_profile_missing_state(self) -> None:
        probe = _probe()
        self.assertEqual(lifecycle_state(awg_profiles=1, probe=probe), lifecycle.STATE_PROFILE_MISSING)

    def test_profile_unknown_state_on_partial_unknown_runtime(self) -> None:
        components = {
            "awg": _component("awg", present=True, provenance="unknown", version="v0.0"),
            "awg-quick": _component("awg-quick", present=False),
            "amneziawg-go": _component("amneziawg-go", present=False),
        }
        probe = RuntimeProbe(components=components, all_present=False, runtime_available=False)
        self.assertEqual(lifecycle_state(awg_profiles=1, probe=probe), lifecycle.STATE_PROFILE_UNKNOWN)

    def test_no_runtime_detection_without_context_is_not_an_error(self) -> None:
        probe = _probe()
        self.assertEqual(lifecycle_state(awg_profiles=0, probe=probe), lifecycle.STATE_CONTEXT_ABSENT)


class ReleaseResolverTests(unittest.TestCase):
    def _fake_fetch(self, responses: dict[str, str]) -> Callable[[str], str]:
        def fetch(url: str) -> str:
            if url not in responses:
                raise OSError(f"unexpected url {url}")
            return responses[url]
        return fetch

    def test_resolves_latest_release_to_commit(self) -> None:
        responses = {
            f"https://api.github.com/repos/{AMNEZIAWG_TOOLS_REPO}/releases/latest": json.dumps(
                {"tag_name": "v1.0.20260618-2"}
            ),
            f"https://api.github.com/repos/{AMNEZIAWG_TOOLS_REPO}/git/ref/tags/v1.0.20260618-2": json.dumps(
                {"ref": "refs/tags/v1.0.20260618-2", "object": {"sha": "61e741780e8465a67a7d7fb6cffe14a8a15d624a", "type": "commit"}}
            ),
        }
        resolver = OfficialReleaseResolver(fetch=self._fake_fetch(responses))
        release = resolver.resolve(AMNEZIAWG_TOOLS_REPO)
        self.assertEqual(release.tag, "v1.0.20260618-2")
        self.assertEqual(release.commit, "61e741780e8465a67a7d7fb6cffe14a8a15d624a")
        self.assertTrue(release.resolved_at)

    def test_dereferences_annotated_tag(self) -> None:
        tag_object = "aa" * 20
        commit = "bb" * 20
        responses = {
            f"https://api.github.com/repos/{AMNEZIAWG_TRANSPORT_REPO}/releases/latest": json.dumps({"tag_name": "v3.0.2"}),
            f"https://api.github.com/repos/{AMNEZIAWG_TRANSPORT_REPO}/git/ref/tags/v3.0.2": json.dumps(
                {"ref": "refs/tags/v3.0.2", "object": {"sha": tag_object, "type": "tag"}}
            ),
            f"https://api.github.com/repos/{AMNEZIAWG_TRANSPORT_REPO}/git/tags/{tag_object}": json.dumps(
                {"object": {"sha": commit, "type": "commit"}}
            ),
        }
        resolver = OfficialReleaseResolver(fetch=self._fake_fetch(responses))
        release = resolver.resolve(AMNEZIAWG_TRANSPORT_REPO)
        self.assertEqual(release.commit, commit)

    def test_resolves_latest_tag_when_repo_has_no_releases(self) -> None:
        def fetch(url: str) -> str:
            if "/git/ref/tags/" in url:
                return json.dumps({"ref": "refs/tags/v3.1.20260828", "object": {"sha": "b5928efb6ca19f0153958460c3d141f04abc5c2e", "type": "commit"}})
            if "/releases/latest" in url:
                raise OSError("404 Not Found (no GitHub Releases published)")
            if "/tags" in url:
                return json.dumps([{"name": "v3.1.20260828", "commit": {"sha": "b5928efb6ca19f0153958460c3d141f04abc5c2e"}}])
            raise OSError(f"unexpected url {url}")

        resolver = OfficialReleaseResolver(fetch=fetch)
        release = resolver.resolve(AMNEZIAWG_TRANSPORT_REPO)
        self.assertEqual(release.tag, "v3.1.20260828")
        self.assertEqual(release.commit, "b5928efb6ca19f0153958460c3d141f04abc5c2e")

    def test_fails_loudly_when_github_unavailable(self) -> None:
        def fetch(_url: str) -> str:
            raise OSError("network down")
        resolver = OfficialReleaseResolver(fetch=fetch)
        with self.assertRaises(ReleaseResolutionError):
            resolver.resolve(AMNEZIAWG_TOOLS_REPO)

    def test_fails_when_no_resolvable_tag(self) -> None:
        responses = {
            f"https://api.github.com/repos/{AMNEZIAWG_TOOLS_REPO}/releases/latest": json.dumps({}),
        }
        resolver = OfficialReleaseResolver(fetch=self._fake_fetch(responses))
        with self.assertRaises(ReleaseResolutionError):
            resolver.resolve(AMNEZIAWG_TOOLS_REPO)

    def test_refuses_third_party_repository(self) -> None:
        resolver = OfficialReleaseResolver(fetch=lambda _url: "{}")
        with self.assertRaises(ReleaseResolutionError):
            resolver.resolve("evil/repo")


class RecipeTests(unittest.TestCase):
    def test_recipe_pins_tags_and_commits_and_never_uses_head(self) -> None:
        recipe = build_recipe(releases=_certified_releases())
        commands = " ".join(str(entry.get("command", "")) for entry in recipe["commands"])
        self.assertIn(CERTIFIED_PINS[AMNEZIAWG_TOOLS_REPO]["commit"], commands)
        self.assertIn(CERTIFIED_PINS[AMNEZIAWG_TRANSPORT_REPO]["commit"], commands)
        for forbidden in (" main ", " master ", "git checkout HEAD", "git clone --branch HEAD"):
            self.assertNotIn(forbidden, commands)
        self.assertIn("rev-parse HEAD", commands)
        self.assertIn("watchdog awg verify", commands)
        self.assertIs(recipe["executed_by_watchdogvpn"], False)
        self.assertIs(recipe["certified_on_opensuse_leap"], True)
        self.assertEqual(set(recipe["sources"]), {AMNEZIAWG_TOOLS_URL, AMNEZIAWG_TRANSPORT_URL})
        self.assertEqual(recipe["compatibility"]["status"], "verified")

    def test_recipe_uses_safe_mktemp_workspace_and_verifies_checkout(self) -> None:
        recipe = build_recipe(releases=_certified_releases())
        commands = " ".join(str(entry.get("command", "")) for entry in recipe["commands"])
        script = str(recipe["script"])
        self.assertIn("mktemp -d /tmp/watchdogvpn-amneziawg.XXXXXX", commands)
        self.assertIn("rev-parse HEAD", commands)
        self.assertIn("test \"$(git -C", commands)
        self.assertIn("trap 'rm -rf \"$build_dir\"' EXIT", script)
        for forbidden in ("rm -rf /tmp/amneziawg-tools", "rm -rf /tmp/amneziawg-go"):
            self.assertNotIn(forbidden, commands)
            self.assertNotIn(forbidden, script)

    def test_recipe_marks_upstream_latest_as_not_certified(self) -> None:
        now = "2026-09-05T00:00:00Z"
        releases = [
            ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "v9.9.9", "dd" * 20, now),
            ResolvedRelease(AMNEZIAWG_TRANSPORT_REPO, "v9.9.9", "ee" * 20, now),
        ]
        recipe = build_recipe(releases=releases)
        self.assertIs(recipe["certified_on_opensuse_leap"], False)
        self.assertEqual(recipe["compatibility"]["status"], "not_verified")

    def test_recipe_for_certified_pins_is_offline_and_exact(self) -> None:
        recipe = recipe_for_certified_pins()
        commands = " ".join(str(entry.get("command", "")) for entry in recipe["commands"])
        self.assertIn(CERTIFIED_PINS[AMNEZIAWG_TOOLS_REPO]["commit"], commands)
        self.assertIs(recipe["certified_on_opensuse_leap"], True)
        self.assertNotIn("api.github.com", commands)

    def test_verification_report(self) -> None:
        probe = _probe(awg=True, awg_quick=True, amneziawg_go=True)
        report = verification_report(probe)
        self.assertIs(report["verified"], True)
        self.assertEqual(len(report["checks"]), 3)


class ProbeRuntimeTests(unittest.TestCase):
    def test_probe_reports_missing_when_nothing_present(self) -> None:
        with mock.patch.object(lifecycle, "_find_binary", return_value=None):
            probe = probe_runtime()
        self.assertFalse(probe.all_present)
        self.assertFalse(probe.runtime_available)
        self.assertTrue(all(component.provenance == "missing" for component in probe.components.values()))

    def test_probe_requires_all_three_outputs(self) -> None:
        fake_path = Path("/usr/local/bin/awg")

        def fake_find(name: str, root: Path | None = None) -> Path | None:
            return fake_path if name == "awg" else None

        with (
            mock.patch.object(lifecycle, "_find_binary", side_effect=fake_find),
            mock.patch.object(lifecycle, "_run_version", return_value="awg 1.0"),
            mock.patch.object(lifecycle, "_sha256_of", return_value="aa" * 32),
        ):
            probe = probe_runtime()
        self.assertFalse(probe.runtime_available)

    def test_probe_uses_root_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("awg", "awg-quick", "amneziawg-go"):
                binary = root / name
                binary.write_text("#!/bin/sh\necho test\n", encoding="utf-8")
                binary.chmod(0o755)
            probe = probe_runtime(root=root)
            self.assertTrue(probe.all_present)
            for component in probe.components.values():
                self.assertTrue(component.path.startswith(tmp))


class ImportGuidanceTests(unittest.TestCase):
    def _set_env(self) -> tempfile.TemporaryDirectory[str]:
        tmp = tempfile.TemporaryDirectory()
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "WATCHDOGVPN_CONFIG_DIR": tmp.name,
                "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp.name) / "profiles.json"),
            },
            clear=False,
        )
        self._env_patch.start()
        return tmp

    def _tear_env(self) -> None:
        self._env_patch.stop()

    def test_import_guidance_uses_dynamic_recipe_not_static_pins(self) -> None:
        tmp = self._set_env()
        try:
            with mock.patch.object(lifecycle, "probe_runtime", return_value=_probe()), mock.patch.object(
                lifecycle.OfficialReleaseResolver, "resolve"
            ) as resolve:
                resolve.side_effect = [
                    ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "v9.9.9", "dd" * 20, "2026-09-05T00:00:00Z"),
                    ResolvedRelease(AMNEZIAWG_TRANSPORT_REPO, "v9.9.9", "ee" * 20, "2026-09-05T00:00:00Z"),
                ]
                guidance = import_guidance_payload()
            self.assertFalse(bool(guidance["available"]))
            self.assertIs(guidance["blocked"], False)
            commands = " ".join(str(entry.get("command", "")) for entry in guidance["commands"])
            self.assertIn("dddddddddddddddddddddddddddddddddddddddd", commands)
            self.assertIn("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", commands)
            self.assertNotIn(CERTIFIED_PINS[AMNEZIAWG_TOOLS_REPO]["commit"], commands)
            self.assertIn("rev-parse HEAD", commands)
            self.assertNotIn("git clone --branch HEAD", commands)
            self.assertNotIn(" main ", commands)
            self.assertNotIn(" master ", commands)
        finally:
            self._tear_env()

    def test_import_guidance_blocks_when_release_unresolvable(self) -> None:
        tmp = self._set_env()
        try:
            with mock.patch.object(lifecycle, "probe_runtime", return_value=_probe()), mock.patch.object(
                lifecycle.OfficialReleaseResolver, "resolve",
                side_effect=ReleaseResolutionError("network down"),
            ):
                guidance = import_guidance_payload()
            self.assertTrue(bool(guidance["blocked"]))
            self.assertEqual(guidance["commands"], [])
            self.assertIn("network down", guidance["message"])
        finally:
            self._tear_env()


class InstallRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._env_patch = mock.patch.dict(
            os.environ,
            {"WATCHDOGVPN_CONFIG_DIR": self._tmp.name, "WATCHDOGVPN_PROFILES_FILE": str(Path(self._tmp.name) / "profiles.json")},
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._tmp.cleanup()

    def _probe_with_sha(self, sha: str) -> RuntimeProbe:
        components = {
            name: _component(name, present=True, provenance="unknown", version="v1", sha256=sha)
            for name in ("awg", "awg-quick", "amneziawg-go")
        }
        return RuntimeProbe(components=components, all_present=True, runtime_available=True)

    def test_record_and_previous_release(self) -> None:
        releases_a = [
            ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "vA", "aa" * 20, "2026-09-05T00:00:00Z"),
            ResolvedRelease(AMNEZIAWG_TRANSPORT_REPO, "vA2", "ab" * 20, "2026-09-05T00:00:00Z"),
        ]
        record_installed_release(releases_a, self._probe_with_sha("11" * 32), platform={"distro": "opensuse_leap", "version": "15.6", "arch": "x86_64"})
        releases_b = [
            ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "vB", "cc" * 20, "2026-09-05T01:00:00Z"),
            ResolvedRelease(AMNEZIAWG_TRANSPORT_REPO, "vB2", "cd" * 20, "2026-09-05T01:00:00Z"),
        ]
        record_installed_release(releases_b, self._probe_with_sha("22" * 32), platform={"distro": "opensuse_leap", "version": "15.6", "arch": "x86_64"})
        previous = previous_installed_release(self._probe_with_sha("22" * 32))
        self.assertEqual(len(previous), 2)
        self.assertEqual({entry.tag for entry in previous}, {"vA", "vA2"})

    def test_previous_release_empty_when_no_history(self) -> None:
        self.assertEqual(previous_installed_release(self._probe_with_sha("11" * 32)), [])


class BuildManifestTests(unittest.TestCase):
    PLATFORM = {"arch": "x86_64", "distro": "opensuse_leap", "version": "15.6"}

    def _manifest(self, releases: list[ResolvedRelease], sha: str, **overrides: object) -> dict[str, object]:
        by_repo = {release.repository: release for release in releases}
        manifest: dict[str, object] = {
            "schema": 1,
            "tools": {
                "repository": AMNEZIAWG_TOOLS_REPO,
                "tag": by_repo[AMNEZIAWG_TOOLS_REPO].tag,
                "commit": by_repo[AMNEZIAWG_TOOLS_REPO].commit,
            },
            "transport": {
                "repository": AMNEZIAWG_TRANSPORT_REPO,
                "tag": by_repo[AMNEZIAWG_TRANSPORT_REPO].tag,
                "commit": by_repo[AMNEZIAWG_TRANSPORT_REPO].commit,
            },
            "outputs": {name: sha for name in ("awg", "awg-quick", "amneziawg-go")},
            "arch": "x86_64",
            "distro": "opensuse_leap",
        }
        manifest.update(overrides)
        return manifest

    def _verdict(
        self,
        manifest: dict[str, object] | None,
        releases: list[ResolvedRelease],
        probe: RuntimeProbe,
        platform: dict[str, str] | None = None,
    ) -> dict[str, object]:
        return lifecycle.validate_build_manifest(manifest, releases, probe, platform=platform or dict(self.PLATFORM))

    def test_valid_manifest_and_matching_binaries_is_accepted(self) -> None:
        releases = _certified_releases()
        verdict = self._verdict(self._manifest(releases, "aa" * 32), releases, _probe_sha("aa" * 32))
        self.assertTrue(verdict["valid"])
        self.assertTrue(verdict["checks"]["arch_matches"])
        self.assertTrue(verdict["checks"]["distro_matches"])

    def test_missing_manifest_is_unknown_not_supported(self) -> None:
        releases = _certified_releases()
        verdict = self._verdict(None, releases, _probe_sha("aa" * 32))
        self.assertFalse(verdict["valid"])
        self.assertIn("no independent build manifest", verdict["reason"])

    def test_pending_a_binaries_b_is_rejected(self) -> None:
        releases = _certified_releases()
        verdict = self._verdict(self._manifest(releases, "aa" * 32), releases, _probe_sha("bb" * 32))
        self.assertFalse(verdict["valid"])
        self.assertIn("does not match the build manifest", verdict["reason"])

    def test_manifest_commit_mismatch_is_rejected(self) -> None:
        releases = _certified_releases()
        tampered = self._manifest(releases, "aa" * 32)
        tampered["tools"] = {
            "repository": AMNEZIAWG_TOOLS_REPO,
            "tag": "v9.9.9",
            "commit": "cc" * 20,
        }
        verdict = self._verdict(tampered, releases, _probe_sha("aa" * 32))
        self.assertFalse(verdict["valid"])
        self.assertIn("tools commit/tag", verdict["reason"])

    def test_mixed_component_digests_are_rejected(self) -> None:
        releases = _certified_releases()
        manifest = self._manifest(releases, "aa" * 32)
        manifest["outputs"] = {"awg": "aa" * 32, "awg-quick": "bb" * 32, "amneziawg-go": "aa" * 32}
        verdict = self._verdict(manifest, releases, _probe_sha("aa" * 32))
        self.assertFalse(verdict["valid"])
        self.assertIn("awg-quick digest", verdict["reason"])

    def test_altered_manifest_is_rejected(self) -> None:
        releases = _certified_releases()
        manifest = self._manifest(releases, "aa" * 32)
        manifest["outputs"] = {"awg": "aa" * 32, "awg-quick": "aa" * 32, "amneziawg-go": "dd" * 32}
        verdict = self._verdict(manifest, releases, _probe_sha("aa" * 32))
        self.assertFalse(verdict["valid"])

    def test_manifest_x86_64_on_aarch64_host_is_rejected(self) -> None:
        releases = _certified_releases()
        manifest = self._manifest(releases, "aa" * 32)
        verdict = self._verdict(manifest, releases, _probe_sha("aa" * 32), platform={"arch": "aarch64", "distro": "opensuse_leap", "version": "15.6"})
        self.assertFalse(verdict["valid"])
        self.assertFalse(verdict["checks"]["arch_matches"])

    def test_manifest_opensuse_on_fedora_host_is_rejected(self) -> None:
        releases = _certified_releases()
        manifest = self._manifest(releases, "aa" * 32)
        verdict = self._verdict(manifest, releases, _probe_sha("aa" * 32), platform={"arch": "x86_64", "distro": "fedora", "version": "44"})
        self.assertFalse(verdict["valid"])
        self.assertFalse(verdict["checks"]["distro_matches"])

    def test_manifest_without_arch_is_rejected(self) -> None:
        releases = _certified_releases()
        manifest = self._manifest(releases, "aa" * 32)
        manifest.pop("arch", None)
        verdict = self._verdict(manifest, releases, _probe_sha("aa" * 32))
        self.assertFalse(verdict["valid"])
        self.assertIn("no architecture", verdict["reason"])

    def test_manifest_without_distro_is_rejected(self) -> None:
        releases = _certified_releases()
        manifest = self._manifest(releases, "aa" * 32)
        manifest.pop("distro", None)
        verdict = self._verdict(manifest, releases, _probe_sha("aa" * 32))
        self.assertFalse(verdict["valid"])
        self.assertIn("no distro", verdict["reason"])

    def test_manifest_with_unsupported_schema_is_rejected(self) -> None:
        releases = _certified_releases()
        manifest = self._manifest(releases, "aa" * 32)
        manifest["schema"] = 99
        verdict = self._verdict(manifest, releases, _probe_sha("aa" * 32))
        self.assertFalse(verdict["valid"])
        self.assertFalse(verdict["checks"]["schema_supported"])

    def test_manifest_with_third_party_repository_is_rejected(self) -> None:
        releases = _certified_releases()
        manifest = self._manifest(releases, "aa" * 32)
        manifest["tools"] = {
            "repository": "evil/amneziawg-tools",
            "tag": "v1",
            "commit": "aa" * 20,
        }
        verdict = self._verdict(manifest, releases, _probe_sha("aa" * 32))
        self.assertFalse(verdict["valid"])
        self.assertFalse(verdict["checks"]["tools_repo_official"])

    def test_unknown_host_platform_is_rejected(self) -> None:
        releases = _certified_releases()
        verdict = self._verdict(self._manifest(releases, "aa" * 32), releases, _probe_sha("aa" * 32), platform={"arch": "", "distro": "unknown", "version": ""})
        self.assertFalse(verdict["valid"])
        self.assertFalse(verdict["checks"]["host_arch_known"])

    def test_substituted_binary_is_detected_by_status(self) -> None:
        releases = _certified_releases()
        manifest = self._manifest(releases, "aa" * 32)
        self.assertTrue(lifecycle.build_manifest_matches_current(manifest, _probe_sha("aa" * 32)))
        base = _probe_sha("aa" * 32)
        components = dict(base.components)
        components["awg"] = _component("awg", present=True, provenance="unknown", version="v1", sha256="bb" * 32)
        substituted = RuntimeProbe(components=components, all_present=True, runtime_available=True)
        self.assertFalse(lifecycle.build_manifest_matches_current(manifest, substituted))

    def test_registry_without_evidence_does_not_elevate_to_supported(self) -> None:
        recorded = [
            lifecycle.InstalledRelease(
                repository=AMNEZIAWG_TOOLS_REPO,
                tag=CERTIFIED_PINS[AMNEZIAWG_TOOLS_REPO]["tag"],
                commit=CERTIFIED_PINS[AMNEZIAWG_TOOLS_REPO]["commit"],
                resolved_at="t",
                recorded_at="t",
                arch="x86_64",
                distro="opensuse_leap",
                binary_sha256={"awg": "aa" * 32},
                build_manifest_sha256=None,
            )
        ]
        self.assertEqual(lifecycle._provenance_from_metadata("awg", "aa" * 32, recorded), lifecycle.PROVENANCE_UNKNOWN)


class CliHandlerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "WATCHDOGVPN_CONFIG_DIR": self._tmp.name,
                "WATCHDOGVPN_PROFILES_FILE": str(Path(self._tmp.name) / "profiles.json"),
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._tmp.cleanup()

    def _args(self, json_output: bool = False, **extra: object) -> argparse.Namespace:
        return argparse.Namespace(json=json_output, **extra)

    def _write_awg_profile(self) -> None:
        store_path = Path(self._tmp.name) / "profiles.json"
        store_path.write_text(
            json.dumps(
                [{"id": "awg-test", "protocol": "amneziawg", "name": "Server 1", "source": "manual"}]
            ),
            encoding="utf-8",
        )

    def test_awg_profile_count_respects_context(self) -> None:
        self.assertEqual(_awg_profile_count(), 0)
        self._write_awg_profile()
        self.assertEqual(_awg_profile_count(), 1)

    def test_awg_status_without_context_does_not_probe(self) -> None:
        with mock.patch("cli.main.probe_runtime", side_effect=AssertionError("must not probe without context")):
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_status(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["state"], lifecycle.STATE_CONTEXT_ABSENT)
        self.assertIs(payload["detection_performed"], False)

    def test_awg_status_with_probe_flag_does_probe(self) -> None:
        with mock.patch("cli.main.probe_runtime", return_value=_probe()):
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_status(self._args(json_output=True, probe=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIs(payload["detection_performed"], True)

    def test_awg_setup_blocked_when_release_unresolvable(self) -> None:
        self._write_awg_profile()
        with mock.patch("cli.main.OfficialReleaseResolver") as resolver_cls:
            resolver_cls.return_value.resolve.side_effect = ReleaseResolutionError("network down")
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_setup(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["blocked"])
        self.assertIn("network down", payload["reason"])
        self.assertIs(payload["executed_by_watchdogvpn"], False)

    def test_awg_setup_generates_exact_recipe_and_pending(self) -> None:
        self._write_awg_profile()
        with mock.patch("cli.main.OfficialReleaseResolver") as resolver_cls:
            resolver_cls.return_value.resolve.side_effect = [
                ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "v9.9.9", "dd" * 20, "2026-09-05T00:00:00Z"),
                ResolvedRelease(AMNEZIAWG_TRANSPORT_REPO, "v9.9.9", "ee" * 20, "2026-09-05T00:00:00Z"),
            ]
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_setup(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertFalse(payload["blocked"])
        self.assertIs(payload["executed_by_watchdogvpn"], False)
        commands = " ".join(str(c.get("command", "")) for c in payload["recipe"]["commands"])
        self.assertIn("dddddddddddddddddddddddddddddddddddddddd", commands)
        self.assertIn("rev-parse HEAD", commands)
        self.assertNotIn("git clone --branch HEAD", commands)
        self.assertEqual(len(lifecycle.load_pending_releases()), 2)

    def test_awg_update_marks_uncertified_upstream(self) -> None:
        self._write_awg_profile()
        with mock.patch("cli.main.OfficialReleaseResolver") as resolver_cls:
            resolver_cls.return_value.resolve.side_effect = [
                ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "v9.9.9", "dd" * 20, "2026-09-05T00:00:00Z"),
                ResolvedRelease(AMNEZIAWG_TRANSPORT_REPO, "v9.9.9", "ee" * 20, "2026-09-05T00:00:00Z"),
            ]
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_update(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIs(payload["certified_on_opensuse_leap"], False)

    def test_awg_repair_is_offline_and_read_only(self) -> None:
        self._write_awg_profile()
        stdout = StringIO()
        with redirect_stdout(stdout):
            rc = _awg_repair(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIs(payload["executed_by_watchdogvpn"], False)
        commands = " ".join(str(c.get("command", "")) for c in payload["recipe"]["commands"])
        self.assertIn(CERTIFIED_PINS[AMNEZIAWG_TOOLS_REPO]["commit"], commands)
        self.assertNotIn("api.github.com", commands)

    def test_awg_rollback_without_history_is_explicit(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout):
            rc = _awg_rollback(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIs(payload["rolled_back"], False)
        self.assertIn("nothing to roll back to", payload["reason"])

    def _write_manifest(self, releases: list[ResolvedRelease], sha: str, **overrides: object) -> None:
        by_repo = {release.repository: release for release in releases}
        manifest: dict[str, object] = {
            "schema": 1,
            "tools": {
                "repository": AMNEZIAWG_TOOLS_REPO,
                "tag": by_repo[AMNEZIAWG_TOOLS_REPO].tag,
                "commit": by_repo[AMNEZIAWG_TOOLS_REPO].commit,
            },
            "transport": {
                "repository": AMNEZIAWG_TRANSPORT_REPO,
                "tag": by_repo[AMNEZIAWG_TRANSPORT_REPO].tag,
                "commit": by_repo[AMNEZIAWG_TRANSPORT_REPO].commit,
            },
            "outputs": {name: sha for name in ("awg", "awg-quick", "amneziawg-go")},
            "arch": "x86_64",
            "distro": "opensuse_leap",
        }
        manifest.update(overrides)
        Path(self._tmp.name, "amneziawg_build_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    def _matching_platform(self) -> mock._patch:
        return mock.patch(
            "cli.main.detect_platform",
            return_value={"arch": "x86_64", "distro": "opensuse_leap", "version": "15.6"},
        )

    def test_awg_verify_refuses_without_manifest(self) -> None:
        releases = _certified_releases()
        store_pending_releases(releases)
        with mock.patch("cli.main.probe_runtime", return_value=_probe(awg=True, awg_quick=True, amneziawg_go=True)):
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_verify(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertFalse(payload["recorded"])
        self.assertIs(payload["verified"], False)
        self.assertEqual(payload["provenance"], "unknown")
        self.assertIn("no independent build manifest", payload["reason"])
        self.assertEqual(lifecycle.load_pending_releases(), releases)

    def test_awg_verify_rejects_binary_mismatch(self) -> None:
        releases = _certified_releases()
        store_pending_releases(releases)
        self._write_manifest(releases, "aa" * 32)
        with self._matching_platform(), mock.patch("cli.main.probe_runtime", return_value=_probe_sha("bb" * 32)):
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_verify(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertFalse(payload["recorded"])
        self.assertIn("does not match the build manifest", payload["reason"])
        self.assertEqual(lifecycle.load_installed_history(), [])

    def test_awg_verify_rejects_host_platform_mismatch(self) -> None:
        releases = _certified_releases()
        store_pending_releases(releases)
        self._write_manifest(releases, "aa" * 32)
        with mock.patch("cli.main.detect_platform", return_value={"arch": "aarch64", "distro": "fedora", "version": "44"}), mock.patch(
            "cli.main.probe_runtime", return_value=_probe_sha("aa" * 32)
        ):
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_verify(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertFalse(payload["recorded"])
        self.assertIs(payload["verified"], False)
        self.assertEqual(lifecycle.load_installed_history(), [])

    def test_awg_verify_records_with_valid_manifest(self) -> None:
        releases = _certified_releases()
        store_pending_releases(releases)
        self._write_manifest(releases, "aa" * 32)
        with self._matching_platform(), mock.patch("cli.main.probe_runtime", return_value=_probe(awg=True, awg_quick=True, amneziawg_go=True)):
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_verify(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["recorded"])
        self.assertIs(payload["verified"], True)
        self.assertTrue(payload["verification"].get("verified"))
        self.assertEqual({entry["tag"] for entry in payload["recorded_releases"]}, {"v1.0.20260618-2", "v3.0.2"})
        self.assertEqual(lifecycle.load_pending_releases(), [])
        history = lifecycle.load_installed_history()
        self.assertTrue(all(entry.build_manifest_sha256 for entry in history))

    def test_awg_verify_records_pending_and_rollback_restores_previous(self) -> None:
        releases_a = [
            ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "vA", "aa" * 20, "2026-09-05T00:00:00Z"),
            ResolvedRelease(AMNEZIAWG_TRANSPORT_REPO, "vA2", "ab" * 20, "2026-09-05T00:00:00Z"),
        ]
        store_pending_releases(releases_a)
        self._write_manifest(releases_a, "aa" * 32)
        with self._matching_platform(), mock.patch("cli.main.probe_runtime", return_value=_probe(awg=True, awg_quick=True, amneziawg_go=True)):
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_verify(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["recorded"])
        self.assertEqual({entry["tag"] for entry in payload["recorded_releases"]}, {"vA", "vA2"})
        self.assertEqual(lifecycle.load_pending_releases(), [])

        releases_b = [
            ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "vB", "cc" * 20, "2026-09-05T01:00:00Z"),
            ResolvedRelease(AMNEZIAWG_TRANSPORT_REPO, "vB2", "cd" * 20, "2026-09-05T01:00:00Z"),
        ]
        store_pending_releases(releases_b)
        self._write_manifest(releases_b, "aa" * 32)
        with self._matching_platform(), mock.patch("cli.main.probe_runtime", return_value=_probe(awg=True, awg_quick=True, amneziawg_go=True)):
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_verify(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual({entry["tag"] for entry in payload["recorded_releases"]}, {"vB", "vB2"})

        with mock.patch("cli.main.probe_runtime", return_value=_probe(awg=True, awg_quick=True, amneziawg_go=True)):
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = _awg_rollback(self._args(json_output=True))
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["rolled_back"])
        self.assertEqual({entry["commit"] for entry in payload["previous_releases"]}, {"aa" * 20, "ab" * 20})


if __name__ == "__main__":
    unittest.main()