"""Focused tests for Task 23.7.5.12B.1 — deterministic public docs generator."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "compat_public_docs.py"
PRODUCT_MANIFEST = ROOT / "compat" / "compatibility.json"
PRESENTATION_MAP = ROOT / "compat" / "distribution_presentation.json"

spec = importlib.util.spec_from_file_location("compat_public_docs", TOOL)
assert spec is not None
docs = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(docs)


FIXTURE_MARKDOWN = """# Fixture

Outside before.

<!-- BEGIN GENERATED: compat-support-table -->
STALE CONTENT THAT MUST BE REPLACED
<!-- END GENERATED: compat-support-table -->

Middle narrative must stay byte-identical.

<!-- BEGIN GENERATED: compat-protocol-list -->
stale
<!-- END GENERATED: compat-protocol-list -->

Outside after.
"""


def load_authoritative_map() -> dict:
    """The only place tests obtain public display labels: the repository artifact."""
    return json.loads(PRESENTATION_MAP.read_text(encoding="utf-8"))


def load_authoritative_distributions() -> dict:
    return load_authoritative_map()["distributions"]


def load_authoritative_protocols() -> dict:
    return load_authoritative_map()["protocols"]


def run_tool(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=str(cwd or ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )


def write_fixture_tree(base: Path, markdown: str = FIXTURE_MARKDOWN, manifest: Path | None = None) -> Path:
    root = base / "tree"
    root.mkdir(parents=True, exist_ok=True)
    target = root / "doc.md"
    target.write_text(markdown, encoding="utf-8")
    if manifest is not None:
        dest = base / "manifest.json"
        if manifest.resolve() != dest.resolve():
            shutil.copyfile(manifest, dest)
    return root


def region_span(text: str, region_id: str) -> tuple[int, int]:
    begin = "<!-- BEGIN GENERATED: %s -->" % region_id
    end = "<!-- END GENERATED: %s -->" % region_id
    start = text.index(begin) + len(begin)
    if start < len(text) and text[start] == "\n":
        start += 1
    finish = text.index(end)
    if finish > start and text[finish - 1] == "\n":
        finish -= 1
    return start, finish


class PublicDocsGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.labels = load_authoritative_distributions()
        self.manifest_path = self.base / "manifest.json"
        shutil.copyfile(PRODUCT_MANIFEST, self.manifest_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _fixture(self, markdown: str = FIXTURE_MARKDOWN) -> Path:
        return write_fixture_tree(self.base, markdown=markdown, manifest=self.manifest_path)

    def _map_path(self) -> Path:
        return PRESENTATION_MAP

    def _run(self, mode_args: list[str], root: Path, map_path: Path | None = None) -> subprocess.CompletedProcess:
        args = [*mode_args, "--root", str(root), "--manifest", str(self.manifest_path)]
        args += ["--presentation-map", str(map_path if map_path else self._map_path())]
        return run_tool(args)

    def _generate(self, root: Path, map_path: Path | None = None) -> subprocess.CompletedProcess:
        return self._run(["generate"], root, map_path)

    def _check(self, root: Path, map_path: Path | None = None) -> subprocess.CompletedProcess:
        return self._run(["--check"], root, map_path)

    # ------------------------------------------------------------------ #
    # Presentation map authority and coverage.
    # ------------------------------------------------------------------ #
    def test_presentation_map_is_single_repository_source(self) -> None:
        self.assertTrue(PRESENTATION_MAP.is_file(), "authoritative artifact must exist in the repo")
        document = json.loads(PRESENTATION_MAP.read_text(encoding="utf-8"))
        self.assertEqual(document.get("schema_version"), docs.PRESENTATION_MAP_SCHEMA_VERSION)
        self.assertIsInstance(document.get("distributions"), dict)
        self.assertIsInstance(document.get("protocols"), dict)

        # The generator module must not embed any label value, map, or fallback.
        source = TOOL.read_text(encoding="utf-8")
        self.assertNotIn("DISTRIBUTION_DISPLAY_LABELS", source)
        for section in ("distributions", "protocols"):
            for label in load_authoritative_map()[section].values():
                self.assertNotIn(
                    label, source, "label value %r must not be embedded in the tool" % label
                )

    def test_presentation_map_covers_current_manifest_ids_exactly(self) -> None:
        manifest = docs.load_manifest(self.manifest_path)
        labels = load_authoritative_map()
        distributions = labels["distributions"]
        manifest_ids = set(manifest["distributions"])
        self.assertEqual(set(distributions), manifest_ids)
        for dist_id, label in distributions.items():
            self.assertIsInstance(label, str)
            self.assertTrue(label.strip(), "empty label for %r" % dist_id)

        # Valid coverage builds the full projection without error.
        projection = docs.build_public_projection(
            manifest, now=datetime(2026, 9, 22, 0, 0, 0), presentation_map=labels
        )
        row_ids = {row["distribution_id"] for row in projection["rows"]}
        self.assertTrue(row_ids)
        self.assertLessEqual(row_ids, manifest_ids)
        # A distribution appears if it is rolling or has at least one release.
        expected_ids = {
            dist_id
            for dist_id, dist in manifest["distributions"].items()
            if dist["release_model"] == "rolling"
        } | {rel["distribution"] for rel in manifest["releases"].values()}
        self.assertEqual(expected_ids, row_ids)

    def _mutated_map(self, mutate) -> Path:
        document = json.loads(PRESENTATION_MAP.read_text(encoding="utf-8"))
        mutate(document)
        path = self.base / "presentation_bad.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def _assert_fail_closed_no_write(self, map_path: Path, expected_fragment: str) -> None:
        root = self._fixture()
        path = root / "doc.md"
        before = path.read_bytes()
        for runner in (self._generate, self._check):
            result = runner(root, map_path)
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn(expected_fragment, result.stderr)
            self.assertEqual(path.read_bytes(), before, "no write on failure")

    def test_missing_presentation_map_fails_closed_no_write(self) -> None:
        missing = self.base / "does-not-exist.json"
        self._assert_fail_closed_no_write(missing, "cannot read distribution presentation map")

    def test_malformed_presentation_map_fails_closed_no_write(self) -> None:
        path = self.base / "malformed.json"
        path.write_text("{ not json", encoding="utf-8")
        self._assert_fail_closed_no_write(path, "malformed distribution presentation map")

    def test_unsupported_schema_version_fails_closed_no_write(self) -> None:
        path = self._mutated_map(lambda doc: doc.__setitem__("schema_version", "9.9.9"))
        self._assert_fail_closed_no_write(path, "unsupported presentation map schema_version")

    def test_missing_manifest_id_fails_closed_no_write(self) -> None:
        def drop_one(document: dict) -> None:
            del document["distributions"][sorted(document["distributions"])[0]]

        path = self._mutated_map(drop_one)
        self._assert_fail_closed_no_write(path, "must match the manifest id set exactly")

    def test_extra_unknown_id_fails_closed_no_write(self) -> None:
        path = self._mutated_map(
            lambda doc: doc["distributions"].__setitem__("not_a_real_distro", "Not Real")
        )
        self._assert_fail_closed_no_write(path, "must match the manifest id set exactly")

    def test_empty_label_fails_closed_no_write(self) -> None:
        def blank(document: dict) -> None:
            document["distributions"][sorted(document["distributions"])[0]] = ""

        self._assert_fail_closed_no_write(self._mutated_map(blank), "non-empty string")

    def test_non_string_label_fails_closed_no_write(self) -> None:
        def numeric(document: dict) -> None:
            document["distributions"][sorted(document["distributions"])[0]] = 5

        self._assert_fail_closed_no_write(self._mutated_map(numeric), "non-empty string")

    # ------------------------------------------------------------------ #
    # Generation, check mode, markers, determinism, privacy.
    # ------------------------------------------------------------------ #
    def test_two_consecutive_generate_runs_are_byte_identical(self) -> None:
        root = self._fixture()
        first = self._generate(root)
        self.assertEqual(first.returncode, 0, first.stderr)
        bytes_1 = (root / "doc.md").read_bytes()
        second = self._generate(root)
        self.assertEqual(second.returncode, 0, second.stderr)
        bytes_2 = (root / "doc.md").read_bytes()
        self.assertEqual(bytes_1, bytes_2)

    def test_real_repository_check_passes_with_managed_regions(self) -> None:
        # 12B.2 wires managed regions into the public surfaces; the checked-in
        # repository must already be in sync with the generator.
        result = run_tool(["--check"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("files_with_markers=", result.stdout)
        self.assertNotIn("files_with_markers=0", result.stdout)
        self.assertNotIn("drift", result.stderr)

    def test_check_passes_after_generate_and_detects_controlled_drift(self) -> None:
        root = self._fixture()
        gen = self._generate(root)
        self.assertEqual(gen.returncode, 0, gen.stderr)
        ok = self._check(root)
        self.assertEqual(ok.returncode, 0, ok.stderr)

        path = root / "doc.md"
        original = path.read_bytes()
        text = original.decode("utf-8")
        start, end = region_span(text, "compat-support-table")
        drifted = text[:start] + "TAMPERED\n" + text[end:]
        path.write_text(drifted, encoding="utf-8", newline="")
        after_drift = path.read_bytes()

        failed = self._check(root)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("drift", failed.stderr)
        self.assertEqual(path.read_bytes(), after_drift, "--check must not write")

    def test_malformed_marker_classes_fail_closed_without_write(self) -> None:
        cases = {
            "missing_end": (
                "<!-- BEGIN GENERATED: compat-protocol-list -->\ncontent\n"
            ),
            "missing_begin": (
                "outside\n<!-- END GENERATED: compat-protocol-list -->\n"
            ),
            "duplicate": (
                "<!-- BEGIN GENERATED: compat-protocol-list -->\n"
                "<!-- END GENERATED: compat-protocol-list -->\n"
                "<!-- BEGIN GENERATED: compat-protocol-list -->\n"
                "<!-- END GENERATED: compat-protocol-list -->\n"
            ),
            "nested": (
                "<!-- BEGIN GENERATED: compat-support-table -->\n"
                "<!-- BEGIN GENERATED: compat-protocol-list -->\n"
                "<!-- END GENERATED: compat-protocol-list -->\n"
                "<!-- END GENERATED: compat-support-table -->\n"
            ),
            "mismatched": (
                "<!-- BEGIN GENERATED: compat-support-table -->\n"
                "body\n"
                "<!-- END GENERATED: compat-protocol-list -->\n"
            ),
            "misordered": (
                "<!-- END GENERATED: compat-support-table -->\n"
                "<!-- BEGIN GENERATED: compat-support-table -->\n"
                "<!-- END GENERATED: compat-support-table -->\n"
            ),
        }
        for name, markdown in cases.items():
            with self.subTest(name=name):
                root = self._fixture(markdown=markdown)
                path = root / "doc.md"
                before = path.read_bytes()
                for runner in (self._generate, self._check):
                    result = runner(root)
                    self.assertNotEqual(result.returncode, 0, name)
                    self.assertEqual(path.read_bytes(), before, name)
                self.assertTrue(
                    "fail-closed" in (result.stderr or ""),
                    "expected fail-closed message, got: %r" % result.stderr,
                )

    def test_content_outside_regions_remains_byte_identical(self) -> None:
        root = self._fixture()
        before = (root / "doc.md").read_text(encoding="utf-8")
        gen = self._generate(root)
        self.assertEqual(gen.returncode, 0, gen.stderr)
        after = (root / "doc.md").read_text(encoding="utf-8")

        def outside_view(text: str) -> str:
            out = []
            cursor = 0
            for rid in ("compat-support-table", "compat-protocol-list"):
                begin = "<!-- BEGIN GENERATED: %s -->" % rid
                end = "<!-- END GENERATED: %s -->" % rid
                b = text.index(begin, cursor)
                e = text.index(end, cursor) + len(end)
                out.append(text[cursor:b])
                out.append(begin + "\n" + "<SENTINEL>" + "\n" + end)
                cursor = e
            out.append(text[cursor:])
            return "".join(out)

        self.assertEqual(outside_view(before), outside_view(after))
        self.assertIn("<!-- BEGIN GENERATED: compat-support-table -->", after)
        self.assertIn("<!-- END GENERATED: compat-support-table -->", after)
        self.assertIn("Outside before.", after)
        self.assertIn("Middle narrative must stay byte-identical.", after)
        self.assertIn("Outside after.", after)
        self.assertNotIn("STALE CONTENT THAT MUST BE REPLACED", after)

    def test_private_and_unsupported_fields_never_appear(self) -> None:
        manifest = docs.load_manifest(self.manifest_path)
        evidence_values: list[str] = []
        for cert in manifest["certifications"].values():
            if isinstance(cert.get("evidence"), str):
                evidence_values.append(cert["evidence"])
            for proto in (cert.get("protocol_results") or {}).values():
                if isinstance(proto.get("evidence"), str):
                    evidence_values.append(proto["evidence"])
                for key in proto:
                    if key != "disposition":
                        evidence_values.append(key)
        self.assertTrue(evidence_values)

        projection = docs.build_public_projection(
            manifest, now=datetime(2026, 9, 22, 0, 0, 0)
        )
        rendered = (
            docs.render_compat_support_table(projection)
            + docs.render_compat_protocol_list(projection)
        )
        for value in evidence_values:
            self.assertNotIn(value, rendered)
        self.assertNotIn("nls1", rendered)
        self.assertNotIn("/home/", rendered)
        self.assertNotIn("evidence_refs", rendered)

        # Default-deny: unexpected projection shape is rejected.
        bad = dict(projection)
        bad["raw_evidence"] = ["should not be allowed"]
        with self.assertRaises(docs.GeneratorError):
            docs._assert_projection_public(bad)

        bad_row = dict(projection["rows"][0])
        bad_row["evidence"] = "/home/gabodev/secret"
        bad_projection = {"rows": [bad_row], "protocol_ids": projection["protocol_ids"]}
        with self.assertRaises(docs.GeneratorError):
            docs._assert_projection_public(bad_projection)

    def test_protocol_map_covers_manifest_protocol_ids_exactly(self) -> None:
        manifest = docs.load_manifest(self.manifest_path)
        protocols = load_authoritative_protocols()
        manifest_ids = set(manifest["protocols"])
        self.assertEqual(set(protocols), manifest_ids)
        self.assertEqual(len(protocols), 12)
        for proto_id, label in protocols.items():
            self.assertIsInstance(label, str)
            self.assertTrue(label.strip(), "empty label for %r" % proto_id)

    def test_protocol_map_missing_id_fails_closed_no_write(self) -> None:
        def drop_one(document: dict) -> None:
            del document["protocols"][sorted(document["protocols"])[0]]

        path = self._mutated_map(drop_one)
        self._assert_fail_closed_no_write(path, "protocols presentation map must match")

    def test_protocol_map_unknown_id_fails_closed_no_write(self) -> None:
        path = self._mutated_map(
            lambda doc: doc["protocols"].__setitem__("not_a_real_protocol", "Not Real")
        )
        self._assert_fail_closed_no_write(path, "protocols presentation map must match")

    def test_protocol_map_empty_label_fails_closed_no_write(self) -> None:
        def blank(document: dict) -> None:
            document["protocols"][sorted(document["protocols"])[0]] = ""

        self._assert_fail_closed_no_write(self._mutated_map(blank), "protocols label for")

    def test_generated_regions_use_human_readable_protocol_names(self) -> None:
        manifest = docs.load_manifest(self.manifest_path)
        projection = docs.build_public_projection(
            manifest, now=datetime(2026, 9, 22, 0, 0, 0)
        )
        section = docs.render_compat_protocol_list(projection)
        for label in load_authoritative_protocols().values():
            self.assertIn(label, section, "human-readable name %r must appear" % label)
        self.assertIn("in scope for certified releases", section)
        self.assertIn("family_inferred", section)
        self.assertIn("experimental", section)
        # Raw ids must not be the primary presentation.
        self.assertNotIn("openvpn_cloak", section)

    def test_generated_tables_never_emit_green_or_ratio(self) -> None:
        manifest = docs.load_manifest(self.manifest_path)
        projection = docs.build_public_projection(
            manifest, now=datetime(2026, 9, 22, 0, 0, 0)
        )
        table = docs.render_compat_support_table(projection)
        section = docs.render_compat_protocol_list(projection)
        for rendered in (table, section):
            self.assertNotIn("green", rendered)
            self.assertNotIn("12/12", rendered)
        # A fully covered certified release uses the user-facing wording.
        certified = [r for r in projection["rows"] if r["support_classification"] == "certified"]
        self.assertTrue(certified)
        for row in certified:
            self.assertIn("in-scope protocols", row["protocol_summary"])

    def test_non_certified_releases_do_not_claim_protocol_coverage(self) -> None:
        manifest = docs.load_manifest(self.manifest_path)
        projection = docs.build_public_projection(
            manifest, now=datetime(2026, 9, 22, 0, 0, 0)
        )
        table = docs.render_compat_support_table(projection)
        for row in projection["rows"]:
            if row["support_classification"] != "certified":
                self.assertEqual(row["protocol_summary"], "—")
        rhel = next(r for r in projection["rows"] if r["distribution_id"] == "rhel")
        self.assertEqual(rhel["support_classification"], "family_inferred")
        self.assertEqual(rhel["protocol_summary"], "—")
        rhel_line = next(line for line in table.splitlines() if "family_inferred" in line)
        self.assertIn("| — |", rhel_line)
        self.assertNotIn("in-scope protocols", rhel_line)

    def test_family_inferred_and_rolling_claim_boundaries(self) -> None:
        manifest = docs.load_manifest(self.manifest_path)
        labels = load_authoritative_distributions()
        projection = docs.build_public_projection(
            manifest, now=datetime(2026, 9, 22, 0, 0, 0)
        )
        table = docs.render_compat_support_table(projection)

        rhel = next(r for r in projection["rows"] if r["distribution_id"] == "rhel")
        rhel_version = next(
            m["version"]
            for m in manifest["releases"].values()
            if m["distribution"] == "rhel"
        )
        self.assertEqual(rhel["support_classification"], "family_inferred")
        self.assertIsNone(rhel["certification_date"])
        rhel_line = next(
            line for line in table.splitlines() if labels["rhel"] in line and rhel_version in line
        )
        self.assertIn("| family_inferred |", rhel_line)
        self.assertNotIn("| certified |", rhel_line)

        # Claim-boundary: rolling rows must expose freshness/expiry.
        self.assertIn("Freshness", table.splitlines()[0])
        arch = next(r for r in projection["rows"] if r["distribution_id"] == "arch")
        arch_line = next(line for line in table.splitlines() if line.startswith("| %s |" % labels["arch"]))
        self.assertIn("rolling", arch_line)
        self.assertIn("certified", arch_line)
        self.assertIn(
            "%s (%s)" % (arch["rolling_freshness"], arch["rolling_expiry_window"]),
            arch_line,
        )

        ubuntu = next(r for r in projection["rows"] if r["distribution_id"] == "ubuntu")
        ubuntu_line = next(line for line in table.splitlines() if line.startswith("| %s |" % labels["ubuntu"]))
        self.assertIn("stable", ubuntu_line)
        self.assertNotIn("current (", ubuntu_line)

    def test_deterministic_order_lf_and_trailing_newline(self) -> None:
        manifest = docs.load_manifest(self.manifest_path)
        labels = load_authoritative_distributions()
        now = datetime(2026, 9, 22, 0, 0, 0)
        first = docs.build_public_projection(manifest, now=now)
        second = docs.build_public_projection(manifest, now=now)
        self.assertEqual(first, second)

        row_labels = [r["distribution_label"] for r in first["rows"]]
        self.assertEqual(row_labels, sorted(row_labels))
        self.assertEqual(first["protocol_ids"], sorted(first["protocol_ids"]))

        table = docs.render_compat_support_table(first)
        self.assertNotIn("\r", table)
        self.assertTrue(table.endswith("\n"))
        self.assertFalse(table.endswith("\n\n"))
        protos = docs.render_compat_protocol_list(first)
        self.assertNotIn("\r", protos)
        self.assertTrue(protos.endswith("\n"))
        self.assertFalse(protos.endswith("\n\n"))

        # Stable release label = map label + exact manifest version.
        ubuntu_version = next(
            m["version"] for m in manifest["releases"].values() if m["distribution"] == "ubuntu"
        )
        ubuntu_rows = [r for r in first["rows"] if r["distribution_id"] == "ubuntu"]
        self.assertIn("%s %s" % (labels["ubuntu"], ubuntu_version), {r["release_label"] for r in ubuntu_rows})

        # Rolling label = map label only.
        arch_rows = [r for r in first["rows"] if r["distribution_id"] == "arch"]
        self.assertEqual(arch_rows[0]["release_label"], labels["arch"])
        self.assertEqual(arch_rows[0]["release_model"], "rolling")

    def test_unknown_region_id_fails_closed(self) -> None:
        markdown = (
            "<!-- BEGIN GENERATED: not-a-known-region -->\n"
            "x\n"
            "<!-- END GENERATED: not-a-known-region -->\n"
        )
        root = self._fixture(markdown=markdown)
        path = root / "doc.md"
        before = path.read_bytes()
        result = self._generate(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown managed region", result.stderr)
        self.assertEqual(path.read_bytes(), before)

    def test_official_usage_requires_generate_or_check(self) -> None:
        result = run_tool([])
        self.assertEqual(result.returncode, docs.EXIT_USAGE)
        both = run_tool(["generate", "--check"])
        self.assertEqual(both.returncode, docs.EXIT_USAGE)

    def test_product_manifest_validate_still_ok(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "compat_read.py"), "validate"],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload.get("ok"))


if __name__ == "__main__":
    unittest.main()
