#!/usr/bin/env python3
"""Fail-closed integrity, privacy, and editorial checks for public docs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import compat_public_docs  # noqa: E402

REGISTRY_PATH = ROOT / "compat" / "public_surfaces.json"
AUDIENCES = frozenset({"product", "technical_reference"})
SURFACE_KEYS = frozenset({"path", "type", "owner", "managed_region", "disposition"})
POLICY_KEYS = frozenset(
    {"default_audience", "audience_overrides", "privacy_exceptions", "editorial_exceptions"}
)
EXCEPTION_KEYS = frozenset({"surface", "rule", "value", "reason", "owner", "review_date"})
PUBLIC_TEXT_SUFFIXES = frozenset({".md", ".markdown", ".txt"})
PUBLISHABLE_MARKDOWN_SUFFIXES = frozenset({".md", ".markdown"})


class PolicyError(Exception):
    """A public documentation policy violation."""


@dataclass(frozen=True)
class Surface:
    path: str
    type: str
    disposition: str
    audience: str


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    value: str

    def message(self) -> str:
        return "%s:%d: %s" % (self.path, self.line, self.rule)


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError("cannot read registry %s: %s" % (path, exc)) from exc
    if not isinstance(value, dict):
        raise PolicyError("registry must be a JSON object")
    return value


def _validate_exceptions(items: object, name: str, known_paths: set[str]) -> dict[tuple[str, str], set[str]]:
    if not isinstance(items, list):
        raise PolicyError("%s must be a list" % name)
    allowed: dict[tuple[str, str], set[str]] = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != EXCEPTION_KEYS:
            raise PolicyError("%s entries must contain exactly %s" % (name, sorted(EXCEPTION_KEYS)))
        surface, rule, value = item["surface"], item["rule"], item["value"]
        if surface not in known_paths or not all(isinstance(v, str) and v.strip() for v in item.values()):
            raise PolicyError("%s contains an invalid exception" % name)
        review_date = item["review_date"]
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", review_date):
            raise PolicyError("%s review_date must be ISO YYYY-MM-DD" % name)
        try:
            date.fromisoformat(review_date)
        except ValueError as exc:
            raise PolicyError("%s review_date must be ISO YYYY-MM-DD" % name) from exc
        allowed.setdefault((surface, rule), set()).add(value)
    return allowed


def load_registry(path: Path = REGISTRY_PATH) -> tuple[list[Surface], dict[tuple[str, str], set[str]]]:
    document = _load_json(path)
    if set(document) != {"schema_version", "policy", "surfaces"}:
        raise PolicyError("registry keys must be schema_version, policy, and surfaces")
    if document.get("schema_version") != "1.0.0":
        raise PolicyError("unsupported registry schema_version")
    raw_surfaces = document["surfaces"]
    if not isinstance(raw_surfaces, list) or not raw_surfaces:
        raise PolicyError("registry surfaces must be a non-empty list")
    policy = document["policy"]
    if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
        raise PolicyError("registry policy keys are invalid")
    default = policy["default_audience"]
    overrides = policy["audience_overrides"]
    if default not in AUDIENCES or not isinstance(overrides, dict):
        raise PolicyError("registry audience policy is invalid")

    paths: set[str] = set()
    raw_by_path: dict[str, dict] = {}
    for item in raw_surfaces:
        if not isinstance(item, dict) or set(item) != SURFACE_KEYS:
            raise PolicyError("each surface must contain exactly %s" % sorted(SURFACE_KEYS))
        item_path = item["path"]
        if not isinstance(item_path, str) or not item_path or item_path in paths:
            raise PolicyError("surface paths must be unique non-empty strings")
        if not all(isinstance(item[key], str) and item[key] for key in ("type", "owner", "disposition")):
            raise PolicyError("surface metadata is invalid for %s" % item_path)
        paths.add(item_path)
        raw_by_path[item_path] = item
    if set(overrides) - paths or any(value not in AUDIENCES for value in overrides.values()):
        raise PolicyError("registry audience overrides are invalid")

    exceptions = {
        "privacy": _validate_exceptions(policy["privacy_exceptions"], "privacy_exceptions", paths),
        "editorial": _validate_exceptions(policy["editorial_exceptions"], "editorial_exceptions", paths),
    }
    return [
        Surface(item_path, raw_by_path[item_path]["type"], raw_by_path[item_path]["disposition"], overrides.get(item_path, default))
        for item_path in sorted(paths)
    ], exceptions


def iter_existing_surfaces(root: Path, surfaces: Iterable[Surface]) -> Iterable[tuple[Surface, str]]:
    for surface in surfaces:
        if surface.path.startswith("external:"):
            continue
        path = root / surface.path
        if not path.is_file():
            if surface.disposition != "MIGRATE_TO_VAULT":
                raise PolicyError("declared public surface is missing: %s" % surface.path)
            continue
        if path.suffix.lower() not in PUBLIC_TEXT_SUFFIXES:
            continue
        try:
            yield surface, path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PolicyError("cannot read public surface %s: %s" % (surface.path, exc)) from exc


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _is_excepted(
    exceptions: dict[str, dict[tuple[str, str], set[str]]], category: str, finding: Finding
) -> bool:
    return finding.value in exceptions[category].get((finding.path, finding.rule), set())


PRIVATE_PATTERNS = (
    ("private-path", re.compile(r"/(?:home|root)/[^\s`<>()]+")),
    ("private-host", re.compile(r"\b(?:nls\d+|wdvpn-l3-\d+)\b", re.IGNORECASE)),
    (
        "private-ipv4",
        re.compile(
            r"\b(?:10(?:\.\d{1,3}){3}|127(?:\.\d{1,3}){3}|169\.254(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b"
        ),
    ),
    (
        "private-ipv6",
        re.compile(
            r"(?i)(?<![0-9a-f:])(?:::1|fe[89ab][0-9a-f]{0,2}(?::[0-9a-f]{0,4}){1,7}|f[cd][0-9a-f]{0,2}(?::[0-9a-f]{0,4}){1,7})(?![0-9a-f:])"
        ),
    ),
    ("credential", re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[^\s`]+")),
    ("credential-uri", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)),
    ("authorization-credential", re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic|token)\s+[^\s`]+")),
)
EDITORIAL_PATTERNS = (
    ("internal-task", re.compile(r"(?i)\b(?:phase|task)\s+\d+(?:\.\d+)*(?:[a-z][a-z0-9.-]*)?\b")),
    ("internal-status", re.compile(r"(?i)\b(?:pending|closed_approved|closed\s*/\s*approved)\b")),
    ("evidence-route", re.compile(r"(?i)\b(?:phase23_evidence|chat_handoff|evidence route)\b")),
    ("private-path", re.compile(r"/(?:home|root)/[^\s`<>()]+")),
    ("internal-host", re.compile(r"\b(?:nls\d+|wdvpn-l3-\d+)\b", re.IGNORECASE)),
    ("internal-profile", re.compile(r"(?i)\b(?:internal|lab|test)[_-]?profile\b")),
    (
        "process-narrative",
        re.compile(r"\bCI\b|(?i:\b(?:continuous integration|tests?|testing|certification(?:\s+process)?)\b)"),
    ),
)


def scan_privacy(
    root: Path, surfaces: Iterable[Surface], exceptions: dict[str, dict[tuple[str, str], set[str]]]
) -> list[Finding]:
    findings: list[Finding] = []
    for surface, text in iter_existing_surfaces(root, surfaces):
        for rule, pattern in PRIVATE_PATTERNS:
            for match in pattern.finditer(text):
                finding = Finding(surface.path, _line_number(text, match.start()), rule, match.group(0))
                if not _is_excepted(exceptions, "privacy", finding):
                    findings.append(finding)
    return findings


def scan_editorial(
    root: Path, surfaces: Iterable[Surface], exceptions: dict[str, dict[tuple[str, str], set[str]]]
) -> list[Finding]:
    findings: list[Finding] = []
    for surface, text in iter_existing_surfaces(root, surfaces):
        if surface.audience != "product":
            continue
        generated_spans = [(start, end) for _region_id, start, end in compat_public_docs._parse_regions(text)]
        for rule, pattern in EDITORIAL_PATTERNS:
            for match in pattern.finditer(text):
                if any(start <= match.start() < end for start, end in generated_spans):
                    continue
                finding = Finding(surface.path, _line_number(text, match.start()), rule, match.group(0))
                if not _is_excepted(exceptions, "editorial", finding):
                    findings.append(finding)
    return findings


def check_claim_integrity(root: Path = ROOT) -> list[Finding]:
    manifest = compat_public_docs.load_manifest(root / "compat" / "compatibility.json")
    presentation = compat_public_docs.load_presentation_map(root / "compat" / "distribution_presentation.json")
    projection = compat_public_docs.build_public_projection(manifest, presentation_map=presentation)
    updates = compat_public_docs.plan_updates(root, projection)
    findings = [
        Finding(str(path.relative_to(root)), 1, "generated-drift", "managed region differs from source")
        for path, actual, expected in updates
        if actual != expected
    ]
    findings.extend(validate_projection_claims(projection))
    return findings


def validate_projection_claims(projection: dict) -> list[Finding]:
    """Validate claim-bearing projection fields before they become prose."""
    findings: list[Finding] = []
    protocol_count = len(projection.get("protocol_ids", []))
    for row in projection.get("rows", []):
        path = "compatibility-projection"
        classification = row.get("support_classification")
        certification = row.get("certification_date")
        summary = str(row.get("protocol_summary") or "")
        if classification == "family_inferred" and certification is not None:
            findings.append(Finding(path, 1, "family-inferred-certified", str(row.get("release_label"))))
        if row.get("release_model") == "rolling" and classification == "certified" and row.get("rolling_freshness") != "current":
            findings.append(Finding(path, 1, "stale-rolling-current", str(row.get("release_label"))))
        if summary.startswith("All "):
            match = re.fullmatch(r"All (\d+) in-scope protocols", summary)
            if match is None or int(match.group(1)) != protocol_count:
                findings.append(Finding(path, 1, "incomplete-matrix-all-green", summary))
    return findings


def discover_unregistered_candidates(root: Path, surfaces: Iterable[Surface]) -> list[str]:
    declared = {surface.path for surface in surfaces}
    candidates: list[str] = []
    candidate_paths = [path for path in root.iterdir() if path.is_file() and path.suffix.lower() in PUBLISHABLE_MARKDOWN_SUFFIXES]
    for directory in ("docs", "distros"):
        base = root / directory
        if base.is_dir():
            candidate_paths.extend(
                path for path in base.rglob("*") if path.is_file() and path.suffix.lower() in PUBLISHABLE_MARKDOWN_SUFFIXES
            )
    for path in sorted(set(candidate_paths)):
        relative = path.relative_to(root).as_posix()
        if relative not in declared:
            candidates.append(relative)
    return candidates


def check(root: Path = ROOT) -> list[Finding]:
    surfaces, exceptions = load_registry(root / "compat" / "public_surfaces.json")
    findings = check_claim_integrity(root)
    findings.extend(Finding(path, 1, "unregistered-surface", "public document is absent from registry") for path in discover_unregistered_candidates(root, surfaces))
    findings.extend(scan_privacy(root, surfaces, exceptions))
    findings.extend(scan_editorial(root, surfaces, exceptions))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check",))
    args = parser.parse_args(argv)
    findings = check()
    if findings:
        for finding in findings:
            print(finding.message(), file=sys.stderr)
        return 1
    print("public-policy: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
