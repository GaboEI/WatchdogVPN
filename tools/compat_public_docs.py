#!/usr/bin/env python3
"""Deterministic public compatibility documentation generator (Task 23.7.5.12B.1).

Official commands::

    python3 tools/compat_public_docs.py generate
    python3 tools/compat_public_docs.py --check

Managed region markers (exact syntax)::

    <!-- BEGIN GENERATED: <region-id> -->
    <!-- END GENERATED: <region-id> -->

``<region-id>`` matches ``[a-z0-9][a-z0-9-]*``. Missing, duplicated, nested,
mismatched, or misordered markers fail closed: non-zero exit and zero writes.

Only bytes inside valid managed regions may change. Content outside regions is
preserved byte-for-byte. Output regions are UTF-8, LF-only, deterministically
ordered, and end with a single trailing newline before the END marker.

The generator consumes only the normalized public projection defined by the
Task 12A.2 public projection allowlist. Raw evidence, private paths, hosts,
IPs, credentials, vault paths, and unapproved manifest fields are denied by
default and never rendered.

Public distribution display labels come only from the single authoritative,
versioned repository artifact ``compat/distribution_presentation.json``. That
artifact must match the manifest distribution id set exactly; a missing,
malformed, unsupported-schema, or mismatched map fails closed with zero writes.
No label value is embedded in this module, tests, fixtures, or any other file.

Region ids implemented by this gate (closed set; unknown ids fail closed):

- ``compat-support-table`` — allowlisted distribution/release support table.
- ``compat-protocol-list`` — sorted canonical protocol ids.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from compat import (  # noqa: E402
    RollingFacts,
    StableReleaseFacts,
    classify_support_rolling,
    classify_support_stable,
    support_model,
)
from tools import compat_read  # noqa: E402

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

REGION_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
BEGIN_STRICT_RE = re.compile(r"<!-- BEGIN GENERATED: ([a-z0-9][a-z0-9-]*) -->")
END_STRICT_RE = re.compile(r"<!-- END GENERATED: ([a-z0-9][a-z0-9-]*) -->")
BEGIN_LOOSE_RE = re.compile(r"<!--\s*BEGIN GENERATED:")
END_LOOSE_RE = re.compile(r"<!--\s*END GENERATED:")

# Single authoritative, versioned, machine-readable Distribution Presentation
# Map. Presentation-only; it is not a source of support, certification, policy,
# or classification facts. The mapping values live ONLY in this repository
# artifact; no copy exists in this module, tests, fixtures, or any other file.
PRESENTATION_MAP_PATH = ROOT / "compat" / "distribution_presentation.json"
PRESENTATION_MAP_SCHEMA_VERSION = "1.0.0"
PRESENTATION_MAP_TOP_LEVEL_KEYS = frozenset({"schema_version", "description", "distributions"})

SUPPORT_VALUES = frozenset(
    {"certified", "supported", "family_inferred", "experimental", "unsupported"}
)
RELEASE_MODELS = frozenset({"stable", "rolling"})
FRESHNESS_VALUES = frozenset({"current", "expired", "absent"})

# Structural denylist for defense-in-depth on rendered strings.
_PRIVATE_VALUE_PATTERNS = (
    re.compile(r"/home/"),
    re.compile(r"/root/"),
    re.compile(r"/var/lib/"),
    re.compile(r"phase23_evidence"),
    re.compile(r"temporales"),
    re.compile(r"chat_handoff"),
    re.compile(r"MASTER_PLAN"),
    re.compile(r"evidence_refs"),
    re.compile(r"\bevidence\b", re.IGNORECASE),
    re.compile(r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}\b"),
    re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b"),
    re.compile(r"\bnls1\b"),
    re.compile(r"\bwdvpn-l3-\d+\b"),
)


class GeneratorError(Exception):
    """Fail-closed generator error."""


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_manifest_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1]
    if "T" in text:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S")
    return datetime.strptime(text, "%Y-%m-%d")


def _iso_date(value: str) -> str:
    return _parse_manifest_timestamp(value).strftime("%Y-%m-%d")


def load_manifest(manifest_path: Path | None = None) -> dict:
    path = Path(manifest_path) if manifest_path else Path(compat_read.DEFAULT_MANIFEST_PATH)
    manifest = compat_read.load_manifest_file(path, product_path=manifest_path is None)
    compat_read.validate_manifest(manifest)
    return manifest


def load_presentation_map(path: Path | None = None) -> dict:
    """Load and strictly validate the single authoritative presentation map."""
    map_path = Path(path) if path else PRESENTATION_MAP_PATH
    try:
        raw = map_path.read_bytes()
    except OSError as exc:
        raise GeneratorError(
            "fail-closed: cannot read distribution presentation map %s: %s" % (map_path, exc)
        ) from exc
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise GeneratorError(
            "fail-closed: malformed distribution presentation map %s: %s" % (map_path, exc)
        ) from exc
    if not isinstance(document, dict):
        raise GeneratorError("fail-closed: presentation map must be a JSON object")
    if set(document) != PRESENTATION_MAP_TOP_LEVEL_KEYS:
        raise GeneratorError(
            "fail-closed: presentation map top-level keys must be exactly %s"
            % (sorted(PRESENTATION_MAP_TOP_LEVEL_KEYS),)
        )
    if document.get("schema_version") != PRESENTATION_MAP_SCHEMA_VERSION:
        raise GeneratorError(
            "fail-closed: unsupported presentation map schema_version %r (expected %r)"
            % (document.get("schema_version"), PRESENTATION_MAP_SCHEMA_VERSION)
        )
    mapping = document.get("distributions")
    if not isinstance(mapping, dict) or not mapping:
        raise GeneratorError(
            "fail-closed: presentation map distributions must be a non-empty object"
        )
    for key, value in mapping.items():
        if not isinstance(key, str) or not key:
            raise GeneratorError(
                "fail-closed: presentation map distribution id must be a non-empty string"
            )
        if not isinstance(value, str) or not value.strip():
            raise GeneratorError(
                "fail-closed: presentation map label for %r must be a non-empty string" % (key,)
            )
    return mapping


def _assert_presentation_map_covers_manifest(presentation_map: dict, manifest: dict) -> None:
    manifest_ids = set(manifest.get("distributions", {}))
    map_ids = set(presentation_map)
    missing = sorted(manifest_ids - map_ids)
    extra = sorted(map_ids - manifest_ids)
    if missing or extra:
        raise GeneratorError(
            "fail-closed: distribution presentation map must match the manifest id set "
            "exactly (missing=%s extra=%s)" % (missing, extra)
        )


def _distribution_label(dist_id: str, presentation_map: dict) -> str:
    try:
        return presentation_map[dist_id]
    except KeyError as exc:
        raise GeneratorError(
            "fail-closed: distribution id %r is absent from the Distribution Presentation Map"
            % (dist_id,)
        ) from exc


def _current_certifications(manifest: dict) -> list[tuple[str, dict]]:
    rows: list[tuple[str, dict]] = []
    for cert_id, cert in manifest.get("certifications", {}).items():
        if cert.get("current") is True:
            rows.append((cert_id, cert))
    rows.sort(key=lambda item: (item[1].get("date") or "", item[0]))
    return rows


def _select_cert(
    certs: Sequence[tuple[str, dict]],
    *,
    distribution: str,
    release_id: str | None,
    release_model: str,
) -> tuple[str, dict] | None:
    matches = [
        (cert_id, cert)
        for cert_id, cert in certs
        if cert.get("distribution") == distribution
        and (
            (release_model == "rolling" and not cert.get("release"))
            or (release_id is not None and cert.get("release") == release_id)
        )
    ]
    if not matches:
        return None
    # Deterministic pick: latest date, then highest cert id.
    matches.sort(key=lambda item: (item[1].get("date") or "", item[0]))
    return matches[-1]


def _stable_classification(manifest: dict, release_id: str) -> str:
    data = compat_read._stable_facts(manifest, release_id)
    return classify_support_stable(StableReleaseFacts(**data["facts"])).value


def _rolling_classification(manifest: dict, dist_id: str, now: datetime) -> tuple[str, dict]:
    data = compat_read._rolling_facts(manifest, dist_id)
    payload = dict(data["facts"])
    last_validated_raw = payload.get("last_validated")
    last_validated = None
    if last_validated_raw is not None:
        last_validated = _parse_manifest_timestamp(str(last_validated_raw))
        payload["last_validated"] = last_validated
    classification = classify_support_rolling(
        RollingFacts(**payload),
        expiry=timedelta(seconds=int(data["expiry_seconds"])),
        now=now,
    ).value
    return classification, {
        "last_validated": last_validated,
        "expiry_seconds": int(data["expiry_seconds"]),
    }


def _rolling_freshness_at(rolling_meta: dict, now: datetime) -> tuple[str, str]:
    last_validated = rolling_meta.get("last_validated")
    expiry_seconds = int(rolling_meta["expiry_seconds"])
    if last_validated is None:
        state = "absent"
    else:
        state = support_model.evaluate_freshness(
            last_validated, timedelta(seconds=expiry_seconds), now
        ).value
    return state, _format_expiry_window(expiry_seconds)


def _format_expiry_window(expiry_seconds: int) -> str:
    if expiry_seconds % 86400 == 0:
        days = expiry_seconds // 86400
        return "%d days" % days if days != 1 else "1 day"
    return "%d seconds" % expiry_seconds


def _protocol_summary(cert: dict | None, protocol_ids: Sequence[str]) -> str:
    if cert is None:
        return "—"
    results = cert.get("protocol_results") or {}
    if not results:
        return "—"
    green = 0
    total = 0
    for proto_id in protocol_ids:
        if proto_id not in results:
            continue
        total += 1
        disposition = results[proto_id].get("disposition")
        if disposition == "green":
            green += 1
    if total == 0:
        return "—"
    return "%d/%d green" % (green, total)


def build_public_projection(
    manifest: dict,
    *,
    now: datetime | None = None,
    presentation_map: dict | None = None,
) -> dict:
    """Build the normalized typed public projection under the 12A.2 allowlist."""
    if now is None:
        now = _utc_now_naive()
    if presentation_map is None:
        presentation_map = load_presentation_map()
    _assert_presentation_map_covers_manifest(presentation_map, manifest)

    protocol_ids = sorted(manifest.get("protocols", {}).keys())
    if not protocol_ids:
        raise GeneratorError("fail-closed: manifest protocols list is empty")

    certs = _current_certifications(manifest)
    rows: list[dict] = []

    for dist_id, dist in sorted(manifest.get("distributions", {}).items(), key=lambda kv: kv[0]):
        release_model = dist.get("release_model")
        if release_model not in RELEASE_MODELS:
            raise GeneratorError(
                "fail-closed: unsupported release_model %r for %r" % (release_model, dist_id)
            )
        display = _distribution_label(dist_id, presentation_map)

        if release_model == "rolling":
            classification, rolling_meta = _rolling_classification(manifest, dist_id, now)
            freshness, expiry_window = _rolling_freshness_at(rolling_meta, now)
            cert = _select_cert(
                certs, distribution=dist_id, release_id=None, release_model="rolling"
            )
            cert_date = _iso_date(cert[1]["date"]) if cert else None
            rows.append(
                {
                    "distribution_id": dist_id,
                    "distribution_label": display,
                    "release_label": display,
                    "release_model": "rolling",
                    "support_classification": classification,
                    "certification_date": cert_date,
                    "rolling_freshness": freshness,
                    "rolling_expiry_window": expiry_window,
                    "protocol_summary": _protocol_summary(
                        cert[1] if cert else None, protocol_ids
                    ),
                }
            )
            continue

        release_ids = sorted(
            (
                rid
                for rid, rel in manifest.get("releases", {}).items()
                if rel.get("distribution") == dist_id
            ),
            key=lambda rid: str(manifest["releases"][rid].get("version") or rid),
        )
        for release_id in release_ids:
            release = manifest["releases"][release_id]
            version = release.get("version")
            if not isinstance(version, str) or not version:
                raise GeneratorError(
                    "fail-closed: missing or non-string version for release %r" % (release_id,)
                )
            classification = _stable_classification(manifest, release_id)
            cert = _select_cert(
                certs,
                distribution=dist_id,
                release_id=release_id,
                release_model="stable",
            )
            cert_date = _iso_date(cert[1]["date"]) if cert else None
            rows.append(
                {
                    "distribution_id": dist_id,
                    "distribution_label": display,
                    "release_label": "%s %s" % (display, version),
                    "release_model": "stable",
                    "support_classification": classification,
                    "certification_date": cert_date,
                    "rolling_freshness": None,
                    "rolling_expiry_window": None,
                    "protocol_summary": _protocol_summary(
                        cert[1] if cert else None, protocol_ids
                    ),
                }
            )

    rows.sort(key=lambda row: (row["distribution_label"], row["release_label"]))

    projection = {
        "rows": rows,
        "protocol_ids": list(protocol_ids),
    }
    _assert_projection_public(projection)
    return projection


def _iter_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def _assert_projection_public(projection: dict) -> None:
    allowed_row_keys = {
        "distribution_id",
        "distribution_label",
        "release_label",
        "release_model",
        "support_classification",
        "certification_date",
        "rolling_freshness",
        "rolling_expiry_window",
        "protocol_summary",
    }
    allowed_top = {"rows", "protocol_ids"}
    if set(projection) != allowed_top:
        raise GeneratorError(
            "fail-closed: unexpected projection top-level keys: %r" % (sorted(projection),)
        )
    for row in projection["rows"]:
        if set(row) != allowed_row_keys:
            raise GeneratorError(
                "fail-closed: unexpected projection row keys: %r" % (sorted(row),)
            )
        if row["support_classification"] not in SUPPORT_VALUES:
            raise GeneratorError(
                "fail-closed: unsupported classification %r" % (row["support_classification"],)
            )
        if row["release_model"] not in RELEASE_MODELS:
            raise GeneratorError(
                "fail-closed: unsupported release model %r" % (row["release_model"],)
            )
        if row["rolling_freshness"] is not None and row["rolling_freshness"] not in FRESHNESS_VALUES:
            raise GeneratorError(
                "fail-closed: unsupported freshness %r" % (row["rolling_freshness"],)
            )
        for text in _iter_strings(row):
            for pattern in _PRIVATE_VALUE_PATTERNS:
                if pattern.search(text):
                    raise GeneratorError(
                        "fail-closed: private or non-public value matched pattern %s in projection"
                        % (pattern.pattern,)
                    )


def render_compat_support_table(projection: dict) -> str:
    lines = [
        "| Distribution | Release | Model | Support | Certification | Freshness | Protocols |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in projection["rows"]:
        cert = row["certification_date"] or "—"
        if row["release_model"] == "rolling":
            freshness = row["rolling_freshness"] or "absent"
            expiry = row["rolling_expiry_window"] or "—"
            freshness_cell = "%s (%s)" % (freshness, expiry)
        else:
            freshness_cell = "—"
        lines.append(
            "| %s | %s | %s | %s | %s | %s | %s |"
            % (
                row["distribution_label"],
                row["release_label"],
                row["release_model"],
                row["support_classification"],
                cert,
                freshness_cell,
                row["protocol_summary"],
            )
        )
    return "\n".join(lines) + "\n"


def render_compat_protocol_list(projection: dict) -> str:
    return ", ".join(projection["protocol_ids"]) + "\n"


REGION_RENDERERS: dict[str, Callable[[dict], str]] = {
    "compat-support-table": render_compat_support_table,
    "compat-protocol-list": render_compat_protocol_list,
}


class _Marker:
    __slots__ = ("kind", "region_id", "start", "end")

    def __init__(self, kind: str, region_id: str, start: int, end: int) -> None:
        self.kind = kind
        self.region_id = region_id
        self.start = start
        self.end = end


def _scan_markers(text: str) -> list[_Marker]:
    markers: list[_Marker] = []
    for match in BEGIN_LOOSE_RE.finditer(text):
        strict = BEGIN_STRICT_RE.match(text, match.start())
        if not strict:
            raise GeneratorError(
                "fail-closed: malformed or invalid BEGIN marker at offset %d" % match.start()
            )
        markers.append(_Marker("begin", strict.group(1), strict.start(), strict.end()))
    for match in END_LOOSE_RE.finditer(text):
        strict = END_STRICT_RE.match(text, match.start())
        if not strict:
            raise GeneratorError(
                "fail-closed: malformed or invalid END marker at offset %d" % match.start()
            )
        markers.append(_Marker("end", strict.group(1), strict.start(), strict.end()))
    markers.sort(key=lambda marker: (marker.start, 0 if marker.kind == "begin" else 1))
    return markers


def _parse_regions(text: str) -> list[tuple[str, int, int]]:
    """Return (region_id, content_start, content_end) spans; raise on any defect."""
    markers = _scan_markers(text)
    if not markers:
        return []

    open_stack: list[_Marker] = []
    seen_ids: set[str] = set()
    spans: list[tuple[str, int, int]] = []

    for marker in markers:
        if marker.kind == "begin":
            if open_stack:
                raise GeneratorError(
                    "fail-closed: nested managed region %r inside open region %r"
                    % (marker.region_id, open_stack[-1].region_id)
                )
            if marker.region_id in seen_ids:
                raise GeneratorError(
                    "fail-closed: duplicated managed region id %r" % (marker.region_id,)
                )
            if not REGION_ID_RE.match(marker.region_id):
                raise GeneratorError(
                    "fail-closed: invalid managed region id %r" % (marker.region_id,)
                )
            seen_ids.add(marker.region_id)
            open_stack.append(marker)
            continue

        # end marker
        if not open_stack:
            raise GeneratorError(
                "fail-closed: END marker without matching BEGIN for region %r"
                % (marker.region_id,)
            )
        current = open_stack.pop()
        if current.region_id != marker.region_id:
            raise GeneratorError(
                "fail-closed: mismatched END marker %r for open region %r"
                % (marker.region_id, current.region_id)
            )
        content_start = current.end
        # Include the newline that terminates the BEGIN marker line, if present.
        if content_start < len(text) and text[content_start] == "\n":
            content_start += 1
        elif content_start + 1 < len(text) and text[content_start : content_start + 2] == "\r\n":
            content_start += 2
        content_end = marker.start
        # Exclude the newline that terminates the last content line before END.
        if content_end > content_start and text[content_end - 1] == "\n":
            content_end -= 1
            if content_end > content_start and text[content_end - 1] == "\r":
                content_end -= 1
        spans.append((current.region_id, content_start, content_end))

    if open_stack:
        raise GeneratorError(
            "fail-closed: missing END marker for region %r" % (open_stack[-1].region_id,)
        )
    return spans


def _normalize_region_body(body: str) -> str:
    text = body.replace("\r\n", "\n").replace("\r", "\n")
    text = text.strip("\n")
    if not text:
        return ""
    return text + "\n"


def apply_regions(text: str, projection: dict) -> str:
    spans = _parse_regions(text)
    if not spans:
        return text

    pieces: list[str] = []
    cursor = 0
    for region_id, content_start, content_end in spans:
        renderer = REGION_RENDERERS.get(region_id)
        if renderer is None:
            raise GeneratorError(
                "fail-closed: unknown managed region id %r (known: %s)"
                % (region_id, ", ".join(sorted(REGION_RENDERERS)))
            )
        rendered = _normalize_region_body(renderer(projection))
        for pattern in _PRIVATE_VALUE_PATTERNS:
            if pattern.search(rendered):
                raise GeneratorError(
                    "fail-closed: rendered region %r matched forbidden pattern %s"
                    % (region_id, pattern.pattern)
                )
        pieces.append(text[cursor:content_start])
        pieces.append(rendered)
        cursor = content_end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _is_candidate_file(path: Path) -> bool:
    parts = set(path.parts)
    if ".git" in parts or "__pycache__" in parts or "node_modules" in parts:
        return False
    return path.suffix.lower() in {".md", ".markdown", ".txt"}


def discover_candidate_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if _is_candidate_file(root) else []
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and _is_candidate_file(path):
            found.append(path)
    return found


def _read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise GeneratorError("fail-closed: cannot read %s: %s" % (path, exc)) from exc
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GeneratorError("fail-closed: non-UTF-8 file %s" % (path,)) from exc


def plan_updates(root: Path, projection: dict) -> list[tuple[Path, str, str]]:
    """Validate markers and compute expected contents without writing."""
    updates: list[tuple[Path, str, str]] = []
    for path in discover_candidate_files(root):
        original = _read_text(path)
        if not BEGIN_LOOSE_RE.search(original) and not END_LOOSE_RE.search(original):
            continue
        expected = apply_regions(original, projection)
        updates.append((path, original, expected))
    return updates


def cmd_generate(root: Path, manifest_path: Path | None, presentation_map_path: Path | None) -> int:
    manifest = load_manifest(manifest_path)
    presentation_map = load_presentation_map(presentation_map_path)
    projection = build_public_projection(manifest, presentation_map=presentation_map)
    try:
        updates = plan_updates(root, projection)
    except GeneratorError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_FAILURE

    written = 0
    for path, original, expected in updates:
        if original == expected:
            continue
        path.write_bytes(expected.encode("utf-8"))
        written += 1
    print(
        "generate: files_scanned_with_markers=%d files_written=%d"
        % (len(updates), written)
    )
    return EXIT_OK


def cmd_check(root: Path, manifest_path: Path | None, presentation_map_path: Path | None) -> int:
    manifest = load_manifest(manifest_path)
    presentation_map = load_presentation_map(presentation_map_path)
    projection = build_public_projection(manifest, presentation_map=presentation_map)
    try:
        updates = plan_updates(root, projection)
    except GeneratorError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_FAILURE

    drifted: list[str] = []
    for path, original, expected in updates:
        if original != expected:
            drifted.append(str(path))
    if drifted:
        for item in drifted:
            print("check: drift in %s" % item, file=sys.stderr)
        print("check: %d file(s) drifted" % len(drifted), file=sys.stderr)
        return EXIT_FAILURE
    print("check: ok files_with_markers=%d" % len(updates))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deterministic public compatibility documentation generator."
    )
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("generate",),
        help="write managed regions (official: generate)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="read-only verification; never writes files",
    )
    parser.add_argument(
        "--root",
        default=str(ROOT),
        help="tree to scan for managed regions (default: repository root)",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="optional manifest path override (tests/fixtures)",
    )
    parser.add_argument(
        "--presentation-map",
        default=None,
        help="optional presentation map override (default: compat/distribution_presentation.json)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.check and args.mode:
        print("error: use either --check or generate, not both", file=sys.stderr)
        return EXIT_USAGE
    if not args.check and args.mode != "generate":
        parser.print_usage(sys.stderr)
        print("error: expected 'generate' or '--check'", file=sys.stderr)
        return EXIT_USAGE

    root = Path(args.root)
    if not root.exists():
        print("error: root does not exist: %s" % root, file=sys.stderr)
        return EXIT_USAGE
    manifest_path = Path(args.manifest) if args.manifest else None
    presentation_map_path = Path(args.presentation_map) if args.presentation_map else None

    try:
        if args.check:
            return cmd_check(root, manifest_path, presentation_map_path)
        return cmd_generate(root, manifest_path, presentation_map_path)
    except GeneratorError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_FAILURE
    except Exception as exc:  # pragma: no cover - unexpected fail-closed path
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
