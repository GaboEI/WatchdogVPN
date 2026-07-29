#!/usr/bin/env python3
"""Internal distro classifier for shell bootstrap (Task 23.7.5.7).

This is NOT a public WatchdogVPN CLI. It is a thin wrapper that exposes the
manifest+engine classification to the Bash bootstrap layer in lib/distro.sh.
It consumes the internal API of compat.detection and is allowed to change in
lock-step with that module during Phase 23.7.5.

The stable contract for the shell layer is the JSON shape emitted on stdout,
not the Python functions used underneath.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from compat import detection
from tools import compat_read


EXIT_USAGE = 1
EXIT_DETECTION_ERROR = 2


def _load_manifest(path: str | None):
    manifest_path = Path(path) if path else Path(compat_read.DEFAULT_MANIFEST_PATH)
    manifest = compat_read.load_manifest_file(manifest_path, product_path=path is None)
    compat_read.validate_manifest(manifest)
    return manifest


def _load_os_release(args) -> detection.OsReleaseData:
    if args.os_release:
        return detection.read_os_release(
            etc_path=Path(args.os_release),
            usr_path=Path(args.usr_os_release) if args.usr_os_release else Path(args.os_release),
        )
    return detection.read_os_release(
        usr_path=Path(args.usr_os_release) if args.usr_os_release else Path("/usr/lib/os-release"),
    )


def _support_classification_value(manifest, facts) -> str:
    """Return the support classification string for the given facts.

    This is an internal helper that mirrors detection.evaluate() without
    running capability probes, because the shell bootstrap only needs the
    classification and identity fields.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    classification = detection._support_classification(manifest, facts, now=now)
    return classification.value


def _build_payload(facts: detection.DistroFacts, support_classification: str) -> dict:
    return {
        "status": "ok",
        "distro_id": facts.id_normalized or facts.id_raw or "unknown",
        "distro_name": facts.pretty_name or "Unknown Linux",
        "adapter_id": facts.adapter or "unknown",
        "family_id": facts.technical_family or "unknown",
        "package_manager": facts.package_manager or "unknown",
        "release_model": facts.release_model or "unknown",
        "resolved_distribution": facts.resolved_distribution,
        "resolved_release": facts.resolved_release,
        "mapped_base_release": facts.mapped_base_release,
        "support_classification": support_classification,
        "resolution_status": facts.resolution_status or "unknown",
    }


def _print(value) -> None:
    print(detection.stable_json(detection.to_jsonable(value)))


def cmd_classify(args) -> int:
    manifest = _load_manifest(args.manifest)
    os_release = _load_os_release(args)
    env = detection.ProbeEnvironment()
    facts = detection.distro_facts_from_os_release(
        os_release,
        manifest,
        kernel_release=env.kernel_release,
        machine_architecture=env.machine_architecture,
    )
    support_classification = _support_classification_value(manifest, facts)
    _print(_build_payload(facts, support_classification))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", help="manifest path; defaults to product manifest")
    parser.add_argument("--os-release", help="explicit /etc/os-release fixture path")
    parser.add_argument("--usr-os-release", help="explicit /usr/lib/os-release fallback fixture path")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("classify").set_defaults(func=cmd_classify)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (compat_read.ManifestError, detection.DetectionError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_DETECTION_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
