"""Run the real L2 per-family/release matrix and emit raw + rendered reports.

This script is the bridge between the test harness
(tests/test_compat_dependency_l2_real.py) and the reporter
(tools/compat_l2_reporter.py). It is intentionally separate from the reporter
so the reporter stays a pure transformation tool while this script owns the
execution side.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Allow importing the test module and project modules without running it as a test script.
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))
import test_compat_dependency_l2_real as l2

from compat import detection
from tools import compat_l2_reporter as reporter


def _detect_runtime() -> str | None:
    for name in ("podman", "docker"):
        if shutil.which(name):
            return name
    return None


def run_matrix() -> list[dict]:
    runtime = _detect_runtime()
    if runtime is None:
        raise RuntimeError("Container runtime unavailable — L2 matrix cannot run. This is a CI infrastructure failure, not a product test pass.")
    manifest = detection.load_product_manifest()
    results = []
    for case in l2.CASES:
        name = "watchdogvpn-l2-matrix-%s-%d" % (case["target"], int(time.time() * 1000))
        result = l2.execute_l2_matrix_case(runtime, case, name, manifest)
        results.append(result)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the L2 compatibility matrix")
    parser.add_argument("--raw-output", default="compat-l2-matrix-raw.json", help="Path for raw case results JSON")
    parser.add_argument("--json-output", default="compat-l2-matrix.json", help="Path for rendered matrix report JSON")
    parser.add_argument("--markdown-output", default="compat-l2-matrix.md", help="Path for rendered matrix report Markdown")
    parser.add_argument("--fail-on-red", action="store_true", help="Exit non-zero if any mandatory target is not green")
    args = parser.parse_args(argv)

    try:
        results = run_matrix()
    except RuntimeError as exc:
        # Produce a minimal artifact so the workflow can still upload it.
        results = [{
            "target": "ALL",
            "image": "",
            "runtime": None,
            "overall_status": "runtime_error",
            "probe_aggregate": "runtime_error",
            "pull": {"status": "runtime_error"},
            "os_release": {"status": "not_run"},
            "package_manager": {"status": "not_run"},
            "metadata_refresh": {"status": "not_run"},
            "cleanup": {"status": "not_needed", "residual_possible": False},
            "limitations": [str(exc)],
            "dependency_decisions": [],
            "resolver_package_queries": [],
        }]

    Path(args.raw_output).write_text(json.dumps(results, indent=2), encoding="utf-8")
    report = reporter.build_matrix_report(results)
    Path(args.json_output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    Path(args.markdown_output).write_text(reporter.render_matrix_markdown(report), encoding="utf-8")

    if args.fail_on_red:
        for result in results:
            case = next((c for c in l2.CASES if c["target"] == result["target"]), {})
            if l2.is_optional_image_exception(case, result):
                continue
            if result.get("overall_status") != "available":
                print("FAIL: target %s is %s" % (result["target"], result.get("overall_status")), file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
