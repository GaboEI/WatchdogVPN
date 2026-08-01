"""Reporter for L2 compatibility matrix and repository-availability cron results.

Reads structured JSON results (produced by the L2 matrix harness or by the
read-only cron checks) and writes:

- compat-l2-matrix.json / compat-l2-matrix.md
- repo-availability-report.json

Also provides a CLI mode that executes the cron checks directly against
external repositories, artifacts, source tags and container registries.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.compat_read import load_manifest_file


DEFAULT_CONTAINER_RUNTIME = ("docker", "podman")
MATRIX_IMAGES = (
    "ubuntu:24.04",
    "ubuntu:26.04",
    "debian:13",
    "fedora:44",
    "rockylinux:9",
    "opensuse/leap:15.6",
    "archlinux:latest",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _head_url(url: str, timeout: int = 15) -> dict[str, Any]:
    """Perform a HEAD request and return a structured status."""
    try:
        request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "WatchdogVPN-compat-l2-cron/1.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {
                "status": "available",
                "http_status": response.status,
                "url": url,
                "evidence": "HEAD %d" % response.status,
            }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "status": "unavailable",
                "http_status": exc.code,
                "url": url,
                "evidence": "HEAD 404",
            }
        return {
            "status": "unknown",
            "http_status": exc.code,
            "url": url,
            "evidence": "HTTP error %d" % exc.code,
        }
    except urllib.error.URLError as exc:
        return {
            "status": "unknown",
            "url": url,
            "evidence": "URL error: %s" % exc.reason,
        }
    except Exception as exc:
        return {
            "status": "unknown",
            "url": url,
            "evidence": "request failed: %s" % exc,
        }


def _container_runtime() -> str | None:
    for name in DEFAULT_CONTAINER_RUNTIME:
        if shutil.which(name) is not None:
            return name
    return None


def _check_container_image(image: str, runtime: str | None) -> dict[str, Any]:
    if runtime is None:
        return {
            "category": "container_image",
            "name": image,
            "status": "unknown",
            "evidence": "no container runtime available for cron image check",
        }
    try:
        result = subprocess.run(
            [runtime, "manifest", "inspect", image],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            return {
                "category": "container_image",
                "name": image,
                "status": "available",
                "evidence": "%s manifest inspect succeeded" % runtime,
            }
        stderr = (result.stderr or "").lower()
        if "manifest unknown" in stderr or "not found" in stderr or "no such image" in stderr:
            return {
                "category": "container_image",
                "name": image,
                "status": "unavailable",
                "evidence": "%s manifest inspect reported image not found" % runtime,
            }
        return {
            "category": "container_image",
            "name": image,
            "status": "unknown",
            "evidence": "%s manifest inspect failed: %s" % (runtime, result.stderr.strip()[:200]),
        }
    except subprocess.TimeoutExpired:
        return {
            "category": "container_image",
            "name": image,
            "status": "unknown",
            "evidence": "%s manifest inspect timed out" % runtime,
        }
    except Exception as exc:
        return {
            "category": "container_image",
            "name": image,
            "status": "unknown",
            "evidence": "failed to invoke %s: %s" % (runtime, exc),
        }


def _load_manifest_for_cron() -> dict[str, Any]:
    """Load the product manifest from the canonical repository location."""
    root = Path(__file__).resolve().parent.parent
    return load_manifest_file(str(root / "compat" / "compatibility.json"), product_path=True)


def dnf_repository_series_path(series: str) -> str:
    """Return the path segment used by DNF repository metadata URLs."""
    if series.lower().startswith("epel"):
        return series[4:] or series
    return series


def _repo_url_for(candidate: dict[str, Any]) -> list[dict[str, str]]:
    """Derive the external repository URL(s) for a candidate."""
    repo = candidate.get("repository") or {}
    base_url = (repo.get("url") or "").rstrip("/")
    series = repo.get("series")
    if not base_url or not series:
        return []
    package_manager = candidate.get("package_manager")
    arches = candidate.get("architectures") or ["x86_64"]
    results = []
    if package_manager == "apt":
        results.append({
            "category": "external_repository",
            "name": "%s_%s" % (repo.get("id", "repo"), series),
            "url": "%s/dists/%s/Release" % (base_url, series),
        })
    elif package_manager == "dnf":
        series_path = dnf_repository_series_path(series)
        for arch in arches:
            results.append({
                "category": "external_repository",
                "name": "%s_%s_%s" % (repo.get("id", "repo"), series, arch),
                "url": "%s/%s/Everything/%s/repodata/repomd.xml" % (base_url, series_path, arch),
            })
    else:
        # Other package managers are not represented by external_repo_exact
        # candidates today; fail loudly rather than silently skipping.
        raise ValueError("unsupported package_manager for external_repo_exact cron URL: %r" % package_manager)
    return results


def _artifact_urls_for(candidate: dict[str, Any]) -> list[dict[str, str]]:
    """Derive artifact asset URLs from a candidate."""
    base_url = (candidate.get("official_download_base") or "").rstrip("/")
    if not base_url:
        return []
    results = []
    candidate_id = candidate.get("id", "artifact")
    for asset in candidate.get("assets", []):
        asset_name = asset.get("asset_name")
        if not asset_name:
            continue
        arch = asset.get("architecture", "unknown")
        results.append({
            "category": "artifact",
            "name": "%s_%s" % (candidate_id, arch),
            "url": "%s/%s" % (base_url, asset_name),
        })
    return results


def _source_urls_for(candidate: dict[str, Any]) -> list[dict[str, str]]:
    """Derive pinned source-build release-tag URLs from a candidate."""
    results = []
    candidate_id = candidate.get("id", "source")
    for component in candidate.get("components", []):
        repo = (component.get("repository") or "").rstrip("/")
        tag = component.get("tag")
        if not repo or not tag:
            continue
        component_id = component.get("component_id", "component")
        results.append({
            "category": "source",
            "name": "%s_%s" % (candidate_id, component_id),
            "url": "%s/releases/tag/%s" % (repo, tag),
        })
    return results


def _collect_cron_urls_from_manifest(manifest: dict[str, Any]) -> list[dict[str, str]]:
    """Return the list of external URLs the cron checks, derived from the manifest.

    The cron must track the exact versions, assets, repositories and tags the
    product manifest declares. Hardcoding them here would silently drift when the
    manifest is updated, which is exactly the failure mode this guardrail exists
    to prevent.
    """
    seen: set[str] = set()
    checks: list[dict[str, str]] = []
    for requirement in manifest.get("dependency_requirements", {}).values():
        for candidate in requirement.get("method_chain", []):
            kind = candidate.get("kind")
            collected: list[dict[str, str]] = []
            if kind == "external_repo_exact":
                collected = _repo_url_for(candidate)
            elif kind == "official_artifact_pinned":
                collected = _artifact_urls_for(candidate)
            elif kind == "pinned_source_build":
                collected = _source_urls_for(candidate)
            for entry in collected:
                url = entry["url"]
                if url in seen:
                    continue
                seen.add(url)
                checks.append(entry)
    return checks


def _collect_cron_urls() -> list[dict[str, str]]:
    """Backwards-compatible wrapper that loads the manifest and derives URLs."""
    return _collect_cron_urls_from_manifest(_load_manifest_for_cron())


def run_cron_checks() -> dict[str, Any]:
    """Execute the read-only cron checks and return a structured report."""
    runtime = _container_runtime()
    checks: list[dict[str, Any]] = []
    for image in MATRIX_IMAGES:
        checks.append(_check_container_image(image, runtime))
    for entry in _collect_cron_urls():
        result = _head_url(entry["url"])
        checks.append({
            "category": entry["category"],
            "name": entry["name"],
            "url": entry["url"],
            "status": result["status"],
            "evidence": result["evidence"],
        })
    summary = _summarize_cron(checks)
    return {
        "schema_version": "1.0.0",
        "report_kind": "repo_availability",
        "generated_at": _now_iso(),
        "summary": summary,
        "checks": checks,
    }


def _summarize_cron(checks: list[dict[str, Any]]) -> dict[str, int]:
    total = len(checks)
    available = sum(1 for c in checks if c["status"] == "available")
    unavailable = sum(1 for c in checks if c["status"] == "unavailable")
    unknown = total - available - unavailable
    return {
        "total": total,
        "available": available,
        "unavailable": unavailable,
        "unknown": unknown,
    }


def _summarize_matrix(targets: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(targets)
    available = sum(1 for t in targets if t.get("overall_status") == "available")
    image_not_found = sum(1 for t in targets if t.get("pull_status") == "image_not_found")
    unavailable = sum(1 for t in targets if t.get("overall_status") == "unavailable")
    return {
        "total_targets": total,
        "available": available,
        "unavailable": unavailable,
        "image_not_found": image_not_found,
    }


def build_matrix_report(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a normalized matrix report from a list of execute_l2_case results."""
    targets = []
    for raw in results:
        cleanup = raw.get("cleanup", {})
        targets.append(
            {
                "target": raw.get("target"),
                "image": raw.get("image"),
                "runtime": raw.get("runtime"),
                "overall_status": raw.get("overall_status"),
                "probe_aggregate": raw.get("probe_aggregate"),
                "pull_status": raw.get("pull", {}).get("status"),
                "os_release_status": raw.get("os_release", {}).get("status"),
                "package_manager_status": raw.get("package_manager", {}).get("status"),
                "metadata_refresh_status": raw.get("metadata_refresh", {}).get("status"),
                "cleanup_status": cleanup.get("status"),
                "residual_possible": cleanup.get("residual_possible", True),
                "limitations": raw.get("limitations", []),
                "dependency_decisions": raw.get("dependency_decisions", []),
                "resolver_package_queries": raw.get("resolver_package_queries", []),
            }
        )
    return {
        "schema_version": "1.0.0",
        "report_kind": "compat_l2_matrix",
        "generated_at": _now_iso(),
        "summary": _summarize_matrix(targets),
        "targets": targets,
    }


def render_matrix_markdown(report: dict[str, Any]) -> str:
    """Render a human-readable markdown summary of the matrix report."""
    summary = report["summary"]
    lines = [
        "# L2 Compatibility Matrix Report",
        "",
        "- Generated: %s" % report["generated_at"],
        "- Schema: %s" % report["schema_version"],
        "",
        "## Summary",
        "",
        "| Total targets | Available | Unavailable | Image not found |",
        "|--------------:|----------:|------------:|----------------:|",
        "| %d | %d | %d | %d |" % (
            summary["total_targets"],
            summary["available"],
            summary["unavailable"],
            summary["image_not_found"],
        ),
        "",
        "## Per-target results",
        "",
        "| Target | Image | Overall | Pull | OS release | Manager | Refresh | Cleanup | Residual | Limitations |",
        "|--------|-------|---------|------|------------|---------|---------|---------|----------|-------------|",
    ]
    for target in report["targets"]:
        limitations = ", ".join(target["limitations"]) if target["limitations"] else "-"
        if len(limitations) > 60:
            limitations = limitations[:57] + "..."
        lines.append(
            "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |"
            % (
                target["target"],
                target["image"],
                target["overall_status"],
                target["pull_status"],
                target["os_release_status"],
                target["package_manager_status"],
                target["metadata_refresh_status"],
                target["cleanup_status"],
                target["residual_possible"],
                limitations,
            )
        )
    lines.append("")
    lines.append("## Dependency decisions")
    lines.append("")
    for target in report["targets"]:
        lines.append("### %s" % target["target"])
        lines.append("")
        if not target["dependency_decisions"]:
            lines.append("_No dependency decisions recorded._")
            lines.append("")
            continue
        lines.append("| Dependency | Resolution | Selected method | Kind | Ready |")
        lines.append("|------------|------------|-----------------|------|-------|")
        for decision in target["dependency_decisions"]:
            lines.append(
                "| %s | %s | %s | %s | %s |"
                % (
                    decision["dependency_id"],
                    decision["resolution_status"],
                    decision["selected_method_id"] or "-",
                    decision["selected_method_kind"] or "-",
                    decision["execution_ready"],
                )
            )
        lines.append("")
    lines.append("")
    return "\n".join(lines)


def render_cron_markdown(report: dict[str, Any]) -> str:
    """Render a human-readable markdown summary of the cron report."""
    summary = report["summary"]
    lines = [
        "# Repository Availability Report",
        "",
        "- Generated: %s" % report["generated_at"],
        "- Schema: %s" % report["schema_version"],
        "",
        "## Summary",
        "",
        "| Total | Available | Unavailable | Unknown |",
        "|------:|----------:|------------:|--------:|",
        "| %d | %d | %d | %d |" % (
            summary["total"],
            summary["available"],
            summary["unavailable"],
            summary["unknown"],
        ),
        "",
        "## Checks",
        "",
        "| Category | Name | Status | URL | Evidence |",
        "|----------|------|--------|-----|----------|",
    ]
    for check in report["checks"]:
        url = check.get("url", "-")
        lines.append(
            "| %s | %s | %s | %s | %s |"
            % (
                check["category"],
                check["name"],
                check["status"],
                url,
                check["evidence"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def _load_json(path: str) -> Any:
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: str, data: Any) -> None:
    with Path(path).open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _write_text(path: str, text: str) -> None:
    with Path(path).open("w", encoding="utf-8") as f:
        f.write(text)


def _cmd_matrix(args: argparse.Namespace) -> int:
    data = _load_json(args.input)
    if not isinstance(data, list):
        print("error: matrix input must be a JSON array of case results", file=sys.stderr)
        return 1
    report = build_matrix_report(data)
    _write_json(args.json_output, report)
    if args.markdown_output:
        _write_text(args.markdown_output, render_matrix_markdown(report))
    return 0


def _cmd_cron(args: argparse.Namespace) -> int:
    if args.input:
        report = _load_json(args.input)
    else:
        report = run_cron_checks()
    if not isinstance(report, dict) or report.get("report_kind") != "repo_availability":
        print("error: cron input must be a repo_availability report", file=sys.stderr)
        return 1
    _write_json(args.json_output, report)
    if args.markdown_output:
        _write_text(args.markdown_output, render_cron_markdown(report))
    if args.fail_on_unavailable and report["summary"]["unavailable"] > 0:
        print("error: %d unavailable resources" % report["summary"]["unavailable"], file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="L2 compatibility reporter")
    subparsers = parser.add_subparsers(dest="command", required=True)

    matrix = subparsers.add_parser("matrix", help="Render a matrix report from raw L2 case results")
    matrix.add_argument("--input", required=True, help="Path to JSON array of execute_l2_case results")
    matrix.add_argument("--json-output", required=True, help="Path to write compat-l2-matrix.json")
    matrix.add_argument("--markdown-output", help="Path to write compat-l2-matrix.md")
    matrix.set_defaults(func=_cmd_matrix)

    cron = subparsers.add_parser("cron", help="Run or render a repository availability cron report")
    cron.add_argument("--input", help="Path to existing repo_availability JSON (omit to run checks)")
    cron.add_argument("--json-output", required=True, help="Path to write repo-availability-report.json")
    cron.add_argument("--markdown-output", help="Path to write repo-availability-report.md")
    cron.add_argument("--fail-on-unavailable", action="store_true", help="Exit non-zero if any check is unavailable")
    cron.set_defaults(func=_cmd_cron)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
