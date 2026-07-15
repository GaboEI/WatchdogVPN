#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import os
import subprocess
from pathlib import Path

from phase23_prepare_private_manifest import FIXTURE_FILES, main as prepare_manifest_main


MULTILINE_PROTOCOLS = {"wireguard", "amneziawg", "openvpn", "openvpn_cloak", "socks", "http"}


def _write_secret_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip("\n") + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def _open_editor(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("", encoding="utf-8")
        os.chmod(path, 0o600)
    editor = os.environ.get("EDITOR") or "nano"
    subprocess.run([editor, str(path)], check=False)
    os.chmod(path, 0o600)


def _choice(prompt: str, valid: set[str]) -> str:
    while True:
        answer = input(prompt).strip().lower()
        if answer in valid:
            return answer
        print(f"Choose one of: {', '.join(sorted(valid))}")


def _collect_profile(fixtures_dir: Path, protocol: str) -> None:
    path = fixtures_dir / FIXTURE_FILES[protocol]
    default_mode = "e" if protocol in MULTILINE_PROTOCOLS else "p"
    print()
    print(f"{protocol}: {path}")
    print("  p = paste one secret line without echo")
    print("  e = open editor for multi-line config")
    print("  k = keep existing file / skip")
    mode = _choice(f"Mode [{default_mode}]: ", {"", "p", "e", "k"}) or default_mode
    if mode == "k":
        return
    if mode == "e":
        _open_editor(path)
        return
    value = getpass.getpass(f"Paste {protocol} profile line: ")
    if not value.strip():
        print(f"Skipped empty {protocol} value")
        return
    _write_secret_file(path, value)


def _collect_provider_url(path: Path) -> None:
    print()
    print(f"provider_url: {path}")
    mode = _choice("Paste provider URL now? [y/N]: ", {"", "y", "n"}) or "n"
    if mode != "y":
        return
    value = getpass.getpass("Paste provider URL: ")
    if not value.strip():
        print("Skipped empty provider URL")
        return
    _write_secret_file(path, value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect private Phase 23 profile fixtures locally")
    parser.add_argument("--fixtures-dir", type=Path, default=Path("/tmp/watchdogvpn-phase23-fixtures"))
    parser.add_argument("--provider-url-file", type=Path, default=Path("/tmp/watchdogvpn-phase23-provider-url.txt"))
    parser.add_argument("--skip-provider", action="store_true")
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="generate the manifest even when some protocol fixtures are not ready yet",
    )
    args = parser.parse_args()

    print("This helper writes private local files only.")
    print("Do not paste profile contents or provider URLs into chat.")
    print("Single-line paste uses hidden input; multi-line configs open your editor.")

    for protocol in FIXTURE_FILES:
        _collect_profile(args.fixtures_dir, protocol)

    if not args.skip_provider:
        _collect_provider_url(args.provider_url_file)

    print()
    print("Generating private manifest...")
    prepare_args = [
        "--fixtures-dir",
        str(args.fixtures_dir),
        "--provider-url-file",
        str(args.provider_url_file),
    ]
    if args.allow_missing:
        prepare_args.append("--allow-missing")
    return prepare_manifest_main(prepare_args)


if __name__ == "__main__":
    raise SystemExit(main())
