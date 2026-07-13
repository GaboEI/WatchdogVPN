#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from cli.command_inventory import (  # noqa: E402
    build_command_inventory,
    render_inventory_json,
    render_inventory_markdown,
)
from cli.main import _build_parser  # noqa: E402


JSON_SNAPSHOT = ROOT_DIR / "docs" / "generated" / "cli-command-inventory.json"
MARKDOWN_SNAPSHOT = ROOT_DIR / "docs" / "generated" / "cli-command-inventory.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate or verify the committed WatchdogVPN CLI inventory",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the committed inventory differs from the current parser",
    )
    args = parser.parse_args(argv)

    inventory = build_command_inventory(_build_parser())
    outputs = {
        JSON_SNAPSHOT: render_inventory_json(inventory),
        MARKDOWN_SNAPSHOT: render_inventory_markdown(inventory),
    }
    if args.check:
        stale = [path for path, content in outputs.items() if not _matches(path, content)]
        if stale:
            for path in stale:
                print(f"stale generated CLI inventory: {path.relative_to(ROOT_DIR)}", file=sys.stderr)
            print(
                "run: python3 scripts/generate_cli_inventory.py",
                file=sys.stderr,
            )
            return 1
        print(
            "CLI inventory parity verified: "
            f"{inventory['route_count']}/{inventory['route_count']} routes documented"
        )
        return 0

    for path, content in outputs.items():
        _atomic_write_text(path, content)
        print(f"wrote {path.relative_to(ROOT_DIR)}")
    print(f"documented CLI routes: {inventory['route_count']}")
    return 0


def _matches(path: Path, expected: str) -> bool:
    try:
        return path.read_text(encoding="utf-8") == expected
    except FileNotFoundError:
        return False


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.chmod(0o644)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
