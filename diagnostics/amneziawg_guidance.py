"""Bridge CLI imports to the shared shell AmneziaWG guidance contract."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable


ROOT_DIR = Path(__file__).resolve().parents[1]


def dependency_guidance(
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    """Read the same distro-aware guidance used by doctor.sh without mutating.

    The shell helper sources lib/distro.sh, so distro aliases and adapters stay
    aligned with the installer instead of being reimplemented in Python.
    """

    script = (
        'source "$1/lib/common.sh"; '
        'source "$1/lib/distro.sh"; '
        'detect_distro; '
        'adapter="$(distro_adapter_path "$1")"; '
        'if [[ -r "$adapter" ]]; then source "$adapter"; fi; '
        'source "$1/lib/amneziawg.sh"; '
        'amneziawg_import_guidance_json'
    )
    try:
        result = run(
            ["bash", "-c", script, "watchdog-amneziawg-guidance", str(ROOT_DIR)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return _unavailable_guidance()
    if result.returncode != 0:
        return _unavailable_guidance()
    try:
        guidance = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return _unavailable_guidance()
    return guidance if isinstance(guidance, dict) else _unavailable_guidance()


def _unavailable_guidance() -> dict[str, object]:
    return {
        "available": False,
        "distro": "unknown",
        "distro_adapter": "unknown",
        "tools_available": False,
        "kernel_module_available": False,
        "userspace_fallback_available": False,
        "commands": [],
        "message": (
            "AmneziaWG profile saved, but runtime guidance could not be read.\n"
            "Run watchdog doctor before connecting."
        ),
    }
