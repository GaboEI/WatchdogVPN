from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile


@dataclass(slots=True)
class _BinaryPaths:
    sing_box: tuple[str, str, str] = (
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        os.path.expanduser("~/.local/bin/sing-box"),
    )


class SingBoxDriver(BaseDriver):
    """sing-box integration entry point.

    Task 4.1 only covers binary detection and version inspection. Process
    management and connectivity logic are intentionally deferred to later tasks.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()

    def find_singbox_binary(self) -> str | None:
        for candidate in self.binaries.sing_box:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return shutil.which("sing-box")

    def check_version(self) -> str:
        binary = self.find_singbox_binary()
        if not binary:
            raise FileNotFoundError("sing-box binary not found")
        result = subprocess.run([binary, "version"], text=True, capture_output=True, check=False)
        output = (result.stdout or result.stderr or "").strip()
        if not output:
            raise RuntimeError("sing-box version output is empty")
        return output

    def is_available(self) -> bool:
        return self.find_singbox_binary() is not None

    def connect(self, profile: Profile) -> bool:
        raise NotImplementedError("Task 4.1 does not implement connect yet")

    def disconnect(self) -> bool:
        raise NotImplementedError("Task 4.1 does not implement disconnect yet")

    def health_check(self) -> str:
        raise NotImplementedError("Task 4.1 does not implement health_check yet")

    def status(self) -> ConnectionState:
        raise NotImplementedError("Task 4.1 does not implement status yet")
