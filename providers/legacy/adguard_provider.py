from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from models.profile import Profile, ProfileSource, ProtocolType
from providers.base import BaseProvider


@dataclass(slots=True)
class _BinaryPaths:
    adguard_cli: str = "/usr/local/bin/adguardvpn-cli"


class AdGuardProvider(BaseProvider):
    """Legacy AdGuard VPN provider integration.

    This provider preserves the current AdGuard-based workflow and exposes the
    provider-facing pieces that already exist in the shell tooling: CLI
    availability, installation guidance and the location inventory surfaced by
    the vendor client. It is retained only for v2 compatibility.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()

    def _adguard_cli(self) -> str:
        candidate = self.binaries.adguard_cli
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
        resolved = shutil.which("adguardvpn-cli")
        if resolved:
            return resolved
        return candidate

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, text=True, capture_output=True)

    def _locations(self) -> list[Profile]:
        result = self._run([self._adguard_cli(), "list-locations"])
        profiles: list[Profile] = []
        for line in result.stdout.splitlines():
            raw = line.strip()
            if not raw:
                continue
            if raw.lower().startswith("location") or raw.startswith("#"):
                continue
            tokens = raw.split()
            code = tokens[0].strip().upper() if tokens else ""
            if len(code) == 2 and code.isalpha():
                profiles.append(
                    Profile(
                        id=code,
                        name=code,
                        protocol=ProtocolType.ADGUARD,
                        config={"location": code, "raw": raw},
                        source=ProfileSource.MANUAL,
                    )
                )
        return profiles

    def load_profiles(self) -> list[Profile]:
        if not self.is_available():
            return []
        return self._locations()

    def update(self) -> bool:
        return self.is_available()

    def status(self) -> dict:
        cli = self._adguard_cli()
        available = self.is_available()
        result = {
            "provider": "adguard",
            "available": available,
            "cli": cli,
            "profiles": 0,
        }
        if available:
            result["profiles"] = len(self.load_profiles())
        return result

    def is_available(self) -> bool:
        return bool(shutil.which("adguardvpn-cli") or os.path.exists(self.binaries.adguard_cli))

