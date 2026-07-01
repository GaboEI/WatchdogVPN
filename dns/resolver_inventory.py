from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol


class ResolverManager(str, Enum):
    SYSTEMD_RESOLVED = "systemd-resolved"
    NETWORK_MANAGER = "networkmanager"
    RESOLV_CONF = "resolv_conf"
    UNKNOWN = "unknown"


class CommandRunner(Protocol):
    def __call__(self, command: list[str]) -> str:
        ...


@dataclass(slots=True)
class ResolverInventory:
    manager: ResolverManager
    resolv_conf_path: Path
    resolv_conf_target: str | None = None
    nameservers: list[str] = field(default_factory=list)
    search_domains: list[str] = field(default_factory=list)
    systemd_resolved_active: bool = False
    network_manager_active: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "manager": self.manager.value,
            "resolv_conf_path": str(self.resolv_conf_path),
            "resolv_conf_target": self.resolv_conf_target,
            "nameservers": list(self.nameservers),
            "search_domains": list(self.search_domains),
            "systemd_resolved_active": self.systemd_resolved_active,
            "network_manager_active": self.network_manager_active,
            "notes": list(self.notes),
        }


def _run(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.SubprocessError, TimeoutError):
        return ""
    return completed.stdout.strip()


def _service_active(service: str, runner: CommandRunner) -> bool:
    return runner(["systemctl", "is-active", service]).strip() == "active"


def _read_resolv_conf(path: Path) -> tuple[list[str], list[str], list[str]]:
    nameservers: list[str] = []
    search_domains: list[str] = []
    notes: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        notes.append("resolv.conf missing")
        return nameservers, search_domains, notes
    except OSError as exc:
        notes.append(f"resolv.conf unreadable: {exc}")
        return nameservers, search_domains, notes

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if parts[0] == "nameserver" and len(parts) >= 2:
            nameservers.append(parts[1])
        elif parts[0] == "search" and len(parts) >= 2:
            search_domains.extend(parts[1:])
        elif parts[0] == "domain" and len(parts) >= 2:
            search_domains.append(parts[1])
    return nameservers, search_domains, notes


def _resolv_conf_target(path: Path) -> str | None:
    if not path.is_symlink():
        return None
    try:
        return str(path.resolve())
    except OSError:
        return None


def detect_resolver_manager(
    resolv_conf_path: Path = Path("/etc/resolv.conf"),
    runner: CommandRunner = _run,
) -> ResolverInventory:
    nameservers, search_domains, notes = _read_resolv_conf(resolv_conf_path)
    target = _resolv_conf_target(resolv_conf_path)
    resolved_active = _service_active("systemd-resolved.service", runner)
    nm_active = _service_active("NetworkManager.service", runner)

    manager = ResolverManager.UNKNOWN
    if resolved_active or (target is not None and "/run/systemd/resolve/" in target):
        manager = ResolverManager.SYSTEMD_RESOLVED
    elif nm_active:
        manager = ResolverManager.NETWORK_MANAGER
    elif resolv_conf_path.exists():
        manager = ResolverManager.RESOLV_CONF

    if manager == ResolverManager.UNKNOWN:
        notes.append("no supported resolver manager detected")

    return ResolverInventory(
        manager=manager,
        resolv_conf_path=resolv_conf_path,
        resolv_conf_target=target,
        nameservers=nameservers,
        search_domains=search_domains,
        systemd_resolved_active=resolved_active,
        network_manager_active=nm_active,
        notes=notes,
    )
