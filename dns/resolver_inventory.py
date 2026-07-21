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

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "ResolverInventory":
        return cls(
            manager=ResolverManager(str(data["manager"])),
            resolv_conf_path=Path(str(data["resolv_conf_path"])),
            resolv_conf_target=(
                str(data["resolv_conf_target"])
                if data.get("resolv_conf_target") is not None
                else None
            ),
            nameservers=[str(item) for item in data.get("nameservers", [])],
            search_domains=[str(item) for item in data.get("search_domains", [])],
            systemd_resolved_active=bool(data.get("systemd_resolved_active", False)),
            network_manager_active=bool(data.get("network_manager_active", False)),
            notes=[str(item) for item in data.get("notes", [])],
        )


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


def _network_manager_has_managed_non_loopback_connection(runner: CommandRunner) -> bool:
    output = runner(
        ["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "con", "show", "--active"]
    )
    for line in output.splitlines():
        fields = line.strip().split(":")
        if len(fields) < 3:
            continue
        _name, connection_type, device = fields[:3]
        if connection_type == "loopback" or device in {"", "lo"}:
            continue
        return True
    return False


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


def _resolv_conf_generated_by_network_manager(path: Path, target: str | None) -> bool:
    if target is not None and "/NetworkManager/" in target:
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:512]
    except OSError:
        return False
    return "NetworkManager" in head


def detect_resolver_manager(
    resolv_conf_path: Path = Path("/etc/resolv.conf"),
    runner: CommandRunner = _run,
) -> ResolverInventory:
    nameservers, search_domains, notes = _read_resolv_conf(resolv_conf_path)
    target = _resolv_conf_target(resolv_conf_path)
    resolved_active = _service_active("systemd-resolved.service", runner)
    nm_active = _service_active("NetworkManager.service", runner)
    nm_managed = (
        _network_manager_has_managed_non_loopback_connection(runner)
        if nm_active
        else False
    )
    nm_resolv_conf = _resolv_conf_generated_by_network_manager(resolv_conf_path, target)

    manager = ResolverManager.UNKNOWN
    if resolved_active or (target is not None and "/run/systemd/resolve/" in target):
        manager = ResolverManager.SYSTEMD_RESOLVED
    elif nm_managed and nm_resolv_conf:
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
