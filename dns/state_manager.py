from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from config.paths import resolve_config_dir
from config.persistence import (
    PersistentStoreError,
    dump_json,
    file_lock,
    load_json,
    require_mapping,
)
from .resolver_inventory import (
    ResolverInventory,
    ResolverManager,
    detect_resolver_manager,
)


class DNSStateError(RuntimeError):
    pass


DEFAULT_DNS_SNAPSHOT_NAME = "dns-state.json"


def default_snapshot_path() -> Path:
    return Path(
        os.environ.get(
            "WATCHDOGVPN_DNS_SNAPSHOT_FILE",
            resolve_config_dir() / DEFAULT_DNS_SNAPSHOT_NAME,
        )
    )


def load_snapshot(path: Path) -> "DNSStateSnapshot | None":
    if not path.exists():
        return None
    try:
        with file_lock(path):
            data = require_mapping(load_json(path, {}), path)
            return DNSStateSnapshot.from_dict(data)
    except PersistentStoreError as exc:
        raise DNSStateError(str(exc)) from exc


def save_snapshot(path: Path, snapshot: "DNSStateSnapshot") -> None:
    try:
        with file_lock(path):
            dump_json(path, snapshot.to_dict())
    except PersistentStoreError as exc:
        raise DNSStateError(str(exc)) from exc


class DNSCommandRunner(Protocol):
    def __call__(self, command: list[str]) -> str:
        ...


@dataclass(frozen=True, slots=True)
class NetworkManagerConnectionState:
    name: str
    ipv4_dns: str = ""
    ipv4_ignore_auto_dns: str = "no"
    ipv4_dns_search: str = ""
    ipv6_dns: str = ""
    ipv6_ignore_auto_dns: str = "no"
    ipv6_dns_search: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "ipv4_dns": self.ipv4_dns,
            "ipv4_ignore_auto_dns": self.ipv4_ignore_auto_dns,
            "ipv4_dns_search": self.ipv4_dns_search,
            "ipv6_dns": self.ipv6_dns,
            "ipv6_ignore_auto_dns": self.ipv6_ignore_auto_dns,
            "ipv6_dns_search": self.ipv6_dns_search,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "NetworkManagerConnectionState":
        return cls(
            name=str(data["name"]),
            ipv4_dns=str(data.get("ipv4_dns", "")),
            ipv4_ignore_auto_dns=str(data.get("ipv4_ignore_auto_dns", "no")),
            ipv4_dns_search=str(data.get("ipv4_dns_search", "")),
            ipv6_dns=str(data.get("ipv6_dns", "")),
            ipv6_ignore_auto_dns=str(data.get("ipv6_ignore_auto_dns", "no")),
            ipv6_dns_search=str(data.get("ipv6_dns_search", "")),
        )


@dataclass(frozen=True, slots=True)
class DNSStateSnapshot:
    inventory: ResolverInventory
    resolv_conf_content: str | None = None
    resolv_conf_target: str | None = None
    network_manager_connections: tuple[NetworkManagerConnectionState, ...] = ()
    systemd_link: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "inventory": self.inventory.to_dict(),
            "resolv_conf_content": self.resolv_conf_content,
            "resolv_conf_target": self.resolv_conf_target,
            "network_manager_connections": [
                connection.to_dict()
                for connection in self.network_manager_connections
            ],
            "systemd_link": self.systemd_link,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "DNSStateSnapshot":
        raw_inventory = data.get("inventory")
        if not isinstance(raw_inventory, dict):
            raise ValueError("dns state snapshot requires inventory")
        raw_connections = data.get("network_manager_connections", [])
        if not isinstance(raw_connections, list):
            raise ValueError("dns state snapshot connections must be a list")
        return cls(
            inventory=ResolverInventory.from_dict(raw_inventory),
            resolv_conf_content=(
                str(data["resolv_conf_content"])
                if data.get("resolv_conf_content") is not None
                else None
            ),
            resolv_conf_target=(
                str(data["resolv_conf_target"])
                if data.get("resolv_conf_target") is not None
                else None
            ),
            network_manager_connections=tuple(
                NetworkManagerConnectionState.from_dict(item)
                for item in raw_connections
                if isinstance(item, dict)
            ),
            systemd_link=(
                str(data["systemd_link"])
                if data.get("systemd_link") is not None
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class LocalDNSEntryPoint:
    address: str = "127.0.0.1"
    port: int = 53
    systemd_link: str | None = None


class SystemDNSStateManager:
    def __init__(
        self,
        resolv_conf_path: Path = Path("/etc/resolv.conf"),
        runner: DNSCommandRunner | None = None,
        rescue_command: Path = Path("/usr/local/bin/vpn_dns_rescue"),
    ) -> None:
        self.resolv_conf_path = resolv_conf_path
        self.runner = runner or _run_command
        self.rescue_command = rescue_command

    def save_state(self, systemd_link: str | None = None) -> DNSStateSnapshot:
        inventory = detect_resolver_manager(
            resolv_conf_path=self.resolv_conf_path,
            runner=self.runner,
        )
        return DNSStateSnapshot(
            inventory=inventory,
            resolv_conf_content=_read_text(self.resolv_conf_path),
            resolv_conf_target=inventory.resolv_conf_target,
            network_manager_connections=self._save_network_manager_connections(
                inventory
            ),
            systemd_link=systemd_link,
        )

    def apply_local_dns(
        self,
        entrypoint: LocalDNSEntryPoint,
        snapshot: DNSStateSnapshot | None = None,
    ) -> DNSStateSnapshot:
        saved = snapshot or self.save_state(systemd_link=entrypoint.systemd_link)
        try:
            self._apply_for_manager(saved.inventory.manager, entrypoint, saved)
        except Exception as exc:
            self.restore_state(saved)
            raise DNSStateError("failed to apply local DNS entry point") from exc
        return saved

    def restore_state(self, snapshot: DNSStateSnapshot) -> None:
        manager = snapshot.inventory.manager
        if manager == ResolverManager.SYSTEMD_RESOLVED:
            self._restore_systemd_resolved(snapshot)
        elif manager == ResolverManager.NETWORK_MANAGER:
            self._restore_network_manager(snapshot)
        elif manager == ResolverManager.RESOLV_CONF:
            self._restore_resolv_conf(snapshot)
        else:
            self.run_rescue_fallback()

    def run_rescue_fallback(self, mode: str = "auto") -> str:
        return self.runner([str(self.rescue_command), mode, "--no-reconnect"])

    def _apply_for_manager(
        self,
        manager: ResolverManager,
        entrypoint: LocalDNSEntryPoint,
        snapshot: DNSStateSnapshot,
    ) -> None:
        if manager == ResolverManager.SYSTEMD_RESOLVED:
            self._apply_systemd_resolved(entrypoint, snapshot)
        elif manager == ResolverManager.NETWORK_MANAGER:
            self._apply_network_manager(entrypoint, snapshot)
        elif manager == ResolverManager.RESOLV_CONF:
            self._write_resolv_conf(entrypoint)
        else:
            raise DNSStateError("unsupported resolver manager")

    def _save_network_manager_connections(
        self,
        inventory: ResolverInventory,
    ) -> tuple[NetworkManagerConnectionState, ...]:
        if not inventory.network_manager_active:
            return ()
        names_output = self.runner(["nmcli", "-t", "-f", "NAME", "con", "show", "--active"])
        states: list[NetworkManagerConnectionState] = []
        for name in [line.strip() for line in names_output.splitlines() if line.strip()]:
            values = self.runner(
                [
                    "nmcli",
                    "-g",
                    ",".join(
                        [
                            "ipv4.dns",
                            "ipv4.ignore-auto-dns",
                            "ipv4.dns-search",
                            "ipv6.dns",
                            "ipv6.ignore-auto-dns",
                            "ipv6.dns-search",
                        ]
                    ),
                    "con",
                    "show",
                    name,
                ]
            ).splitlines()
            values += [""] * (6 - len(values))
            states.append(
                NetworkManagerConnectionState(
                    name=name,
                    ipv4_dns=values[0],
                    ipv4_ignore_auto_dns=values[1] or "no",
                    ipv4_dns_search=values[2],
                    ipv6_dns=values[3],
                    ipv6_ignore_auto_dns=values[4] or "no",
                    ipv6_dns_search=values[5],
                )
            )
        return tuple(states)

    def _apply_systemd_resolved(
        self,
        entrypoint: LocalDNSEntryPoint,
        snapshot: DNSStateSnapshot,
    ) -> None:
        link = entrypoint.systemd_link or snapshot.systemd_link
        if not link:
            raise DNSStateError("systemd-resolved apply requires a link name")
        self.runner(["resolvectl", "dns", link, entrypoint.address])
        self.runner(["resolvectl", "domain", link, "~."])

    def _restore_systemd_resolved(self, snapshot: DNSStateSnapshot) -> None:
        link = snapshot.systemd_link
        if link:
            self.runner(["resolvectl", "revert", link])
        self._restore_resolv_conf(snapshot)

    def _apply_network_manager(
        self,
        entrypoint: LocalDNSEntryPoint,
        snapshot: DNSStateSnapshot,
    ) -> None:
        for connection in snapshot.network_manager_connections:
            self.runner(
                [
                    "nmcli",
                    "con",
                    "mod",
                    connection.name,
                    "ipv4.ignore-auto-dns",
                    "yes",
                    "ipv4.dns",
                    entrypoint.address,
                    "ipv6.ignore-auto-dns",
                    "yes",
                    "ipv6.dns",
                    "",
                ]
            )

    def _restore_network_manager(self, snapshot: DNSStateSnapshot) -> None:
        for connection in snapshot.network_manager_connections:
            self.runner(
                [
                    "nmcli",
                    "con",
                    "mod",
                    connection.name,
                    "ipv4.ignore-auto-dns",
                    connection.ipv4_ignore_auto_dns,
                    "ipv4.dns",
                    connection.ipv4_dns,
                    "ipv4.dns-search",
                    connection.ipv4_dns_search,
                    "ipv6.ignore-auto-dns",
                    connection.ipv6_ignore_auto_dns,
                    "ipv6.dns",
                    connection.ipv6_dns,
                    "ipv6.dns-search",
                    connection.ipv6_dns_search,
                ]
            )
        self._restore_resolv_conf(snapshot)

    def _write_resolv_conf(self, entrypoint: LocalDNSEntryPoint) -> None:
        content = f"nameserver {entrypoint.address}\n"
        self.resolv_conf_path.write_text(content, encoding="utf-8")

    def _restore_resolv_conf(self, snapshot: DNSStateSnapshot) -> None:
        if snapshot.resolv_conf_target:
            _replace_symlink(self.resolv_conf_path, Path(snapshot.resolv_conf_target))
        elif snapshot.resolv_conf_content is not None:
            self.resolv_conf_path.write_text(
                snapshot.resolv_conf_content,
                encoding="utf-8",
            )


def _run_command(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.SubprocessError, TimeoutError) as exc:
        if command[:2] == ["systemctl", "is-active"]:
            return ""
        raise DNSStateError(str(exc)) from exc
    if command[:2] == ["systemctl", "is-active"]:
        return completed.stdout.strip()
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise DNSStateError(message or f"command failed: {' '.join(command)}")
    return completed.stdout.strip()


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _replace_symlink(path: Path, target: Path) -> None:
    tmp_path = path.with_name(f".{path.name}.watchdogvpn.tmp")
    try:
        tmp_path.unlink()
    except FileNotFoundError:
        pass
    os.symlink(target, tmp_path)
    os.replace(tmp_path, path)
