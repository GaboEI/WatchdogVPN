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
    fsync_parent_directory,
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
PRODUCT_OWNED_NETWORKMANAGER_CONNECTIONS = frozenset({"wdvpn-tun0", "watchdogvpn_awg"})


def default_snapshot_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_DNS_SNAPSHOT_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / DEFAULT_DNS_SNAPSHOT_NAME


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
    uuid: str = ""
    ipv4_dns: str = ""
    ipv4_ignore_auto_dns: str = "no"
    ipv4_dns_search: str = ""
    ipv6_dns: str = ""
    ipv6_ignore_auto_dns: str = "no"
    ipv6_dns_search: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "uuid": self.uuid,
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
            uuid=str(data.get("uuid", "")),
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
            raise DNSStateError(f"failed to apply local DNS entry point: {exc}") from exc
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

    def _nmcli_connection_property(self, name: str, prop: str) -> str:
        # One property per call, not a single comma-joined -g query for all
        # six: nmcli -g with multiple fields prints one line per field,
        # blank for an empty/unset one (most commonly ipv4.dns itself, on
        # any plain DHCP connection with no manual DNS override - the
        # ordinary case, not an edge case). The shared runner strips the
        # whole blob (self._run_command / _run_command), which eats a
        # leading or trailing blank line whenever the first or last
        # requested field is empty and shifts every value that follows by
        # one position - so, for example, ipv4.ignore-auto-dns's "no"/"yes"
        # would land in ipv4_dns instead. A later dns reset then feeds that
        # garbage straight to `nmcli con mod ... ipv4.dns no`, which nmcli
        # correctly rejects ("DNS server address is invalid"), leaving DNS
        # not restored. Found live on a Rocky Linux 9 certification VM
        # (Task 23.6.5b) - no prior distro certification ever exercised the
        # real NetworkManager resolver branch with an active DHCP
        # connection (Fedora/Ubuntu run systemd-resolved on top of NM, so
        # they take the systemd-resolved branch instead; Debian's NM
        # connection was loopback-only or dhcpcd-managed both times it was
        # certified), so this was never caught before.
        return self.runner(["nmcli", "-g", prop, "con", "show", name]).strip()

    def _save_network_manager_connections(
        self,
        inventory: ResolverInventory,
    ) -> tuple[NetworkManagerConnectionState, ...]:
        if not inventory.network_manager_active:
            return ()
        names_output = self.runner(
            ["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "con", "show", "--active"]
        )
        states: list[NetworkManagerConnectionState] = []
        for line in [line.strip() for line in names_output.splitlines() if line.strip()]:
            fields = line.split(":")
            if len(fields) < 3:
                continue
            name, connection_type, device = fields[:3]
            if connection_type == "loopback" or device in {"", "lo"}:
                continue
            if (
                name in PRODUCT_OWNED_NETWORKMANAGER_CONNECTIONS
                or device in PRODUCT_OWNED_NETWORKMANAGER_CONNECTIONS
            ):
                continue
            states.append(
                NetworkManagerConnectionState(
                    name=name,
                    uuid=self._nmcli_connection_property(name, "connection.uuid"),
                    ipv4_dns=self._nmcli_connection_property(name, "ipv4.dns"),
                    ipv4_ignore_auto_dns=self._nmcli_connection_property(
                        name, "ipv4.ignore-auto-dns"
                    )
                    or "no",
                    ipv4_dns_search=self._nmcli_connection_property(name, "ipv4.dns-search"),
                    ipv6_dns=self._nmcli_connection_property(name, "ipv6.dns"),
                    ipv6_ignore_auto_dns=self._nmcli_connection_property(
                        name, "ipv6.ignore-auto-dns"
                    )
                    or "no",
                    ipv6_dns_search=self._nmcli_connection_property(name, "ipv6.dns-search"),
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
        # _apply_systemd_resolved only ever calls resolvectl - it never
        # touches /etc/resolv.conf, which stays the same
        # systemd-resolved-managed symlink throughout. resolvectl revert
        # already fully undoes it and typically works for an unprivileged
        # caller (polkit-mediated D-Bus call). Also replacing the resolv.conf
        # symlink here is both redundant and was failing reset in the field
        # with a real "Permission denied" writing /etc/.resolv.conf.*.tmp,
        # since unlike resolvectl that write needs root.
        link = snapshot.systemd_link
        if not link:
            return
        if not self._link_exists(link):
            # A field run showed apply failing against a link that was never
            # actually brought up (profile connected in proxy-only capture
            # mode, no TUN device), which left a saved snapshot naming that
            # link. Restoring against a link that doesn't exist made
            # "resolvectl revert" fail with "No such device" every time,
            # permanently stranding both the failed apply's own rollback and
            # every later "dns reset" against the same stale snapshot. If the
            # link is gone, whatever systemd-resolved config it would have
            # carried is already gone with it - nothing left to revert.
            self._flush_systemd_resolved_caches()
            return
        self.runner(["resolvectl", "revert", link])
        self._flush_systemd_resolved_caches()

    def _flush_systemd_resolved_caches(self) -> None:
        self.runner(["resolvectl", "flush-caches"])

    def _link_exists(self, link: str) -> bool:
        try:
            self.runner(["ip", "-o", "link", "show", link])
            return True
        except Exception:
            return False

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
        # Repointing the symlink is not enough on its own: a resolver stack
        # like openSUSE's netconfig/wicked writes a static target file once
        # and never regenerates it, so apply_local_dns's direct write_text
        # (which follows the symlink) permanently clobbers that file's
        # content. Restoring only the symlink then leaves it pointed at the
        # same file, still containing WatchdogVPN's own 127.0.0.1 entry -
        # every DNS lookup breaks the moment the daemon's local resolver goes
        # away on disconnect. Writing the captured content back afterward
        # fixes that while staying a harmless no-op for resolver stacks (NM,
        # dhcpcd) whose own restore step already regenerated the same bytes.
        if snapshot.resolv_conf_target:
            _replace_symlink(self.resolv_conf_path, Path(snapshot.resolv_conf_target))
        if snapshot.resolv_conf_content is not None:
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
    try:
        fsync_parent_directory(path)
    except PersistentStoreError as exc:
        raise DNSStateError(str(exc)) from exc
