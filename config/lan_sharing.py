from __future__ import annotations

import json
import os
import secrets
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from config.persistence import PersistentStoreError, file_lock, fsync_parent_directory


LAN_SHARING_CREDENTIALS_NAME = "lan-sharing-credentials.json"
LAN_SHARING_USERNAME = "watchdogvpn"


@dataclass(frozen=True, slots=True)
class LANProxyRuntimeConfig:
    bind_address: str
    socks_port: int
    http_port: int
    username: str
    password: str
    firewall_managed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class LANGatewayRuntimeConfig:
    lan_interface: str
    client_cidr: str
    dns_mode: str = "manual"
    firewall_managed: bool = True
    tunnel_interface: str = "wdvpn-tun0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def lan_sharing_credentials_path(config_path: Path) -> Path:
    return config_path.parent / LAN_SHARING_CREDENTIALS_NAME


def load_or_create_lan_sharing_credentials(path: Path) -> dict[str, str]:
    with file_lock(path):
        if path.exists():
            return _load_lan_sharing_credentials(path)
        credentials = {
            "username": LAN_SHARING_USERNAME,
            "password": secrets.token_urlsafe(32),
        }
        _write_private_json(path, credentials)
        return credentials


def _load_lan_sharing_credentials(path: Path) -> dict[str, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PersistentStoreError(f"invalid LAN sharing credentials in {path}") from exc
    if not isinstance(raw, dict):
        raise PersistentStoreError(f"invalid LAN sharing credentials in {path}")
    username = raw.get("username")
    password = raw.get("password")
    if not isinstance(username, str) or not username:
        raise PersistentStoreError(f"invalid LAN sharing credentials in {path}: missing username")
    if not isinstance(password, str) or not password:
        raise PersistentStoreError(f"invalid LAN sharing credentials in {path}: missing password")
    _chmod_private(path)
    return {"username": username, "password": password}


def _write_private_json(path: Path, payload: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        _chmod_private(path)
        fsync_parent_directory(path)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _chmod_private(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass
