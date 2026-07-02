from __future__ import annotations

import os
from pathlib import Path

from config.paths import resolve_config_dir
from config.persistence import dump_json, file_lock, load_json, require_mapping
from dns.models import DNSPolicy


def _config_dir() -> Path:
    return resolve_config_dir()


def _dns_policy_path() -> Path:
    return Path(os.environ.get("WATCHDOGVPN_DNS_POLICY_FILE", _config_dir() / "dns-policy.json"))


class DNSPolicyStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _dns_policy_path()

    def load(self) -> DNSPolicy:
        with file_lock(self.path):
            data = require_mapping(load_json(self.path, {}), self.path)
            if not data:
                return DNSPolicy()
            return DNSPolicy.from_dict(data)

    def save(self, policy: DNSPolicy) -> None:
        with file_lock(self.path):
            self.path.parent.mkdir(parents=True, exist_ok=True)
            dump_json(self.path, policy.to_dict())
