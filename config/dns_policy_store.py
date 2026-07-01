from __future__ import annotations

import json
import os
from pathlib import Path

from dns.models import DNSPolicy


def _config_dir() -> Path:
    return Path(
        os.environ.get(
            "WATCHDOGVPN_CONFIG_DIR",
            Path.home() / ".config" / "watchdogvpn",
        )
    )


def _dns_policy_path() -> Path:
    return Path(os.environ.get("WATCHDOGVPN_DNS_POLICY_FILE", _config_dir() / "dns-policy.json"))


class DNSPolicyStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _dns_policy_path()

    def load(self) -> DNSPolicy:
        if not self.path.exists():
            return DNSPolicy()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("dns policy file must contain a JSON object")
        return DNSPolicy.from_dict(data)

    def save(self, policy: DNSPolicy) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(policy.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

