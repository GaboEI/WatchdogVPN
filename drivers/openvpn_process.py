from __future__ import annotations

import shutil
from pathlib import Path

OPENVPN_CHILD_CAPABILITIES = ("net_admin", "net_raw")


def build_openvpn_command(
    binary: str,
    config_path: Path,
    *,
    runtime_options: tuple[str, ...] = (),
) -> list[str]:
    """Run OpenVPN with only the network capabilities it needs.

    The daemon needs broader capabilities for process attribution and other
    product features. OpenVPN must not inherit those capabilities merely
    because it consumes untrusted profile material.
    """

    setpriv = shutil.which("setpriv")
    if not setpriv:
        raise RuntimeError("setpriv is required to launch OpenVPN safely")

    cap_spec = "-all,+" + ",+".join(OPENVPN_CHILD_CAPABILITIES)
    return [
        setpriv,
        "--nnp",
        f"--inh-caps={cap_spec}",
        f"--ambient-caps={cap_spec}",
        "--",
        binary,
        "--config",
        str(config_path),
        *runtime_options,
    ]
