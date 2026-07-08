#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

from config.lan_sharing import LANGatewayRuntimeConfig
from drivers.singbox_driver import LAN_GATEWAY_NFT_TABLE, SingBoxDriver


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def read_ip_forward() -> str:
    with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="utf-8") as handle:
        return handle.read().strip()


def nft_table_exists() -> bool:
    result = run(["nft", "list", "table", "inet", LAN_GATEWAY_NFT_TABLE])
    return result.returncode == 0


def nft_table_text() -> str:
    result = run(["nft", "list", "table", "inet", LAN_GATEWAY_NFT_TABLE])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"cannot read gateway nft table: {detail}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 20.6 LAN gateway VM validation")
    parser.add_argument("--lan-interface", required=True)
    parser.add_argument("--client-cidr", required=True)
    parser.add_argument("--tun-interface", default="wdvpn-tun0")
    args = parser.parse_args()

    require(os.environ.get("WATCHDOGVPN_VM_SMOKE") == "1", "set WATCHDOGVPN_VM_SMOKE=1")
    require(os.geteuid() == 0, "phase20_6 validation must run as root")
    require(shutil.which("nft") is not None, "nft is required")

    before_forward = read_ip_forward()
    before_table = nft_table_exists()
    require(not before_table, f"gateway nft table already exists: {LAN_GATEWAY_NFT_TABLE}")

    driver = SingBoxDriver()
    driver._tun_expected = True
    gateway = LANGatewayRuntimeConfig(
        lan_interface=args.lan_interface,
        client_cidr=args.client_cidr,
        dns_mode="manual",
        firewall_managed=True,
        tunnel_interface=args.tun_interface,
    )

    try:
        require(driver._apply_lan_gateway(gateway), "gateway apply failed")
        require(read_ip_forward() == "1", "ip_forward was not enabled")
        table = nft_table_text()
        require(args.lan_interface in table, "gateway interface missing from nft table")
        require(args.client_cidr in table, "client CIDR missing from nft table")
        require(args.tun_interface in table, "TUN interface missing from nft table")
        require("masquerade" in table, "NAT masquerade rule missing")
        require("reject" in table, "fail-closed reject rule missing")
        print("PHASE20_6_GATEWAY_APPLY_OK")
    finally:
        driver._cleanup_lan_gateway()

    require(read_ip_forward() == before_forward, "ip_forward snapshot was not restored")
    require(not nft_table_exists(), "gateway nft table was not removed")
    print("PHASE20_6_GATEWAY_CLEANUP_OK")
    print("PHASE20_6_LAN_GATEWAY_VM_VALIDATION_OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PHASE20_6_LAN_GATEWAY_VM_VALIDATION_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
