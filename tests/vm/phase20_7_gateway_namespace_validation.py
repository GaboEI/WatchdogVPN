#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

from config.lan_sharing import LANGatewayRuntimeConfig
from drivers.singbox_driver import LAN_GATEWAY_NFT_TABLE, SingBoxDriver


LAB_NAMESPACE = "wdvpn-p20-client"
LAB_LAN_HOST = "wdvpn-p20-lan"
LAB_LAN_CLIENT = "wdvpn-p20-peer"
LAB_TUN = "wdvpn-p20-tun"
LAB_CLIENT_CIDR = "10.20.7.0/24"
LAB_HOST_ADDRESS = "10.20.7.1/24"
LAB_CLIENT_ADDRESS = "10.20.7.2/24"
LAB_ROUTE_TARGET = "198.51.100.77/32"
LAB_ROUTE_HOST = "198.51.100.77"


def run(command: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"command failed: {' '.join(command)}: {detail}")
    return result


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def read_ip_forward() -> str:
    with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="utf-8") as handle:
        return handle.read().strip()


def nft_table_exists() -> bool:
    return run(["nft", "list", "table", "inet", LAN_GATEWAY_NFT_TABLE]).returncode == 0


def nft_table_text() -> str:
    result = run(["nft", "list", "table", "inet", LAN_GATEWAY_NFT_TABLE])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"cannot read gateway nft table: {detail}")
    return result.stdout


def cleanup_lab() -> None:
    run(["ip", "route", "del", LAB_ROUTE_TARGET, "dev", LAB_TUN])
    run(["ip", "link", "del", LAB_TUN])
    run(["ip", "link", "del", LAB_LAN_HOST])
    run(["ip", "netns", "del", LAB_NAMESPACE])


def setup_lab() -> None:
    cleanup_lab()
    run(["ip", "netns", "add", LAB_NAMESPACE], check=True)
    run(["ip", "link", "add", LAB_LAN_HOST, "type", "veth", "peer", "name", LAB_LAN_CLIENT], check=True)
    run(["ip", "link", "set", LAB_LAN_CLIENT, "netns", LAB_NAMESPACE], check=True)
    run(["ip", "addr", "add", LAB_HOST_ADDRESS, "dev", LAB_LAN_HOST], check=True)
    run(["ip", "link", "set", LAB_LAN_HOST, "up"], check=True)
    run(["ip", "netns", "exec", LAB_NAMESPACE, "ip", "addr", "add", LAB_CLIENT_ADDRESS, "dev", LAB_LAN_CLIENT], check=True)
    run(["ip", "netns", "exec", LAB_NAMESPACE, "ip", "link", "set", "lo", "up"], check=True)
    run(["ip", "netns", "exec", LAB_NAMESPACE, "ip", "link", "set", LAB_LAN_CLIENT, "up"], check=True)
    run(["ip", "netns", "exec", LAB_NAMESPACE, "ip", "route", "add", "default", "via", "10.20.7.1"], check=True)
    run(["ip", "link", "add", LAB_TUN, "type", "dummy"], check=True)
    run(["ip", "link", "set", LAB_TUN, "up"], check=True)
    run(["ip", "route", "add", LAB_ROUTE_TARGET, "dev", LAB_TUN], check=True)


def validate_lab_routing() -> None:
    client_route = run(["ip", "netns", "exec", LAB_NAMESPACE, "ip", "route", "get", LAB_ROUTE_HOST], check=True)
    require("via 10.20.7.1" in client_route.stdout, "client namespace does not route through gateway host")
    host_route = run(
        ["ip", "route", "get", LAB_ROUTE_HOST, "from", "10.20.7.2", "iif", LAB_LAN_HOST],
        check=True,
    )
    require(f"dev {LAB_TUN}" in host_route.stdout, "host route decision does not use lab tunnel interface")


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 20.7 LAN gateway namespace VM validation")
    parser.parse_args()

    require(os.environ.get("WATCHDOGVPN_VM_SMOKE") == "1", "set WATCHDOGVPN_VM_SMOKE=1")
    require(os.geteuid() == 0, "phase20_7 gateway namespace validation must run as root")
    for command in ("ip", "nft"):
        require(shutil.which(command) is not None, f"{command} is required")
    require(not nft_table_exists(), f"gateway nft table already exists: {LAN_GATEWAY_NFT_TABLE}")

    before_forward = read_ip_forward()
    driver = SingBoxDriver()
    driver._tun_expected = True
    gateway = LANGatewayRuntimeConfig(
        lan_interface=LAB_LAN_HOST,
        client_cidr=LAB_CLIENT_CIDR,
        dns_mode="manual",
        firewall_managed=True,
        tunnel_interface=LAB_TUN,
    )

    try:
        setup_lab()
        validate_lab_routing()
        require(driver._apply_lan_gateway(gateway), "gateway apply failed in namespace lab")
        require(read_ip_forward() == "1", "ip_forward was not enabled in namespace lab")
        table = nft_table_text()
        require("hook forward" in table and "policy drop" in table, "namespace lab forward chain is not default-drop")
        require(LAB_LAN_HOST in table, "namespace lab LAN interface missing from nft table")
        require(LAB_CLIENT_CIDR in table, "namespace lab client CIDR missing from nft table")
        require(LAB_TUN in table, "namespace lab tunnel interface missing from nft table")
        require("ct state established,related accept" in table, "namespace lab established flow rule missing")
        require("masquerade" in table, "namespace lab NAT masquerade missing")
        require("reject" in table, "namespace lab LAN reject rule missing")
        print("PHASE20_7_GATEWAY_NAMESPACE_APPLY_OK")
    finally:
        driver._cleanup_lan_gateway()
        cleanup_lab()

    require(read_ip_forward() == before_forward, "namespace lab ip_forward snapshot was not restored")
    require(not nft_table_exists(), "namespace lab gateway nft table was not removed")
    require(run(["ip", "netns", "list"]).stdout.find(LAB_NAMESPACE) == -1, "namespace lab netns residue remains")
    require(run(["ip", "link", "show", LAB_LAN_HOST]).returncode != 0, "namespace lab LAN host link remains")
    require(run(["ip", "link", "show", LAB_TUN]).returncode != 0, "namespace lab tunnel link remains")
    print("PHASE20_7_GATEWAY_NAMESPACE_CLEANUP_OK")
    print("PHASE20_7_GATEWAY_NAMESPACE_VM_VALIDATION_OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PHASE20_7_GATEWAY_NAMESPACE_VM_VALIDATION_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
