#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path

from phase23_cli_field_validation_plan import REQUIRED_PROTOCOLS, validate_manifest


FIXTURE_FILES: dict[str, str] = {
    "vless": "phase23-vless.txt",
    "vmess": "phase23-vmess.txt",
    "trojan": "phase23-trojan.txt",
    "hysteria2": "phase23-hysteria2.txt",
    "tuic": "phase23-tuic.txt",
    "shadowsocks": "phase23-shadowsocks.txt",
    "wireguard": "phase23-wireguard.conf",
    "amneziawg": "phase23-amneziawg.conf",
    "openvpn": "phase23-openvpn.ovpn",
    "openvpn_cloak": "phase23-openvpn-cloak.txt",
    "socks": "phase23-socks.json",
    "http": "phase23-http.json",
}

EXPECTED_IDS: dict[str, str] = {
    "vless": "phase23-vless",
    "vmess": "phase23-vmess",
    "trojan": "phase23-trojan",
    "hysteria2": "phase23-hysteria2",
    "tuic": "phase23-tuic",
    "shadowsocks": "phase23-shadowsocks",
    "wireguard": "phase23-wireguard",
    "amneziawg": "phase23-amneziawg",
    "openvpn": "phase23-openvpn",
    "openvpn_cloak": "phase23-openvpn-cloak",
    "socks": "phase23-socks",
    "http": "phase23-http",
}


def _build_manifest(
    *,
    fixtures_dir: Path,
    provider_url_file: Path,
    evidence_dir: Path,
    probe_domain: str,
    provider_name: str,
    provider_id: str,
    provider_node_id: str,
) -> dict:
    profiles = []
    for protocol, expected_category in REQUIRED_PROTOCOLS.items():
        profiles.append(
            {
                "protocol": protocol,
                "expected_id": EXPECTED_IDS[protocol],
                "expected_category": expected_category,
                "fixture_path": str(fixtures_dir / FIXTURE_FILES[protocol]),
            }
        )

    return {
        "evidence_dir": str(evidence_dir),
        "external_vpn_states": ["absent", "present"],
        "probe_domain": probe_domain,
        "profiles": profiles,
        "provider": {
            "name": provider_name,
            "url_file": str(provider_url_file),
            "expected_provider_id": provider_id,
            "expected_node_id": provider_node_id,
        },
        "app_policy": {
            "direct_probe_path": "/tmp/phase23-direct-probe",
            "vpn_probe_path": "/tmp/phase23-vpn-probe",
            "block_probe_path": "/tmp/phase23-block-probe",
        },
        "rotation": {
            "primary_profile_id": "phase23-vless",
            "secondary_profile_id": "phase23-trojan",
            "all_failed_profile_ids": ["phase23-vless", "phase23-trojan"],
        },
        "reboot": {"connected_profile_id": "phase23-vless"},
    }


def _missing_files(manifest: dict) -> list[str]:
    missing: list[str] = []
    for profile in manifest["profiles"]:
        path = Path(profile["fixture_path"])
        if not path.is_file():
            missing.append(str(path))
    provider_url_file = Path(manifest["provider"]["url_file"])
    if not provider_url_file.is_file():
        missing.append(str(provider_url_file))
    return missing


def _provider_url_empty(manifest: dict) -> bool:
    provider_url_file = Path(manifest["provider"]["url_file"])
    if not provider_url_file.is_file():
        return False
    return provider_url_file.read_text(encoding="utf-8").strip() == ""


def _print_layout(fixtures_dir: Path, provider_url_file: Path) -> None:
    print("Place your local, private Phase 23 fixtures at these paths:")
    for protocol, filename in FIXTURE_FILES.items():
        print(f"  {protocol:14s} {fixtures_dir / filename}")
    print(f"  provider_url   {provider_url_file}")
    print()
    print("Do not paste fixture contents or provider URLs into chat.")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare a private Phase 23 field validation manifest")
    parser.add_argument("--fixtures-dir", type=Path, default=Path("/tmp/watchdogvpn-phase23-fixtures"))
    parser.add_argument("--provider-url-file", type=Path, default=Path("/tmp/watchdogvpn-phase23-provider-url.txt"))
    parser.add_argument("--output", type=Path, default=Path("/tmp/watchdogvpn-phase23-field-manifest.json"))
    parser.add_argument("--evidence-dir", type=Path, default=Path("/tmp/watchdogvpn-phase23-field-evidence"))
    parser.add_argument("--probe-domain", default="example.com")
    parser.add_argument("--provider-name", default="phase23-provider")
    parser.add_argument("--provider-id", default="phase23-provider")
    parser.add_argument("--provider-node-id", default="phase23-provider:node-1")
    parser.add_argument("--allow-missing", action="store_true", help="write manifest even when fixture files are absent")
    parser.add_argument("--print-layout", action="store_true", help="print expected private fixture paths")
    args = parser.parse_args(argv)

    if args.print_layout:
        _print_layout(args.fixtures_dir, args.provider_url_file)
        return 0

    manifest = _build_manifest(
        fixtures_dir=args.fixtures_dir,
        provider_url_file=args.provider_url_file,
        evidence_dir=args.evidence_dir,
        probe_domain=args.probe_domain,
        provider_name=args.provider_name,
        provider_id=args.provider_id,
        provider_node_id=args.provider_node_id,
    )
    validate_manifest(manifest)

    missing = _missing_files(manifest)
    if missing and not args.allow_missing:
        print("PHASE23_PRIVATE_MANIFEST_MISSING_FILES")
        for path in missing:
            print(path)
        print("Create these local files, or rerun with --allow-missing only to inspect the generated manifest.")
        return 2

    if _provider_url_empty(manifest) and not args.allow_missing:
        print("PHASE23_PRIVATE_MANIFEST_PROVIDER_URL_EMPTY")
        print(str(args.provider_url_file))
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(args.output, 0o600)
    print("PHASE23_PRIVATE_MANIFEST_OK")
    print(f"PHASE23_PRIVATE_MANIFEST={args.output}")
    print("The manifest contains file paths only. Do not paste the manifest or fixture contents into chat.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
