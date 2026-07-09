#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    if override := os.environ.get("WATCHDOGVPN_REPO_DIR"):
        return Path(override)
    path = Path(__file__).resolve()
    if len(path.parents) >= 3:
        return path.parents[2]
    return Path.cwd()


ROOT_DIR = _repo_root()
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dns.models import DNSChannel, DNSChannelName, DNSPolicy, Resolver  # noqa: E402
from drivers.singbox_driver import SingBoxDriver  # noqa: E402
from models.profile import Profile, ProfileSource, ProtocolType  # noqa: E402
from route_chains.runtime import (  # noqa: E402
    ChainDNSPathStatus,
    ChainHopRuntimeStatus,
    ChainRuntimeHopPlan,
    ChainRuntimePlan,
    ChainRuntimeStatus,
)
from rules.models import Rule, RuleGroup  # noqa: E402


CHAIN_ID = "vm-chain-proof"
CHAIN_ACTION = f"chain:{CHAIN_ID}"
CHAIN_DOMAIN = "phase215-chain-proof.test"
HTTP_BODY = b"WATCHDOGVPN_PHASE21_5_CHAIN_PROOF_OK\n"


@dataclass(slots=True)
class SocksRecord:
    host: str
    port: int
    atyp: int


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ProofHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.seen_paths.append(self.path)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(HTTP_BODY)))
        self.end_headers()
        self.wfile.write(HTTP_BODY)

    def log_message(self, _format: str, *args: object) -> None:
        return


class ProofHTTPServer:
    def __init__(self) -> None:
        self.server = ThreadingTCPServer(("127.0.0.1", 0), ProofHTTPHandler)
        self.server.seen_paths = []  # type: ignore[attr-defined]
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "ProofHTTPServer":
        self.thread.start()
        wait_port("127.0.0.1", self.port, open_expected=True)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)

    @property
    def seen_paths(self) -> list[str]:
        return list(self.server.seen_paths)  # type: ignore[attr-defined]


class SocksBridge:
    def __init__(self, *, domain_map: dict[str, str] | None = None) -> None:
        self.domain_map = domain_map or {}
        self.records: list[SocksRecord] = []
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.port = 0

    def __enter__(self) -> "SocksBridge":
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(32)
        listener.settimeout(0.2)
        self._listener = listener
        self.port = int(listener.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=2.0):
            raise RuntimeError("SOCKS bridge did not start")
        wait_port("127.0.0.1", self.port, open_expected=True)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                pass
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._listener is not None:
            self._listener.close()

    def _serve(self) -> None:
        assert self._listener is not None
        self._ready.set()
        while not self._stop.is_set():
            try:
                client, _addr = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

    def _handle_client(self, client: socket.socket) -> None:
        with client:
            client.settimeout(5.0)
            try:
                host, port, atyp = _read_socks_connect(client)
                self.records.append(SocksRecord(host=host, port=port, atyp=atyp))
                connect_host = self.domain_map.get(host, host)
                upstream = socket.create_connection((connect_host, port), timeout=5.0)
            except OSError:
                _send_socks_reply(client, success=False)
                return
            with upstream:
                _send_socks_reply(client, success=True)
                _bridge_bidirectional(client, upstream)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("socket closed")
        data += chunk
    return data


def _read_socks_connect(sock: socket.socket) -> tuple[str, int, int]:
    greeting = _recv_exact(sock, 2)
    if greeting[0] != 5:
        raise OSError("unsupported SOCKS version")
    methods = greeting[1]
    _recv_exact(sock, methods)
    sock.sendall(b"\x05\x00")
    request = _recv_exact(sock, 4)
    if request[:3] != b"\x05\x01\x00":
        raise OSError("only SOCKS CONNECT is supported")
    atyp = request[3]
    if atyp == 1:
        host = socket.inet_ntoa(_recv_exact(sock, 4))
    elif atyp == 3:
        size = _recv_exact(sock, 1)[0]
        host = _recv_exact(sock, size).decode("idna")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))
    else:
        raise OSError("unsupported SOCKS address type")
    port = int.from_bytes(_recv_exact(sock, 2), "big")
    return host, port, atyp


def _send_socks_reply(sock: socket.socket, *, success: bool) -> None:
    code = b"\x00" if success else b"\x05"
    sock.sendall(b"\x05" + code + b"\x00\x01\x00\x00\x00\x00\x00\x00")


def _bridge_bidirectional(left: socket.socket, right: socket.socket) -> None:
    sockets = (left, right)
    for item in sockets:
        item.settimeout(0.2)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        moved = False
        for source, target in ((left, right), (right, left)):
            try:
                data = source.recv(65536)
            except TimeoutError:
                continue
            except OSError:
                return
            if not data:
                return
            try:
                target.sendall(data)
            except OSError:
                return
            moved = True
        if not moved:
            time.sleep(0.01)


def wait_port(
    host: str,
    port: int,
    *,
    open_expected: bool,
    timeout: float = 5.0,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                if open_expected:
                    return
        except OSError:
            if not open_expected:
                return
        time.sleep(0.05)
    raise AssertionError(f"port state mismatch for {host}:{port}")


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def profile(profile_id: str, name: str, port: int) -> Profile:
    return Profile(
        id=profile_id,
        name=name,
        protocol=ProtocolType.SOCKS,
        source=ProfileSource.MANUAL,
        config={
            "host": "127.0.0.1",
            "port": port,
            "version": "5",
            "bind_interface": "none",
        },
    )


def dns_policy() -> DNSPolicy:
    return DNSPolicy(
        channels={
            DNSChannelName.BOOTSTRAP: DNSChannel(
                name=DNSChannelName.BOOTSTRAP,
                resolvers=[Resolver(uri="local")],
            ),
            DNSChannelName.PROXY: DNSChannel(
                name=DNSChannelName.PROXY,
                resolvers=[Resolver(uri="udp://127.0.0.1:53535")],
            )
        },
        tun_hijack=False,
    )


def chain_plan(hop_one: Profile, hop_two: Profile) -> ChainRuntimePlan:
    return ChainRuntimePlan(
        route_action=CHAIN_ACTION,
        chain_id=CHAIN_ID,
        status=ChainRuntimeStatus.RESOLVED,
        dns_path_status=ChainDNSPathStatus.CHAIN_OWNED,
        route_outbound_tag=f"watchdogvpn-chain-{CHAIN_ID}-hop-2",
        hops=(
            ChainRuntimeHopPlan(
                index=1,
                hop_type="profile",
                target=hop_one.id,
                status=ChainHopRuntimeStatus.RESOLVED,
                outbound_tag=f"watchdogvpn-chain-{CHAIN_ID}-hop-1",
                resolved_profile_id=hop_one.id,
                resolved_profile=hop_one,
            ),
            ChainRuntimeHopPlan(
                index=2,
                hop_type="profile",
                target=hop_two.id,
                status=ChainHopRuntimeStatus.RESOLVED,
                outbound_tag=f"watchdogvpn-chain-{CHAIN_ID}-hop-2",
                resolved_profile_id=hop_two.id,
                resolved_profile=hop_two,
            ),
        ),
    )


def blocked_plan(hop_one: Profile) -> ChainRuntimePlan:
    return ChainRuntimePlan(
        route_action=CHAIN_ACTION,
        chain_id=CHAIN_ID,
        status=ChainRuntimeStatus.BLOCKED,
        dns_path_status=ChainDNSPathStatus.UNAVAILABLE,
        failure_reason="dns_path_unavailable",
        hops=(
            ChainRuntimeHopPlan(
                index=1,
                hop_type="profile",
                target=hop_one.id,
                status=ChainHopRuntimeStatus.RESOLVED,
                outbound_tag=f"watchdogvpn-chain-{CHAIN_ID}-hop-1",
                resolved_profile_id=hop_one.id,
                resolved_profile=hop_one,
            ),
        ),
    )


def rule_groups() -> list[RuleGroup]:
    return [
        RuleGroup(
            name="custom",
            rules=[
                Rule(
                    id="phase21-5-chain-proof",
                    action=CHAIN_ACTION,
                    conditions={"domain": [CHAIN_DOMAIN]},
                )
            ],
        )
    ]


def assert_rules_config_contract(config: dict[str, Any], *, target_port: int) -> None:
    outbounds = {item["tag"]: item for item in config["outbounds"]}
    hop1 = outbounds[f"watchdogvpn-chain-{CHAIN_ID}-hop-1"]
    hop2 = outbounds[f"watchdogvpn-chain-{CHAIN_ID}-hop-2"]
    require(hop1["type"] == "socks", "hop 1 outbound is not SOCKS")
    require(hop2["type"] == "socks", "hop 2 outbound is not SOCKS")
    require("detour" not in hop1, "hop 1 must not detour through another hop")
    require(hop2.get("detour") == hop1["tag"], "hop 2 does not detour through hop 1")
    require(
        config["route"]["rules"][-1] == {"action": "route", "outbound": hop2["tag"]},
        "final route does not target final chain hop",
    )
    require(
        any(
            rule.get("domain") == [CHAIN_DOMAIN]
            and rule.get("action") == "route"
            and rule.get("outbound") == hop2["tag"]
            for rule in config["route"]["rules"]
        ),
        "domain route rule does not target final chain hop",
    )
    require(
        not any(
            rule.get("action") == "route" and rule.get("outbound") == "direct"
            for rule in config["route"]["rules"]
        ),
        "chain route unexpectedly falls back to direct",
    )
    require(target_port > 0, "target HTTP port was not allocated")


def assert_global_dns_detour(driver: SingBoxDriver, active: Profile, plan: ChainRuntimePlan) -> None:
    config = driver.generate_singbox_config(
        active,
        dns_policy=dns_policy(),
        mode="global",
        final_policy=CHAIN_ACTION,
        chain_runtime_plans={CHAIN_ACTION: plan},
    )
    proxy_servers = [
        server for server in config.get("dns", {}).get("servers", [])
        if server.get("tag") == "watchdogvpn-proxy-1"
    ]
    require(proxy_servers, "proxy DNS server is missing")
    require(
        proxy_servers[0].get("detour") == plan.route_outbound_tag,
        "global proxy DNS server does not detour through final chain hop",
    )
    require(
        config["route"]["rules"][-1] == {
            "action": "route",
            "outbound": plan.route_outbound_tag,
        },
        "global chain final route does not target final chain hop",
    )
    require(
        config["route"].get("default_domain_resolver") == "watchdogvpn-bootstrap-1",
        "global chain config is missing bootstrap default_domain_resolver",
    )
    print("PHASE21_5_GLOBAL_CHAIN_DNS_DETOUR_OK")


def assert_blocked_contract(driver: SingBoxDriver, active: Profile, blocked: ChainRuntimePlan) -> None:
    config = driver.generate_singbox_config(
        active,
        mode="rules",
        groups=rule_groups(),
        final_policy=CHAIN_ACTION,
        chain_runtime_plans={CHAIN_ACTION: blocked},
    )
    require(
        all(rule.get("action") != "route" for rule in config["route"]["rules"]),
        "blocked chain emitted a route action",
    )
    require(
        config["route"]["rules"][-1] == {"action": "reject"},
        "blocked final chain did not fail closed to reject",
    )
    print("PHASE21_5_FAIL_CLOSED_CONFIG_OK")


def singbox_check(driver: SingBoxDriver, config_path: Path | None) -> None:
    binary = driver.find_singbox_binary()
    require(binary is not None, "sing-box binary is required")
    require(config_path is not None and config_path.exists(), "sing-box config path is missing")
    result = run([binary, "check", "-c", str(config_path)])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"sing-box check failed: {detail}")
    print("PHASE21_5_SINGBOX_CHECK_OK")


def start_singbox_runtime(driver: SingBoxDriver) -> subprocess.Popen[str]:
    binary = driver.find_singbox_binary()
    config_path, log_path = driver._ensure_runtime_paths()
    require(binary is not None, "sing-box binary is required")
    require(config_path.exists(), "sing-box config path is missing")
    log_file = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [binary, "run", "-c", str(config_path)],
        text=True,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    log_file.close()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = log_path.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(f"sing-box exited during startup: {detail.strip()}")
        try:
            wait_port("127.0.0.1", 2080, open_expected=True, timeout=0.2)
            print("PHASE21_5_SINGBOX_RUNTIME_STARTED_OK")
            return process
        except AssertionError:
            time.sleep(0.05)
    detail = log_path.read_text(encoding="utf-8", errors="replace")
    raise RuntimeError(f"sing-box local proxy did not become ready: {detail.strip()}")


def stop_singbox_runtime(driver: SingBoxDriver, process: subprocess.Popen[str]) -> None:
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    finally:
        driver._cleanup_runtime()


def curl_chain(target_port: int) -> str:
    require(shutil.which("curl") is not None, "curl is required")
    url = f"http://{CHAIN_DOMAIN}:{target_port}/chain-proof"
    result = run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "10",
            "--socks5-hostname",
            "127.0.0.1:2080",
            url,
        ]
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"curl through chain failed: {detail}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 21.5 chain installed VM validation")
    parser.add_argument("--write-evidence", type=Path)
    args = parser.parse_args()

    require(os.environ.get("WATCHDOGVPN_VM_SMOKE") == "1", "set WATCHDOGVPN_VM_SMOKE=1")

    with ProofHTTPServer() as http_target:
        with SocksBridge(domain_map={CHAIN_DOMAIN: "127.0.0.1"}) as hop_two:
            with SocksBridge() as hop_one:
                active = profile("phase21-5-active", "phase21-5-active", 9)
                first = profile("phase21-5-hop-one", "phase21-5-hop-one", hop_one.port)
                second = profile("phase21-5-hop-two", "phase21-5-hop-two", hop_two.port)
                plan = chain_plan(first, second)
                driver = SingBoxDriver()
                config = driver.generate_singbox_config(
                    active,
                    dns_policy=dns_policy(),
                    mode="rules",
                    groups=rule_groups(),
                    final_policy=CHAIN_ACTION,
                    chain_runtime_plans={CHAIN_ACTION: plan},
                )
                assert_rules_config_contract(config, target_port=http_target.port)
                singbox_check(driver, driver._config_path)
                assert_global_dns_detour(driver, active, plan)
                assert_blocked_contract(driver, active, blocked_plan(first))

                driver.generate_singbox_config(
                    active,
                    dns_policy=dns_policy(),
                    mode="rules",
                    groups=rule_groups(),
                    final_policy=CHAIN_ACTION,
                    chain_runtime_plans={CHAIN_ACTION: plan},
                )
                process = start_singbox_runtime(driver)
                try:
                    output = curl_chain(http_target.port)
                    require(output.encode("utf-8") == HTTP_BODY, "unexpected HTTP proof body")
                    require(http_target.seen_paths == ["/chain-proof"], "HTTP proof target was not reached once")
                    require(
                        any(record.host == "127.0.0.1" and record.port == hop_two.port for record in hop_one.records),
                        "hop 1 did not connect to hop 2",
                    )
                    require(
                        any(record.host == CHAIN_DOMAIN and record.port == http_target.port for record in hop_two.records),
                        "hop 2 did not receive the final destination domain",
                    )
                    print("PHASE21_5_CHAIN_TRAFFIC_PROOF_OK")
                finally:
                    stop_singbox_runtime(driver, process)
                    wait_port("127.0.0.1", 2080, open_expected=False)
                    wait_port("127.0.0.1", 2081, open_expected=False)
                    print("PHASE21_5_CHAIN_TEARDOWN_OK")

                evidence = {
                    "chain_action": CHAIN_ACTION,
                    "route_outbound_tag": plan.route_outbound_tag,
                    "hop_one_records": [asdict(record) for record in hop_one.records],
                    "hop_two_records": [asdict(record) for record in hop_two.records],
                    "http_paths": http_target.seen_paths,
                    "dns_proxy_detour": "watchdogvpn-chain-vm-chain-proof-hop-2",
                    "validation": "installed-vm-local-chain-proof",
                }
                if args.write_evidence is not None:
                    args.write_evidence.write_text(
                        json.dumps(evidence, indent=2, sort_keys=True),
                        encoding="utf-8",
                    )

    print("PHASE21_5_CHAIN_INSTALLED_VM_VALIDATION_OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PHASE21_5_CHAIN_INSTALLED_VM_VALIDATION_FAILED: {exc}", file=sys.stderr)
        if os.environ.get("WATCHDOGVPN_VM_SMOKE_TRACE") == "1":
            traceback.print_exc()
        raise SystemExit(1)
