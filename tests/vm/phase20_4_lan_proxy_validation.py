#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
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

from cli.main import main as watchdog_main  # noqa: E402
from config.lan_sharing import LANProxyRuntimeConfig  # noqa: E402
from drivers.singbox_driver import SingBoxDriver  # noqa: E402
from models.profile import Profile, ProfileSource, ProtocolType  # noqa: E402


@dataclass(slots=True)
class UpstreamRecord:
    atyp: int
    host: str
    port: int


class FakeSocksUpstream:
    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host
        self.records: list[UpstreamRecord] = []
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.port = 0

    def __enter__(self) -> "FakeSocksUpstream":
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, 0))
        listener.listen(8)
        self.port = listener.getsockname()[1]

        def serve() -> None:
            listener.settimeout(0.2)
            self._ready.set()
            try:
                while not self._stop.is_set():
                    try:
                        conn, _addr = listener.accept()
                    except TimeoutError:
                        continue
                    except OSError:
                        break
                    with conn:
                        conn.settimeout(2.0)
                        record = _handle_socks_upstream_connection(conn)
                        if record is not None:
                            self.records.append(record)
            finally:
                listener.close()

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=2.0):
            raise RuntimeError("fake upstream did not start")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        try:
            with socket.create_connection((self.host, self.port), timeout=0.2):
                pass
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _handle_socks_upstream_connection(conn: socket.socket) -> UpstreamRecord | None:
    try:
        greeting = _recv_exact(conn, 2)
        if greeting[0] != 5:
            return None
        method_count = greeting[1]
        _recv_exact(conn, method_count)
        conn.sendall(b"\x05\x00")
        request = _recv_exact(conn, 4)
        if request[:3] != b"\x05\x01\x00":
            return None
        atyp = request[3]
        if atyp == 1:
            host = socket.inet_ntoa(_recv_exact(conn, 4))
        elif atyp == 3:
            length = _recv_exact(conn, 1)[0]
            host = _recv_exact(conn, length).decode("idna")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, _recv_exact(conn, 16))
        else:
            return None
        port = int.from_bytes(_recv_exact(conn, 2), "big")
        conn.sendall(b"\x05\x00\x00\x01\x127\x00\x01\x00\x00")
        return UpstreamRecord(atyp=atyp, host=host, port=port)
    except OSError:
        return None


def run(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False, env=env)


def wait_port(host: str, port: int, *, open_expected: bool = True, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    last: str | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                if open_expected:
                    return
                last = "open"
        except OSError as exc:
            if not open_expected:
                return
            last = str(exc)
        time.sleep(0.1)
    raise AssertionError(
        f"port state mismatch {host}:{port} expected_open={open_expected} last={last}"
    )


def http_proxy_status(
    host: str,
    port: int,
    target_host: str,
    *,
    username: str | None = None,
    password: str | None = None,
) -> str:
    with socket.create_connection((host, port), timeout=2.0) as sock:
        sock.settimeout(2.0)
        headers = [
            f"GET http://{target_host}/ HTTP/1.1",
            f"Host: {target_host}",
            "Connection: close",
        ]
        if username is not None and password is not None:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers.append(f"Proxy-Authorization: Basic {token}")
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
        data = sock.recv(128)
    return data.decode("latin1", errors="replace").split("\r\n", 1)[0]


def socks_connect(
    host: str,
    port: int,
    target_host: str,
    target_port: int,
    *,
    username: str,
    password: str,
) -> bytes:
    user = username.encode()
    pw = password.encode()
    encoded_host = target_host.encode("idna")
    with socket.create_connection((host, port), timeout=2.0) as sock:
        sock.settimeout(2.0)
        sock.sendall(b"\x05\x01\x02")
        method = _recv_exact(sock, 2)
        if method != b"\x05\x02":
            raise AssertionError(f"SOCKS auth method rejected: {method!r}")
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
        auth = _recv_exact(sock, 2)
        if auth != b"\x01\x00":
            raise AssertionError(f"SOCKS auth failed: {auth!r}")
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(encoded_host)])
            + encoded_host
            + target_port.to_bytes(2, "big")
        )
        return _recv_exact(sock, 10)


def allocate_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def configure_lan_sharing(
    env: dict[str, str],
    bind_address: str,
    socks_port: int,
    http_port: int,
) -> tuple[str, str]:
    old_env = os.environ.copy()
    try:
        os.environ.update(env)
        for args in (
            ["config", "set", "lan_sharing.mode", "proxy"],
            ["config", "set", "lan_sharing.bind_address", bind_address],
            ["config", "set", "lan_sharing.socks_port", str(socks_port)],
            ["config", "set", "lan_sharing.http_port", str(http_port)],
            ["config", "set", "lan_sharing.enabled", "true"],
        ):
            code = watchdog_main(args)
            if code != 0:
                raise SystemExit(code)
    finally:
        os.environ.clear()
        os.environ.update(old_env)
    watchdog = env.get("WATCHDOGVPN_WATCHDOG_BIN", str(ROOT_DIR / "bin" / "watchdog"))
    shown = run(
        [watchdog, "config", "lan-sharing-credentials", "--show-secret", "--json"],
        env=env,
    )
    if shown.returncode != 0:
        raise AssertionError(shown.stderr)
    data = json.loads(shown.stdout)
    return str(data["username"]), str(data["password"])


def make_profile(name: str, upstream_port: int) -> Profile:
    return Profile(
        id=name.lower().replace(" ", "-"),
        name=name,
        protocol=ProtocolType.SOCKS,
        config={"host": "127.0.0.1", "port": upstream_port},
        source=ProfileSource.MANUAL,
    )


def start_singbox_with_lan(
    profile: Profile,
    bind_address: str,
    socks_port: int,
    http_port: int,
    username: str,
    password: str,
) -> tuple[SingBoxDriver, subprocess.Popen[bytes]]:
    driver = SingBoxDriver()
    lan_proxy = LANProxyRuntimeConfig(
        bind_address=bind_address,
        socks_port=socks_port,
        http_port=http_port,
        username=username,
        password=password,
    )
    config = driver.generate_singbox_config(profile, lan_proxy=lan_proxy)
    outbounds = {outbound["tag"]: outbound for outbound in config["outbounds"]}
    if "direct" in outbounds:
        raise AssertionError("LAN proxy validation config unexpectedly contains direct outbound")
    config_path, _log_path = driver._ensure_runtime_paths()
    check = run(["sing-box", "check", "-c", str(config_path)])
    if check.returncode != 0:
        raise AssertionError(check.stderr or check.stdout)
    process = subprocess.Popen(
        ["sing-box", "run", "-c", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait_port("127.0.0.1", 2080)
    wait_port("127.0.0.1", 2081)
    wait_port(bind_address, socks_port)
    wait_port(bind_address, http_port)
    return driver, process


def stop_singbox(driver: SingBoxDriver, process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    driver._cleanup_runtime()


def prove_fail_closed(
    bind_address: str,
    socks_port: int,
    http_port: int,
    username: str,
    password: str,
    closed_upstream_port: int,
) -> None:
    driver, process = start_singbox_with_lan(
        make_profile("Closed Upstream", closed_upstream_port),
        bind_address,
        socks_port,
        http_port,
        username,
        password,
    )
    try:
        status = http_proxy_status(
            bind_address,
            http_port,
            "fail-closed.invalid",
            username=username,
            password=password,
        )
        if status.startswith("HTTP/1.1 200") or status.startswith("HTTP/1.0 200"):
            raise AssertionError(f"LAN proxy unexpectedly succeeded with dead upstream: {status}")
        reply = socks_connect(
            bind_address,
            socks_port,
            "fail-closed.invalid",
            80,
            username=username,
            password=password,
        )
        if len(reply) >= 2 and reply[1] == 0:
            raise AssertionError("SOCKS LAN proxy unexpectedly succeeded with dead upstream")
        print("FAIL_CLOSED_NO_DIRECT_FALLBACK_OK")
    finally:
        stop_singbox(driver, process)


def prove_proxy_dns(
    bind_address: str,
    socks_port: int,
    http_port: int,
    username: str,
    password: str,
) -> None:
    target_hosts = {"socks": "socks-dns-proof.invalid", "http": "http-dns-proof.invalid"}
    with FakeSocksUpstream() as upstream:
        driver, process = start_singbox_with_lan(
            make_profile("DNS Proof Upstream", upstream.port),
            bind_address,
            socks_port,
            http_port,
            username,
            password,
        )
        try:
            socks_connect(
                bind_address,
                socks_port,
                target_hosts["socks"],
                80,
                username=username,
                password=password,
            )
            http_proxy_status(
                bind_address,
                http_port,
                target_hosts["http"],
                username=username,
                password=password,
            )
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and len(upstream.records) < 2:
                time.sleep(0.1)
            seen = {(record.atyp, record.host) for record in upstream.records}
            expected = {(3, target_hosts["socks"]), (3, target_hosts["http"])}
            missing = expected - seen
            if missing:
                raise AssertionError(
                    f"upstream did not receive domain-form proxy DNS requests; "
                    f"missing={missing} records={upstream.records}"
                )
            print("PROXY_DNS_DOMAIN_FORWARDING_OK")
        finally:
            stop_singbox(driver, process)


def prove_teardown(
    bind_address: str,
    socks_port: int,
    http_port: int,
) -> None:
    wait_port(bind_address, socks_port, open_expected=False)
    wait_port(bind_address, http_port, open_expected=False)
    driver = SingBoxDriver()
    profile = make_profile("Disabled LAN Upstream", 9)
    driver.generate_singbox_config(profile)
    config_path, _log_path = driver._ensure_runtime_paths()
    process = subprocess.Popen(
        ["sing-box", "run", "-c", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_port("127.0.0.1", 2080)
        wait_port("127.0.0.1", 2081)
        wait_port(bind_address, socks_port, open_expected=False)
        wait_port(bind_address, http_port, open_expected=False)
        print("DISABLED_CONFIG_HAS_NO_LAN_LISTENERS_OK")
    finally:
        stop_singbox(driver, process)


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 20.4 LAN proxy VM validation")
    parser.add_argument("--bind-address", required=True)
    parser.add_argument("--socks-port", type=int)
    parser.add_argument("--http-port", type=int)
    parser.add_argument("--watchdog-bin", default=str(ROOT_DIR / "bin" / "watchdog"))
    args = parser.parse_args()

    if os.environ.get("WATCHDOGVPN_VM_SMOKE") != "1":
        print("ERROR: refusing to run without WATCHDOGVPN_VM_SMOKE=1", file=sys.stderr)
        return 64
    if not Path(args.watchdog_bin).exists():
        print(f"ERROR: watchdog binary not found: {args.watchdog_bin}", file=sys.stderr)
        return 66
    if not shutil_which("sing-box"):
        print("ERROR: sing-box not found in PATH", file=sys.stderr)
        return 69

    if (args.socks_port is None) != (args.http_port is None):
        print("ERROR: --socks-port and --http-port must be provided together", file=sys.stderr)
        return 64
    if args.socks_port is not None and args.http_port is not None:
        socks_port = args.socks_port
        http_port = args.http_port
        closed_upstream_port = allocate_ports(1)[0]
    else:
        socks_port, http_port, closed_upstream_port = allocate_ports(3)

    with tempfile.TemporaryDirectory(prefix="wdvpn-phase20-4-") as tmp:
        tmp_path = Path(tmp)
        env = os.environ.copy()
        env["WATCHDOGVPN_CONFIG_DIR"] = str(tmp_path / "config")
        env["WATCHDOGVPN_STATE_FILE"] = str(tmp_path / "state.toml")
        env["WATCHDOGVPN_RUNTIME_DIR"] = str(tmp_path / "runtime")
        env["WATCHDOGVPN_WATCHDOG_BIN"] = args.watchdog_bin
        env["PYTHONPATH"] = os.environ.get("PYTHONPATH", str(ROOT_DIR))

        route_before = run(["ip", "route"]).stdout.strip()
        rule_before = run(["ip", "rule"]).stdout.strip()
        username, password = configure_lan_sharing(
            env,
            args.bind_address,
            socks_port,
            http_port,
        )
        prove_fail_closed(
            args.bind_address,
            socks_port,
            http_port,
            username,
            password,
            closed_upstream_port,
        )
        prove_proxy_dns(args.bind_address, socks_port, http_port, username, password)
        prove_teardown(args.bind_address, socks_port, http_port)
        route_after = run(["ip", "route"]).stdout.strip()
        rule_after = run(["ip", "rule"]).stdout.strip()
        if route_before != route_after:
            raise AssertionError("ip route changed during LAN proxy validation")
        if rule_before != rule_after:
            raise AssertionError("ip rule changed during LAN proxy validation")
        print("ROUTE_RULE_UNCHANGED_OK")
        print("PHASE20_4_LAN_PROXY_VM_VALIDATION_OK")
    return 0


def shutil_which(command: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / command
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


if __name__ == "__main__":
    raise SystemExit(main())
