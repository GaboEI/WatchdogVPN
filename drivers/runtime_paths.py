from __future__ import annotations

import json
import os
import shutil
import signal
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


OWNER_PID_NAME = "owner.pid"
CHILD_PIDS_NAME = "children.json"
PROCESS_IDENTITY_RETRY_TIMEOUT = 0.25
PROCESS_IDENTITY_RETRY_INTERVAL = 0.01


@dataclass(frozen=True, slots=True)
class OwnedProcess:
    """A hint-verified process attributable to a WatchdogVPN runtime."""

    pid: int
    executable: str


@dataclass(frozen=True, slots=True)
class TCPListenerObservation:
    """Owned TCP listener ports and whether /proc evidence was readable."""

    observable: bool
    ports: tuple[int, ...]


def runtime_base_dir() -> Path:
    configured = os.environ.get("WATCHDOGVPN_RUNTIME_DIR")
    if configured:
        return Path(configured)

    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        path = Path(xdg_runtime)
        if path.exists() and os.access(path, os.W_OK | os.X_OK):
            return path

    run_user = Path("/run/user") / str(os.getuid())
    if run_user.exists() and os.access(run_user, os.W_OK | os.X_OK):
        return run_user

    return Path(tempfile.gettempdir())


def _pid_is_alive(pid: int) -> bool:
    # kill(pid, 0) reports zombies as existing until their parent reaps them.
    # A zombie owns no sockets, routes or tunnel state and cannot be signaled
    # into a different state, so cleanup must treat it as exited rather than
    # burn both TERM/KILL timeout windows waiting for an impossible change.
    if _process_state(pid) == "Z":
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return False


def _process_state(pid: int) -> str | None:
    stat_fields = _process_stat_fields(pid)
    return stat_fields[0] if stat_fields else None


def _process_start_time_ticks(pid: int) -> int | None:
    stat_fields = _process_stat_fields(pid)
    if stat_fields is None or len(stat_fields) <= 19:
        return None
    try:
        return int(stat_fields[19])
    except ValueError:
        return None


def _process_stat_fields(pid: int) -> list[str] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    closing_parenthesis = raw.rfind(")")
    if closing_parenthesis < 0:
        return None
    remaining = raw[closing_parenthesis + 1 :].split()
    return remaining or None


def _runtime_dir_has_live_owner(path: Path) -> bool:
    pid_path = path / OWNER_PID_NAME
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    return _pid_is_alive(pid)


def cleanup_stale_runtime_dirs(prefix: str) -> None:
    base = runtime_base_dir()
    for path in base.glob(f"{prefix}*"):
        if not path.is_dir():
            continue
        if _runtime_dir_has_live_owner(path):
            continue
        # The directory's owner (the daemon process that created it) is
        # dead, but a child VPN process it spawned may still be running -
        # reap it before deleting the one durable record of its PID.
        kill_recorded_children(path)
        try:
            shutil.rmtree(path)
        except OSError:
            pass


def make_runtime_dir(prefix: str) -> Path:
    base = runtime_base_dir()
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))
    try:
        path.chmod(0o700)
        write_private_file(path / OWNER_PID_NAME, str(os.getpid()))
    except OSError:
        shutil.rmtree(path, ignore_errors=True)
        raise
    return path


def write_private_file(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    path.chmod(0o600)


def record_child_process(runtime_dir: Path, label: str, pid: int, exe_hint: str) -> None:
    """Durably record a spawned child process's PID and expected binary name.

    Call this immediately after Popen() returns, before any health-check
    wait, so even a crash right after spawn leaves a trail. The in-memory
    Popen object is not durable - it is lost across a reconnect bug, a
    daemon crash, or a daemon restart, which is exactly how an orphaned
    process becomes unrecoverable without this record. Existing labels for
    the same runtime dir are preserved (a driver may record more than one
    child, e.g. OpenVPNCloakDriver's cloak client + openvpn process).
    """
    children = _read_children(runtime_dir)
    children[label] = {
        "pid": pid,
        "exe_hint": exe_hint,
        "start_time_ticks": _process_start_time_ticks(pid),
    }
    write_private_file(runtime_dir / CHILD_PIDS_NAME, json.dumps(children))


def _read_children(runtime_dir: Path) -> dict[str, dict[str, object]]:
    try:
        raw = (runtime_dir / CHILD_PIDS_NAME).read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): value for key, value in data.items() if isinstance(value, dict)}


def _process_matches_hint(pid: int, exe_hint: str) -> bool:
    """Refuse to signal a PID unless it still looks like the process we
    started. PIDs are reused by the OS, and this application runs with real
    kill-switch/TUN/nft privileges, so signaling the wrong process on a
    stale, reused PID would be a serious regression, not a fix. An empty
    hint or an unreadable /proc entry means "cannot verify" and refuses,
    rather than assuming a match.
    """
    if not exe_hint:
        return False
    hint = os.path.basename(exe_hint)
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        raw = b""
    if raw:
        argv0 = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        if os.path.basename(argv0) == hint:
            return True
    try:
        resolved = os.path.basename(os.readlink(f"/proc/{pid}/exe"))
    except OSError:
        return False
    return resolved == hint


def _recorded_process_matches(
    pid: int,
    entry: dict[str, object],
    *,
    retry_timeout: float = 0.0,
) -> bool:
    """Verify durable PID identity before treating a process as product-owned.

    Linux exposes a process start-time tick in /proc/<pid>/stat that remains
    stable across exec and changes when a PID is reused. New records store that
    token so an executable-name collision cannot make a reused PID look owned.
    Legacy records without the token retain the existing executable check.

    Immediately after Popen(), /proc/<pid>/cmdline can transiently be empty even
    though the child is live and its stat identity is already stable. Mutating
    cleanup paths may retry that observation briefly; every retry still requires
    both the recorded start time (when present) and executable hint to match.
    """
    expected_start_time: int | None = None
    raw_start_time = entry.get("start_time_ticks")
    if raw_start_time is not None:
        try:
            expected_start_time = int(raw_start_time)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False

    deadline = time.monotonic() + max(0.0, retry_timeout)
    while True:
        if expected_start_time is not None:
            observed_start_time = _process_start_time_ticks(pid)
            if observed_start_time is None:
                if not _pid_is_alive(pid) or time.monotonic() >= deadline:
                    return False
                time.sleep(
                    min(
                        PROCESS_IDENTITY_RETRY_INTERVAL,
                        max(0.0, deadline - time.monotonic()),
                    )
                )
                continue
            if observed_start_time != expected_start_time:
                return False
        if _process_matches_hint(pid, str(entry.get("exe_hint", ""))):
            return True
        if not _pid_is_alive(pid) or time.monotonic() >= deadline:
            return False
        time.sleep(
            min(
                PROCESS_IDENTITY_RETRY_INTERVAL,
                max(0.0, deadline - time.monotonic()),
            )
        )


def _terminate_then_kill(pid: int, *, timeout: float = 5.0) -> bool:
    """SIGTERM, poll for exit, escalate to SIGKILL, poll again.

    No os.waitpid(): a recorded child may have been reparented to init (its
    original daemon process died, or lost the in-memory reference), so we
    are not necessarily its parent - signal-and-poll _pid_is_alive() is the
    only portable way to observe its exit from here.
    """
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return not _pid_is_alive(pid)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_is_alive(pid):
            return True
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        return not _pid_is_alive(pid)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_is_alive(pid):
            return True
        time.sleep(0.1)
    return not _pid_is_alive(pid)


def kill_recorded_children(runtime_dir: Path, *, timeout: float = 5.0) -> None:
    """Best-effort: stop every child process recorded for this runtime dir.

    Never raises - this runs from cleanup paths (driver __init__,
    disconnect()) that must not fail the caller's own operation just
    because a leftover process could not be reaped this time.
    """
    for entry in _read_children(runtime_dir).values():
        try:
            pid = int(entry.get("pid"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if not _pid_is_alive(pid):
            continue
        if not _recorded_process_matches(
            pid,
            entry,
            retry_timeout=PROCESS_IDENTITY_RETRY_TIMEOUT,
        ):
            continue
        try:
            _terminate_then_kill(pid, timeout=timeout)
        except OSError:
            continue


def recorded_children_terminated(runtime_dir: Path) -> bool:
    """Return whether every durable child record is safe to discard.

    A live PID keeps its record and runtime directory unless a recorded kernel
    start time proves that the PID was reused by an unrelated process. This is
    intentionally stricter than read-only ownership reporting: teardown must
    retain recovery evidence whenever it cannot prove the recorded child ended.
    """
    for entry in _read_children(runtime_dir).values():
        try:
            pid = int(entry.get("pid"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        if not _pid_is_alive(pid):
            continue
        raw_start_time = entry.get("start_time_ticks")
        if raw_start_time is None:
            return False
        try:
            expected_start_time = int(raw_start_time)
        except (TypeError, ValueError):
            return False
        observed_start_time = _process_start_time_ticks(pid)
        if observed_start_time is None or observed_start_time == expected_start_time:
            return False
    return True


def kill_all_recorded_children(prefix: str) -> None:
    """Reap every recorded child under every runtime dir matching prefix,
    regardless of whether that dir's owner (the daemon) is still alive.

    Used from disconnect(): an explicit "fully tear down this driver type"
    intent, unlike cleanup_stale_runtime_dirs()'s dead-owner gate, which
    must never disturb a sibling driver instance's still-live connection
    within the same running daemon.
    """
    base = runtime_base_dir()
    for path in base.glob(f"{prefix}*"):
        if path.is_dir():
            kill_recorded_children(path)


def any_recorded_child_alive(prefix: str) -> bool:
    """Read-only: is there a live, hint-verified child process recorded
    under any runtime dir for this driver prefix? Used by status() to
    detect an orphan without taking any action on it - status() must never
    have side effects.
    """
    base = runtime_base_dir()
    for path in base.glob(f"{prefix}*"):
        if not path.is_dir():
            continue
        for entry in _read_children(path).values():
            try:
                pid = int(entry.get("pid"))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            if _pid_is_alive(pid) and _recorded_process_matches(
                pid,
                entry,
                retry_timeout=PROCESS_IDENTITY_RETRY_TIMEOUT,
            ):
                return True
    return False


def owned_processes(
    prefix: str,
    *,
    executable_names: Iterable[str] = (),
) -> tuple[OwnedProcess, ...]:
    """Return live processes attributable to a runtime prefix.

    Durable child records are the primary source. A process can still be
    recovered when that record was lost if its verified executable is inside
    the daemon's systemd cgroup or its argv references a private runtime path
    under the requested prefix. Merely sharing a binary name is never enough.
    """

    found: dict[int, OwnedProcess] = {}
    base = runtime_base_dir()
    for path in base.glob(f"{prefix}*"):
        if not path.is_dir():
            continue
        for entry in _read_children(path).values():
            try:
                pid = int(entry.get("pid"))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            hint = os.path.basename(str(entry.get("exe_hint", "")))
            if _pid_is_alive(pid) and _recorded_process_matches(
                pid,
                entry,
                retry_timeout=PROCESS_IDENTITY_RETRY_TIMEOUT,
            ):
                found[pid] = OwnedProcess(pid=pid, executable=hint)

    expected_names = {os.path.basename(name) for name in executable_names if name}
    if expected_names:
        try:
            proc_entries = tuple(Path("/proc").iterdir())
        except OSError:
            proc_entries = ()
        for entry in proc_entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            executable = _process_executable_name(pid)
            if executable not in expected_names:
                continue
            if not _process_in_watchdogvpn_service_cgroup(
                pid
            ) and not _process_references_runtime_path(
                pid,
                base=base,
                prefix=prefix,
            ):
                continue
            found[pid] = OwnedProcess(pid=pid, executable=executable)
    return tuple(found[pid] for pid in sorted(found))


def observe_tcp_listener_ports(processes: Iterable[OwnedProcess]) -> TCPListenerObservation:
    """Resolve LISTEN sockets owned by the supplied processes through /proc."""

    process_list = tuple(processes)
    if not process_list:
        return TCPListenerObservation(observable=True, ports=())

    socket_inodes: set[str] = set()
    observed_fd_pids: set[int] = set()
    for process in process_list:
        fd_dir = Path(f"/proc/{process.pid}/fd")
        try:
            descriptors = tuple(fd_dir.iterdir())
            observed_fd_pids.add(process.pid)
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                socket_inodes.add(target[8:-1])

    expected_tables = [Path("/proc/net/tcp")]
    if Path("/proc/net/tcp6").exists():
        expected_tables.append(Path("/proc/net/tcp6"))
    observed_tables = 0
    ports: set[int] = set()
    for table_path in expected_tables:
        try:
            lines = table_path.read_text(encoding="utf-8").splitlines()[1:]
            observed_tables += 1
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A" or parts[9] not in socket_inodes:
                continue
            try:
                ports.add(int(parts[1].rsplit(":", 1)[1], 16))
            except (IndexError, ValueError):
                continue
    return TCPListenerObservation(
        observable=(
            len(observed_fd_pids) == len(process_list)
            and observed_tables == len(expected_tables)
        ),
        ports=tuple(sorted(ports)),
    )


def _process_executable_name(pid: int) -> str:
    try:
        return os.path.basename(os.readlink(f"/proc/{pid}/exe"))
    except OSError:
        pass
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    argv0 = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return os.path.basename(argv0)


def _process_references_runtime_path(pid: int, *, base: Path, prefix: str) -> bool:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    for raw_argument in raw.split(b"\x00"):
        if not raw_argument:
            continue
        argument = raw_argument.decode("utf-8", errors="replace")
        path = Path(argument)
        if not path.is_absolute():
            continue
        try:
            relative = path.relative_to(base)
        except ValueError:
            continue
        if relative.parts and relative.parts[0].startswith(prefix):
            return True
    return False


def _process_in_watchdogvpn_service_cgroup(pid: int) -> bool:
    try:
        lines = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) == 3 and "watchdogvpn.service" in Path(fields[2]).parts:
            return True
    return False
