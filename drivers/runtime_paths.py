from __future__ import annotations

import json
import os
import shutil
import signal
import tempfile
import time
from pathlib import Path


OWNER_PID_NAME = "owner.pid"
CHILD_PIDS_NAME = "children.json"


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
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return False


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
    path.chmod(0o700)
    write_private_file(path / OWNER_PID_NAME, str(os.getpid()))
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
    children[label] = {"pid": pid, "exe_hint": exe_hint}
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
        if not _process_matches_hint(pid, str(entry.get("exe_hint", ""))):
            continue
        try:
            _terminate_then_kill(pid, timeout=timeout)
        except OSError:
            continue


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
            if _pid_is_alive(pid) and _process_matches_hint(pid, str(entry.get("exe_hint", ""))):
                return True
    return False
