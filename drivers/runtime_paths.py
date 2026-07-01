from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path


OWNER_PID_NAME = "owner.pid"


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
