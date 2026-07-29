"""Structured subprocess boundary for production provisioning executors.

This module deliberately exposes only argv-based process execution. Callers
cannot pass shell strings, and stdout/stderr are bounded before being returned
to journals or CLI diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import pwd
import subprocess
from pathlib import Path
from typing import Mapping, Sequence


MAX_CAPTURE_BYTES = 128 * 1024


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    cwd: str | None
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        run_as_user: str | None = None,
        timeout: float = 120.0,
    ) -> CommandResult:
        raise NotImplementedError


class SubprocessCommandRunner(CommandRunner):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        run_as_user: str | None = None,
        timeout: float = 120.0,
    ) -> CommandResult:
        if not argv or any(type(item) is not str or not item for item in argv):
            raise ValueError("argv must be a non-empty sequence of non-empty strings")
        if any("\x00" in item for item in argv):
            raise ValueError("argv entries must not contain NUL bytes")
        preexec_fn = None
        if run_as_user is not None:
            info = pwd.getpwnam(run_as_user)
            if info.pw_uid == 0:
                raise ValueError("build user must not be root")

            def demote() -> None:
                os.initgroups(run_as_user, info.pw_gid)
                os.setgid(info.pw_gid)
                os.setuid(info.pw_uid)

            preexec_fn = demote
        completed = subprocess.run(
            tuple(argv),
            cwd=str(cwd) if cwd is not None else None,
            env=dict(env) if env is not None else None,
            text=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            shell=False,
            preexec_fn=preexec_fn,
        )
        return CommandResult(
            argv=tuple(argv),
            cwd=str(cwd) if cwd is not None else None,
            returncode=completed.returncode,
            stdout=_decode_bounded(completed.stdout),
            stderr=_decode_bounded(completed.stderr),
        )


def _decode_bounded(data: bytes) -> str:
    clipped = data[:MAX_CAPTURE_BYTES]
    suffix = "\n[truncated]" if len(data) > MAX_CAPTURE_BYTES else ""
    return clipped.decode("utf-8", errors="replace") + suffix
