from __future__ import annotations

import email.utils
import subprocess
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


DEFAULT_REFERENCE_URL = "https://example.com"
DEFAULT_TIMEOUT_SECONDS = 3.0
SEVERE_SKEW_SECONDS = 300


@dataclass(frozen=True, slots=True)
class TimeDiagnostic:
    status: str
    system_time_available: bool
    local_utc: str | None
    ntp_state: str
    ntp_synchronized: bool | None
    system_clock_synchronized: bool | None
    reference_utc: str | None
    skew_seconds: int | None
    message: str

    def to_lines(self) -> list[str]:
        return [
            f"STATUS={self.status}",
            f"SYSTEM_TIME_AVAILABLE={'yes' if self.system_time_available else 'no'}",
            f"LOCAL_UTC={self.local_utc or ''}",
            f"NTP_STATE={self.ntp_state}",
            f"NTP_SYNCHRONIZED={_bool_to_text(self.ntp_synchronized)}",
            f"SYSTEM_CLOCK_SYNCHRONIZED={_bool_to_text(self.system_clock_synchronized)}",
            f"REFERENCE_UTC={self.reference_utc or ''}",
            f"SKEW_SECONDS={'' if self.skew_seconds is None else self.skew_seconds}",
            f"MESSAGE={self.message}",
        ]


def diagnose_time(
    *,
    now: Callable[[], datetime] | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    reference_fetcher: Callable[[str, float], datetime | None] | None = None,
    reference_url: str = DEFAULT_REFERENCE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> TimeDiagnostic:
    now = now or (lambda: datetime.now(timezone.utc))
    runner = runner or subprocess.run
    reference_fetcher = reference_fetcher or fetch_https_date

    try:
        local_now = _ensure_utc(now())
    except Exception as exc:
        return TimeDiagnostic(
            status="warn",
            system_time_available=False,
            local_utc=None,
            ntp_state="unknown",
            ntp_synchronized=None,
            system_clock_synchronized=None,
            reference_utc=None,
            skew_seconds=None,
            message=f"system time unavailable: {exc}",
        )

    ntp_synchronized, system_clock_synchronized, ntp_error = _read_ntp_state(runner)
    reference_time: datetime | None = None
    reference_error: str | None = None
    try:
        reference_time = reference_fetcher(reference_url, timeout)
    except Exception as exc:
        reference_error = str(exc)

    skew_seconds: int | None = None
    if reference_time is not None:
        reference_time = _ensure_utc(reference_time)
        skew_seconds = int(round((local_now - reference_time).total_seconds()))

    warnings: list[str] = []
    if ntp_synchronized is False or system_clock_synchronized is False:
        warnings.append("NTP/system clock synchronization is not active")
    elif ntp_synchronized is None and system_clock_synchronized is None:
        warnings.append(f"NTP synchronization state is unknown{': ' + ntp_error if ntp_error else ''}")
    if skew_seconds is not None and abs(skew_seconds) >= SEVERE_SKEW_SECONDS:
        warnings.append(
            f"severe clock skew detected ({skew_seconds}s); TLS and VPN handshakes may fail"
        )
    elif reference_time is None:
        warnings.append(
            f"clock skew could not be checked{': ' + reference_error if reference_error else ''}"
        )

    return TimeDiagnostic(
        status="warn" if warnings else "ok",
        system_time_available=True,
        local_utc=local_now.isoformat(),
        ntp_state=_ntp_state(ntp_synchronized, system_clock_synchronized),
        ntp_synchronized=ntp_synchronized,
        system_clock_synchronized=system_clock_synchronized,
        reference_utc=reference_time.isoformat() if reference_time else None,
        skew_seconds=skew_seconds,
        message="; ".join(warnings) if warnings else "system time and NTP checks passed",
    )


def fetch_https_date(url: str, timeout: float) -> datetime | None:
    request = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        date_header = response.headers.get("Date")
    if not date_header:
        return None
    parsed = email.utils.parsedate_to_datetime(date_header)
    return _ensure_utc(parsed)


def _read_ntp_state(
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> tuple[bool | None, bool | None, str | None]:
    try:
        result = runner(
            [
                "timedatectl",
                "show",
                "-p",
                "NTPSynchronized",
                "-p",
                "SystemClockSynchronized",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        return None, None, "timedatectl not found"
    except Exception as exc:
        return None, None, str(exc)
    if result.returncode != 0:
        return None, None, (result.stderr or "timedatectl failed").strip()
    values = _parse_timedatectl_show(result.stdout)
    return (
        _parse_bool(values.get("NTPSynchronized")),
        _parse_bool(values.get("SystemClockSynchronized")),
        None,
    )


def _parse_timedatectl_show(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    return values


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized == "yes":
        return True
    if normalized == "no":
        return False
    return None


def _ntp_state(ntp: bool | None, system_clock: bool | None) -> str:
    if ntp is False or system_clock is False:
        return "unsynchronized"
    if ntp is True or system_clock is True:
        return "synchronized"
    return "unknown"


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _bool_to_text(value: bool | None) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def main() -> int:
    diagnostic = diagnose_time()
    for line in diagnostic.to_lines():
        print(line)
    return 0 if diagnostic.system_time_available else 1


if __name__ == "__main__":
    raise SystemExit(main())
