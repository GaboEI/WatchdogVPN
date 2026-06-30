from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Callable

from drivers.base import BaseDriver
from models.profile import Profile


LOGGER = logging.getLogger(__name__)

EXTERNAL_CHECK_URL = "https://example.com"
PUBLIC_IP_URL = "https://api.ipify.org"
LOCAL_SOCKS_PROXY = "127.0.0.1:2080"

VerifyFn = Callable[[bool], "tuple[bool, str | None]"]


def _curl(args: list[str], timeout: float) -> tuple[bool, str]:
    if not shutil.which("curl"):
        return False, ""
    result = subprocess.run(
        ["curl", "--silent", "--show-error", "--fail", "--max-time", str(int(timeout)), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0, (result.stdout or "").strip()


def reachable_and_public_ip(via_proxy: bool, timeout: float = 5.0) -> tuple[bool, str | None]:
    proxy_args = ["--socks5-hostname", LOCAL_SOCKS_PROXY] if via_proxy else []
    reachable, _ = _curl([*proxy_args, EXTERNAL_CHECK_URL], timeout)
    if not reachable:
        return False, None
    ip_ok, ip_value = _curl([*proxy_args, PUBLIC_IP_URL], timeout)
    return True, (ip_value if ip_ok and ip_value else None)


def check(profile: Profile, driver: BaseDriver, verify: VerifyFn = reachable_and_public_ip) -> str:
    driver_status = driver.health_check()
    if driver_status == "down":
        LOGGER.warning("health_check_down profile_id=%s reason=driver_reported_down", profile.id)
        return "down"

    state = driver.status()
    if state.proxy_active:
        reachable, public_ip = verify(True)
    elif state.tun_active:
        reachable, public_ip = verify(False)
    else:
        LOGGER.warning("health_check_down profile_id=%s reason=no_active_route", profile.id)
        return "down"

    if not reachable:
        LOGGER.warning(
            "health_check_degraded profile_id=%s reason=external_endpoint_unreachable",
            profile.id,
        )
        return "degraded"

    if public_ip:
        LOGGER.info("health_check_public_ip profile_id=%s public_ip=%s", profile.id, public_ip)

    if driver_status == "degraded":
        LOGGER.info("health_check_degraded profile_id=%s reason=driver_reported_degraded", profile.id)
        return "degraded"

    LOGGER.info("health_check_ok profile_id=%s", profile.id)
    return "ok"
