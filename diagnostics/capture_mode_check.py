from __future__ import annotations

from dataclasses import dataclass

from config.state_manager import StateManager, parse_capture_modes


@dataclass(frozen=True, slots=True)
class CaptureModeDiagnostic:
    status: str
    routing_policy: str
    capture_modes: tuple[str, ...]
    default_route_action: str
    message: str

    def to_lines(self) -> list[str]:
        return [
            f"STATUS={self.status}",
            f"ROUTING_POLICY={self.routing_policy}",
            f"CAPTURE_MODES={','.join(self.capture_modes)}",
            f"DEFAULT_ROUTE_ACTION={self.default_route_action}",
            f"MESSAGE={self.message}",
        ]


def diagnose_capture_mode(state_manager: StateManager | None = None) -> CaptureModeDiagnostic:
    manager = state_manager or StateManager()
    state = manager.load()
    routing_policy = str(state.get("routing_policy", "rule"))
    default_route_action = str(state.get("default_route_action", "current"))
    capture_modes = parse_capture_modes(str(state.get("capture_modes", "local_proxy")))

    # default_route_action="current" under "rule"/"global" routing_policy
    # means the operator's configured intent is "route everything through
    # the active profile". If capture_modes does not include "tun", that
    # intent is not actually being met system-wide: only apps manually
    # configured to dial the local SOCKS/HTTP proxy are protected. This
    # combination is silent and persists across state.toml preserved
    # unchanged by update.sh, so a real install can stay unknowingly
    # unprotected indefinitely (Phase 23 Task 23.3.4).
    silently_unprotected = (
        routing_policy in {"rule", "global"}
        and default_route_action == "current"
        and "tun" not in capture_modes
    )
    if silently_unprotected:
        return CaptureModeDiagnostic(
            status="warn",
            routing_policy=routing_policy,
            capture_modes=capture_modes,
            default_route_action=default_route_action,
            message=(
                "capture_modes has no tun while configured to route everything "
                "through the active profile (default_route_action=current): only "
                "apps manually pointed at the local SOCKS/HTTP proxy are actually "
                "protected, not general system traffic. Run "
                "'watchdog config set capture-modes local_proxy,tun' for full "
                "system-wide capture."
            ),
        )
    return CaptureModeDiagnostic(
        status="ok",
        routing_policy=routing_policy,
        capture_modes=capture_modes,
        default_route_action=default_route_action,
        message="capture configuration matches the configured routing intent",
    )


def main() -> int:
    diagnostic = diagnose_capture_mode()
    for line in diagnostic.to_lines():
        print(line)
    return 0 if diagnostic.status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
