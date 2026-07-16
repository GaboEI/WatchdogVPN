from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
import socket
from typing import Any

from drivers.amneziawg_driver import INTERFACE_NAME as AMNEZIAWG_INTERFACE_NAME
from drivers.base import DRIVER_POLICY_CAPABILITIES, BaseDriver, ReentrantConnectGuard
from drivers.singbox_driver import SingBoxDriver
from models.connection_state import ConnectionState
from models.profile import Profile

COMPANION_TUN_INTERFACE = "wdvpn-tun0"

KNOWN_OWNED_INTERFACES = (AMNEZIAWG_INTERFACE_NAME, COMPANION_TUN_INTERFACE)


class NativePolicyDriver(BaseDriver, ReentrantConnectGuard):
    """Compose a native tunnel transport with the sing-box policy runtime.

    The native driver never gains policy capabilities itself. This wrapper owns
    the transaction: native transport must be healthy before the policy
    companion starts, and a companion failure rolls the native transport back.
    """

    policy_capabilities = DRIVER_POLICY_CAPABILITIES

    requires_profile_egress_check = True

    def __init__(self, native: BaseDriver, companion: SingBoxDriver | None = None) -> None:
        self.native = native
        self.companion = companion or SingBoxDriver()
        self._active_profile: Profile | None = None
        self._connected_at: datetime | None = None
        self.last_error = ""

    def _has_existing_connection(self) -> bool:
        return self._active_profile is not None

    @staticmethod
    def _native_endpoint_bypass_cidrs(profile: Profile) -> tuple[str, ...]:
        """Return the native transport's UDP endpoints as stable CIDRs.

        The companion's transparent TUN must never recapture encrypted native
        transport packets. Resolve a hostname before TUN activation; an IP
        export takes the fast deterministic path.
        """
        raw_host = profile.config.get("host") or profile.config.get("server")
        if not isinstance(raw_host, str) or not raw_host.strip():
            return ()
        host = raw_host.strip().strip("[]")
        try:
            address = ip_address(host)
            return (f"{address}/{128 if address.version == 6 else 32}",)
        except ValueError:
            pass
        try:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
        except OSError:
            return ()
        addresses = {
            ip_address(record[4][0])
            for record in records
            if record[4] and record[4][0]
        }
        return tuple(sorted(
            f"{address}/{128 if address.version == 6 else 32}"
            for address in addresses
        ))

    def connect(self, profile: Profile, dns_policy=None, **options: Any) -> bool:
        self.last_error = ""
        if not self._ensure_disconnected_before_connect():
            self.last_error = "existing native policy runtime teardown failed"
            return False
        try:
            management_routes = self.companion.preflight_native_management_routes(
                mode=str(options.get("mode", "global")),
                capture_modes=options.get("capture_modes"),
                known_owned_interfaces=KNOWN_OWNED_INTERFACES,
            )
        except Exception as exc:
            self.last_error = str(exc)
            return False
        if not self.native.connect(profile):
            self.last_error = getattr(self.native, "last_error", "") or "native transport failed"
            return False
        # Native drivers can expose their owned interface before the first
        # authenticated handshake/ping completes. Require truthful ownership
        # before starting policy, then let the normal continuous health gate
        # require the stronger handshake/egress proof.
        if self.native.status().status != "connected":
            self.last_error = "native transport readiness is incomplete"
            self.native.disconnect()
            return False
        companion_options = dict(options)
        companion_options["native_transport"] = True
        companion_options["native_bypass_cidrs"] = self._native_endpoint_bypass_cidrs(profile)
        # Native preflight above already installed the only safe SSH plan; do not
        # invoke the ordinary profile-bound preflight a second time.
        companion_options["management_peers"] = ()
        if management_routes:
            companion_options["management_routes"] = management_routes
        if not self.companion.connect(profile, dns_policy=dns_policy, **companion_options):
            self.last_error = self.companion.last_error or "policy companion failed"
            companion_stopped = self.companion.disconnect()
            native_stopped = self.native.disconnect()
            if not companion_stopped or not native_stopped:
                self.last_error += "; rollback cleanup failed"
            return False
        if self.companion.health_check() != "ok":
            self.last_error = "policy companion readiness is incomplete"
            self.disconnect()
            return False
        self._active_profile = profile
        self._connected_at = datetime.now().astimezone()
        return True

    def disconnect(self) -> bool:
        companion_stopped = self.companion.disconnect()
        if not companion_stopped:
            self.last_error = "policy companion teardown failed"
            return False
        native_stopped = self.native.disconnect()
        if not native_stopped:
            self.last_error = "native transport teardown failed"
            return False
        self._active_profile = None
        self._connected_at = None
        return True

    def health_check(self) -> str:
        native = self.native.health_check()
        companion = self.companion.health_check()
        if native == "down" or companion == "down":
            return "down"
        if native != "ok" or companion != "ok":
            return "degraded"
        return "ok"

    def status(self) -> ConnectionState:
        native = self.native.status()
        companion = self.companion.status()
        if native.status == "runtime_mismatch" or companion.status == "runtime_mismatch":
            return ConnectionState(
                active_profile_id=self._active_profile.id if self._active_profile else "",
                mode="native-policy",
                tun_active=companion.tun_active,
                proxy_active=companion.proxy_active,
                runtime_mismatch_severity="critical",
                runtime_artifacts=tuple(sorted(set((*native.runtime_artifacts, *companion.runtime_artifacts)))),
                status="runtime_mismatch",
            )
        if self._active_profile is not None and native.status == "connected" and companion.status == "connected":
            return ConnectionState(
                active_profile_id=self._active_profile.id,
                connected_at=self._connected_at,
                mode="native-policy",
                tun_active=companion.tun_active,
                proxy_active=companion.proxy_active,
                lan_gateway_active=companion.lan_gateway_active,
                lan_gateway_interface=companion.lan_gateway_interface,
                lan_gateway_client_cidr=companion.lan_gateway_client_cidr,
                lan_gateway_dns_mode=companion.lan_gateway_dns_mode,
                lan_gateway_status=companion.lan_gateway_status,
                status="connected",
            )
        return ConnectionState(status="standby")

    def is_available(self) -> bool:
        return self.native.is_available() and self.companion.is_available()
