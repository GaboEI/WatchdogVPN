from __future__ import annotations

import subprocess
import unittest
from typing import Any

from network_context.models import (
    ActionIntent,
    NetworkContextPolicy,
    NetworkContextTrigger,
    NetworkMatch,
    NetworkProfile,
)
from network_context.monitor import (
    ActiveNetwork,
    ConnectivityState,
    MonitorStatus,
    NetworkContextMonitor,
    NetworkObservation,
    ProfileMatchStatus,
    evaluate_network_context,
)


def completed(args: list[str], stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout, stderr="")


class FakeRunner:
    def __init__(self, outputs: dict[tuple[str, ...], subprocess.CompletedProcess[str]]) -> None:
        self.outputs = outputs
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(args))
        try:
            return self.outputs[tuple(args)]
        except KeyError as exc:
            raise AssertionError(f"unexpected command: {args}") from exc


def which_all(command: str) -> str | None:
    if command in {"nmcli", "ip"}:
        return f"/usr/bin/{command}"
    return None


class NetworkContextMonitorTests(unittest.TestCase):
    def test_observe_collects_networkmanager_and_default_route_read_only(self) -> None:
        runner = FakeRunner(
            {
                ("nmcli", "-t", "-f", "CONNECTIVITY", "general"): completed(
                    ["nmcli"],
                    "full\n",
                ),
                (
                    "nmcli",
                    "-t",
                    "-f",
                    "NAME,TYPE,DEVICE,STATE",
                    "connection",
                    "show",
                    "--active",
                ): completed(
                    ["nmcli"],
                    "Home Wi-Fi:802-11-wireless:wlp3s0:activated\n",
                ),
                (
                    "nmcli",
                    "-t",
                    "-f",
                    "ACTIVE,SSID,BSSID,DEVICE",
                    "dev",
                    "wifi",
                ): completed(
                    ["nmcli"],
                    "yes:Home Wi-Fi:aa\\:bb\\:cc\\:dd\\:ee\\:ff:wlp3s0\n",
                ),
                ("ip", "-j", "route", "show", "default"): completed(
                    ["ip"],
                    '[{"dst":"default","gateway":"192.0.2.1","dev":"wlp3s0"}]',
                ),
            }
        )

        observation = NetworkContextMonitor(runner=runner, which=which_all).observe()

        self.assertEqual(observation.status, MonitorStatus.OBSERVED)
        self.assertEqual(observation.connectivity, ConnectivityState.ONLINE)
        self.assertEqual(observation.default_route_interfaces, ("wlp3s0",))
        self.assertEqual(len(observation.active_networks), 1)
        self.assertEqual(observation.active_networks[0].interface_type, "wifi")
        self.assertEqual(observation.active_networks[0].bssid, "aa:bb:cc:dd:ee:ff")
        redacted = observation.to_dict()
        rendered = repr(redacted)
        self.assertIn("<redacted-interface>", rendered)
        self.assertIn("<redacted-ssid>", rendered)
        self.assertIn("<redacted-bssid>", rendered)
        self.assertIn("<not-observed-gateway>", rendered)
        self.assertNotIn("Home Wi-Fi", rendered)
        self.assertNotIn("wlp3s0", rendered)
        self.assertNotIn("aa:bb:cc:dd:ee:ff", rendered)
        self.assertEqual(
            redacted["active_networks"][0]["gateway_identifier"],
            "<not-observed-gateway>",
        )

    def test_malformed_nmcli_output_fails_closed_even_when_route_observation_works(self) -> None:
        def runner(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if args[0] == "nmcli":
                raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
            if args[0] == "ip":
                return completed(args, '[{"dst":"default","dev":"eth0"}]')
            raise AssertionError(f"unexpected command: {args}")

        observation = NetworkContextMonitor(runner=runner, which=which_all).observe()

        self.assertEqual(observation.status, MonitorStatus.ERROR)
        self.assertEqual(
            observation.diagnostics,
            ("NetworkManager monitor returned undecodable output",),
        )
        self.assertNotIn("ff", " ".join(observation.diagnostics))
        decision = evaluate_network_context(NetworkContextPolicy(enabled=True), observation)
        self.assertEqual(decision.status, ProfileMatchStatus.UNSUPPORTED)
        self.assertEqual(decision.action.value, "manual")

    def test_malformed_ip_output_fails_closed_even_when_nmcli_observation_works(self) -> None:
        outputs = {
            ("nmcli", "-t", "-f", "CONNECTIVITY", "general"): completed(["nmcli"], "full\n"),
            (
                "nmcli",
                "-t",
                "-f",
                "NAME,TYPE,DEVICE,STATE",
                "connection",
                "show",
                "--active",
            ): completed(["nmcli"], "Office:802-3-ethernet:eth0:activated\n"),
            (
                "nmcli",
                "-t",
                "-f",
                "ACTIVE,SSID,BSSID,DEVICE",
                "dev",
                "wifi",
            ): completed(["nmcli"], ""),
        }

        def runner(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if args[0] == "ip":
                raise UnicodeDecodeError("utf-8", b"\xfe", 0, 1, "invalid start byte")
            return outputs[tuple(args)]

        observation = NetworkContextMonitor(runner=runner, which=which_all).observe()

        self.assertEqual(observation.status, MonitorStatus.ERROR)
        self.assertEqual(
            observation.diagnostics,
            ("default route monitor returned undecodable output",),
        )
        decision = evaluate_network_context(NetworkContextPolicy(enabled=True), observation)
        self.assertEqual(decision.action.value, "manual")

    def test_monitor_timeout_and_nonzero_remain_controlled_observations(self) -> None:
        def timeout_runner(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if args[0] == "nmcli":
                raise subprocess.TimeoutExpired(args, 2)
            return completed(args, '[{"dst":"default","dev":"eth0"}]')

        timed_out = NetworkContextMonitor(runner=timeout_runner, which=which_all).observe()
        self.assertEqual(timed_out.status, MonitorStatus.ERROR)
        self.assertEqual(
            evaluate_network_context(NetworkContextPolicy(enabled=True), timed_out).action.value,
            "manual",
        )

        runner = FakeRunner(
            {
                ("nmcli", "-t", "-f", "CONNECTIVITY", "general"): completed(
                    ["nmcli"], "", returncode=1
                ),
                (
                    "nmcli",
                    "-t",
                    "-f",
                    "NAME,TYPE,DEVICE,STATE",
                    "connection",
                    "show",
                    "--active",
                ): completed(["nmcli"], "", returncode=1),
                (
                    "nmcli",
                    "-t",
                    "-f",
                    "ACTIVE,SSID,BSSID,DEVICE",
                    "dev",
                    "wifi",
                ): completed(["nmcli"], "", returncode=1),
                ("ip", "-j", "route", "show", "default"): completed(
                    ["ip"], '[{"dst":"default","dev":"eth0"}]'
                ),
            }
        )
        nonzero = NetworkContextMonitor(runner=runner, which=which_all).observe()
        self.assertEqual(nonzero.status, MonitorStatus.PARTIAL)
        self.assertIn("NetworkManager connectivity state unavailable", nonzero.diagnostics)

    def test_redacted_observation_distinguishes_absent_from_redacted_values(self) -> None:
        observation = NetworkObservation(
            status=MonitorStatus.OBSERVED,
            active_networks=(
                ActiveNetwork(
                    source="test",
                    interface_name="eth0",
                    interface_type="ethernet",
                    gateway_identifier="192.0.2.1",
                ),
                ActiveNetwork(source="test", interface_type="loopback"),
            ),
            default_route_interfaces=("eth0",),
        )

        redacted = observation.to_dict()

        self.assertEqual(
            redacted["active_networks"][0]["interface_name"],
            "<redacted-interface>",
        )
        self.assertEqual(
            redacted["active_networks"][0]["ssid"],
            "<not-observed-ssid>",
        )
        self.assertEqual(
            redacted["active_networks"][0]["gateway_identifier"],
            "<redacted-gateway>",
        )
        self.assertEqual(
            redacted["active_networks"][1]["interface_name"],
            "<not-observed-interface>",
        )
        self.assertEqual(redacted["default_route_interfaces"], ["<redacted-interface>"])

    def test_missing_nmcli_degrades_to_partial_route_only(self) -> None:
        runner = FakeRunner(
            {
                ("ip", "-j", "route", "show", "default"): completed(
                    ["ip"],
                    '[{"dst":"default","dev":"eth0"}]',
                ),
            }
        )

        observation = NetworkContextMonitor(
            runner=runner,
            which=lambda command: "/usr/bin/ip" if command == "ip" else None,
        ).observe()

        self.assertEqual(observation.status, MonitorStatus.PARTIAL)
        self.assertEqual(observation.default_route_interfaces, ("eth0",))
        self.assertIn("nmcli not found", " ".join(observation.diagnostics))

    def test_missing_nmcli_and_ip_degrades_to_unsupported(self) -> None:
        observation = NetworkContextMonitor(
            runner=FakeRunner({}),
            which=lambda command: None,
        ).observe()

        self.assertEqual(observation.status, MonitorStatus.UNSUPPORTED)
        self.assertIn("unsupported", evaluate_network_context(NetworkContextPolicy(enabled=True), observation).to_dict()["status"])

    def test_detects_interface_and_default_route_changes_from_transient_previous_state(self) -> None:
        previous = NetworkObservation(
            status=MonitorStatus.OBSERVED,
            active_networks=(ActiveNetwork(source="test", interface_name="eth0", interface_type="ethernet"),),
            default_route_interfaces=("eth0",),
        )
        runner = FakeRunner(
            {
                ("nmcli", "-t", "-f", "CONNECTIVITY", "general"): completed(["nmcli"], "full\n"),
                (
                    "nmcli",
                    "-t",
                    "-f",
                    "NAME,TYPE,DEVICE,STATE",
                    "connection",
                    "show",
                    "--active",
                ): completed(["nmcli"], "Office:802-3-ethernet:eth1:activated\n"),
                (
                    "nmcli",
                    "-t",
                    "-f",
                    "ACTIVE,SSID,BSSID,DEVICE",
                    "dev",
                    "wifi",
                ): completed(["nmcli"], ""),
                ("ip", "-j", "route", "show", "default"): completed(
                    ["ip"],
                    '[{"dst":"default","dev":"eth1"}]',
                ),
            }
        )

        observation = NetworkContextMonitor(runner=runner, which=which_all).observe(previous)

        self.assertTrue(observation.interface_changed)
        self.assertTrue(observation.default_route_changed)


class NetworkContextEvaluationTests(unittest.TestCase):
    def test_disabled_policy_stays_manual_even_when_observation_matches(self) -> None:
        observation = NetworkObservation(
            status=MonitorStatus.OBSERVED,
            connectivity=ConnectivityState.ONLINE,
            active_networks=(ActiveNetwork(source="test", interface_type="wifi", ssid="Home"),),
        )

        decision = evaluate_network_context(NetworkContextPolicy(), observation)

        self.assertEqual(decision.status, ProfileMatchStatus.UNSUPPORTED)
        self.assertFalse(decision.enabled)
        self.assertEqual(decision.action.value, "manual")

    def test_untrusted_profile_selects_modeled_connect_intent_without_execution(self) -> None:
        observation = NetworkObservation(
            status=MonitorStatus.OBSERVED,
            connectivity=ConnectivityState.ONLINE,
            active_networks=(ActiveNetwork(source="test", interface_type="wifi"),),
        )
        policy = NetworkContextPolicy(
            enabled=True,
            profiles=[
                NetworkProfile(
                    id="public-wifi",
                    label="Public Wi-Fi",
                    trust="untrusted",
                    matches=[NetworkMatch(kind="interface_type", value="wifi")],
                )
            ],
            triggers={
                NetworkContextTrigger.UNTRUSTED_NETWORK: ActionIntent(
                    enabled=True,
                    action="connect",
                    explanation="Connect only when untrusted network policy is enabled.",
                    disable_hint="Disable the untrusted network trigger.",
                    reversible=True,
                    reversal="Disconnect or return policy to manual mode.",
                )
            },
        )

        decision = evaluate_network_context(policy, observation)

        self.assertEqual(decision.status, ProfileMatchStatus.MATCHED)
        self.assertEqual(decision.trigger, NetworkContextTrigger.UNTRUSTED_NETWORK)
        self.assertTrue(decision.enabled)
        self.assertEqual(decision.action.value, "connect")
        self.assertFalse(decision.to_dict()["runtime_action_executed"])
        self.assertIn("modeled only", " ".join(decision.diagnostics))

    def test_captive_portal_and_offline_are_advisory_triggers(self) -> None:
        policy = NetworkContextPolicy(enabled=True)

        captive = evaluate_network_context(
            policy,
            NetworkObservation(
                status=MonitorStatus.OBSERVED,
                connectivity=ConnectivityState.CAPTIVE_PORTAL,
            ),
        )
        offline = evaluate_network_context(
            policy,
            NetworkObservation(
                status=MonitorStatus.OBSERVED,
                connectivity=ConnectivityState.OFFLINE,
            ),
        )

        self.assertEqual(captive.trigger, NetworkContextTrigger.CAPTIVE_PORTAL)
        self.assertEqual(offline.trigger, NetworkContextTrigger.OFFLINE)
        self.assertFalse(captive.enabled)
        self.assertFalse(offline.enabled)

    def test_interface_change_takes_precedence_over_trusted_match(self) -> None:
        observation = NetworkObservation(
            status=MonitorStatus.OBSERVED,
            connectivity=ConnectivityState.ONLINE,
            active_networks=(ActiveNetwork(source="test", interface_type="ethernet"),),
            interface_changed=True,
        )
        policy = NetworkContextPolicy(
            enabled=True,
            profiles=[
                NetworkProfile(
                    id="wired",
                    label="Wired",
                    trust="trusted",
                    matches=[NetworkMatch(kind="interface_type", value="ethernet")],
                )
            ],
        )

        decision = evaluate_network_context(policy, observation)

        self.assertEqual(decision.trigger, NetworkContextTrigger.INTERFACE_CHANGED)
        self.assertFalse(decision.enabled)

    def test_raw_explicit_consent_match_is_transient_and_redacted_in_observation(self) -> None:
        observation = NetworkObservation(
            status=MonitorStatus.OBSERVED,
            connectivity=ConnectivityState.ONLINE,
            active_networks=(ActiveNetwork(source="test", ssid="Lab SSID"),),
        )
        policy = NetworkContextPolicy(
            enabled=True,
            profiles=[
                NetworkProfile(
                    id="lab",
                    label="Lab",
                    trust="trusted",
                    matches=[
                        NetworkMatch(
                            kind="raw_ssid",
                            value="Lab SSID",
                            explicit_consent=True,
                            consent_note="User chose raw SSID matching.",
                        )
                    ],
                )
            ],
        )

        decision = evaluate_network_context(policy, observation)

        self.assertEqual(decision.trigger, NetworkContextTrigger.TRUSTED_NETWORK)
        self.assertNotIn("Lab SSID", repr(observation.to_dict()))
