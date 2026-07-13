from __future__ import annotations

import unittest
from unittest.mock import patch

from core.runtime_observation import (
    EffectiveRuntimeObservation,
    ObservationCommandResult,
    observe_effective_runtime,
)
from drivers.runtime_paths import OwnedProcess, TCPListenerObservation


class FakeRunner:
    def __init__(self, responses: dict[tuple[str, ...], ObservationCommandResult]) -> None:
        self.responses = responses
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> ObservationCommandResult:
        self.commands.append(command)
        return self.responses.get(tuple(command), ObservationCommandResult(returncode=1))


class EffectiveRuntimeObservationTests(unittest.TestCase):
    def test_observes_only_owned_runtime_and_exact_watchdog_artifacts(self) -> None:
        runner = FakeRunner(
            {
                ("nft", "list", "table", "inet", "sing-box"): ObservationCommandResult(0),
                ("ip", "rule", "show"): ObservationCommandResult(
                    0, "9000: from all fwmark 0x2023 lookup 2022"
                ),
                ("ip", "route", "show", "table", "all"): ObservationCommandResult(
                    0, "default dev wdvpn-tun0 table 2022"
                ),
            }
        )
        processes = (
            OwnedProcess(pid=101, executable="sing-box"),
            OwnedProcess(pid=102, executable="ck-client"),
        )
        with (
            patch("core.runtime_observation.owned_processes", return_value=processes),
            patch(
                "core.runtime_observation.observe_tcp_listener_ports",
                return_value=TCPListenerObservation(True, (2080, 2081, 1984)),
            ),
            patch(
                "core.runtime_observation._interface_exists",
                side_effect=lambda name: name == "wdvpn-tun0",
            ),
        ):
            observation = observe_effective_runtime(runner=runner)

        self.assertEqual(observation.processes, ("ck-client", "sing-box"))
        self.assertEqual(observation.listener_ports, (2080, 2081, 1984))
        self.assertEqual(observation.interfaces, ("wdvpn-tun0",))
        self.assertIn("routing:nft/sing-box", observation.routing_artifacts)
        self.assertIn("routing:ip-rule/sing-box-mark", observation.routing_artifacts)
        self.assertIn("routing:ipv4/watchdog-interface", observation.routing_artifacts)
        self.assertNotIn("routing:ipv6/watchdog-interface", observation.routing_artifacts)

    def test_no_evidence_returns_empty_observation(self) -> None:
        runner = FakeRunner({})
        with (
            patch("core.runtime_observation.owned_processes", return_value=()),
            patch(
                "core.runtime_observation.observe_tcp_listener_ports",
                return_value=TCPListenerObservation(True, ()),
            ),
            patch("core.runtime_observation._interface_exists", return_value=False),
        ):
            observation = observe_effective_runtime(runner=runner)

        self.assertEqual(observation, EffectiveRuntimeObservation())

    def test_artifact_labels_are_stable_and_deduplicated(self) -> None:
        observation = EffectiveRuntimeObservation(
            processes=("sing-box", "sing-box"),
            interfaces=("wdvpn-tun0",),
            listener_ports=(2080,),
            routing_artifacts=("routing:nft/sing-box", "routing:nft/sing-box"),
        )

        self.assertEqual(
            observation.artifacts,
            (
                "interface:wdvpn-tun0",
                "owned_listener:tcp/2080",
                "owned_process:sing-box",
                "routing:nft/sing-box",
            ),
        )


if __name__ == "__main__":
    unittest.main()
