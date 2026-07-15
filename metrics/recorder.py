from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Mapping

from models.connection_state import ALLOWED_STATUSES, ConnectionState

from .store import MetricsStore


LOGGER = logging.getLogger(__name__)
NODE_GROUP_RESULTS = frozenset({"selected", "unavailable"})


@dataclass(slots=True)
class MetricsRecorder:
    store: MetricsStore = field(default_factory=MetricsStore)

    def increment(self, counters: Mapping[str, int]) -> bool:
        try:
            return self.store.increment(counters)
        except Exception:
            LOGGER.warning("metrics_record_failed", exc_info=True)
            return False

    def record_connection_result(self, *, profile_id: str, connected: bool) -> None:
        result = "success" if connected else "failure"
        self.increment(
            {
                "command.connect.attempt": 1,
                f"command.connect.{result}": 1,
            }
        )

    def record_disconnect_result(self, *, disconnected: bool) -> None:
        result = "success" if disconnected else "failure"
        self.increment(
            {
                "command.disconnect.attempt": 1,
                f"command.disconnect.{result}": 1,
            }
        )

    def record_manual_rotation(self, state: ConnectionState) -> None:
        self._record_rotation("manual", state)

    def record_scheduled_rotation(self, state: ConnectionState) -> None:
        self._record_rotation("scheduled", state)

    def record_health_check(self, state: ConnectionState) -> None:
        self._record_state("health_check", state)

    def record_node_group_auto_test(self, *, group_name: str, result: str) -> None:
        category = result if result in NODE_GROUP_RESULTS else "unknown"
        self.increment(
            {
                "node_group.auto_test.attempt": 1,
                f"node_group.auto_test.{category}": 1,
            }
        )

    def record_runtime_error(self, name: str) -> None:
        self.increment({"error.runtime": 1})

    def record_route_action(self, action: str) -> None:
        self.increment({"route_action.recorded": 1})

    def record_rule_group(self, group_name: str) -> None:
        self.increment({"rule_group.recorded": 1})

    def record_profile_event(self, *, profile_id: str, event: str) -> None:
        if not profile_id:
            return
        self.increment({"profile.event": 1})

    def _record_rotation(self, kind: str, state: ConnectionState) -> None:
        status = _aggregate_status(state.status)
        self.increment(
            {
                f"rotation.{kind}.attempt": 1,
                f"rotation.{kind}.status.{status}": 1,
            }
        )

    def _record_state(self, source: str, state: ConnectionState) -> None:
        status = _aggregate_status(state.status)
        counters = {f"{source}.status.{status}": 1}
        if status in {
            "reconnecting",
            "recovered",
            "all_failed",
            "kill_switch_active",
            "rotation_unavailable",
        }:
            counters[f"recovery.status.{status}"] = 1
        self.increment(counters)


def _aggregate_status(status: str) -> str:
    return status if status in ALLOWED_STATUSES else "standby"
