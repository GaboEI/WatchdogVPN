from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Mapping

from models.connection_state import ConnectionState

from .store import MetricsStore


LOGGER = logging.getLogger(__name__)
SAFE_COUNTER_PART = re.compile(r"[^A-Za-z0-9_.:-]+")


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
        counters = {
            "command.connect.attempt": 1,
            f"command.connect.{result}": 1,
        }
        if profile_id:
            counters[f"profile.{_safe_part(profile_id)}.connect.{result}"] = 1
        self.increment(counters)

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
        safe_result = _safe_part(result or "unknown")
        counters = {
            "node_group.auto_test.attempt": 1,
            f"node_group.auto_test.{safe_result}": 1,
        }
        if group_name:
            counters[
                f"node_group.{_safe_part(group_name)}.auto_test.{safe_result}"
            ] = 1
        self.increment(counters)

    def record_runtime_error(self, name: str) -> None:
        self.increment({f"error.{_safe_part(name)}": 1})

    def record_route_action(self, action: str) -> None:
        self.increment({f"route_action.{_safe_part(action)}": 1})

    def record_rule_group(self, group_name: str) -> None:
        self.increment({f"rule_group.{_safe_part(group_name)}": 1})

    def record_profile_event(self, *, profile_id: str, event: str) -> None:
        if not profile_id:
            return
        self.increment({f"profile.{_safe_part(profile_id)}.{_safe_part(event)}": 1})

    def _record_rotation(self, kind: str, state: ConnectionState) -> None:
        counters = {
            f"rotation.{kind}.attempt": 1,
            f"rotation.{kind}.status.{_safe_part(state.status)}": 1,
        }
        if state.active_profile_id:
            profile_id = _safe_part(state.active_profile_id)
            status = _safe_part(state.status)
            counters[
                f"profile.{profile_id}.rotation.{kind}.{status}"
            ] = 1
        self.increment(counters)

    def _record_state(self, source: str, state: ConnectionState) -> None:
        counters = {
            f"{source}.status.{_safe_part(state.status)}": 1,
        }
        if state.status in {
            "reconnecting",
            "recovered",
            "all_failed",
            "kill_switch_active",
            "rotation_unavailable",
        }:
            counters[f"recovery.status.{_safe_part(state.status)}"] = 1
        if state.active_profile_id:
            profile_id = _safe_part(state.active_profile_id)
            status = _safe_part(state.status)
            counters[
                f"profile.{profile_id}.{source}.{status}"
            ] = 1
        self.increment(counters)


def _safe_part(value: str) -> str:
    normalized = SAFE_COUNTER_PART.sub("_", value.strip())
    return normalized.strip("._:-") or "unknown"
