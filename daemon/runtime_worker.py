from __future__ import annotations

import logging
import queue
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Protocol

from daemon.event_bus import EventBus
from drivers.base import ManagementPathSafetyError, TeardownBarrierError, UnsupportedDriverPolicyError
from daemon.protocol import (
    COMMAND_CONNECT,
    COMMAND_DISCONNECT,
    COMMAND_NODE_GROUP_AUTO_TEST,
    COMMAND_ROTATE,
    COMMAND_STATUS,
    EVENT_HEALTH_CHECK,
    EVENT_ROTATION,
    EVENT_STATE_CHANGED,
    ALLOWED_COMMANDS,
    Event,
    MUTATING_COMMANDS,
    Response,
    UnknownCommandError,
)
from metrics.recorder import MetricsRecorder
from models.connection_state import FAILURE_STATUSES, ConnectionState
from models.profile import Profile


LOGGER = logging.getLogger(__name__)


class RuntimeLike(Protocol):
    profile_store: Any

    def connect(self, profile: Profile) -> bool:
        ...

    def disconnect(self) -> bool:
        ...

    def status(self) -> ConnectionState:
        ...

    def automatic_actions_enabled(self) -> bool:
        ...

    def rotate_now(self, force: bool = False) -> ConnectionState:
        ...

    def run_iteration(self) -> ConnectionState:
        ...

    def scheduled_rotate(self) -> ConnectionState:
        ...

    def node_group_auto_test(self, group_name: str) -> dict[str, Any]:
        ...


_STOP = object()
_TICK = object()
_SCHEDULED_ROTATE = object()


@dataclass(slots=True)
class WorkerRequest:
    command: str
    payload: dict[str, Any] = field(default_factory=dict)
    command_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    deadline_monotonic: float | None = None
    response_queue: "queue.Queue[Response]" = field(default_factory=queue.Queue)
    cancellation_requested: threading.Event = field(default_factory=threading.Event)


@dataclass(slots=True)
class _CommandRecord:
    command: str
    state: str = "queued"
    response: Response | None = None
    request: WorkerRequest | None = None


class RuntimeWorker:
    _MAX_RETAINED_FINAL_OUTCOMES = 512

    def __init__(
        self,
        runtime: RuntimeLike,
        event_bus: EventBus | None = None,
        metrics_recorder: MetricsRecorder | None = None,
    ) -> None:
        self.runtime = runtime
        self.event_bus = event_bus or EventBus()
        self.metrics_recorder = metrics_recorder or MetricsRecorder()
        self._queue: "queue.Queue[WorkerRequest | object]" = queue.Queue()
        self._thread = threading.Thread(target=self._run, name="watchdogvpn-runtime-worker", daemon=True)
        self._started = threading.Event()
        self._stopped = threading.Event()
        self._last_tick_status: str | None = None
        self._autonomous_lock = threading.Lock()
        self._runtime_busy = False
        self._tick_pending = False
        self._command_lock = threading.Lock()
        self._command_records: dict[str, _CommandRecord] = {}
        self._final_command_ids: deque[str] = deque()

    def start(self) -> None:
        if self._thread.is_alive():
            return
        self._thread.start()
        self._started.wait(timeout=5.0)

    def stop(self, timeout: float | None = 5.0) -> bool:
        if not self._thread.is_alive():
            return True
        self._queue.put(_STOP)
        self._thread.join(timeout=timeout)
        return not self._thread.is_alive()

    def submit(
        self,
        command: str,
        payload: dict[str, Any] | None = None,
        timeout: float | None = 30.0,
        *,
        command_id: str | None = None,
        deadline_seconds: float | None = None,
    ) -> Response:
        request = WorkerRequest(
            command=command,
            payload=dict(payload or {}),
            command_id=command_id or str(uuid.uuid4()),
            deadline_monotonic=(time.monotonic() + deadline_seconds)
            if deadline_seconds
            else None,
        )
        self.submit_request(request)
        return request.response_queue.get(timeout=timeout)

    def submit_request(self, request: WorkerRequest) -> None:
        if not self._thread.is_alive():
            raise RuntimeError("runtime worker is not running")
        if request.command not in MUTATING_COMMANDS:
            self._queue.put(request)
            return
        with self._command_lock:
            if request.command_id in self._command_records:
                raise RuntimeError(f"duplicate command id: {request.command_id}")
            self._command_records[request.command_id] = _CommandRecord(
                command=request.command,
                request=request,
            )
        self._queue.put(request)

    def command_outcome(self, command_id: str) -> Response:
        """Return the authoritative state or final response for one IPC command.

        This bypasses the serialized runtime queue deliberately: status lookup
        must remain available while a network mutation is still executing.
        """
        with self._command_lock:
            record = self._command_records.get(command_id)
            if record is None:
                return Response(
                    ok=False,
                    payload={"command_id": command_id, "error_kind": "command_not_found"},
                    error="command outcome not found",
                )
            if record.response is not None:
                return record.response
            return Response(
                ok=False,
                payload={
                    "command_id": command_id,
                    "command": record.command,
                    "outcome": record.state,
                    "error_kind": "command_in_progress",
                },
                error="command is still running",
            )

    def cancel_command(self, command_id: str) -> Response:
        """Cancel only a command that has not started executing.

        Runtime network operations are not safely interruptible in this worker.
        A running command is therefore never reported as cancelled; callers get
        its ID and must query the final authoritative outcome instead.
        """
        with self._command_lock:
            record = self._command_records.get(command_id)
            if record is None:
                return Response(
                    ok=False,
                    payload={"command_id": command_id, "error_kind": "command_not_found"},
                    error="command outcome not found",
                )
            if record.response is not None:
                return record.response
            if record.state == "queued" and record.request is not None:
                record.request.cancellation_requested.set()
                response = _cancelled_response(command_id, record.command)
                record.state = "cancelled"
                record.response = response
                self._retain_final_command_locked(command_id)
                return response
            return Response(
                ok=False,
                payload={
                    "command_id": command_id,
                    "command": record.command,
                    "outcome": "running",
                    "error_kind": "command_in_progress",
                },
                error="command is already running; query command outcome for its final result",
            )

    def submit_tick(self) -> None:
        """Enqueue one autonomous health-check tick when the worker is idle.

        Fire-and-forget: goes through the same queue as IPC requests so it
        never runs concurrently with a connect/disconnect/rotate command,
        but nothing waits on a response. Ticks that overlap active or queued
        work are coalesced instead of accumulating behind a long command.
        """
        if not self._thread.is_alive():
            raise RuntimeError("runtime worker is not running")
        with self._autonomous_lock:
            if self._runtime_busy or self._tick_pending or not self._queue.empty():
                return
            self._tick_pending = True
            self._queue.put(_TICK)

    def submit_scheduled_rotation(self) -> None:
        """Enqueue a proactive scheduled rotation (see daemon.scheduled_rotation_loop).

        Same fire-and-forget discipline as submit_tick: the timer only
        decides *when*, execution is always serialized on this single
        worker thread through WatchdogRuntime.scheduled_rotate(), which
        reuses the same pool_builder/RotationEngine path as reactive and
        manual rotation.
        """
        if not self._thread.is_alive():
            raise RuntimeError("runtime worker is not running")
        self._queue.put(_SCHEDULED_ROTATE)

    def is_running(self) -> bool:
        return self._thread.is_alive() and not self._stopped.is_set()

    def _run(self) -> None:
        self._started.set()
        try:
            while True:
                item = self._queue.get()
                if item is _STOP:
                    return
                with self._autonomous_lock:
                    self._runtime_busy = True
                try:
                    if item is _TICK:
                        self._handle_tick()
                        continue
                    if item is _SCHEDULED_ROTATE:
                        self._handle_scheduled_rotation()
                        continue
                    if not isinstance(item, WorkerRequest):
                        continue
                    self._execute_request(item)
                finally:
                    with self._autonomous_lock:
                        self._runtime_busy = False
                        if item is _TICK:
                            self._tick_pending = False
        finally:
            self._stopped.set()

    def _execute_request(self, request: WorkerRequest) -> None:
        if request.command not in MUTATING_COMMANDS:
            request.response_queue.put(self._handle_request(request))
            return
        if request.cancellation_requested.is_set() or _deadline_expired(request):
            response = _cancelled_response(request.command_id, request.command)
            self._record_final_response(request, response, state="cancelled")
            request.response_queue.put(response)
            return
        with self._command_lock:
            record = self._command_records.get(request.command_id)
            if record is None or record.response is not None:
                response = _cancelled_response(request.command_id, request.command)
                request.response_queue.put(response)
                return
            record.state = "running"
        response = _with_command_metadata(
            self._handle_request(request), request.command_id, request.command
        )
        self._record_final_response(request, response, state="completed")
        request.response_queue.put(response)

    def _record_final_response(
        self,
        request: WorkerRequest,
        response: Response,
        *,
        state: str,
    ) -> None:
        with self._command_lock:
            record = self._command_records.get(request.command_id)
            if record is None:
                return
            # A queued cancellation is final before the queued item reaches
            # the worker. Never overwrite that acknowledged cancellation.
            if record.response is None:
                record.state = state
                record.response = response
                self._retain_final_command_locked(request.command_id)

    def _retain_final_command_locked(self, command_id: str) -> None:
        self._final_command_ids.append(command_id)
        while len(self._final_command_ids) > self._MAX_RETAINED_FINAL_OUTCOMES:
            expired_id = self._final_command_ids.popleft()
            record = self._command_records.get(expired_id)
            if record is not None and record.response is not None:
                self._command_records.pop(expired_id, None)

    def _handle_tick(self) -> None:
        # A tick has no caller waiting on a response - an unexpected
        # exception here must never escape and kill this thread, since it
        # also serves every IPC connect/disconnect/status/rotate command.
        try:
            state = self.runtime.run_iteration()
        except Exception:
            LOGGER.error("watchdog_tick_failed", exc_info=True)
            self.metrics_recorder.record_runtime_error("watchdog_tick_failed")
            return
        state_payload = _state_payload(state)
        self.metrics_recorder.record_health_check(state)
        self.event_bus.broadcast(Event(EVENT_HEALTH_CHECK, state_payload))
        if state_payload.get("status") != self._last_tick_status:
            self._last_tick_status = state_payload.get("status")
            self._broadcast_state(state_payload)

    def _handle_scheduled_rotation(self) -> None:
        # Same reasoning as _handle_tick: no caller is waiting on a
        # response, and an unexpected exception must never kill this
        # thread since it also serves every IPC command.
        try:
            state = self.runtime.scheduled_rotate()
        except Exception:
            LOGGER.error("scheduled_rotation_failed", exc_info=True)
            self.metrics_recorder.record_runtime_error("scheduled_rotation_failed")
            return
        state_payload = _state_payload(state)
        self.metrics_recorder.record_scheduled_rotation(state)
        # Mirrors _handle_rotate: EVENT_ROTATION means "a rotation was
        # requested", not "it succeeded" - the payload's status says what
        # actually happened (including a quiet no-op from scheduled_rotate
        # when the feature is disabled or the pool is empty).
        self.event_bus.broadcast(Event(EVENT_ROTATION, state_payload))
        self._broadcast_state(state_payload)

    def _handle_request(self, request: WorkerRequest) -> Response:
        try:
            if request.command not in ALLOWED_COMMANDS:
                raise UnknownCommandError(f"unknown command: {request.command}")
            if request.command == COMMAND_CONNECT:
                return self._handle_connect(request.payload)
            if request.command == COMMAND_DISCONNECT:
                return self._handle_disconnect()
            if request.command == COMMAND_STATUS:
                return self._handle_status()
            if request.command == COMMAND_ROTATE:
                return self._handle_rotate(request.payload)
            if request.command == COMMAND_NODE_GROUP_AUTO_TEST:
                return self._handle_node_group_auto_test(request.payload)
            raise UnknownCommandError(f"unknown command: {request.command}")
        except Exception as exc:
            # request.command is a fixed enum-like string (COMMAND_CONNECT
            # etc.), never user-controlled free text, so safe to interpolate
            # directly. Deliberately not logging request.payload (may carry
            # profile_id/config data) or the full exception text beyond what
            # the traceback itself captures. This was previously a silent
            # swallow at the top-level IPC dispatcher: no logger call here
            # meant any unexpected daemon bug surfaced only as a generic
            # "connect failed" to the CLI, with zero trace anywhere.
            LOGGER.exception("watchdog_ipc_command_failed command=%s", request.command)
            return Response(ok=False, error=str(exc))

    def _handle_connect(self, payload: dict[str, Any]) -> Response:
        try:
            profile_id = _require_string(payload.get("profile_id"), "profile_id")
        except ValueError as exc:
            return Response(ok=False, payload={"error_kind": "invalid_input"}, error=str(exc))
        profile = self.runtime.profile_store.get(profile_id)
        if profile is None:
            return Response(
                ok=False,
                payload={"error_kind": "profile_not_found"},
                error=f"profile not found: {profile_id}",
            )
        try:
            connected = self.runtime.connect(profile)
        except UnsupportedDriverPolicyError as exc:
            state_payload = _state_payload(self.runtime.status())
            self.metrics_recorder.record_connection_result(
                profile_id=profile.id,
                connected=False,
            )
            return Response(
                ok=False,
                payload={
                    "error_kind": "unsupported_policy",
                    "profile_id": profile.id,
                    "state": state_payload,
                    "unsupported_capabilities": list(exc.unsupported_capabilities),
                    "driver": exc.driver_name,
                },
                error=str(exc),
            )
        except ManagementPathSafetyError as exc:
            state_payload = _state_payload(self.runtime.status())
            self.metrics_recorder.record_connection_result(
                profile_id=profile.id,
                connected=False,
            )
            return Response(
                ok=False,
                payload={
                    "error_kind": "management_path_unprotected",
                    "profile_id": profile.id,
                    "state": state_payload,
                    "error_detail": str(exc),
                },
                error=str(exc),
            )
        except TeardownBarrierError as exc:
            state_payload = _state_payload(self.runtime.status())
            self.metrics_recorder.record_connection_result(
                profile_id=profile.id,
                connected=False,
            )
            self._broadcast_state(state_payload)
            return Response(
                ok=False,
                payload={
                    "error_kind": "cleanup_failed",
                    "profile_id": profile.id,
                    "state": state_payload,
                    "error_detail": str(exc),
                },
                error=str(exc),
            )
        state = self.runtime.status()
        state_payload = _state_payload(state)
        self.metrics_recorder.record_connection_result(
            profile_id=profile.id,
            connected=connected,
        )
        self._broadcast_state(state_payload)
        response_payload = {
            "connected": connected,
            "profile_id": profile.id,
            "state": state_payload,
        }
        if not connected:
            response_payload["error_kind"] = "connect_failed"
            error_detail = str(getattr(self.runtime, "last_error", "") or "").strip()
            if error_detail:
                response_payload["error_detail"] = error_detail
        return Response(
            ok=connected,
            payload=response_payload,
            error=None if connected else "connect failed",
        )

    def _handle_disconnect(self) -> Response:
        disconnected = self.runtime.disconnect()
        state = self.runtime.status()
        state_payload = _state_payload(state)
        self.metrics_recorder.record_disconnect_result(disconnected=disconnected)
        self._broadcast_state(state_payload)
        return Response(
            ok=disconnected,
            payload={
                "disconnected": disconnected,
                "state": state_payload,
            },
            error=None if disconnected else "disconnect failed",
        )

    def _handle_status(self) -> Response:
        return Response(ok=True, payload={"state": _state_payload(self.runtime.status())})

    def _handle_rotate(self, payload: dict[str, Any]) -> Response:
        force = payload.get("force", False)
        if not isinstance(force, bool):
            return Response(ok=False, error="force must be a boolean")
        performed = self.runtime.automatic_actions_enabled()
        state = self.runtime.rotate_now(force=force)
        state_payload = _state_payload(state)
        # A no-op because the VPN is intentionally off (performed=False) is
        # not a failure - the command correctly determined there was
        # nothing to rotate. ok only goes False when a rotation was
        # actually attempted and did not land in a healthy status
        # (WDCLI-002): that's the one case that must not look like success.
        ok = (not performed) or state.status not in FAILURE_STATUSES
        self.metrics_recorder.record_manual_rotation(state)
        self.event_bus.broadcast(Event(EVENT_ROTATION, state_payload))
        self._broadcast_state(state_payload)
        return Response(
            ok=ok,
            payload={"state": state_payload, "performed": performed},
            error=None if ok else _rotate_outcome_reason(state.status),
        )

    def _handle_node_group_auto_test(self, payload: dict[str, Any]) -> Response:
        group_name = _require_string(payload.get("group_name"), "group_name")
        result = self.runtime.node_group_auto_test(group_name)
        self.metrics_recorder.record_node_group_auto_test(
            group_name=group_name,
            result=str(result.get("result", "unknown")),
        )
        return Response(ok=True, payload=result)

    def _broadcast_state(self, state_payload: dict[str, Any]) -> None:
        self.event_bus.broadcast(Event(EVENT_STATE_CHANGED, state_payload))


def _state_payload(state: ConnectionState) -> dict[str, Any]:
    return state.to_dict()


def _rotate_outcome_reason(status: str) -> str:
    return f"rotation did not recover a healthy connection: status={status}"


def _deadline_expired(request: WorkerRequest) -> bool:
    return request.deadline_monotonic is not None and time.monotonic() >= request.deadline_monotonic


def _cancelled_response(command_id: str, command: str) -> Response:
    return Response(
        ok=False,
        payload={
            "command_id": command_id,
            "command": command,
            "outcome": "cancelled",
            "error_kind": "command_cancelled",
        },
        error="command cancelled before execution",
    )


def _with_command_metadata(response: Response, command_id: str, command: str) -> Response:
    payload = dict(response.payload)
    payload.update(
        {
            "command_id": command_id,
            "command": command,
            "outcome": "completed",
        }
    )
    return Response(ok=response.ok, payload=payload, error=response.error)


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()
