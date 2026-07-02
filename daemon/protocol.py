from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


PROTOCOL_VERSION = 1

MESSAGE_TYPE_REQUEST = "request"
MESSAGE_TYPE_RESPONSE = "response"
MESSAGE_TYPE_EVENT = "event"

COMMAND_CONNECT = "connect"
COMMAND_DISCONNECT = "disconnect"
COMMAND_STATUS = "status"
COMMAND_ROTATE = "rotate"

ALLOWED_COMMANDS = frozenset(
    {
        COMMAND_CONNECT,
        COMMAND_DISCONNECT,
        COMMAND_STATUS,
        COMMAND_ROTATE,
    }
)

EVENT_STATE_CHANGED = "state_changed"
EVENT_HEALTH_CHECK = "health_check"
EVENT_ROTATION = "rotation"
EVENT_SHUTDOWN = "shutdown"

ALLOWED_EVENTS = frozenset(
    {
        EVENT_STATE_CHANGED,
        EVENT_HEALTH_CHECK,
        EVENT_ROTATION,
        EVENT_SHUTDOWN,
    }
)

REQUEST_FIELDS = frozenset({"version", "type", "command", "payload"})
RESPONSE_FIELDS = frozenset({"version", "type", "ok", "payload", "error"})
EVENT_FIELDS = frozenset({"version", "type", "event", "payload"})


class ProtocolError(ValueError):
    pass


class MalformedMessageError(ProtocolError):
    pass


class UnsupportedVersionError(ProtocolError):
    pass


class UnexpectedMessageTypeError(ProtocolError):
    pass


class UnknownCommandError(ProtocolError):
    pass


class UnknownEventError(ProtocolError):
    pass


@dataclass(frozen=True, slots=True)
class Request:
    command: str
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.command not in ALLOWED_COMMANDS:
            raise UnknownCommandError(f"unknown command: {self.command}")
        _require_mapping(self.payload, "request.payload")

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": PROTOCOL_VERSION,
            "type": MESSAGE_TYPE_REQUEST,
            "command": self.command,
            "payload": dict(self.payload),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Request":
        _validate_version(data)
        _validate_type(data, MESSAGE_TYPE_REQUEST)
        _reject_unknown_keys(data, REQUEST_FIELDS, "request")
        return cls(
            command=_require_string(data.get("command"), "request.command"),
            payload=_optional_mapping(data.get("payload"), "request.payload"),
        )


@dataclass(frozen=True, slots=True)
class Response:
    ok: bool
    payload: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def __post_init__(self) -> None:
        _require_mapping(self.payload, "response.payload")
        if not isinstance(self.ok, bool):
            raise MalformedMessageError("response.ok must be a boolean")
        if self.error is not None and not isinstance(self.error, str):
            raise MalformedMessageError("response.error must be a string or null")

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": PROTOCOL_VERSION,
            "type": MESSAGE_TYPE_RESPONSE,
            "ok": self.ok,
            "payload": dict(self.payload),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Response":
        _validate_version(data)
        _validate_type(data, MESSAGE_TYPE_RESPONSE)
        _reject_unknown_keys(data, RESPONSE_FIELDS, "response")
        ok = data.get("ok")
        if not isinstance(ok, bool):
            raise MalformedMessageError("response.ok must be a boolean")
        error = data.get("error")
        if error is not None and not isinstance(error, str):
            raise MalformedMessageError("response.error must be a string or null")
        return cls(
            ok=ok,
            payload=_optional_mapping(data.get("payload"), "response.payload"),
            error=error,
        )


@dataclass(frozen=True, slots=True)
class Event:
    event: str
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.event not in ALLOWED_EVENTS:
            raise UnknownEventError(f"unknown event: {self.event}")
        _require_mapping(self.payload, "event.payload")

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": PROTOCOL_VERSION,
            "type": MESSAGE_TYPE_EVENT,
            "event": self.event,
            "payload": dict(self.payload),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        _validate_version(data)
        _validate_type(data, MESSAGE_TYPE_EVENT)
        _reject_unknown_keys(data, EVENT_FIELDS, "event")
        return cls(
            event=_require_string(data.get("event"), "event.event"),
            payload=_optional_mapping(data.get("payload"), "event.payload"),
        )


def encode_request(command: str, payload: dict[str, Any] | None = None) -> bytes:
    return encode_message(Request(command=command, payload=payload or {}))


def decode_request_line(line: bytes | str) -> Request:
    return Request.from_dict(_decode_envelope(line))


def encode_response(
    ok: bool,
    payload: dict[str, Any] | None = None,
    error: str | None = None,
) -> bytes:
    return encode_message(Response(ok=ok, payload=payload or {}, error=error))


def decode_response_line(line: bytes | str) -> Response:
    return Response.from_dict(_decode_envelope(line))


def encode_event(event: str, payload: dict[str, Any] | None = None) -> bytes:
    return encode_message(Event(event=event, payload=payload or {}))


def decode_event_line(line: bytes | str) -> Event:
    return Event.from_dict(_decode_envelope(line))


def encode_message(message: Request | Response | Event) -> bytes:
    return (json.dumps(message.to_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def decode_message_line(line: bytes | str) -> Request | Response | Event:
    data = _decode_envelope(line)
    message_type = _require_string(data.get("type"), "message.type")
    if message_type == MESSAGE_TYPE_REQUEST:
        return Request.from_dict(data)
    if message_type == MESSAGE_TYPE_RESPONSE:
        return Response.from_dict(data)
    if message_type == MESSAGE_TYPE_EVENT:
        return Event.from_dict(data)
    raise UnexpectedMessageTypeError(f"unexpected message type: {message_type}")


def _decode_envelope(line: bytes | str) -> dict[str, Any]:
    if isinstance(line, bytes):
        try:
            line = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MalformedMessageError("message line must be valid UTF-8") from exc
    if not isinstance(line, str):
        raise MalformedMessageError("message line must be bytes or string")
    if not line.endswith("\n"):
        raise MalformedMessageError("message line must end with newline")
    if "\n" in line[:-1]:
        raise MalformedMessageError("message line must contain exactly one JSON object")
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        raise MalformedMessageError(f"invalid JSON message: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise MalformedMessageError("message must be a JSON object")
    return data


def _validate_version(data: dict[str, Any]) -> None:
    version = data.get("version")
    if version != PROTOCOL_VERSION:
        raise UnsupportedVersionError(f"unsupported protocol version: {version}")


def _validate_type(data: dict[str, Any], expected: str) -> None:
    actual = _require_string(data.get("type"), "message.type")
    if actual != expected:
        raise UnexpectedMessageTypeError(f"expected {expected} message, got {actual}")


def _reject_unknown_keys(data: dict[str, Any], allowed: frozenset[str], object_name: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        names = ", ".join(unknown)
        raise MalformedMessageError(f"{object_name} contains unsupported fields: {names}")


def _optional_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    return _require_mapping(value, field_name)


def _require_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MalformedMessageError(f"{field_name} must be an object")
    return dict(value)


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise MalformedMessageError(f"{field_name} must be a non-empty string")
    return value
