from __future__ import annotations

import json
import unittest

from daemon.protocol import (
    ALLOWED_COMMANDS,
    COMMAND_CONNECT,
    COMMAND_COMMAND_CANCEL,
    COMMAND_COMMAND_OUTCOME,
    COMMAND_DISCONNECT,
    COMMAND_NODE_GROUP_AUTO_TEST,
    COMMAND_ROTATE,
    COMMAND_STATUS,
    COMMAND_TIMEOUT_SECONDS,
    EVENT_HEALTH_CHECK,
    EVENT_STATE_CHANGED,
    MESSAGE_TYPE_EVENT,
    MESSAGE_TYPE_REQUEST,
    MESSAGE_TYPE_RESPONSE,
    PROTOCOL_VERSION,
    Event,
    MalformedMessageError,
    Request,
    Response,
    UnknownCommandError,
    UnknownEventError,
    UnexpectedMessageTypeError,
    UnsupportedVersionError,
    decode_event_line,
    decode_message_line,
    decode_request_line,
    decode_response_line,
    encode_event,
    encode_message,
    encode_request,
    encode_response,
    command_timeout_seconds,
)


class DaemonProtocolRoundTripTests(unittest.TestCase):
    def test_request_round_trip(self) -> None:
        command_id = "123e4567-e89b-12d3-a456-426614174000"
        line = encode_request(COMMAND_CONNECT, {"profile_id": "p1"}, command_id=command_id)

        request = decode_request_line(line)

        self.assertEqual(request.command, COMMAND_CONNECT)
        self.assertEqual(request.payload, {"profile_id": "p1"})
        self.assertEqual(request.command_id, command_id)
        self.assertEqual(decode_message_line(line), request)

    def test_response_round_trip(self) -> None:
        line = encode_response(True, {"status": "connected"})

        response = decode_response_line(line)

        self.assertTrue(response.ok)
        self.assertEqual(response.payload, {"status": "connected"})
        self.assertIsNone(response.error)
        self.assertEqual(decode_message_line(line), response)

    def test_error_response_round_trip(self) -> None:
        line = encode_response(False, error="profile not found")

        response = decode_response_line(line)

        self.assertFalse(response.ok)
        self.assertEqual(response.payload, {})
        self.assertEqual(response.error, "profile not found")

    def test_event_round_trip(self) -> None:
        line = encode_event(EVENT_STATE_CHANGED, {"status": "recovered"})

        event = decode_event_line(line)

        self.assertEqual(event.event, EVENT_STATE_CHANGED)
        self.assertEqual(event.payload, {"status": "recovered"})
        self.assertEqual(decode_message_line(line), event)

    def test_message_encoding_is_newline_delimited_json(self) -> None:
        line = encode_message(Request(COMMAND_STATUS))

        self.assertTrue(line.endswith(b"\n"))
        data = json.loads(line.decode("utf-8"))
        self.assertEqual(data["version"], PROTOCOL_VERSION)
        self.assertEqual(data["type"], MESSAGE_TYPE_REQUEST)
        self.assertEqual(data["command"], COMMAND_STATUS)

    def test_all_command_constants_are_accepted(self) -> None:
        for command in (
            COMMAND_CONNECT,
            COMMAND_COMMAND_CANCEL,
            COMMAND_COMMAND_OUTCOME,
            COMMAND_DISCONNECT,
            COMMAND_NODE_GROUP_AUTO_TEST,
            COMMAND_STATUS,
            COMMAND_ROTATE,
        ):
            with self.subTest(command=command):
                self.assertEqual(decode_request_line(encode_request(command)).command, command)

    def test_each_command_has_one_authoritative_deadline(self) -> None:
        self.assertEqual(command_timeout_seconds(COMMAND_CONNECT), 30.0)
        self.assertEqual(command_timeout_seconds(COMMAND_DISCONNECT), 30.0)
        self.assertEqual(command_timeout_seconds(COMMAND_ROTATE), 30.0)
        self.assertEqual(command_timeout_seconds(COMMAND_NODE_GROUP_AUTO_TEST), 120.0)
        self.assertEqual(set(COMMAND_TIMEOUT_SECONDS), set(ALLOWED_COMMANDS))


class DaemonProtocolMalformedTests(unittest.TestCase):
    def test_rejects_non_json_line(self) -> None:
        with self.assertRaises(MalformedMessageError):
            decode_message_line(b"not-json\n")

    def test_rejects_missing_newline(self) -> None:
        with self.assertRaises(MalformedMessageError):
            decode_message_line(b"{}\n".rstrip(b"\n"))

    def test_rejects_multiple_lines(self) -> None:
        with self.assertRaises(MalformedMessageError):
            decode_message_line(b"{}\n{}\n")

    def test_rejects_json_array_top_level(self) -> None:
        with self.assertRaises(MalformedMessageError):
            decode_message_line(b"[]\n")

    def test_rejects_invalid_utf8(self) -> None:
        with self.assertRaises(MalformedMessageError):
            decode_message_line(b"\xff\n")

    def test_rejects_unknown_envelope_field(self) -> None:
        line = b'{"version":1,"type":"request","command":"status","payload":{},"extra":true}\n'

        with self.assertRaises(MalformedMessageError):
            decode_request_line(line)

    def test_rejects_unsupported_version(self) -> None:
        line = b'{"version":99,"type":"request","command":"status","payload":{}}\n'

        with self.assertRaises(UnsupportedVersionError):
            decode_request_line(line)

    def test_rejects_unexpected_message_type_for_decoder(self) -> None:
        line = encode_response(True)

        with self.assertRaises(UnexpectedMessageTypeError):
            decode_request_line(line)

    def test_rejects_unknown_message_type(self) -> None:
        line = b'{"version":1,"type":"future","payload":{}}\n'

        with self.assertRaises(UnexpectedMessageTypeError):
            decode_message_line(line)

    def test_rejects_non_object_payload(self) -> None:
        line = b'{"version":1,"type":"request","command":"status","payload":[]}\n'

        with self.assertRaises(MalformedMessageError):
            decode_request_line(line)

    def test_rejects_non_canonical_command_id(self) -> None:
        line = (
            b'{"version":1,"type":"request","command":"status","payload":{},'
            b'"command_id":"not-a-uuid"}\n'
        )

        with self.assertRaises(MalformedMessageError):
            decode_request_line(line)

    def test_rejects_non_boolean_response_ok(self) -> None:
        line = b'{"version":1,"type":"response","ok":"true","payload":{},"error":null}\n'

        with self.assertRaises(MalformedMessageError):
            decode_response_line(line)


class DaemonProtocolCommandEventTests(unittest.TestCase):
    def test_rejects_unknown_command(self) -> None:
        with self.assertRaises(UnknownCommandError):
            decode_request_line(b'{"version":1,"type":"request","command":"future","payload":{}}\n')

    def test_rejects_unknown_command_on_encode(self) -> None:
        with self.assertRaises(UnknownCommandError):
            encode_request("future")

    def test_rejects_unknown_event(self) -> None:
        with self.assertRaises(UnknownEventError):
            decode_event_line(b'{"version":1,"type":"event","event":"future","payload":{}}\n')

    def test_rejects_unknown_event_on_encode(self) -> None:
        with self.assertRaises(UnknownEventError):
            encode_event("future")

    def test_event_type_fields_are_strict(self) -> None:
        event = Event(EVENT_HEALTH_CHECK, {"status": "ok"})

        self.assertEqual(event.to_dict()["type"], MESSAGE_TYPE_EVENT)

    def test_response_type_fields_are_strict(self) -> None:
        response = Response(True)

        self.assertEqual(response.to_dict()["type"], MESSAGE_TYPE_RESPONSE)


if __name__ == "__main__":
    unittest.main()
