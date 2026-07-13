from __future__ import annotations

import re
import shlex

from models.profile import Profile, ProtocolType

SUPPORTED_OPENVPN_DIRECTIVES = frozenset(
    {
        "allow-compression", "allow-pull-fqdn", "allow-recursive-routing",
        "auth", "auth-nocache", "auth-retry", "bcast-buffers", "bind",
        "bind-dev", "block-ipv6", "block-outside-dns", "cipher", "client",
        "comp-lzo", "comp-noadapt", "compress", "connect-retry",
        "connect-retry-max", "connect-timeout", "data-ciphers",
        "data-ciphers-fallback", "dev", "dev-type", "dhcp-option",
        "disable-dco", "disable-occ", "dns", "explicit-exit-notify", "float",
        "fragment", "hand-window", "http-proxy-option", "ifconfig",
        "ifconfig-ipv6", "ifconfig-noexec", "ifconfig-nowarn", "inactive",
        "keepalive", "key-direction", "keying-material-exporter", "link-mtu",
        "lladdr", "local", "lport", "machine-readable-output", "mark",
        "mssfix", "mtu-disc", "mtu-test", "multihome", "mute",
        "mute-replay-warnings", "nice", "nobind", "ns-cert-type", "passtos",
        "persist-key", "persist-local-ip", "persist-remote-ip", "persist-tun",
        "ping", "ping-exit", "ping-restart", "ping-timer-rem", "port",
        "preresolve", "proto", "proto-force", "pull", "pull-filter",
        "push-peer-info", "rcvbuf", "redirect-gateway", "redirect-private",
        "register-dns", "remap-usr1", "remote", "remote-cert-eku",
        "remote-cert-ku", "remote-cert-tls", "remote-random",
        "remote-random-hostname", "reneg-bytes", "reneg-pkts", "reneg-sec",
        "replay-window", "resolv-retry", "route", "route-delay",
        "route-gateway", "route-ipv6", "route-ipv6-gateway", "route-metric",
        "route-noexec", "route-nopull", "route-table", "rport",
        "session-timeout", "shaper", "single-session", "sndbuf",
        "socks-proxy-retry", "static-challenge", "suppress-timestamps",
        "tcp-nodelay", "tcp-queue-limit", "tls-cert-profile", "tls-cipher",
        "tls-ciphersuites", "tls-client", "tls-crypt-v2-max-age", "tls-exit",
        "tls-timeout", "tls-version-max", "tls-version-min", "topology",
        "tran-window", "tun-ipv6", "tun-mtu", "tun-mtu-extra", "tun-mtu-max",
        "txqueuelen", "verb", "verify-hash", "verify-x509-name", "x509-track",
        "x509-username-field",
    }
)
SUPPORTED_OPENVPN_INLINE_BLOCKS = frozenset(
    {
        "auth-user-pass", "ca", "cert", "crl-verify", "extra-certs",
        "http-proxy-user-pass", "key", "peer-fingerprint", "pkcs12", "secret",
        "tls-auth", "tls-crypt", "tls-crypt-v2",
    }
)
_INLINE_PATH_DIRECTIVES = SUPPORTED_OPENVPN_INLINE_BLOCKS - {"auth-user-pass", "peer-fingerprint"}
_SPECIAL_DIRECTIVES = frozenset(
    {"auth-user-pass", "dns-updown", "http-proxy", "ignore-unknown-option", "setenv", "socks-proxy"}
)
_SAFE_OPTIONAL_COMPATIBILITY_DIRECTIVES = frozenset(
    {"block-outside-dns", "register-dns"}
)
_INLINE_TAG = re.compile(r"</?([A-Za-z0-9][A-Za-z0-9_-]*)>")


class OpenVPNConfigValidationError(ValueError):
    """Managed OpenVPN input crossed the fail-closed configuration boundary."""


def _directive_tokens(line: str, line_number: int) -> list[str]:
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#;"
    try:
        return list(lexer)
    except ValueError as exc:
        raise OpenVPNConfigValidationError(
            f"OpenVPN config has invalid quoting at line {line_number}"
        ) from exc


def _validate_special_directive(key: str, args: list[str], line_number: int) -> None:
    normalized = [arg.lower() for arg in args]
    if key == "auth-user-pass":
        if not args or normalized in (["username-only"], ["[inline]"]):
            return
    elif key == "dns-updown":
        if normalized == ["disable"]:
            return
    elif key == "http-proxy":
        if len(args) == 2 or (len(args) == 3 and normalized[2] in {"auto", "auto-nct"}):
            return
    elif key == "ignore-unknown-option":
        names = {arg.lower().removeprefix("--") for arg in args}
        if names and names <= _SAFE_OPTIONAL_COMPATIBILITY_DIRECTIVES:
            return
    elif key == "setenv":
        if len(args) == 2 and normalized[0] == "opt":
            if normalized[1].removeprefix("--") in _SAFE_OPTIONAL_COMPATIBILITY_DIRECTIVES:
                return
    elif key == "socks-proxy":
        if 1 <= len(args) <= 2:
            return
    raise OpenVPNConfigValidationError(
        f"OpenVPN directive '{key}' has unsupported or unsafe arguments at line {line_number}"
    )


def _validate_inline_path_directive(key: str, args: list[str], line_number: int) -> None:
    if not args or args[0].lower() != "[inline]":
        raise OpenVPNConfigValidationError(
            f"OpenVPN directive '{key}' must use managed inline data at line {line_number}"
        )
    if key == "tls-auth":
        valid = len(args) in {1, 2} and (len(args) == 1 or args[1] in {"0", "1"})
    else:
        valid = len(args) == 1
    if not valid:
        raise OpenVPNConfigValidationError(
            f"OpenVPN directive '{key}' has unsupported or unsafe arguments at line {line_number}"
        )


def validate_openvpn_config(text: str) -> dict[str, list[list[str]]]:
    raw_config = str(text or "").strip()
    if not raw_config:
        raise OpenVPNConfigValidationError("OpenVPN config is empty")
    if "\x00" in raw_config:
        raise OpenVPNConfigValidationError("OpenVPN config contains a NUL byte")

    directives: dict[str, list[list[str]]] = {}
    inline_blocks: set[str] = set()
    required_inline_blocks: list[tuple[str, int]] = []
    active_inline_block: str | None = None
    active_inline_has_data = False

    for line_number, raw_line in enumerate(raw_config.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        tag = _INLINE_TAG.fullmatch(line)

        if active_inline_block is not None:
            if tag and line.startswith("</"):
                closing_name = tag.group(1).lower()
                if closing_name != active_inline_block:
                    raise OpenVPNConfigValidationError(
                        f"OpenVPN inline block '{active_inline_block}' has a mismatched close at line {line_number}"
                    )
                if not active_inline_has_data:
                    raise OpenVPNConfigValidationError(
                        f"OpenVPN inline block '{active_inline_block}' is empty"
                    )
                active_inline_block = None
                active_inline_has_data = False
                continue
            if tag:
                raise OpenVPNConfigValidationError(
                    f"OpenVPN inline block nesting is not supported at line {line_number}"
                )
            active_inline_has_data = True
            continue

        if tag:
            block_name = tag.group(1).lower()
            if line.startswith("</"):
                raise OpenVPNConfigValidationError(
                    f"OpenVPN inline block '{block_name}' closes without an opener at line {line_number}"
                )
            if block_name not in SUPPORTED_OPENVPN_INLINE_BLOCKS:
                raise OpenVPNConfigValidationError(
                    f"OpenVPN inline block '{block_name}' is unsupported or unsafe at line {line_number}"
                )
            inline_blocks.add(block_name)
            active_inline_block = block_name
            active_inline_has_data = False
            continue

        parts = _directive_tokens(line, line_number)
        if not parts:
            continue
        key = parts[0].lower().removeprefix("--")
        if not key:
            raise OpenVPNConfigValidationError(
                f"OpenVPN config has an empty directive at line {line_number}"
            )
        args = parts[1:]

        if key in _INLINE_PATH_DIRECTIVES:
            _validate_inline_path_directive(key, args, line_number)
            required_inline_blocks.append((key, line_number))
        elif key in _SPECIAL_DIRECTIVES:
            _validate_special_directive(key, args, line_number)
            if key == "auth-user-pass" and [arg.lower() for arg in args] == ["[inline]"]:
                required_inline_blocks.append((key, line_number))
        elif key not in SUPPORTED_OPENVPN_DIRECTIVES:
            raise OpenVPNConfigValidationError(
                f"OpenVPN directive '{key}' is unsupported or unsafe at line {line_number}"
            )
        directives.setdefault(key, []).append(args)

    if active_inline_block is not None:
        raise OpenVPNConfigValidationError(
            f"OpenVPN inline block '{active_inline_block}' is not closed"
        )
    for block_name, line_number in required_inline_blocks:
        if block_name not in inline_blocks:
            raise OpenVPNConfigValidationError(
                f"OpenVPN directive '{block_name}' requires a matching inline block at line {line_number}"
            )
    return directives


def validate_openvpn_profile(profile: Profile) -> None:
    if profile.protocol not in {ProtocolType.OPENVPN, ProtocolType.OPENVPN_CLOAK}:
        return
    raw_config = str(profile.config.get("raw_config") or "").strip()
    if not raw_config:
        raise OpenVPNConfigValidationError(
            f"{profile.protocol.value} profile requires raw_config"
        )
    validate_openvpn_config(raw_config)
