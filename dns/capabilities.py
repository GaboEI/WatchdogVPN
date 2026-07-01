from __future__ import annotations

from models.profile import ProtocolType


SINGBOX_BACKED_PROTOCOLS = {
    ProtocolType.VLESS,
    ProtocolType.VMESS,
    ProtocolType.TROJAN,
    ProtocolType.HYSTERIA2,
    ProtocolType.TUIC,
    ProtocolType.SHADOWSOCKS,
    ProtocolType.WIREGUARD,
    ProtocolType.SOCKS,
    ProtocolType.HTTP,
}


def supports_fakeip(protocol: ProtocolType) -> bool:
    return protocol in SINGBOX_BACKED_PROTOCOLS
