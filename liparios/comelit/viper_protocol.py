#!/usr/bin/env python3

from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from typing import Any
from .channel import ViperChannel


VIPER_FRAME_MAGIC = b"\x00\x06"
VIPER_CONTROL_MAGIC = b"\xcd\xab"

CHANNEL_OPEN = 0x01
CHANNEL_REPLY = 0x02

CHANNEL_NAME_LENGTH = 4

# DEFAULT_TCP_PORT = 64100
# DEFAULT_UDP_PORT = 64100

@dataclass(frozen=True)
class ViperMessage:
    channel_id: int
    payload: bytes


def build_open_channel(
    channel_name: str,
    channel_id: int,
    flags: int = 0,
) -> bytes:
    channel = ViperChannel(
        name=channel_name,
        channel_id=channel_id,
        flags=flags,
    )

    channel.validate()

    control_payload = (
        VIPER_CONTROL_MAGIC
        + bytes([CHANNEL_OPEN, 0x00])
        + struct.pack("<I", 7)
        + channel.name.encode("ascii")
        + struct.pack("<H", channel.channel_id)
        + bytes([channel.flags])
    )

    return (
        VIPER_FRAME_MAGIC
        + struct.pack("<H", len(control_payload))
        + b"\x00\x00\x00\x00"
        + control_payload
    )


def build_open_channel_from_model(
    channel: ViperChannel,
) -> bytes:
    channel.validate()

    return build_open_channel(
        channel_name=channel.name,
        channel_id=channel.channel_id,
        flags=channel.flags,
    )



def build_json_message(
    channel_id: int,
    payload: dict[str, Any],
) -> bytes:
    body = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    if len(body) > 0xFFFF:
        raise ValueError(
            "Il payload JSON supera la dimensione massima ViPER"
        )

    return (
        VIPER_FRAME_MAGIC
        + struct.pack("<H", len(body))
        + struct.pack("<H", channel_id)
        + b"\x00\x00"
        + body
    )


def recv_exact(
    sock: socket.socket,
    size: int,
) -> bytes:
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError(
                "Connessione chiusa dal dispositivo Comelit"
            )

        data.extend(chunk)

    return bytes(data)



def recv_viper_message(
    sock: socket.socket,
) -> ViperMessage:
    header = recv_exact(sock, 8)

    if header[:2] != VIPER_FRAME_MAGIC:
        raise ValueError(
            f"Header ViPER non valido: {header.hex()}"
        )

    payload_length = struct.unpack("<H", header[2:4])[0]
    channel_id = struct.unpack("<H", header[4:6])[0]

    payload = recv_exact(sock, payload_length)

    return ViperMessage(
        channel_id=channel_id,
        payload=payload,
    )


def decode_json_payload(
    message: ViperMessage,
) -> dict[str, Any] | None:
    try:
        decoded = message.payload.decode("utf-8")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(value, dict):
        return None

    return value


def build_channel_ack(channel_id: int) -> bytes:
    if not 0 <= channel_id <= 0xFFFF:
        raise ValueError("Channel ID ACK non valido")

    payload = (
        VIPER_CONTROL_MAGIC
        + bytes([CHANNEL_REPLY, 0x00])
        + struct.pack("<I", 4)
        + struct.pack("<H", channel_id)
        + b"\x00\x00"
    )

    return (
        VIPER_FRAME_MAGIC
        + struct.pack("<H", len(payload))
        + b"\x00\x00\x00\x00"
        + payload
    )


def build_open_ctpp_channel(
    channel_id: int,
    vip_source_address: str,
) -> bytes:
    address = vip_source_address.encode("ascii") + b"\x00"

    channel_payload = (
        b"CTPP"
        + struct.pack("<H", channel_id)
        + b"\x00\x00"
        + struct.pack("<I", len(address))
        + address
    )

    return (
        VIPER_FRAME_MAGIC
        + struct.pack("<H", len(channel_payload) + 8)
        + b"\x00\x00\x00\x00"
        + VIPER_CONTROL_MAGIC
        + bytes([CHANNEL_OPEN, 0x00])
        + struct.pack("<I", len(channel_payload))
        + channel_payload
    )


def build_udp_association_packet(
    channel_id: int,
    session_id: int,
    sequence: int,
    established: bool = False,
) -> bytes:
    if not 0 <= channel_id <= 0xFFFF:
        raise ValueError("Channel ID UDP non valido")

    if not 0 <= session_id <= 0xFFFF:
        raise ValueError("Session ID UDP non valido")

    if not 0 <= sequence <= 0xFF:
        raise ValueError("Sequence UDP non valida")

    state = b"\x01" if established else b"\x00"

    payload = (
        struct.pack("<H", session_id)
        + b"\x00"
        + bytes([sequence])
        + state
        + b"\x80"
    )

    return (
        VIPER_FRAME_MAGIC
        + struct.pack("<H", len(payload))
        + struct.pack("<H", channel_id)
        + b"\x00\x00"
        + payload
    )



