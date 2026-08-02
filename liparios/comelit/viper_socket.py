from __future__ import annotations

import socket
import struct
from typing import Any

from .viper_protocol import (
    VIPER_FRAME_MAGIC,
    ViperMessage,
    build_json_message,
)


class ViperSocket:
    def __init__(
        self,
        sock: socket.socket,
    ) -> None:
        self._sock = sock

    @property
    def raw_socket(self) -> socket.socket:
        return self._sock

    def send_packet(
        self,
        packet: bytes,
    ) -> None:
        if not packet:
            raise ValueError(
                "Il pacchetto ViPER non può essere vuoto"
            )

        self._sock.sendall(packet)

    def send_json(
        self,
        channel_id: int,
        payload: dict[str, Any],
    ) -> None:
        print(
            f"TX channel=0x{channel_id:04x} "
            f"message={payload.get('message')}"
        )

        packet = build_json_message(
            channel_id=channel_id,
            payload=payload,
        )

        self.send_packet(packet)

    def receive_message(self) -> ViperMessage:
        header = self._recv_exact(8)

        if header[:2] != VIPER_FRAME_MAGIC:
            raise ValueError(
                f"Header ViPER non valido: {header.hex()}"
            )

        payload_length = struct.unpack(
            "<H",
            header[2:4],
        )[0]

        channel_id = struct.unpack(
            "<H",
            header[4:6],
        )[0]

        payload = self._recv_exact(payload_length)

        return ViperMessage(
            channel_id=channel_id,
            payload=payload,
        )

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        self._sock.close()

    def _recv_exact(
        self,
        size: int,
    ) -> bytes:
        if size < 0:
            raise ValueError(
                "La dimensione richiesta non può essere negativa"
            )

        data = bytearray()

        while len(data) < size:
            chunk = self._sock.recv(
                size - len(data)
            )

            if not chunk:
                raise ConnectionError(
                    "Connessione chiusa dal dispositivo Comelit"
                )

            data.extend(chunk)

        return bytes(data)

