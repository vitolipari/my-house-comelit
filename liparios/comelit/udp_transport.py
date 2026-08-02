from __future__ import annotations

import socket
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UdpEndpoint:
    host: str
    port: int


class UdpTransport:
    def __init__(
        self,
        local_host: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not local_host:
            raise ValueError(
                "L'indirizzo locale UDP non può essere vuoto"
            )

        if timeout_seconds <= 0:
            raise ValueError(
                "Il timeout UDP deve essere maggiore di zero"
            )

        self._local_host = local_host
        self._timeout_seconds = timeout_seconds
        self._socket: socket.socket | None = None

    @property
    def socket(self) -> socket.socket:
        if self._socket is None:
            raise RuntimeError(
                "Trasporto UDP non aperto"
            )

        return self._socket

    @property
    def local_endpoint(self) -> UdpEndpoint:
        host, port = self.socket.getsockname()

        return UdpEndpoint(
            host=str(host),
            port=int(port),
        )

    @property
    def is_open(self) -> bool:
        return self._socket is not None

    def open(self) -> UdpEndpoint:
        if self._socket is not None:
            return self.local_endpoint

        udp_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        try:
            udp_socket.settimeout(
                self._timeout_seconds
            )

            udp_socket.bind(
                (self._local_host, 0)
            )

        except Exception:
            udp_socket.close()
            raise

        self._socket = udp_socket

        return self.local_endpoint

    def send(
        self,
        data: bytes,
        remote: UdpEndpoint,
    ) -> int:
        if not data:
            raise ValueError(
                "Il datagramma UDP non può essere vuoto"
            )

        if not 1 <= remote.port <= 65535:
            raise ValueError(
                "Porta UDP remota non valida"
            )

        return self.socket.sendto(
            data,
            (remote.host, remote.port),
        )

    def receive(
        self,
        max_size: int = 65535,
    ) -> tuple[bytes, UdpEndpoint]:
        if max_size <= 0:
            raise ValueError(
                "La dimensione massima deve essere positiva"
            )

        data, sender = self.socket.recvfrom(
            max_size
        )

        return (
            data,
            UdpEndpoint(
                host=str(sender[0]),
                port=int(sender[1]),
            ),
        )

    def close(self) -> None:
        if self._socket is None:
            return

        self._socket.close()
        self._socket = None

    def __enter__(self) -> UdpTransport:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()


