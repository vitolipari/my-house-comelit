from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class RtpPacket:
    version: int
    padding: bool
    extension: bool
    csrc_count: int

    marker: bool
    payload_type: int

    sequence: int
    timestamp: int
    ssrc: int

    payload: bytes


class RtpParser:

    HEADER_SIZE = 12

    @staticmethod
    def parse(data: bytes) -> RtpPacket:

        if len(data) < RtpParser.HEADER_SIZE:
            raise ValueError(
                "Pacchetto RTP troppo corto"
            )

        b0 = data[0]
        b1 = data[1]

        version = b0 >> 6
        padding = bool((b0 >> 5) & 1)
        extension = bool((b0 >> 4) & 1)
        csrc_count = b0 & 0x0F

        marker = bool((b1 >> 7) & 1)
        payload_type = b1 & 0x7F

        sequence = int.from_bytes(
            data[2:4],
            "big",
        )

        timestamp = int.from_bytes(
            data[4:8],
            "big",
        )

        ssrc = int.from_bytes(
            data[8:12],
            "big",
        )

        header_length = 12 + (4 * csrc_count)

        payload = data[header_length:]

        return RtpPacket(
            version=version,
            padding=padding,
            extension=extension,
            csrc_count=csrc_count,
            marker=marker,
            payload_type=payload_type,
            sequence=sequence,
            timestamp=timestamp,
            ssrc=ssrc,
            payload=payload,
        )

