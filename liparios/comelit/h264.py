from __future__ import annotations

from dataclasses import dataclass

from .rtp import RtpPacket


ANNEX_B_START_CODE = b"\x00\x00\x00\x01"

NAL_TYPE_STAP_A = 24
NAL_TYPE_FU_A = 28


@dataclass(frozen=True, slots=True)
class NalUnit:
    nal_type: int
    forbidden_zero: bool
    nri: int
    payload: bytes

    def to_annex_b(self) -> bytes:
        return ANNEX_B_START_CODE + self.payload


class H264Parser:
    @staticmethod
    def parse(payload: bytes) -> NalUnit:
        if not payload:
            raise ValueError("Payload H.264 vuoto")

        first_byte = payload[0]

        forbidden_zero = bool(first_byte & 0x80)
        nri = (first_byte >> 5) & 0x03
        nal_type = first_byte & 0x1F

        if forbidden_zero:
            raise ValueError(
                "Il forbidden_zero_bit della NAL H.264 è impostato"
            )

        return NalUnit(
            nal_type=nal_type,
            forbidden_zero=forbidden_zero,
            nri=nri,
            payload=payload,
        )


class H264Depacketizer:
    """
    Ricostruisce NAL H.264 a partire dai payload RTP.

    Formati supportati:
    - Single NAL Unit: tipi 1-23
    - STAP-A: tipo 24
    - FU-A: tipo 28
    """

    def __init__(self) -> None:
        self._fu_buffer: bytearray | None = None
        self._fu_timestamp: int | None = None
        self._last_sequence: int | None = None

    def push(self, packet: RtpPacket) -> list[NalUnit]:
        payload = packet.payload

        if not payload:
            return []

        nal_type = payload[0] & 0x1F

        if 1 <= nal_type <= 23:
            self._reset_fu_state()

            return [
                H264Parser.parse(payload)
            ]

        if nal_type == NAL_TYPE_STAP_A:
            self._reset_fu_state()

            return self._parse_stap_a(payload)

        if nal_type == NAL_TYPE_FU_A:
            return self._push_fu_a(packet)

        raise ValueError(
            f"Tipo di pacchetto H.264 RTP non supportato: {nal_type}"
        )

    def reset(self) -> None:
        self._reset_fu_state()

    def _push_fu_a(
        self,
        packet: RtpPacket,
    ) -> list[NalUnit]:
        payload = packet.payload

        if len(payload) < 2:
            raise ValueError(
                "Payload FU-A troppo corto"
            )

        fu_indicator = payload[0]
        fu_header = payload[1]
        fragment = payload[2:]

        start = bool(fu_header & 0x80)
        end = bool(fu_header & 0x40)
        reserved = bool(fu_header & 0x20)
        original_nal_type = fu_header & 0x1F

        if reserved:
            self._reset_fu_state()

            raise ValueError(
                "Bit riservato FU-A impostato"
            )

        if original_nal_type == 0:
            self._reset_fu_state()

            raise ValueError(
                "Tipo NAL originale FU-A non valido"
            )

        if start:
            reconstructed_header = (
                (fu_indicator & 0xE0)
                | original_nal_type
            )

            self._fu_buffer = bytearray(
                [reconstructed_header]
            )
            self._fu_buffer.extend(fragment)

            self._fu_timestamp = packet.timestamp
            self._last_sequence = packet.sequence

            if end:
                return self._finish_fu_a()

            return []

        if self._fu_buffer is None:
            raise ValueError(
                "Ricevuto frammento FU-A senza frammento iniziale"
            )

        if packet.timestamp != self._fu_timestamp:
            self._reset_fu_state()

            raise ValueError(
                "Timestamp RTP cambiato durante una NAL FU-A"
            )

        expected_sequence = (
            (self._last_sequence + 1) & 0xFFFF
            if self._last_sequence is not None
            else packet.sequence
        )

        if packet.sequence != expected_sequence:
            received_sequence = packet.sequence

            self._reset_fu_state()

            raise ValueError(
                "Sequenza RTP discontinua durante FU-A: "
                f"attesa 0x{expected_sequence:04x}, "
                f"ricevuta 0x{received_sequence:04x}"
            )

        self._fu_buffer.extend(fragment)
        self._last_sequence = packet.sequence

        if not end:
            return []

        return self._finish_fu_a()

    def _finish_fu_a(self) -> list[NalUnit]:
        if self._fu_buffer is None:
            raise RuntimeError(
                "Buffer FU-A non disponibile"
            )

        payload = bytes(self._fu_buffer)
        self._reset_fu_state()

        return [
            H264Parser.parse(payload)
        ]

    @staticmethod
    def _parse_stap_a(
        payload: bytes,
    ) -> list[NalUnit]:
        offset = 1
        result: list[NalUnit] = []

        while offset < len(payload):
            if offset + 2 > len(payload):
                raise ValueError(
                    "Lunghezza STAP-A incompleta"
                )

            nal_length = int.from_bytes(
                payload[offset:offset + 2],
                "big",
            )
            offset += 2

            if nal_length == 0:
                raise ValueError(
                    "NAL STAP-A di lunghezza zero"
                )

            end = offset + nal_length

            if end > len(payload):
                raise ValueError(
                    "NAL STAP-A oltre la fine del payload"
                )

            result.append(
                H264Parser.parse(
                    payload[offset:end]
                )
            )

            offset = end

        return result

    def _reset_fu_state(self) -> None:
        self._fu_buffer = None
        self._fu_timestamp = None
        self._last_sequence = None

