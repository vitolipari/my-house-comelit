from __future__ import annotations

import struct

from .channel import ViperChannel
from .viper_protocol import (
    VIPER_CONTROL_MAGIC,
    ViperMessage,
    build_channel_ack,
    build_open_channel_from_model,
)
from .viper_socket import ViperSocket


class ChannelAllocator:
    def __init__(
        self,
        start: int = 0x6801,
    ) -> None:
        if not 0 <= start <= 0xFFFF:
            raise ValueError(
                "ID iniziale del canale non valido"
            )

        self._next_channel_id = start

    def allocate(self) -> int:
        channel_id = self._next_channel_id

        if channel_id > 0xFFFF:
            raise RuntimeError(
                "Spazio degli ID canale ViPER esaurito"
            )

        self._next_channel_id += 1

        return channel_id





class ChannelOpenError(RuntimeError):
    """Errore durante l'apertura di un canale ViPER."""


class ChannelManager:
    def __init__(
        self,
        viper_socket: ViperSocket,
    ) -> None:
        self._socket = viper_socket


    def open_with_response(
        self,
        channel: ViperChannel,
    ) -> tuple[ViperChannel, ViperMessage]:
        channel.validate()

        packet = build_open_channel_from_model(channel)

        print(
            f"TX open channel {channel.name} "
            f"id=0x{channel.channel_id:04x} "
            f"flags=0x{channel.flags:02x}"
        )

        self._socket.send_packet(packet)

        response = self._socket.receive_message()

        self.validate_open_ack(
            response=response,
            expected_channel_id=channel.channel_id,
        )

        return channel, response


    def open(
        self,
        channel: ViperChannel,
    ) -> ViperChannel:
        opened_channel, _ = self.open_with_response(channel)
        return opened_channel


#    def open(
#        self,
#        channel: ViperChannel,
#    ) -> ViperChannel:
#        """
#        Invia la richiesta di apertura e attende l'ACK.
#        """
#        channel.validate()
#
#        packet = build_open_channel_from_model(channel)
#
#        print(
#            f"TX open channel {channel.name} "
#            f"id=0x{channel.channel_id:04x} "
#            f"flags=0x{channel.flags:02x}"
#        )
#
#        self._socket.send_packet(packet)
#
#        response = self._socket.receive_message()
#
#        self.validate_open_ack(
#            response=response,
#            expected_channel_id=channel.channel_id,
#        )
#
#        return channel

    def acknowledge(
        self,
        channel_id: int,
    ) -> None:
        """
        Conferma un canale aperto dal dispositivo Comelit.
        """
        packet = build_channel_ack(channel_id)

        self._socket.send_packet(packet)

        print(
            f"TX ACK channel id=0x{channel_id:04x}"
        )

    @staticmethod
    def validate_open_ack(
        response: ViperMessage,
        expected_channel_id: int,
    ) -> None:
        if response.channel_id != 0:
            raise ChannelOpenError(
                "ACK ricevuto su un canale inatteso: "
                f"0x{response.channel_id:04x}"
            )

        payload = response.payload

        if len(payload) < 12:
            raise ChannelOpenError(
                f"ACK troppo corto: {payload.hex()}"
            )

        if payload[:2] != VIPER_CONTROL_MAGIC:
            raise ChannelOpenError(
                f"Magic ACK non valida: {payload.hex()}"
            )

        # cd ab 02 00
        if payload[2:4] != b"\x02\x00":
            raise ChannelOpenError(
                f"Messaggio non riconosciuto come ACK: {payload.hex()}"
            )

        body_length = struct.unpack(
            "<I",
            payload[4:8],
        )[0]

        if body_length != 4:
            raise ChannelOpenError(
                f"Lunghezza ACK inattesa: {body_length}"
            )

        acknowledged_channel_id = struct.unpack(
            "<H",
            payload[8:10],
        )[0]

        if acknowledged_channel_id != expected_channel_id:
            raise ChannelOpenError(
                "Il Comelit ha confermato un canale diverso: "
                f"atteso 0x{expected_channel_id:04x}, "
                f"ricevuto 0x{acknowledged_channel_id:04x}"
            )


