from __future__ import annotations

import struct

from .viper_protocol import VIPER_FRAME_MAGIC



def build_confirm_entrance_session_packet(
    ctpp_channel: int,
    server_transaction: bytes,
    source_address: str,
    entrance_address: str,
) -> bytes:
    if len(server_transaction) != 4:
        raise ValueError(
            "La transaction CTPP deve contenere 4 byte"
        )

    source = source_address.encode("ascii")
    entrance = entrance_address.encode("ascii")

    if len(source) != 9:
        raise ValueError(
            "L'indirizzo sorgente ViP deve essere lungo "
            f"9 caratteri: {source_address}"
        )

    if len(entrance) != 8:
        raise ValueError(
            "L'indirizzo del posto esterno deve essere lungo "
            f"8 caratteri: {entrance_address}"
        )

    # Trasformazione osservata:
    #
    # server:  de f4 cb b3
    # client:  5e f4 b3 cb
    #
    # quindi:
    # - viene azzerato il bit alto del primo byte;
    # - gli ultimi due byte vengono scambiati.
    transaction = bytes(
        [
            server_transaction[0] & 0x7F,
            server_transaction[1],
            server_transaction[3],
            server_transaction[2],
        ]
    )

    payload = (
        b"\x40\x18"
        + transaction
        + b"\x00\x08"
        + b"\x00\x03"
        + b"\x49\x00"
        + b"\x27\x00\x00\x00"
        + b"\xff\xff\xff\xff"
        + source
        + b"\x00"
        + entrance
        + b"\x00\x00"
    )

    if len(payload) != 40:
        raise RuntimeError(
            "Payload conferma CTPP di dimensione inattesa: "
            f"{len(payload)}"
        )

    return (
        VIPER_FRAME_MAGIC
        + struct.pack("<H", len(payload))
        + struct.pack("<H", ctpp_channel)
        + b"\x00\x00"
        + payload
    )



def build_start_entrance_session_packet(
    ctpp_channel: int,
    source_address: str,
    entrance_address: str,
) -> bytes:
    """
    Costruisce la richiesta CTPP osservata nel frame 297.

    Questa prima versione replica alcuni campi binari catturati
    dall'app iPhone. Andranno interpretati e resi dinamici dopo
    aver verificato l'avvio effettivo della sessione.
    """

    if not 0 <= ctpp_channel <= 0xFFFF:
        raise ValueError("Canale CTPP non valido")

    source = source_address.encode("ascii")
    entrance = entrance_address.encode("ascii")

    # Nel protocollo osservato gli indirizzi hanno lunghezza fissa:
    # SB0000011 = 9 caratteri
    # SB100001  = 8 caratteri
    if len(source) != 9:
        raise ValueError(
            "L'indirizzo sorgente ViP deve essere lungo 9 caratteri: "
            f"{source_address}"
        )

    if len(entrance) != 8:
        raise ValueError(
            "L'indirizzo del posto esterno deve essere lungo 8 caratteri: "
            f"{entrance_address}"
        )

    payload = (
        # Intestazione interna CTPP osservata.
        bytes.fromhex("c01867edeb3500280001")

        # Sorgente e destinazione.
        + source
        + b"\x00"
        + entrance
        + b"\x00"

        # Campi ancora da interpretare.
        + bytes.fromhex("000120c5dab02d")

        # Ripetizione indirizzo sorgente.
        + source
        + b"\x00"

        # Tipo/flag osservati.
        + b"II"
        + b"\xff\xff\xff\xff"

        # Coppia sorgente/destinazione finale.
        + source
        + b"\x00"
        + entrance
        + b"\x00\x00"
    )

    if len(payload) != 72:
        raise RuntimeError(
            f"Payload sessione ViP inatteso: {len(payload)} byte"
        )

    return (
        VIPER_FRAME_MAGIC
        + struct.pack("<H", len(payload))
        + struct.pack("<H", ctpp_channel)
        + b"\x00\x00"
        + payload
    )



def build_ctpp_progress_packet(
    ctpp_channel: int,
    client_transaction: bytes,
    source_address: str,
    entrance_address: str,
) -> bytes:
    if len(client_transaction) != 4:
        raise ValueError(
            "La transaction client deve contenere 4 byte"
        )

    source = source_address.encode("ascii")
    entrance = entrance_address.encode("ascii")

    payload = (
        b"\x00\x18"
        + client_transaction
        + b"\x00\x00"
        + b"\xff\xff\xff\xff"
        + source
        + b"\x00"
        + entrance
        + b"\x00\x00"
    )

    if len(payload) != 32:
        raise RuntimeError(
            f"Payload CTPP progress inatteso: {len(payload)}"
        )

    return (
        VIPER_FRAME_MAGIC
        + struct.pack("<H", len(payload))
        + struct.pack("<H", ctpp_channel)
        + b"\x00\x00"
        + payload
    )



def build_ctpp_rtpc_bind_packet(
    ctpp_channel: int,
    client_transaction: bytes,
    rtpc_channel: int,
    source_address: str,
    entrance_address: str,
) -> bytes:
    if len(client_transaction) != 4:
        raise ValueError(
            "La transaction CTPP deve contenere 4 byte"
        )

    source = source_address.encode("ascii")
    entrance = entrance_address.encode("ascii")

    if len(source) != 9:
        raise ValueError(
            f"Indirizzo sorgente non valido: {source_address}"
        )

    if len(entrance) != 8:
        raise ValueError(
            f"Indirizzo ingresso non valido: {entrance_address}"
        )

    # client_transaction = client_transaction

    payload = (
        b"\x40\x18"
        + client_transaction
        + b"\x00\x0a"
        + b"\x00\x11\x18\x02"
        + b"\x00\x00\x00\x00"
        + struct.pack("<H", rtpc_channel)
        + b"\x00\x00"
        + b"\xff\xff\xff\xff"
        + source
        + b"\x00"
        + entrance
        + b"\x00\x00"
    )

    if len(payload) != 44:
        raise RuntimeError(
            f"Payload RTPC bind inatteso: {len(payload)}"
        )

    return (
        VIPER_FRAME_MAGIC
        + struct.pack("<H", len(payload))
        + struct.pack("<H", ctpp_channel)
        + b"\x00\x00"
        + payload
    )




def build_ctpp_video_parameters_packet(
    ctpp_channel: int,
    transaction: bytes,
    rtpc_channel: int,
    source_address: str,
    entrance_address: str,
) -> bytes:
    if len(transaction) != 4:
        raise ValueError(
            "La transaction CTPP deve contenere 4 byte"
        )

    source = source_address.encode("ascii")
    entrance = entrance_address.encode("ascii")

    if len(source) != 9:
        raise ValueError(
            f"Indirizzo sorgente non valido: {source_address}"
        )

    if len(entrance) != 8:
        raise ValueError(
            f"Indirizzo ingresso non valido: {entrance_address}"
        )

    next_transaction = bytearray(transaction)

    # Nella cattura il terzo byte della transazione viene
    # incrementato prima del secondo messaggio multimediale.
    next_transaction[2] = (next_transaction[2] + 1) & 0xFF
    next_transaction[0] &= 0x7F

    payload = (
        b"\x40\x18"
        + bytes(next_transaction)
        + b"\x00\x1a"
        + b"\x00\x11\x14\x32"
        + b"\x00\x00\x00\x00"
        + struct.pack("<H", rtpc_channel)
        + b"\xff\xff"
        + bytes.fromhex(
            "e8030000"
            "2003e001"
            "2003e001"
            "10000000"
        )
        + b"\xff\xff\xff\xff"
        + source
        + b"\x00"
        + entrance
        + b"\x00\x00"
    )

    if len(payload) != 60:
        raise RuntimeError(
            f"Payload parametri video inatteso: {len(payload)}"
        )

    return (
        VIPER_FRAME_MAGIC
        + struct.pack("<H", len(payload))
        + struct.pack("<H", ctpp_channel)
        + b"\x00\x00"
        + payload
    )


def transform_server_ctpp_transaction(
    server_transaction: bytes,
) -> bytes:
    if len(server_transaction) != 4:
        raise ValueError(
            "La transaction CTPP deve contenere 4 byte"
        )

    return bytes(
        [
            server_transaction[0] & 0x7F,
            server_transaction[1],
            server_transaction[3],
            (server_transaction[2] + 1) & 0xFF,
        ]
    )

