#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import time
import secrets

VIPER_MAGIC = b"\x00\x06"


@dataclass(frozen=True)
class ComelitConfig:
    device_id: str
    host: str
    tcp_port: int
    udp_port: int
    token: str
    entrance_address: str
    enabled: bool


@dataclass
class ViperMessage:
    channel_id: int
    payload: bytes


class ChannelAllocator:
    def __init__(
        self,
        start: int = 0x6801,
        restart_from: int = 0x6801,
    ) -> None:
        if not 0 <= start <= 0xFFFF:
            raise ValueError("Channel start deve essere compreso tra 0 e 65535")

        self._next = start
        self._restart_from = restart_from
        

    def allocate(self) -> int:
        channel_id = self._next

        self._next += 1

        if self._next > 0xFFFF:
            self._next = self._restart_from

        return channel_id


def require_non_empty_string(
    data: dict[str, Any],
    field: str,
) -> str:
    value = data.get(field)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Campo '{field}' mancante o non valido"
        )

    return value.strip()


def require_port(
    data: dict[str, Any],
    field: str,
    default: int | None = None,
) -> int:
    value = data.get(field, default)

    if not isinstance(value, int):
        raise ValueError(
            f"Campo '{field}' deve essere un numero intero"
        )

    if not 1 <= value <= 65535:
        raise ValueError(
            f"Campo '{field}' deve essere compreso tra 1 e 65535"
        )

    return value


def load_config(
    config_path: Path,
    device_id: str,
) -> ComelitConfig:
    if not config_path.exists():
        raise FileNotFoundError(
            f"File di configurazione non trovato: {config_path}"
        )

    if not config_path.is_file():
        raise ValueError(
            f"Il percorso non è un file: {config_path}"
        )

    try:
        content = config_path.read_text(encoding="utf-8")
        root = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"JSON non valido in {config_path}: "
            f"riga {exc.lineno}, colonna {exc.colno}"
        ) from exc

    if not isinstance(root, dict):
        raise ValueError(
            "La radice del file JSON deve essere un oggetto"
        )

    devices = root.get("devices")

    if not isinstance(devices, dict):
        raise ValueError(
            "Nel JSON deve essere presente l'oggetto 'devices'"
        )

    device = devices.get(device_id)

    if not isinstance(device, dict):
        available = ", ".join(sorted(devices.keys())) or "nessuno"

        raise ValueError(
            f"Dispositivo '{device_id}' non trovato. "
            f"Dispositivi disponibili: {available}"
        )

    device_type = require_non_empty_string(device, "type")

    if device_type != "COMELIT_VIPER":
        raise ValueError(
            f"Il dispositivo '{device_id}' non è COMELIT_VIPER: "
            f"{device_type}"
        )

    enabled = device.get("enabled", True)

    if not isinstance(enabled, bool):
        raise ValueError(
            "Campo 'enabled' deve essere true oppure false"
        )

    token = require_non_empty_string(device, "token")

    if token == "INSERISCI_QUI_IL_TOKEN":
        raise ValueError(
            "Il token Comelit non è stato configurato"
        )

    return ComelitConfig(
        device_id=device_id,
        host=require_non_empty_string(device, "host"),
        tcp_port=require_port(device, "tcpPort", 64100),
        udp_port=require_port(device, "udpPort", 64100),
        token=token,
        entrance_address=require_non_empty_string(
            device,
            "entranceAddress",
        ),
        enabled=enabled,
    )


def build_open_channel(
    channel_name: str,
    channel_id: int,
    flags: int = 0,
) -> bytes:
    if len(channel_name) != 4:
        raise ValueError(
            "Il nome del canale ViPER deve contenere 4 caratteri"
        )

    if not channel_name.isascii():
        raise ValueError(
            "Il nome del canale ViPER deve essere ASCII"
        )

    if not 0 <= channel_id <= 0xFFFF:
        raise ValueError("Channel ID non valido")

    if not 0 <= flags <= 0xFF:
        raise ValueError("Flags canale non validi")

    return (
        VIPER_MAGIC
        + struct.pack("<H", 15)
        + b"\x00\x00\x00\x00"
        + b"\xcd\xab\x01\x00\x07\x00\x00\x00"
        + channel_name.encode("ascii")
        + struct.pack("<H", channel_id)
        + bytes([flags])
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
        VIPER_MAGIC
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

    if header[:2] != VIPER_MAGIC:
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


def print_message(
    prefix: str,
    message: ViperMessage,
) -> None:
    print(
        f"{prefix} channel=0x{message.channel_id:04x} "
        f"length={len(message.payload)}"
    )

    decoded = decode_json_payload(message)

    if decoded is not None:
        print(
            json.dumps(
                decoded,
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(message.payload.hex())


class ComelitClient:
    def __init__(
        self,
        config: ComelitConfig,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.config = config
        self.timeout_seconds = timeout_seconds

        self.channels = ChannelAllocator()

        self.sock: socket.socket | None = None

        self.uaut_channel: int | None = None
        self.ucfg_channel: int | None = None

        self._next_message_id = 1

        self.udp_sock: socket.socket | None = None
        self.udpm_channel: int | None = None
        self.udp_session_id: int | None = None
        self.udp_sequence = secrets.randbelow(0x80) + 0x40

        self.ctpp_channel: int | None = None
        self.cspb_channel: int | None = None
        self.vip_source_address: str | None = None

        self.incoming_rtpc_channels: list[int] = []
        self.outgoing_rtpc_channels: list[int] = []

        self.ctpp_media_transaction: bytes | None = None
        


    def advance_media_session(self) -> bytes:
        if self.ctpp_channel is None:
            raise RuntimeError("Canale CTPP non disponibile")

        if self.vip_source_address is None:
            raise RuntimeError(
                "Indirizzo sorgente ViP non disponibile"
            )

        sock = self.require_socket()
        previous_timeout = sock.gettimeout()
        sock.settimeout(3.0)

        progress_count = 0
        last_client_transaction: bytes | None = None

        try:
            while progress_count < 2:
                message = recv_viper_message(sock)
                print_message("RX media progress", message)

                # Le richieste di apertura canale vengono comunque gestite.
                if self.handle_incoming_message(message):
                    continue

                if message.channel_id != self.ctpp_channel:
                    continue

                if len(message.payload) < 6:
                    continue

                if message.payload[:2] not in (
                    b"\x00\x18",
                    b"\x40\x18",
                ):
                    continue

                server_transaction = message.payload[2:6]

                client_transaction = (
                    transform_server_ctpp_transaction(
                        server_transaction
                    )
                )

                packet = build_ctpp_progress_packet(
                    ctpp_channel=self.ctpp_channel,
                    client_transaction=client_transaction,
                    source_address=self.vip_source_address,
                    entrance_address=self.config.entrance_address,
                )

                print(
                    "TX CTPP progress:",
                    f"server={server_transaction.hex()}",
                    f"client={client_transaction.hex()}",
                )
                print(packet.hex())

                sock.sendall(packet)

                last_client_transaction = client_transaction
                progress_count += 1

            if last_client_transaction is None:
                raise RuntimeError(
                    "Nessuna transaction CTPP media completata"
                )

            self.ctpp_media_transaction = last_client_transaction

            print(
                "Transaction CTPP pronta per RTPC:",
                last_client_transaction.hex(),
            )

            return last_client_transaction

        finally:
            sock.settimeout(previous_timeout)

    def negotiate_video_stream(self) -> None:
        if self.ctpp_channel is None:
            raise RuntimeError(
                "Canale CTPP non disponibile"
            )

        if self.vip_source_address is None:
            raise RuntimeError(
                "Indirizzo sorgente ViP non disponibile"
            )

        if self.ctpp_media_transaction is None:
            raise RuntimeError(
                "Transaction CTPP media non ricevuta"
            )

        if len(self.outgoing_rtpc_channels) < 2:
            raise RuntimeError(
                "Servono due canali RTPC client"
            )

        sock = self.require_socket()

        first_rtpc = self.outgoing_rtpc_channels[0]
        second_rtpc = self.outgoing_rtpc_channels[1]

        first_packet = build_ctpp_rtpc_bind_packet(
            ctpp_channel=self.ctpp_channel,
            client_transaction=self.ctpp_media_transaction,
            rtpc_channel=first_rtpc,
            source_address=self.vip_source_address,
            entrance_address=self.config.entrance_address,
        )

        print(
            f"TX bind RTPC 0x{first_rtpc:04x}"
        )
        print(first_packet.hex())

        sock.sendall(first_packet)

        time.sleep(0.1)

        second_packet = build_ctpp_video_parameters_packet(
            ctpp_channel=self.ctpp_channel,
            transaction=self.ctpp_media_transaction,
            rtpc_channel=second_rtpc,
            source_address=self.vip_source_address,
            entrance_address=self.config.entrance_address,
        )

        print(
            f"TX parametri video RTPC 0x{second_rtpc:04x}"
        )
        print(second_packet.hex())

        sock.sendall(second_packet)


    def __enter__(self) -> ComelitClient:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()


    def open_client_rtpc_channels(
        self,
        count: int = 2,
    ) -> list[int]:
        if count < 1:
            raise ValueError(
                "Deve essere aperto almeno un canale RTPC"
            )

        self.outgoing_rtpc_channels.clear()

        for index in range(count):
            channel_id = self.open_channel(
                "RTPC",
                flags=0x01,
            )

            self.outgoing_rtpc_channels.append(channel_id)

            print(
                f"Canale RTPC client {index + 1} aperto: "
                f"0x{channel_id:04x}"
            )

        return list(self.outgoing_rtpc_channels)
    


    def open_ctpp_channel(
        self,
        configuration: dict[str, Any],
    ) -> int:
        sock = self.require_socket()

        vip = configuration.get("vip")

        if not isinstance(vip, dict):
            raise RuntimeError(
                "Configurazione ViP non disponibile"
            )

        apt_address = vip.get("apt-address")
        apt_subaddress = vip.get("apt-subaddress")

        if not isinstance(apt_address, str):
            raise RuntimeError(
                "apt-address non disponibile"
            )

        if not isinstance(apt_subaddress, int):
            raise RuntimeError(
                "apt-subaddress non disponibile"
            )

        # Dalla cattura: SB000001 + 1 → SB0000011
        source_address = f"{apt_address}{apt_subaddress}"

        channel_id = self.channels.allocate()

        packet = build_open_ctpp_channel(
            channel_id=channel_id,
            vip_source_address=source_address,
        )

        print(
            f"TX open channel CTPP "
            f"id=0x{channel_id:04x} "
            f"source={source_address}"
        )

        sock.sendall(packet)

        try:
            response = recv_viper_message(sock)
        except socket.timeout as exc:
            raise RuntimeError(
                "Il Comelit non ha risposto alla richiesta iniziale CTPP. "
                "È possibile che una sessione precedente sia rimasta attiva "
                "o che il posto esterno risulti ancora occupato."
            ) from exc


        print_message("RX", response)

        self.validate_channel_ack(
            response=response,
            expected_channel_id=channel_id,
        )

        self.ctpp_channel = channel_id
        self.vip_source_address = source_address

        print("Canale CTPP aperto")

        return channel_id

    def open_cspb_channel(self) -> int:
        self.cspb_channel = self.open_channel("CSPB")

        print(
            f"Canale CSPB aperto: "
            f"0x{self.cspb_channel:04x}"
        )

        return self.cspb_channel



    def open_vip_transport(
        self,
        configuration: dict[str, Any],
    ) -> None:
        self.open_ctpp_channel(configuration)
        self.open_cspb_channel()
        time.sleep(0.2)


    def next_message_id(self) -> int:
        self._next_message_id += 1
        return self._next_message_id

    def require_socket(self) -> socket.socket:
        if self.sock is None:
            raise RuntimeError(
                "Il client Comelit non è connesso"
            )

        return self.sock

    def connect(self) -> None:
        if not self.config.enabled:
            raise RuntimeError(
                f"Il dispositivo '{self.config.device_id}' è disabilitato"
            )

        if self.sock is not None:
            return

        print(
            f"Connessione al dispositivo '{self.config.device_id}' "
            f"su {self.config.host}:{self.config.tcp_port}"
        )

        self.sock = socket.create_connection(
            (
                self.config.host,
                self.config.tcp_port,
            ),
            timeout=self.timeout_seconds,
        )

        self.sock.settimeout(self.timeout_seconds)

        print("Connessione TCP stabilita")

    def close(self) -> None:
        if self.udp_sock is not None:
            self.udp_sock.close()
            self.udp_sock = None

            print("Socket UDP chiusa")

        if self.sock is None:
            return

        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        self.sock.close()
        self.sock = None

        print("Connessione TCP chiusa")

    # def open_channel(
    #     self,
    #     channel_name: str,
    # ) -> int:
    #     sock = self.require_socket()
    #     channel_id = self.channels.allocate()

    #     print(
    #         f"TX open channel {channel_name} "
    #         f"id=0x{channel_id:04x}"
    #     )

    #     sock.sendall(
    #         build_open_channel(
    #             channel_name=channel_name,
    #             channel_id=channel_id,
    #         )
    #     )

    #     response = recv_viper_message(sock)
    #     print_message("RX", response)

    #     self.validate_channel_ack(
    #         response=response,
    #         expected_channel_id=channel_id,
    #     )

    #     return channel_id


    def start_entrance_session(self) -> bytes:
        if self.ctpp_channel is None:
            raise RuntimeError("Canale CTPP non ancora aperto")

        if self.vip_source_address is None:
            raise RuntimeError(
                "Indirizzo sorgente ViP non disponibile"
            )

        sock = self.require_socket()

        packet = build_start_entrance_session_packet(
            ctpp_channel=self.ctpp_channel,
            source_address=self.vip_source_address,
            entrance_address=self.config.entrance_address,
        )

        print(
            "TX richiesta sessione ViP "
            f"{self.vip_source_address} -> "
            f"{self.config.entrance_address}"
        )

        sock.sendall(packet)

        response = recv_viper_message(sock)
        print_message("RX start session", response)

        if response.channel_id != self.ctpp_channel:
            raise RuntimeError(
                "Risposta iniziale ricevuta su un canale inatteso: "
                f"0x{response.channel_id:04x}"
            )

        if len(response.payload) < 8:
            raise RuntimeError(
                "Risposta CTPP iniziale troppo corta: "
                f"{response.payload.hex()}"
            )

        if response.payload[:2] != b"\x00\x18":
            raise RuntimeError(
                "Risposta CTPP iniziale non riconosciuta: "
                f"{response.payload.hex()}"
            )

        # Esempio ricevuto:
        # 00 18 e7 ed 35 ec 00 00 ...
        server_transaction = response.payload[2:6]

        print(
            "Transaction CTPP ricevuta:",
            server_transaction.hex(),
        )

        return server_transaction


    def read_session_responses(
        self,
        max_messages: int = 10,
        timeout_seconds: float = 1.5,
    ) -> None:
        sock = self.require_socket()
        previous_timeout = sock.gettimeout()

        sock.settimeout(timeout_seconds)

        try:
            for _ in range(max_messages):
                try:
                    message = recv_viper_message(sock)
                except socket.timeout:
                    break

                print_message("RX session", message)

                if (
                    message.channel_id == self.ctpp_channel
                    and len(message.payload) >= 6
                    and message.payload[:2] == b"\x00\x18"
                ):
                    self.ctpp_media_transaction = message.payload[2:6]

                    print(
                        "Transaction CTPP media:",
                        self.ctpp_media_transaction.hex(),
                    )

                self.handle_incoming_message(message)

        finally:
            sock.settimeout(previous_timeout)



    def open_channel(
        self,
        channel_name: str,
        flags: int = 0,
    ) -> int:
        channel_id, _ = self.open_channel_with_response(
            channel_name,
            flags=flags,
        )

        return channel_id
    



    @staticmethod
    def validate_channel_ack(
        response: ViperMessage,
        expected_channel_id: int,
    ) -> None:
        if response.channel_id != 0:
            raise RuntimeError(
                "Risposta apertura canale ricevuta "
                "su un channel ID inatteso"
            )

        if len(response.payload) < 12:
            raise RuntimeError(
                "ACK apertura canale troppo corto"
            )

        if response.payload[:4] != b"\xcd\xab\x02\x00":
            raise RuntimeError(
                "ACK apertura canale non riconosciuto: "
                f"{response.payload.hex()}"
            )

        acknowledged_channel = struct.unpack(
            "<H",
            response.payload[8:10],
        )[0]

        if acknowledged_channel != expected_channel_id:
            raise RuntimeError(
                "Il Comelit ha confermato un canale diverso: "
                f"atteso 0x{expected_channel_id:04x}, "
                f"ricevuto 0x{acknowledged_channel:04x}"
            )

    def send_json(
        self,
        channel_id: int,
        payload: dict[str, Any],
    ) -> None:
        sock = self.require_socket()

        print(
            f"TX channel=0x{channel_id:04x} "
            f"message={payload.get('message')}"
        )

        sock.sendall(
            build_json_message(
                channel_id=channel_id,
                payload=payload,
            )
        )

    def wait_for_json_response(
        self,
        expected_message: str,
        expected_message_id: int | None = None,
    ) -> dict[str, Any]:
        sock = self.require_socket()

        while True:
            message = recv_viper_message(sock)
            print_message("RX", message)

            payload = decode_json_payload(message)

            if payload is None:
                continue

            if payload.get("message") != expected_message:
                continue

            if (
                expected_message_id is not None
                and payload.get("message-id") != expected_message_id
            ):
                continue

            return payload

    def login(self) -> dict[str, Any]:
        self.uaut_channel = self.open_channel("UAUT")

        message_id = self.next_message_id()

        request = {
            "message": "access",
            "user-token": self.config.token,
            "message-id": message_id,
            "message-type": "request",
        }

        self.send_json(
            channel_id=self.uaut_channel,
            payload=request,
        )

        response = self.wait_for_json_response(
            expected_message="access",
            expected_message_id=message_id,
        )

        if response.get("response-code") != 200:
            raise RuntimeError(
                "Accesso Comelit rifiutato: "
                f"{response.get('response-code')} "
                f"{response.get('response-string')}"
            )

        print("Access Granted")

        return response

    def get_configuration(self) -> dict[str, Any]:
        self.ucfg_channel = self.open_channel("UCFG")

        message_id = self.next_message_id()

        request = {
            "message": "get-configuration",
            "addressbooks": "none",
            "message-id": message_id,
            "message-type": "request",
        }

        self.send_json(
            channel_id=self.ucfg_channel,
            payload=request,
        )

        response = self.wait_for_json_response(
            expected_message="get-configuration",
            expected_message_id=message_id,
        )

        if response.get("response-code") != 200:
            raise RuntimeError(
                "Errore lettura configurazione: "
                f"{response.get('response-code')} "
                f"{response.get('response-string')}"
            )

        print("Configurazione ricevuta correttamente")

        return response
    

    def open_channel_with_response(
        self,
        channel_name: str,
        flags: int = 0,
    ) -> tuple[int, ViperMessage]:
        sock = self.require_socket()
        channel_id = self.channels.allocate()

        print(
            f"TX open channel {channel_name} "
            f"id=0x{channel_id:04x} "
            f"flags=0x{flags:02x}"
        )

        packet = build_open_channel(
            channel_name=channel_name,
            channel_id=channel_id,
            flags=flags,
        )

        print(f"TX open channel packet: {packet.hex()}")

        sock.sendall(packet)

        response = recv_viper_message(sock)
        print_message("RX", response)

        self.validate_channel_ack(
            response=response,
            expected_channel_id=channel_id,
        )

        return channel_id, response
    

    @staticmethod
    def parse_udpm_session_id(
        response: ViperMessage,
    ) -> int:
        """
        Estrae direttamente l'identificativo della sessione UDP
        restituito nell'ACK di apertura del canale UDPM.
        """

        if len(response.payload) < 18:
            raise RuntimeError(
                "La risposta UDPM non contiene "
                "l'identificativo della sessione UDP: "
                f"{response.payload.hex()}"
            )

        session_id = struct.unpack(
            "<H",
            response.payload[-2:],
        )[0]

        print(
            f"Identificativo associazione UDP: "
            f"0x{session_id:04x}"
        )

        return session_id
    

    def open_udp_transport(self) -> None:
        if self.udp_sock is not None:
            return

        tcp_sock = self.require_socket()

        local_ip = tcp_sock.getsockname()[0]

        udp_sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        udp_sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        # Porta 0: il sistema operativo sceglie una porta libera.
        udp_sock.bind((local_ip, 0))
        udp_sock.settimeout(self.timeout_seconds)

        local_host, local_port = udp_sock.getsockname()

        self.udp_sock = udp_sock

        print(
            f"Socket UDP in ascolto su "
            f"{local_host}:{local_port}"
        )

        channel_id, response = self.open_channel_with_response(
            "UDPM",
            flags=0x01,
        )

        self.udpm_channel = channel_id
        self.udp_session_id = self.parse_udpm_session_id(
            response
        )

        print(
            f"Canale UDPM aperto: "
            f"0x{channel_id:04x}"
        )

        print(
            f"Sessione UDP ViPER: "
            f"0x{self.udp_session_id:04x}"
        )    


    def associate_udp_transport(self) -> None:
        if self.udp_sock is None:
            raise RuntimeError(
                "Socket UDP non ancora aperta"
            )

        if self.udpm_channel is None:
            raise RuntimeError(
                "Canale UDPM non ancora aperto"
            )

        if self.udp_session_id is None:
            raise RuntimeError(
                "Sessione UDP non disponibile"
            )

        destination = (
            self.config.host,
            self.config.udp_port,
        )

        first_sequence = self.udp_sequence
        second_sequence = (first_sequence + 1) & 0xFF

        # La cattura dell'iPhone mostra prima 0xA8,
        # poi 0xA9. Il server risponde al secondo.
        for sequence in (first_sequence, second_sequence):
            packet = build_udp_association_packet(
                channel_id=self.udpm_channel,
                session_id=self.udp_session_id,
                sequence=sequence,
            )

            print(
                f"TX UDP association sequence="
                f"0x{sequence:02x} verso "
                f"{destination[0]}:{destination[1]}"
            )


            print(f"TX UDP packet: {packet.hex()}")

            self.udp_sock.sendto(
                packet,
                destination,
            )

            if sequence == first_sequence:
                time.sleep(0.3)

        print("In attesa della risposta UDP...")

        try:
            data, sender = self.udp_sock.recvfrom(65535)
        except socket.timeout as exc:
            raise RuntimeError(
                "Nessuna risposta all'associazione UDP dopo "
                "l'avvio della sessione verso il posto esterno "
                f"{self.config.entrance_address}."
            ) from exc

        print(
            f"RX UDP da {sender[0]}:{sender[1]} "
            f"length={len(data)}"
        )

        print(data.hex())

        self.validate_udp_association_response(data)

        confirmation_sequence = (second_sequence + 1) & 0xFF

        confirmation_packet = build_udp_association_packet(
            channel_id=self.udpm_channel,
            session_id=self.udp_session_id,
            sequence=confirmation_sequence,
            established=True,
        )

        print(
            f"TX conferma UDP sequence="
            f"0x{confirmation_sequence:02x}"
        )
        print(f"TX UDP packet: {confirmation_packet.hex()}")

        self.udp_sock.sendto(
            confirmation_packet,
            destination,
        )


    @staticmethod
    def parse_incoming_open_channel(
        message: ViperMessage,
    ) -> tuple[str, int, int] | None:
        if message.channel_id != 0:
            return None

        payload = message.payload

        if len(payload) < 15:
            return None

        if payload[:4] != b"\xcd\xab\x01\x00":
            return None

        body_length = struct.unpack("<I", payload[4:8])[0]

        if body_length < 7 or len(payload) < 8 + body_length:
            return None

        try:
            channel_name = payload[8:12].decode("ascii")
        except UnicodeDecodeError:
            return None

        channel_id = struct.unpack("<H", payload[12:14])[0]
        flags = payload[14]

        return channel_name, channel_id, flags


    def handle_incoming_message(
        self,
        message: ViperMessage,
    ) -> bool:
        incoming_channel = self.parse_incoming_open_channel(message)

        if incoming_channel is None:
            return False

        channel_name, channel_id, flags = incoming_channel

        print(
            f"RX richiesta apertura canale {channel_name} "
            f"id=0x{channel_id:04x} flags=0x{flags:02x}"
        )

        sock = self.require_socket()

        ack = build_channel_ack(channel_id)
        sock.sendall(ack)

        print(
            f"TX ACK canale {channel_name} "
            f"id=0x{channel_id:04x}"
        )

        if channel_name == "RTPC":
            self.incoming_rtpc_channels.append(channel_id)

        return True

    def validate_udp_association_response(
        self,
        data: bytes,
    ) -> None:
        if self.udpm_channel is None:
            raise RuntimeError(
                "Canale UDPM non disponibile"
            )

        if self.udp_session_id is None:
            raise RuntimeError(
                "Sessione UDP non disponibile"
            )

        if len(data) < 14:
            raise RuntimeError(
                f"Risposta UDP troppo corta: {data.hex()}"
            )

        if data[:2] != VIPER_MAGIC:
            raise RuntimeError(
                f"Magic UDP ViPER non valida: {data.hex()}"
            )

        payload_length = struct.unpack(
            "<H",
            data[2:4],
        )[0]

        channel_id = struct.unpack(
            "<H",
            data[4:6],
        )[0]

        session_id = struct.unpack(
            "<H",
            data[8:10],
        )[0]

        if payload_length != 6:
            raise RuntimeError(
                f"Payload UDP inatteso: {payload_length}"
            )

        if channel_id != self.udpm_channel:
            raise RuntimeError(
                "Risposta ricevuta su un canale UDP diverso: "
                f"atteso 0x{self.udpm_channel:04x}, "
                f"ricevuto 0x{channel_id:04x}"
            )

        if session_id != self.udp_session_id:
            raise RuntimeError(
                "Session ID UDP diversa: "
                f"attesa 0x{self.udp_session_id:04x}, "
                f"ricevuta 0x{session_id:04x}"
            )

        print("Associazione UDP ViPER completata")


    def confirm_entrance_session(
        self,
        server_transaction: bytes,
    ) -> None:
        if self.ctpp_channel is None:
            raise RuntimeError(
                "Canale CTPP non ancora aperto"
            )

        if self.vip_source_address is None:
            raise RuntimeError(
                "Indirizzo sorgente ViP non disponibile"
            )

        sock = self.require_socket()

        packet = build_confirm_entrance_session_packet(
            ctpp_channel=self.ctpp_channel,
            server_transaction=server_transaction,
            source_address=self.vip_source_address,
            entrance_address=self.config.entrance_address,
        )

        print(
            "TX conferma sessione CTPP "
            f"{self.vip_source_address} -> "
            f"{self.config.entrance_address}"
        )

        print(packet.hex())

        sock.sendall(packet)

        # Nella cattura A8 viene inviato circa 250 ms dopo.
        time.sleep(0.25)




def print_configuration_summary(
    config: ComelitConfig,
    response: dict[str, Any],
) -> None:
    viper_server = response.get("viper-server", {})
    vip = response.get("vip", {})

    print()
    print("Riepilogo dispositivo")
    print("---------------------")
    print(f"ID: {config.device_id}")
    print(
        "Server ViPER:",
        viper_server.get("local-address"),
        viper_server.get("local-tcp-port"),
        viper_server.get("local-udp-port"),
    )
    print(
        "Indirizzo appartamento:",
        vip.get("apt-address"),
    )
    print(
        "Posto esterno configurato:",
        config.entrance_address,
    )



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
        VIPER_MAGIC
        + struct.pack("<H", len(payload))
        + struct.pack("<H", ctpp_channel)
        + b"\x00\x00"
        + payload
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Client di test per dispositivi Comelit ViPER "
            "configurati tramite JSON"
        )
    )

    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/comelit-config.json"),
        help=(
            "Percorso del file JSON di configurazione "
            "(default: config/comelit-config.json)"
        ),
    )

    parser.add_argument(
        "--device",
        required=True,
        help=(
            "Identificativo del dispositivo presente "
            "nell'oggetto devices"
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout socket in secondi",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    try:
        config = load_config(
            config_path=args.config,
            device_id=args.device,
        )

        with ComelitClient(
            config=config,
            timeout_seconds=args.timeout,
        ) as client:
            client.login()
            configuration = client.get_configuration()

            client.open_vip_transport(configuration)

            ctpp_transaction = client.start_entrance_session()

            client.open_udp_transport()

            client.confirm_entrance_session(ctpp_transaction)

            client.associate_udp_transport()

            client.advance_media_session()

            client.open_client_rtpc_channels(count=2)

            client.negotiate_video_stream()

            # Ora aspettiamo il canale RTPC aperto dal Comelit
            # e gli altri messaggi conseguenti.
            client.read_session_responses(
                max_messages=10,
                timeout_seconds=2.0,
            )

            if not client.incoming_rtpc_channels:
                raise RuntimeError(
                    "Il Comelit non ha aperto il canale RTPC server"
                )

            print_configuration_summary(
                config=config,
                response=configuration,
            )

            # client.start_entrance_session()
            # client.read_session_responses()

            # if not client.incoming_rtpc_channels:
            #     raise RuntimeError(
            #         "Il Comelit non ha richiesto alcun canale RTPC"
            #     )

            print(
                "Canali RTPC richiesti dal Comelit:",
                ", ".join(
                    f"0x{channel_id:04x}"
                    for channel_id in client.incoming_rtpc_channels
                ),
            )


            print("In attesa dei pacchetti video...")

            # for index in range(20):
            #     data, sender = client.udp_sock.recvfrom(65535)

            #     print(
            #         f"VIDEO UDP #{index + 1} "
            #         f"da {sender[0]}:{sender[1]} "
            #         f"length={len(data)} "
            #         f"head={data[:24].hex()}"
            #     )

            if client.udp_sock is None:
                raise RuntimeError("Socket UDP non disponibile")

            print("In attesa dei pacchetti RTP/H.264...")

            video_packets = 0
            deadline = time.monotonic() + 10.0

            while video_packets < 20 and time.monotonic() < deadline:
                try:
                    data, sender = client.udp_sock.recvfrom(65535)
                except socket.timeout:
                    continue

                # I pacchetti di controllo UDPM sono lunghi 14 byte.
                if len(data) <= 20:
                    print(
                        f"UDP controllo da {sender[0]}:{sender[1]} "
                        f"length={len(data)} data={data.hex()}"
                    )
                    continue

                video_packets += 1

                print(
                    f"RTP/H264 #{video_packets} "
                    f"da {sender[0]}:{sender[1]} "
                    f"length={len(data)} "
                    f"head={data[:24].hex()}"
                )

            if video_packets == 0:
                raise RuntimeError(
                    "Negoziazione completata, ma nessun pacchetto "
                    "RTP/H.264 è stato ricevuto"
                )
            

            # print_configuration_summary(
            #     config=config,
            #     response=configuration,
            # )

    except (
        FileNotFoundError,
        ValueError,
        ConnectionError,
        TimeoutError,
        socket.timeout,
        OSError,
        RuntimeError,
    ) as exc:
        raise SystemExit(f"ERRORE: {exc}") from exc



def build_channel_ack(channel_id: int) -> bytes:
    if not 0 <= channel_id <= 0xFFFF:
        raise ValueError("Channel ID ACK non valido")

    payload = (
        b"\xcd\xab\x02\x00"
        + struct.pack("<I", 4)
        + struct.pack("<H", channel_id)
        + b"\x00\x00"
    )

    return (
        VIPER_MAGIC
        + struct.pack("<H", len(payload))
        + b"\x00\x00"
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
        VIPER_MAGIC
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
        VIPER_MAGIC
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
        VIPER_MAGIC
        + struct.pack("<H", len(payload))
        + struct.pack("<H", ctpp_channel)
        + b"\x00\x00"
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
        VIPER_MAGIC
        + struct.pack("<H", len(channel_payload) + 8)
        + b"\x00\x00\x00\x00"
        + b"\xcd\xab\x01\x00"
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
        VIPER_MAGIC
        + struct.pack("<H", len(payload))
        + struct.pack("<H", channel_id)
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
        VIPER_MAGIC
        + struct.pack("<H", len(payload))
        + struct.pack("<H", ctpp_channel)
        + b"\x00\x00"
        + payload
    )


if __name__ == "__main__":
    main()

