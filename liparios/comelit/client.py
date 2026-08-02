#!/usr/bin/env python3

from __future__ import annotations

import json
import socket
import struct
from typing import Any
import time
import secrets
from .udp_transport import UdpTransport
from . import viper_protocol as viper
from .channel import ViperChannel
from .viper_socket import ViperSocket
from .configuration import ComelitConfig
from .viper_protocol import (
    ViperMessage,
    build_open_ctpp_channel,
    build_udp_association_packet,
    decode_json_payload,
)
from .ctpp import (
    build_confirm_entrance_session_packet,
    build_ctpp_progress_packet,
    build_ctpp_rtpc_bind_packet,
    build_ctpp_video_parameters_packet,
    build_start_entrance_session_packet,
    transform_server_ctpp_transaction,
)
from .channel_manager import (
    ChannelAllocator,
    ChannelManager,
)
from .udp_transport import (
    UdpEndpoint,
    UdpTransport,
)


VIPER_MAGIC = b"\x00\x06"



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

        self.viper_socket: ViperSocket | None = None
        self.channel_manager: ChannelManager | None = None

        self.udp_transport: UdpTransport | None = None



    def require_udp_transport(self) -> UdpTransport:
        if self.udp_transport is None:
            raise RuntimeError(
                "Trasporto UDP non inizializzato"
            )

        return self.udp_transport


    def require_channel_manager(self) -> ChannelManager:
        if self.channel_manager is None:
            raise RuntimeError(
                "ChannelManager non inizializzato"
            )

        return self.channel_manager


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
                message = self.require_viper_socket().receive_message()
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
            response = self.require_viper_socket().receive_message()
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

    def require_viper_socket(self) -> ViperSocket:
        if self.viper_socket is None:
            raise RuntimeError(
                "ViperSocket non inizializzato"
            )

        return self.viper_socket


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

        self.viper_socket = ViperSocket(self.sock)
        self.channel_manager = ChannelManager(self.viper_socket)

        print("Connessione TCP stabilita")

    def close(self) -> None:
        if self.udp_transport is not None:
            self.udp_transport.close()
            self.udp_transport = None
            self.udp_sock = None

            print("Socket UDP chiusa")

        elif self.udp_sock is not None:
            # Fallback temporaneo per eventuali sessioni
            # create prima dell'introduzione di UdpTransport.
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
        self.viper_socket = None
        self.channel_manager = None

        print("Connessione TCP chiusa")


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

        response = self.require_viper_socket().receive_message()
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
                    message = self.require_viper_socket().receive_message()
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
            viper.build_json_message(
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
            message = self.require_viper_socket().receive_message()
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
        channel_id = self.channels.allocate()

        channel = ViperChannel(
            name=channel_name,
            channel_id=channel_id,
            flags=flags,
        )

        manager = self.require_channel_manager()

        _, response = manager.open_with_response(channel)

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
        if self.udp_transport is not None:
            return

        tcp_sock = self.require_socket()
        local_ip = str(tcp_sock.getsockname()[0])

        transport = UdpTransport(
            local_host=local_ip,
            timeout_seconds=self.timeout_seconds,
        )

        local_endpoint = transport.open()

        self.udp_transport = transport

        # Compatibilità temporanea con session.py e con
        # i metodi che usano ancora direttamente udp_sock.
        self.udp_sock = transport.socket

        print(
            "Socket UDP in ascolto su "
            f"{local_endpoint.host}:{local_endpoint.port}"
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

        manager = self.require_channel_manager()
        manager.acknowledge(channel_id)

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



