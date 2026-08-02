from __future__ import annotations

import socket
import struct
from collections.abc import Iterator

import numpy as np

#from comelit_reference import (
#    ComelitClient,
#    ComelitConfig,
#    VIPER_MAGIC,
#)
from .client import (
    ComelitClient,
    VIPER_MAGIC,
)
from .configuration import ComelitConfig

from .decoder import H264Decoder, H264DecoderError
from .h264 import H264Depacketizer
from .rtp import RtpParser
from time import monotonic


class ComelitSession(ComelitClient):
    """
    Sorgente video Comelit.

    Espone i frame decodificati come array NumPy BGR,
    direttamente utilizzabili da OpenCV.
    """

    def __init__(
        self,
        config: ComelitConfig,
        timeout_seconds: float = 5.0,
        stream_inactivity_timeout_seconds: float = 8.0,
    ) -> None:
        super().__init__(
            config=config,
            timeout_seconds=timeout_seconds,
        )

        if stream_inactivity_timeout_seconds <= 0:
            raise ValueError(
            "Il timeout di inattività video deve essere maggiore di zero"
        )

        self._rtp_parser = RtpParser()
        self._h264_depacketizer = H264Depacketizer()
        self._h264_decoder = H264Decoder()


        self._stream_inactivity_timeout_seconds = (
            stream_inactivity_timeout_seconds
        )

        self._stream_started = False
        self._closed = False

    def start_stream(self) -> None:
        """
        Completa autenticazione e negoziazione del flusso video.

        Può essere richiamato più volte senza riaprire la sessione.
        """

        if self._closed:
            raise RuntimeError(
                "La sessione Comelit è già stata chiusa"
            )

        if self._stream_started:
            return

        # __enter__ chiama già connect(), ma permettiamo anche
        # l'utilizzo senza context manager.
        self.connect()

        self.login()
        configuration = self.get_configuration()

        self.open_vip_transport(configuration)

        initial_transaction = (
            self.start_entrance_session()
        )

        self.open_udp_transport()

        self.confirm_entrance_session(
            initial_transaction
        )

        self.associate_udp_transport()
        self.advance_media_session()
        self.open_client_rtpc_channels(count=2)
        self.negotiate_video_stream()

        self.read_session_responses(
            max_messages=10,
            timeout_seconds=2.0,
        )

        if not self.incoming_rtpc_channels:
            raise RuntimeError(
                "Il Comelit non ha aperto il canale RTPC server"
            )

        if self.udp_sock is None:
            raise RuntimeError(
                "Socket UDP video non disponibile"
            )

        self._stream_started = True

    def frames(self) -> Iterator[np.ndarray]:
        """
        Restituisce continuamente frame OpenCV in formato BGR.

        Solleva TimeoutError se il flusso non produce frame
        per un periodo superiore alla soglia configurata.
        """

        self.start_stream()

        if self.udp_sock is None:
            raise RuntimeError(
                "Socket UDP video non disponibile"
            )

        # Un timeout breve consente di controllare periodicamente
        # da quanto tempo non arrivano frame video.
        self.udp_sock.settimeout(2.0)

        last_frame_at = monotonic()

        while not self._closed:
            try:
                datagram, _sender = self.udp_sock.recvfrom(
                    65535
                )

            except socket.timeout:
                inactive_seconds = (
                    monotonic() - last_frame_at
                )

                if (
                    inactive_seconds
                    >= self._stream_inactivity_timeout_seconds
                ):
                    raise TimeoutError(
                        "Flusso video Comelit inattivo da "
                        f"{inactive_seconds:.1f} secondi"
                    )

                continue

            except OSError:
                if self._closed:
                    return

                raise

            # I messaggi UDPM di controllo non contengono video.
            if len(datagram) <= 20:
                continue

            try:
                rtp_data = self._extract_rtp_data(
                    datagram
                )

                if rtp_data is None:
                    continue

                rtp_packet = self._rtp_parser.parse(
                    rtp_data
                )

                if rtp_packet.version != 2:
                    continue

                nal_units = self._h264_depacketizer.push(
                    rtp_packet
                )

                for nal_unit in nal_units:
                    decoded_frames = self._h264_decoder.push(
                        nal_unit
                    )

                    for frame in decoded_frames:
                        self._validate_frame(frame)

                        last_frame_at = monotonic()

                        yield frame

            except ValueError as exc:
                self._h264_depacketizer.reset()

                print(
                    "Pacchetto video Comelit ignorato: "
                    f"{exc}"
                )

            except H264DecoderError as exc:
                print(
                    "Errore decoder video Comelit: "
                    f"{exc}"
                )

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._stream_started = False

        self._h264_depacketizer.reset()

        try:
            self._h264_decoder.close()
        finally:
            super().close()

    @staticmethod
    def _extract_rtp_data(
        datagram: bytes,
    ) -> bytes | None:
        """
        Rimuove l'header esterno ViPER dal datagramma UDP.
        """

        if len(datagram) < 20:
            return None

        if datagram[:2] != VIPER_MAGIC:
            return None

        payload_length = struct.unpack(
            "<H",
            datagram[2:4],
        )[0]

        expected_length = 8 + payload_length

        if len(datagram) < expected_length:
            raise ValueError(
                "Datagramma ViPER incompleto: "
                f"attesi {expected_length} byte, "
                f"ricevuti {len(datagram)}"
            )

        return datagram[8:expected_length]

    @staticmethod
    def _validate_frame(
        frame: np.ndarray,
    ) -> None:
        if not isinstance(frame, np.ndarray):
            raise TypeError(
                "Il decoder non ha restituito un array NumPy"
            )

        if frame.dtype != np.uint8:
            raise TypeError(
                "Il frame deve avere dtype uint8"
            )

        if frame.ndim != 3 or frame.shape[2] != 3:
            raise ValueError(
                "Il frame deve avere forma "
                "(altezza, larghezza, 3)"
            )


