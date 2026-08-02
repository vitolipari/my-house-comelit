from __future__ import annotations

from typing import Any

import av
import numpy as np

from .h264 import NalUnit


class H264DecoderError(RuntimeError):
    """Errore durante la decodifica del flusso H.264."""


class H264Decoder:
    """
    Decodifica NAL H.264 Annex-B in frame BGR compatibili
    con OpenCV.
    """

    def __init__(
        self,
        codec_context: Any | None = None,
    ) -> None:
        self._codec = (
            codec_context
            if codec_context is not None
            else av.CodecContext.create("h264", "r")
        )

        self._closed = False

    def push(
        self,
        nal_unit: NalUnit,
    ) -> list[np.ndarray]:
        """
        Inserisce una NAL completa e restituisce gli eventuali
        frame decodificati.

        È normale che una singola NAL non produca subito un frame.
        """

        if self._closed:
            raise H264DecoderError(
                "Il decoder H.264 è già stato chiuso"
            )

        annex_b_data = nal_unit.to_annex_b()

        return self.push_annex_b(annex_b_data)

    def push_annex_b(
        self,
        data: bytes,
    ) -> list[np.ndarray]:
        if self._closed:
            raise H264DecoderError(
                "Il decoder H.264 è già stato chiuso"
            )

        if not data:
            return []

        result: list[np.ndarray] = []

        try:
            packets = self._codec.parse(data)

            for packet in packets:
                decoded_frames = self._codec.decode(packet)

                for frame in decoded_frames:
                    image = frame.to_ndarray(
                        format="bgr24",
                    )

                    result.append(image)

        except Exception as exc:
            raise H264DecoderError(
                f"Errore PyAV durante la decodifica H.264: {exc}"
            ) from exc

        return result

    def flush(self) -> list[np.ndarray]:
        """
        Svuota i buffer interni del parser e del decoder.
        """

        if self._closed:
            return []

        result: list[np.ndarray] = []

        try:
            for packet in self._codec.parse(b""):
                for frame in self._codec.decode(packet):
                    result.append(
                        frame.to_ndarray(format="bgr24")
                    )

            for frame in self._codec.decode(None):
                result.append(
                    frame.to_ndarray(format="bgr24")
                )

        except Exception as exc:
            raise H264DecoderError(
                f"Errore durante il flush H.264: {exc}"
            ) from exc

        return result

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._codec = None

