from __future__ import annotations

import unittest

import numpy as np

from liparios.comelit.decoder import (
    H264Decoder,
    H264DecoderError,
)
from liparios.comelit.h264 import NalUnit


class FakeVideoFrame:
    def __init__(
        self,
        image: np.ndarray,
    ) -> None:
        self._image = image
        self.requested_format: str | None = None

    def to_ndarray(
        self,
        format: str,
    ) -> np.ndarray:
        self.requested_format = format
        return self._image


class FakeCodecContext:
    def __init__(self) -> None:
        self.received_data: list[bytes] = []
        self.frame = FakeVideoFrame(
            np.zeros(
                (480, 640, 3),
                dtype=np.uint8,
            )
        )

    def parse(
        self,
        data: bytes,
    ) -> list[bytes]:
        self.received_data.append(data)

        if not data:
            return []

        return [data]

    def decode(
        self,
        packet: bytes | None,
    ) -> list[FakeVideoFrame]:
        if packet is None:
            return []

        return [self.frame]


class H264DecoderTest(unittest.TestCase):

    def test_decode_nal_to_bgr_frame(self) -> None:
        codec = FakeCodecContext()
        decoder = H264Decoder(
            codec_context=codec,
        )

        nal = NalUnit(
            nal_type=7,
            forbidden_zero=False,
            nri=3,
            payload=bytes.fromhex(
                "6742001f"
            ),
        )

        frames = decoder.push(nal)

        self.assertEqual(len(frames), 1)

        self.assertEqual(
            frames[0].shape,
            (480, 640, 3),
        )

        self.assertEqual(
            codec.received_data[0],
            bytes.fromhex(
                "00000001"
                "6742001f"
            ),
        )

        self.assertEqual(
            codec.frame.requested_format,
            "bgr24",
        )

    def test_empty_annex_b_data(self) -> None:
        decoder = H264Decoder(
            codec_context=FakeCodecContext(),
        )

        self.assertEqual(
            decoder.push_annex_b(b""),
            [],
        )

    def test_push_after_close(self) -> None:
        decoder = H264Decoder(
            codec_context=FakeCodecContext(),
        )

        decoder.close()

        nal = NalUnit(
            nal_type=7,
            forbidden_zero=False,
            nri=3,
            payload=bytes.fromhex(
                "6742001f"
            ),
        )

        with self.assertRaises(H264DecoderError):
            decoder.push(nal)


if __name__ == "__main__":
    unittest.main()

