from __future__ import annotations

import unittest

from liparios.comelit.h264 import (
    ANNEX_B_START_CODE,
    H264Depacketizer,
    H264Parser,
)
from liparios.comelit.rtp import RtpPacket


def create_rtp_packet(
    payload: bytes,
    sequence: int,
    timestamp: int = 1000,
    marker: bool = False,
) -> RtpPacket:
    return RtpPacket(
        version=2,
        padding=False,
        extension=False,
        csrc_count=0,
        marker=marker,
        payload_type=99,
        sequence=sequence,
        timestamp=timestamp,
        ssrc=0x12345678,
        payload=payload,
    )


class H264ParserTest(unittest.TestCase):

    def test_sps(self) -> None:
        nal = H264Parser.parse(
            bytes.fromhex("6742001f")
        )

        self.assertEqual(nal.nal_type, 7)
        self.assertEqual(
            nal.to_annex_b(),
            ANNEX_B_START_CODE
            + bytes.fromhex("6742001f"),
        )

    def test_pps(self) -> None:
        nal = H264Parser.parse(
            bytes.fromhex("68ce3880")
        )

        self.assertEqual(nal.nal_type, 8)

    def test_single_nal_packet(self) -> None:
        depacketizer = H264Depacketizer()

        packet = create_rtp_packet(
            payload=bytes.fromhex("6742001f"),
            sequence=10,
        )

        result = depacketizer.push(packet)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].nal_type, 7)
        self.assertEqual(
            result[0].payload,
            bytes.fromhex("6742001f"),
        )

    def test_fu_a_reconstruction(self) -> None:
        depacketizer = H264Depacketizer()

        # FU indicator:
        # 0x7C = NRI 3 + tipo 28 FU-A
        #
        # FU header iniziale:
        # 0x85 = start + tipo NAL originale 5 (IDR)
        start_packet = create_rtp_packet(
            payload=bytes.fromhex(
                "7c85"
                "112233"
            ),
            sequence=100,
        )

        middle_packet = create_rtp_packet(
            payload=bytes.fromhex(
                "7c05"
                "445566"
            ),
            sequence=101,
        )

        # 0x45 = end + tipo NAL originale 5
        end_packet = create_rtp_packet(
            payload=bytes.fromhex(
                "7c45"
                "778899"
            ),
            sequence=102,
            marker=True,
        )

        self.assertEqual(
            depacketizer.push(start_packet),
            [],
        )

        self.assertEqual(
            depacketizer.push(middle_packet),
            [],
        )

        result = depacketizer.push(end_packet)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].nal_type, 5)

        # Header ricostruito:
        # NRI 3 + tipo IDR 5 = 0x65
        self.assertEqual(
            result[0].payload,
            bytes.fromhex(
                "65"
                "112233"
                "445566"
                "778899"
            ),
        )

    def test_fu_a_missing_packet(self) -> None:
        depacketizer = H264Depacketizer()

        start_packet = create_rtp_packet(
            payload=bytes.fromhex(
                "7c85112233"
            ),
            sequence=200,
        )

        end_packet = create_rtp_packet(
            payload=bytes.fromhex(
                "7c45778899"
            ),
            sequence=202,
        )

        depacketizer.push(start_packet)

        with self.assertRaises(ValueError):
            depacketizer.push(end_packet)

    def test_stap_a(self) -> None:
        depacketizer = H264Depacketizer()

        sps = bytes.fromhex("6742001f")
        pps = bytes.fromhex("68ce3880")

        stap_payload = (
            b"\x78"
            + len(sps).to_bytes(2, "big")
            + sps
            + len(pps).to_bytes(2, "big")
            + pps
        )

        packet = create_rtp_packet(
            payload=stap_payload,
            sequence=300,
        )

        result = depacketizer.push(packet)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].nal_type, 7)
        self.assertEqual(result[1].nal_type, 8)


if __name__ == "__main__":
    unittest.main()


