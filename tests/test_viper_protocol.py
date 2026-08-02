from __future__ import annotations

import json
import socket
import unittest

from liparios.comelit.viper_protocol import (
    VIPER_CONTROL_MAGIC,
    VIPER_FRAME_MAGIC,
    ViperMessage,
    build_channel_ack,
    build_json_message,
    build_open_channel,
    build_open_ctpp_channel,
    build_udp_association_packet,
    decode_json_payload,
    recv_viper_message,
    build_open_channel_from_model
)
from liparios.comelit.channel import ViperChannel


class ViperProtocolTest(unittest.TestCase):

    def test_magic_values(self) -> None:
        self.assertEqual(VIPER_FRAME_MAGIC, b"\x00\x06")
        self.assertEqual(VIPER_CONTROL_MAGIC, b"\xcd\xab")

    def test_build_open_uaut_channel(self) -> None:
        packet = build_open_channel(
            channel_name="UAUT",
            channel_id=0x6801,
            flags=0x00,
        )

        self.assertEqual(
            packet.hex(),
            "00060f0000000000"
            "cdab010007000000"
            "55415554"
            "0168"
            "00",
        )

    def test_build_open_udpm_channel(self) -> None:
        packet = build_open_channel(
            channel_name="UDPM",
            channel_id=0x6805,
            flags=0x01,
        )

        self.assertEqual(
            packet.hex(),
            "00060f0000000000"
            "cdab010007000000"
            "5544504d"
            "0568"
            "01",
        )

    def test_build_channel_ack(self) -> None:
        packet = build_channel_ack(0xDF6A)

        self.assertEqual(
            packet.hex(),
            "00060c0000000000"
            "cdab020004000000"
            "6adf0000",
        )

    def test_build_open_ctpp_channel(self) -> None:
        packet = build_open_ctpp_channel(
            channel_id=0x6803,
            vip_source_address="SB0000011",
        )

        self.assertEqual(
            packet.hex(),
            "00061e0000000000"
            "cdab010016000000"
            "43545050"
            "03680000"
            "0a000000"
            "53423030303030313100",
        )

    def test_build_udp_association_packet(self) -> None:
        packet = build_udp_association_packet(
            channel_id=0x6805,
            session_id=0x1003,
            sequence=0x46,
            established=False,
        )

        self.assertEqual(
            packet.hex(),
            "00060600"
            "05680000"
            "031000460080",
        )

    def test_build_udp_confirmation_packet(self) -> None:
        packet = build_udp_association_packet(
            channel_id=0x6805,
            session_id=0x1003,
            sequence=0x48,
            established=True,
        )

        self.assertEqual(
            packet.hex(),
            "00060600"
            "05680000"
            "031000480180",
        )

    def test_build_json_message(self) -> None:
        payload = {
            "message": "access",
            "message-id": 2,
        }

        packet = build_json_message(
            channel_id=0x6801,
            payload=payload,
        )

        expected_body = json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        self.assertEqual(packet[:2], b"\x00\x06")
        self.assertEqual(
            int.from_bytes(packet[2:4], "little"),
            len(expected_body),
        )
        self.assertEqual(packet[4:6], b"\x01\x68")
        self.assertEqual(packet[6:8], b"\x00\x00")
        self.assertEqual(packet[8:], expected_body)

    def test_decode_json_payload(self) -> None:
        message = ViperMessage(
            channel_id=0x6801,
            payload=b'{"message":"access","response-code":200}',
        )

        decoded = decode_json_payload(message)

        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["message"], "access")
        self.assertEqual(decoded["response-code"], 200)

    def test_recv_viper_message(self) -> None:
        reader, writer = socket.socketpair()

        try:
            payload = b'{"message":"test"}'

            packet = (
                b"\x00\x06"
                + len(payload).to_bytes(2, "little")
                + b"\x03\x68"
                + b"\x00\x00"
                + payload
            )

            writer.sendall(packet)

            message = recv_viper_message(reader)

            self.assertEqual(message.channel_id, 0x6803)
            self.assertEqual(message.payload, payload)

        finally:
            reader.close()
            writer.close()



    def test_build_open_channel_from_model(self) -> None:
        channel = ViperChannel(
            name="UAUT",
            channel_id=0x6801,
            flags=0x00,
        )

        packet = build_open_channel_from_model(channel)

        self.assertEqual(
            packet.hex(),
            "00060f0000000000"
            "cdab010007000000"
            "55415554"
            "0168"
            "00",
        )


if __name__ == "__main__":
    unittest.main()


