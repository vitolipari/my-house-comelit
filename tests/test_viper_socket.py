from __future__ import annotations

import socket
import unittest

from liparios.comelit.viper_socket import ViperSocket


class ViperSocketTest(unittest.TestCase):

    def test_receive_message(self) -> None:
        reader, writer = socket.socketpair()

        try:
            viper_socket = ViperSocket(reader)

            payload = b'{"message":"test"}'

            packet = (
                b"\x00\x06"
                + len(payload).to_bytes(2, "little")
                + b"\x03\x68"
                + b"\x00\x00"
                + payload
            )

            writer.sendall(packet)

            message = viper_socket.receive_message()

            self.assertEqual(
                message.channel_id,
                0x6803,
            )

            self.assertEqual(
                message.payload,
                payload,
            )

        finally:
            reader.close()
            writer.close()


if __name__ == "__main__":
    unittest.main()


