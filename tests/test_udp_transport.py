from __future__ import annotations

import socket
import unittest

from liparios.comelit.udp_transport import (
    UdpEndpoint,
    UdpTransport,
)


class UdpTransportTest(unittest.TestCase):

    def test_open_and_close(self) -> None:
        transport = UdpTransport(
            local_host="127.0.0.1",
            timeout_seconds=1.0,
        )

        endpoint = transport.open()

        self.assertTrue(transport.is_open)
        self.assertEqual(
            endpoint.host,
            "127.0.0.1",
        )
        self.assertGreater(endpoint.port, 0)

        transport.close()

        self.assertFalse(transport.is_open)

    def test_open_is_idempotent(self) -> None:
        transport = UdpTransport(
            local_host="127.0.0.1",
        )

        try:
            first = transport.open()
            second = transport.open()

            self.assertEqual(first, second)

        finally:
            transport.close()

    def test_send_and_receive(self) -> None:
        receiver = UdpTransport(
            local_host="127.0.0.1",
            timeout_seconds=1.0,
        )

        sender_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        try:
            receiver_endpoint = receiver.open()

            sender_socket.sendto(
                b"test-comelit",
                (
                    receiver_endpoint.host,
                    receiver_endpoint.port,
                ),
            )

            data, sender = receiver.receive()

            self.assertEqual(
                data,
                b"test-comelit",
            )
            self.assertEqual(
                sender.host,
                "127.0.0.1",
            )
            self.assertGreater(sender.port, 0)

        finally:
            sender_socket.close()
            receiver.close()

    def test_send(self) -> None:
        receiver_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )
        receiver_socket.bind(
            ("127.0.0.1", 0)
        )
        receiver_socket.settimeout(1.0)

        receiver_host, receiver_port = (
            receiver_socket.getsockname()
        )

        transport = UdpTransport(
            local_host="127.0.0.1",
            timeout_seconds=1.0,
        )

        try:
            transport.open()

            sent = transport.send(
                b"udp-packet",
                UdpEndpoint(
                    host=str(receiver_host),
                    port=int(receiver_port),
                ),
            )

            data, _ = receiver_socket.recvfrom(
                1024
            )

            self.assertEqual(sent, 10)
            self.assertEqual(
                data,
                b"udp-packet",
            )

        finally:
            transport.close()
            receiver_socket.close()


if __name__ == "__main__":
    unittest.main()


