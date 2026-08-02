from __future__ import annotations

import socket
import unittest

from liparios.comelit.channel import ViperChannel
from liparios.comelit.channel_manager import (
    ChannelManager,
    ChannelOpenError,
)
from liparios.comelit.viper_socket import ViperSocket
from liparios.comelit.channel_manager import (
    ChannelAllocator,
    ChannelManager,
    ChannelOpenError,
)

class ChannelManagerTest(unittest.TestCase):

    def test_open_channel(self) -> None:
        client_socket, server_socket = socket.socketpair()

        try:
            manager = ChannelManager(
                ViperSocket(client_socket)
            )

            channel = ViperChannel(
                name="UAUT",
                channel_id=0x6801,
                flags=0,
            )

            server_socket.sendall(
                bytes.fromhex(
                    "00060c0000000000"
                    "cdab020004000000"
                    "01680000"
                )
            )

            opened_channel = manager.open(channel)

            self.assertEqual(
                opened_channel,
                channel,
            )

            request = server_socket.recv(1024)

            self.assertEqual(
                request.hex(),
                "00060f0000000000"
                "cdab010007000000"
                "55415554"
                "0168"
                "00",
            )

        finally:
            client_socket.close()
            server_socket.close()

    def test_reject_ack_for_different_channel(self) -> None:
        client_socket, server_socket = socket.socketpair()

        try:
            manager = ChannelManager(
                ViperSocket(client_socket)
            )

            channel = ViperChannel(
                name="UAUT",
                channel_id=0x6801,
            )

            server_socket.sendall(
                bytes.fromhex(
                    "00060c0000000000"
                    "cdab020004000000"
                    "02680000"
                )
            )

            with self.assertRaises(ChannelOpenError):
                manager.open(channel)

        finally:
            client_socket.close()
            server_socket.close()

    def test_acknowledge_incoming_channel(self) -> None:
        client_socket, server_socket = socket.socketpair()

        try:
            manager = ChannelManager(
                ViperSocket(client_socket)
            )

            manager.acknowledge(0xDF6A)

            packet = server_socket.recv(1024)

            self.assertEqual(
                packet.hex(),
                "00060c0000000000"
                "cdab020004000000"
                "6adf0000",
            )

        finally:
            client_socket.close()
            server_socket.close()


    def test_open_channel_with_response(self) -> None:
        client_socket, server_socket = socket.socketpair()

        try:
            manager = ChannelManager(
                ViperSocket(client_socket)
            )

            channel = ViperChannel(
                name="UDPM",
                channel_id=0x6805,
                flags=0x01,
            )

            server_socket.sendall(
                bytes.fromhex(
                    "0006120000000000"
                    "cdab020004000000"
                    "05680000"
                    "02000000"
                    "0310"
                )
            )

            opened_channel, response = (
                manager.open_with_response(channel)
            )

            self.assertEqual(opened_channel, channel)
            self.assertEqual(response.channel_id, 0)
            self.assertEqual(
                response.payload.hex(),
                "cdab020004000000"
                "05680000"
                "02000000"
                "0310",
            )

        finally:
            client_socket.close()
            server_socket.close()


def test_channel_allocator(self) -> None:
    allocator = ChannelAllocator(
        start=0x6801,
    )

    self.assertEqual(
        allocator.allocate(),
        0x6801,
    )

    self.assertEqual(
        allocator.allocate(),
        0x6802,
    )


def test_channel_allocator_rejects_invalid_start(self) -> None:
    with self.assertRaises(ValueError):
        ChannelAllocator(start=-1)

    with self.assertRaises(ValueError):
        ChannelAllocator(start=0x10000)





if __name__ == "__main__":
    unittest.main()


