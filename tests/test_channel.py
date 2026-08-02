from __future__ import annotations

import unittest

from liparios.comelit.channel import ViperChannel


class ChannelTest(unittest.TestCase):

    def test_valid_channel(self) -> None:
        channel = ViperChannel(
            name="UAUT",
            channel_id=0x6801,
        )

        channel.validate()

    def test_invalid_name_length(self) -> None:
        channel = ViperChannel(
            name="ABC",
            channel_id=0x6801,
        )

        with self.assertRaises(ValueError):
            channel.validate()

    def test_invalid_non_ascii_name(self) -> None:
        channel = ViperChannel(
            name="UÀUT",
            channel_id=0x6801,
        )

        with self.assertRaises(ValueError):
            channel.validate()

    def test_invalid_channel_id_too_high(self) -> None:
        channel = ViperChannel(
            name="UAUT",
            channel_id=70000,
        )

        with self.assertRaises(ValueError):
            channel.validate()

    def test_invalid_channel_id_negative(self) -> None:
        channel = ViperChannel(
            name="UAUT",
            channel_id=-1,
        )

        with self.assertRaises(ValueError):
            channel.validate()

    def test_invalid_flags(self) -> None:
        channel = ViperChannel(
            name="UAUT",
            channel_id=0x6801,
            flags=256,
        )

        with self.assertRaises(ValueError):
            channel.validate()


if __name__ == "__main__":
    unittest.main()

