from __future__ import annotations

import unittest

from liparios.comelit.rtp import (
    RtpParser,
)


class RtpParserTest(unittest.TestCase):

    def test_parse(self):

        packet = bytes.fromhex(

            # RTP Header

            "8063"
            "4193"
            "00020f58"
            "81a57503"

            # Payload

            "6742001f"

        )

        rtp = RtpParser.parse(packet)

        self.assertEqual(rtp.version, 2)
        self.assertFalse(rtp.padding)
        self.assertFalse(rtp.extension)

        self.assertEqual(rtp.payload_type, 99)

        self.assertEqual(rtp.sequence, 0x4193)

        self.assertEqual(
            rtp.timestamp,
            0x00020F58,
        )

        self.assertEqual(
            rtp.ssrc,
            0x81A57503,
        )

        self.assertEqual(
            rtp.payload,
            bytes.fromhex("6742001f"),
        )


if __name__ == "__main__":
    unittest.main()
