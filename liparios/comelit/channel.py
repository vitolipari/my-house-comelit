from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ViperChannel:
    name: str
    channel_id: int
    flags: int = 0

    def validate(self) -> None:
        if len(self.name) != 4:
            raise ValueError(
                "Il nome del canale deve essere composto da 4 caratteri"
            )

        if not self.name.isascii():
            raise ValueError(
                "Il nome del canale deve essere ASCII"
            )

        if not 0 <= self.channel_id <= 0xFFFF:
            raise ValueError(
                "Channel ID non valido"
            )

        if not 0 <= self.flags <= 0xFF:
            raise ValueError(
                "Flags non validi"
            )


