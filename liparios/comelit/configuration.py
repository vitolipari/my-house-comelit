from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ComelitConfig:
    device_id: str
    host: str
    tcp_port: int
    udp_port: int
    token: str
    entrance_address: str
    enabled: bool


def _require_non_empty_string(
    data: dict[str, Any],
    field: str,
) -> str:
    value = data.get(field)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Campo '{field}' mancante o non valido"
        )

    return value.strip()


def _require_port(
    data: dict[str, Any],
    field: str,
    default: int | None = None,
) -> int:
    value = data.get(field, default)

    if not isinstance(value, int):
        raise ValueError(
            f"Campo '{field}' deve essere un numero intero"
        )

    if not 1 <= value <= 65535:
        raise ValueError(
            f"Campo '{field}' deve essere compreso tra 1 e 65535"
        )

    return value


def load_comelit_config(
    path: Path | str,
    device_id: str,
) -> ComelitConfig:
    config_path = Path(path)

    if not config_path.exists():
        raise FileNotFoundError(
            f"File di configurazione non trovato: {config_path}"
        )

    if not config_path.is_file():
        raise ValueError(
            f"Il percorso non è un file: {config_path}"
        )

    try:
        root = json.loads(
            config_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"JSON non valido in {config_path}: "
            f"riga {exc.lineno}, colonna {exc.colno}"
        ) from exc

    if not isinstance(root, dict):
        raise ValueError(
            "La radice del JSON deve essere un oggetto"
        )

    availableDevices = root.get("availableDevices")

    if not isinstance(availableDevices, dict):
        raise ValueError(
            "Nel JSON deve essere presente l'oggetto 'availableDevices'"
        )

    device = availableDevices.get(device_id)

    if not isinstance(device, dict):
        available = ", ".join(sorted(availableDevices.keys())) or "nessuno"

        raise ValueError(
            f"Dispositivo '{device_id}' non trovato. "
            f"Disponibili: {available}"
        )

    device_type = _require_non_empty_string(device, "type")

    if device_type != "COMELIT_VIPER":
        raise ValueError(
            f"Il dispositivo '{device_id}' non è COMELIT_VIPER: "
            f"{device_type}"
        )

    enabled = device.get("enabled", True)

    if not isinstance(enabled, bool):
        raise ValueError(
            "Campo 'enabled' deve essere true oppure false"
        )

    token = _require_non_empty_string(device, "token")

    if token == "INSERISCI_QUI_IL_TOKEN":
        raise ValueError(
            "Il token Comelit non è stato configurato"
        )

    return ComelitConfig(
        device_id=device_id,
        host=_require_non_empty_string(device, "host"),
        tcp_port=_require_port(device, "tcpPort", 64100),
        udp_port=_require_port(device, "udpPort", 64100),
        token=token,
        entrance_address=_require_non_empty_string(
            device,
            "entranceAddress",
        ),
        enabled=enabled,
    )

