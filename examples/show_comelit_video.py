#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

import cv2

from liparios.comelit import (
    ComelitSession
#    load_comelit_config,
)

from config import load_comelit_config


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Visualizza lo streaming live Comelit"
    )

    parser.add_argument(
        "--config",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--device",
        required=True,
    )

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    config = load_comelit_config(
        path=args.config,
        device_id=args.device,
    )

    with ComelitSession(config) as session:
        for frame in session.frames():
            cv2.imshow("Citofono Comelit", frame)

            key = cv2.waitKey(1) & 0xFF

            if key in (27, ord("q")):
                break

    cv2.destroyAllWindows()


if __name__ == "__main__":
    main()

    
