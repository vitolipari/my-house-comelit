from __future__ import annotations

import argparse
from pathlib import Path

import cv2

#from comelit_reference import load_config
#from liparios.comelit.session import ComelitSession
from liparios.comelit import (
    ComelitSession,
    load_comelit_config,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--config",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--device",
        required=True,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "/tmp/comelit-session-frame.jpg"
        ),
    )

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

#    config = load_config(
#        config_path=args.config,
#        device_id=args.device,
#    )
    config = load_comelit_config(
        path=args.config,
        device_id=args.device,
    )

    with ComelitSession(config) as session:
        for frame_number, frame in enumerate(
            session.frames(),
            start=1,
        ):
            print(
                f"Frame #{frame_number}: "
                f"{frame.shape[1]}x{frame.shape[0]}"
            )

            if not cv2.imwrite(
                str(args.output),
                frame,
            ):
                raise RuntimeError(
                    f"Impossibile salvare {args.output}"
                )

            print(
                f"Frame salvato in {args.output}"
            )

            break


if __name__ == "__main__":
    main()

