from __future__ import annotations

import argparse
from uuid import UUID


def checklist_uuid(value: str) -> UUID:
    try:
        return UUID(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid checklist UUID: {value!r}"
        ) from exc


def add_checklist_reference_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument(
        "--checklist-id",
        required=True,
        type=checklist_uuid,
        help="UUID of the checklist to inspect.",
    )