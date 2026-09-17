from __future__ import annotations

import argparse

from SAVE.modules.persistence.interface import (
    PersistenceOptions,
    PersistenceTarget,
    PersistenceWriteMode,
)


def positive_float(value: str) -> float:
    parsed = float(value)

    if parsed <= 0:
        raise argparse.ArgumentTypeError(
            "Value must be greater than zero."
        )

    return parsed


def add_persistence_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    """
    Add options used by SAVE's unified persistence interface.

    The location is intentionally a string rather than pathlib.Path because
    future REMOTE_SQL targets may use a DSN or connection URL rather than
    a filesystem path.
    """
    parser.add_argument(
        "--store-target",
        default=PersistenceTarget.SQLITE.value,
        choices=[
            target.value
            for target in PersistenceTarget
        ],
        help=(
            "Persistence backend target. "
            "Default: sqlite."
        ),
    )

    parser.add_argument(
        "--store-location",
        "--database",
        dest="store_location",
        default="save.db",
        help=(
            "Persistence location. For SQLite, this is the database path. "
            "Default: save.db."
        ),
    )

    parser.add_argument(
        "--write-mode",
        default=PersistenceWriteMode.UPSERT.value,
        choices=[
            mode.value
            for mode in PersistenceWriteMode
        ],
        help=(
            "Behavior when the checklist UUID already exists. "
            "Default: upsert."
        ),
    )

    parser.add_argument(
        "--create-parent-directories",
        action="store_true",
        help=(
            "Create missing parent directories for file-backed "
            "persistence targets."
        ),
    )

    parser.add_argument(
        "--sqlite-timeout-seconds",
        type=positive_float,
        default=5.0,
        help=(
            "SQLite lock timeout in seconds. "
            "Default: 5.0."
        ),
    )

    parser.add_argument(
        "--no-sqlite-wal",
        dest="sqlite_enable_wal",
        action="store_false",
        default=True,
        help=(
            "Disable SQLite write-ahead logging mode for this operation."
        ),
    )

    parser.add_argument(
        "--no-source-metadata",
        dest="include_source_metadata",
        action="store_false",
        default=True,
        help=(
            "Do not request source metadata persistence when the selected "
            "backend supports it."
        ),
    )

    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help=(
            "Do not persist the checklist when the importer reports "
            "non-fatal warnings."
        ),
    )


def build_persistence_options(
    args: argparse.Namespace,
) -> PersistenceOptions:
    """
    Convert parsed CLI arguments into a typed PersistenceOptions object.
    """
    return PersistenceOptions(
        create_parent_directories=args.create_parent_directories,
        sqlite_timeout_seconds=args.sqlite_timeout_seconds,
        sqlite_enable_wal=args.sqlite_enable_wal,
        include_source_metadata=args.include_source_metadata,
    )