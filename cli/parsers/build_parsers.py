from __future__ import annotations

import argparse

from SAVE.cli.parsers.export_options import (
    add_common_export_arguments,
)
from SAVE.cli.parsers.import_options import (
    add_common_import_arguments,
)
from SAVE.cli.parsers.persistence_options import (
    add_persistence_arguments,
)
from SAVE.cli.parsers.checklist_options import (
    add_checklist_reference_arguments,
)
from SAVE.cli.parsers.database_options import (
    add_database_argument,
)


def add_inspect_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect a stored normalized checklist.",
    )

    add_database_argument(inspect_parser)
    add_checklist_reference_arguments(inspect_parser)

    return inspect_parser


def add_import_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    """
    Add the `save import` command.

    Workflow:

        source file
            -> unified importer
            -> normalized Checklist
            -> unified persistence store
    """
    import_parser = subparsers.add_parser(
        "import",
        help="Import, normalize, and persist a supported source file.",
    )

    # Adds source plus CKL/CKLB/CSV/XCCDF import options.
    add_common_import_arguments(import_parser)

    # Adds persistence target, database/store location, and write options.
    add_persistence_arguments(import_parser)

    return import_parser


def add_convert_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    """
    Add the `save convert` command.

    Workflow:

        source file
            -> unified importer
            -> normalized Checklist
            -> unified exporter
            -> destination file
    """
    convert_parser = subparsers.add_parser(
        "convert",
        help=(
            "Import a supported source file and export it in another format."
        ),
    )

    # Adds `source` plus all importer options.
    add_common_import_arguments(convert_parser)

    # Adds `destination` plus all exporter options.
    add_common_export_arguments(convert_parser)

    return convert_parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="save",
        description=(
            "SAVE - Security and Vulnerability Evaluation "
            "STIG CLI utility."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # Register each command with argparse.
    add_inspect_parser(subparsers)
    add_import_parser(subparsers)
    add_convert_parser(subparsers)

    return parser