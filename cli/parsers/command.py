from __future__ import annotations

import argparse
from SAVE.cli.parsers.export_options import add_common_export_arguments
from SAVE.cli.parsers.import_options import add_common_import_arguments

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

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Detect, import, and summarize a supported source file.",
    )

    add_common_import_arguments(inspect_parser)

    convert_parser = subparsers.add_parser(
        "convert",
        help="Import a source file and export it in another format.",
    )

    add_common_import_arguments(convert_parser)

    add_common_export_arguments(convert_parser)

    convert_parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help=(
            "Return exit code 1 when import or normalization warnings "
            "are present."
        ),
    )

    return parser