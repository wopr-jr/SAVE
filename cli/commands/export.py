from __future__ import annotations

import argparse

from SAVE.cli.cli_common import *
from SAVE.modules.exporter.interface import (
    ExportAvailableFormat,
    ExportErrorBase,
    export_file,
)


def command_export_file(
    *,
    checklist,
    args: argparse.Namespace,
) -> int:
    """
    Export an already-normalized Checklist.

    This function does not import source files or query a database.
    """
    try:
        export_result = export_file(
            checklist,
            args.destination,
            export_format=ExportAvailableFormat(args.export_format),
            options=build_export_options(args),
        )

    except ExportErrorBase as exc:
        print(f"Export failed: {exc}")
        return 5

    print(
        f"Exported {export_result.export_format.value} file to "
        f"{export_result.destination}"
    )

    print(
        f"Bytes written: {export_result.bytes_written}"
    )

    for warning in export_result.warnings:
        print(f"WARNING: {warning}")

    if args.fail_on_warning and result.warnings:
        return EXIT_WARNINGS

    return EXIT_SUCCESS