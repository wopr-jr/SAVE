from __future__ import annotations

import argparse
import sys

from SAVE.cli.parsers.export_options import build_export_options
from SAVE.cli.parsers.import_options import build_import_options

from SAVE.modules.importer.interface import (
    ImportErrorBase,
    import_file,
)

from SAVE.modules.exporter.interface import (
    ExportAvailableFormat,
    ExportErrorBase,
    export_file,
)


def command_convert_file(
    args: argparse.Namespace,
) -> int:
    try:
        import_result = import_file(
            args.source,
            options=build_import_options(args),
        )

    except (ImportErrorBase, ValueError, OSError) as exc:
        print(
            f"Import failed: {exc}",
            file=sys.stderr,
        )
        return 4

    try:
        export_result = export_file(
            import_result.checklist,
            args.destination,
            export_format=ExportAvailableFormat(args.export_format),
            options=build_export_options(args),
        )

    except (ExportErrorBase, ValueError, OSError) as exc:
        print(
            f"Export failed: {exc}",
            file=sys.stderr,
        )
        return 5

    print(
        f"Converted {args.source} to "
        f"{export_result.destination}"
    )

    print(
        f"Output format: "
        f"{export_result.export_format.value}"
    )

    print(
        f"Bytes written: "
        f"{export_result.bytes_written}"
    )

    for warning in import_result.warnings:
        print(
            f"IMPORT WARNING: {warning}",
            file=sys.stderr,
        )

    for warning in export_result.warnings:
        print(
            f"EXPORT WARNING: {warning}",
            file=sys.stderr,
        )

    if import_result.warnings or export_result.warnings:
        return 1

    return 0