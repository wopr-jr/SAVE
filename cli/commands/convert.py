 from __future__ import annotations

import argparse

from SAVE.cli.cli_common import *
from SAVE.cli.parsers.export_options import build_export_options
from SAVE.cli.parsers.import_options import build_import_options
from SAVE.modules.importer.interface import ImportErrorBase, import_file
 
def command_convert_file(
    args: argparse.Namespace,
) -> int:
    """
    Import a source file, normalize it, and export it to a requested format.
    """
    try:
        import_result = import_file(
            args.source,
        )

    except ImportErrorBase as exc:
        print(f"Import failed: {exc}")
        return EXIT_IMPORT_ERROR

    return command_export_file(
        checklist=import_result.checklist,
        args=args,
    )


        