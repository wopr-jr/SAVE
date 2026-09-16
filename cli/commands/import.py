from __future__ import annotations

import argparse

from SAVE.cli.parsers.import_options import build_import_options
from SAVE.modules.import_stig import (
    FormatDetectionError,
    ImportErrorBase,
    ImportFormat,
    ImportOptions,
    UnsupportedFormatError,
    import_file,
)

def command_import_file(args: argparse.Namespace) -> result.checklist: 
    try:
        options = build_import_options(args)
        result = import_file(
            args.source,
            options=options,
        )

    except UnsupportedFormatError as exc:
        print(f"Unsupported format: {exc}", file=sys.stderr)
        return EXIT_UNSUPPORTED_FORMAT

    except (FormatDetectionError, ImportErrorBase, OSError, ValueError) as exc:
        print(f"Import failed: {exc}", file=sys.stderr)
        return EXIT_IMPORT_ERROR

    checklist = result.checklist