from __future__ import annotations

import argparse
import sys
from pathlib import Path

from SAVE.modules.import_stig import (
    FormatDetectionError,
    ImportErrorBase,
    ImportFormat,
    ImportOptions,
    UnsupportedFormatError,
    import_file,
)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
  
    if args.command == "import":
        return command_import_file(args=args)
        

    if args.command == "inspect":
        return command_inspect_checklist(args=args)
        
    
    try:
        export_checklist(
            checklist=checklist,
            destination=args.destination,
            output_format=args.output_format,
        )

    except (OSError, ValueError) as exc:
        print(f"Export failed: {exc}", file=sys.stderr)
        return EXIT_EXPORT_ERROR

    print_summary(
        checklist=checklist,
        detected_format=result.detected_format,
        detection_confidence=result.detection.confidence,
        detection_evidence=result.detection.evidence,
        warnings=result.warnings,
    )

    print()
    print(f"Exported {args.output_format} to: {args.destination}")

    if args.fail_on_warning and result.warnings:
        return EXIT_WARNINGS

    return EXIT_SUCCESS











def export_checklist(
    *,
    checklist,
    destination: Path,
    output_format: str,
) -> None:
    """
    Dispatch normalized data to a SAVE exporter.

    Import detection and normalization are intentionally absent from this
    function. It receives only a validated normalized Checklist object.
    """
    match output_format:
        case "normalized-json":
            export_normalized_json(
                checklist,
                destination,
            )

        case "csv":
            export_csv(
                checklist,
                destination,
            )

        case "cklb":
            export_cklb(
                checklist,
                destination,
            )

        case _:
            raise ValueError(
                f"Unsupported output format: {output_format!r}"
            )



if __name__ == "__main__":
    sys.exit(main())