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

from SAVE.modules.export_stig import (
    ExportErrorBase,
    DestinationExistsError,
    ExportFormat,
    UnsupportedExportFormatError,
    export_file,
)


from SAVE.cli.parsers.export_options import build_export_options


EXIT_SUCCESS = 0
EXIT_WARNINGS = 1
EXIT_IMPORT_ERROR = 2
EXIT_UNSUPPORTED_FORMAT = 3
EXIT_EXPORT_ERROR = 4


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    

    
    if args.command == "import":
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

    if args.command == "inspect":
        print_summary(
            checklist=checklist,
            detected_format=result.detected_format,
            detection_confidence=result.detection.confidence,
            detection_evidence=result.detection.evidence,
            warnings=result.warnings,
        )

        return EXIT_WARNINGS if result.warnings else EXIT_SUCCESS

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


def print_summary(
    *,
    checklist,
    detected_format: ImportFormat,
    detection_confidence: str,
    detection_evidence: str,
    warnings: list[str],
) -> None:
    rule_count = sum(
        len(stig.rules)
        for stig in checklist.stigs
    )

    status_counts = {
        "open": 0,
        "not_a_finding": 0,
        "not_applicable": 0,
        "not_reviewed": 0,
    }

    for stig in checklist.stigs:
        for rule in stig.rules:
            status_counts[rule.status.value] = (
                status_counts.get(rule.status.value, 0) + 1
            )

    print("SAVE Import Summary")
    print(f"  Source file:          {checklist.source_filename}")
    print(f"  Detected format:      {detected_format.value}")
    print(f"  Detection confidence: {detection_confidence}")
    print(f"  Detection evidence:   {detection_evidence}")
    print(f"  Checklist UUID:       {checklist.checklist_uuid}")
    print(f"  Source SHA-256:       {checklist.source_sha256}")
    print(f"  Title:                {checklist.title or '<unspecified>'}")
    print(f"  STIG count:           {len(checklist.stigs)}")
    print(f"  Rule count:           {rule_count}")

    if checklist.asset:
        print(
            "  Target:               "
            f"{checklist.asset.host_name or '<unspecified>'}"
        )

        if checklist.asset.ip_address:
            print(f"  Target IP:            {checklist.asset.ip_address}")

    print()
    print("Finding Status Totals")
    print(f"  Open:                 {status_counts.get('open', 0)}")
    print(
        "  Not a Finding:        "
        f"{status_counts.get('not_a_finding', 0)}"
    )
    print(
        "  Not Applicable:       "
        f"{status_counts.get('not_applicable', 0)}"
    )
    print(
        "  Not Reviewed:         "
        f"{status_counts.get('not_reviewed', 0)}"
    )

    if warnings:
        print()
        print(f"Warnings ({len(warnings)}):")

        for warning in warnings:
            print(f"  - {warning}")


if __name__ == "__main__":
    sys.exit(main())