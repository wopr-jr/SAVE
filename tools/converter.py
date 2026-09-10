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

from SAVE.modules.export_cklb import export_cklb
from SAVE.modules.export_csv import export_csv
from SAVE.modules.export_normalized_json import export_normalized_json


EXIT_SUCCESS = 0
EXIT_WARNINGS = 1
EXIT_IMPORT_ERROR = 2
EXIT_UNSUPPORTED_FORMAT = 3
EXIT_EXPORT_ERROR = 4


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="save",
        description=(
            "SAVE - Security and Vulnerability Evaluation "
            "STIG import and conversion utility."
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

    convert_parser.add_argument(
        "destination",
        type=Path,
        help="Output file path.",
    )

    convert_parser.add_argument(
        "--output-format",
        required=True,
        choices=(
            "normalized-json",
            "csv",
            "cklb",
        ),
        help="Requested output format.",
    )

    convert_parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help=(
            "Return exit code 1 when import or normalization warnings "
            "are present."
        ),
    )

    return parser


def add_common_import_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument(
        "source",
        type=Path,
        help="Input source file.",
    )

    parser.add_argument(
        "--input-format",
        default=ImportFormat.AUTO.value,
        choices=tuple(format_type.value for format_type in ImportFormat),
        help=(
            "Source format. Default: auto, which uses content-based "
            "format detection."
        ),
    )

    parser.add_argument(
        "--checklist-uuid",
        default=None,
        help=(
            "Existing SAVE checklist UUID to reuse. Useful when re-importing "
            "an updated source for an existing checklist."
        ),
    )

    # CSV-specific options.
    parser.add_argument(
        "--csv-delimiter",
        default=",",
        help="CSV delimiter. Default: comma.",
    )

    parser.add_argument(
        "--csv-encoding",
        default="utf-8-sig",
        help="CSV file encoding. Default: utf-8-sig.",
    )

    parser.add_argument(
        "--default-stig-id",
        default=None,
        help=(
            "Fallback STIG ID for CSV sources that do not contain "
            "a STIG ID column."
        ),
    )

    parser.add_argument(
        "--default-stig-name",
        default=None,
        help=(
            "Fallback STIG name for CSV sources that do not contain "
            "a STIG name column."
        ),
    )

    # XCCDF-specific options.
    parser.add_argument(
        "--include-xccdf-test-results",
        action="store_true",
        help=(
            "Import XCCDF TestResult/rule-result data when present. "
            "Without this option, XCCDF Benchmark rules default to "
            "Not Reviewed."
        ),
    )

    parser.add_argument(
        "--xccdf-test-result-id",
        default=None,
        help=(
            "Specific XCCDF TestResult ID to import when a source contains "
            "multiple TestResult elements."
        ),
    )

    parser.add_argument(
        "--max-file-mb",
        type=int,
        default=100,
        help=(
            "Maximum accepted source-file size in MiB. "
            "Set to 0 to disable the size limit."
        ),
    )


def build_import_options(args: argparse.Namespace) -> ImportOptions:
    checklist_uuid = None

    if args.checklist_uuid:
        from uuid import UUID

        try:
            checklist_uuid = UUID(args.checklist_uuid)
        except ValueError as exc:
            raise ValueError(
                f"Invalid --checklist-uuid value: {args.checklist_uuid!r}"
            ) from exc

    max_file_bytes = None

    if args.max_file_mb > 0:
        max_file_bytes = args.max_file_mb * 1024 * 1024

    return ImportOptions(
        format_hint=ImportFormat(args.input_format),
        checklist_uuid=checklist_uuid,

        csv_delimiter=args.csv_delimiter,
        csv_encoding=args.csv_encoding,
        default_stig_id=args.default_stig_id,
        default_stig_name=args.default_stig_name,

        include_xccdf_test_results=args.include_xccdf_test_results,
        xccdf_test_result_id=args.xccdf_test_result_id,

        max_file_bytes=max_file_bytes,
    )


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