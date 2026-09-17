import argparse

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