import argparse
from pathlib import Path

from SAVE.modules.exporter.interface import (
    ExportAvailableFormat,
    ExportOptions,
)

def add_common_export_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    """
    Add arguments that map directly to ExportOptions and export_file().

    Intended for reuse by:
      - save convert
      - save export
      - future report-generation commands
    """
    parser.add_argument(
        "destination",
        type=Path,
        help="Destination file path.",
    )

    parser.add_argument(
        "--to",
        "--export-format",
        dest="export_format",
        required=True,
        choices=[
            export_format.value
            for export_format in ExportAvailableFormat
        ],
        metavar="FORMAT",
        help=(
            "Requested output format. Supported values: "
            + ", ".join(
                export_format.value
                for export_format in ExportAvailableFormat
            )
        ),
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow SAVE to replace an existing destination file.",
    )

    parser.add_argument(
        "--create-parent-directories",
        action="store_true",
        help="Create missing parent directories for the destination path.",
    )

    parser.add_argument(
        "--no-atomic-write",
        dest="atomic_write",
        action="store_false",
        default=True,
        help=(
            "Write directly to the destination instead of writing to a "
            "temporary file and replacing the destination after success."
        ),
    )

    parser.add_argument(
        "--cklb-version",
        default="1.0",
        help=(
            "CKLB version to emit when exporting in CKLB format. "
            "Default: 1.0."
        ),
    )

    parser.add_argument(
        "--include-empty-fields",
        action="store_true",
        help=(
            "Request that exporters retain empty or null fields where "
            "the target format supports them."
        ),
    )

    parser.add_argument(
        "--no-source-metadata",
        dest="include_source_metadata",
        action="store_false",
        default=True,
        help=(
            "Do not include available SAVE source/provenance metadata "
            "in exported output."
        ),
    )
    
def build_export_options(
    args: argparse.Namespace,
) -> ExportOptions:
    return ExportOptions(
        overwrite=args.overwrite,
        create_parent_directories=args.create_parent_directories,
        atomic_write=args.atomic_write,
        cklb_version=args.cklb_version,
        include_empty_fields=args.include_empty_fields,
        include_source_metadata=args.include_source_metadata,
    )
    